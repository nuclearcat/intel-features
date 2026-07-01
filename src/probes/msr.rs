//! Model-Specific Register probe (root).
//!
//! Reads (never writes) `/dev/cpu/0/msr` via `pread`. This is the first probe that
//! needs privilege: without root — or without the `msr` module — it emits a single
//! `msr` status detection explaining why, and every MSR-only feature is simply left
//! "not probed" (hidden by default, shown with `--all`).
//!
//! Individual MSRs may `#GP` if unimplemented on this part; the kernel surfaces that as
//! `EIO`, which we treat as "feature not determinable here" and skip. We gate the most
//! commonly-absent reads (VMX capability MSRs) behind a probe read so we don't provoke
//! avoidable faults.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use crate::model::{Detection, Status};
use crate::probes::{Context, Probe};

pub struct MsrProbe;

const SRC: &str = "msr";

impl Probe for MsrProbe {
    fn name(&self) -> &'static str {
        SRC
    }

    fn detect(&self, _ctx: &Context) -> Vec<(&'static str, Detection)> {
        let mut out = Vec::new();
        let msr = match Msr::open(0) {
            Ok(m) => m,
            Err(e) => {
                let reason = match e.kind() {
                    io::ErrorKind::PermissionDenied => "requires root".to_string(),
                    io::ErrorKind::NotFound => "no /dev/cpu/0/msr (modprobe msr)".to_string(),
                    other => format!("open failed: {other:?}"),
                };
                out.push(("msr", Detection::with_detail(Status::Disabled, SRC, reason)));
                return out;
            }
        };
        out.push((
            "msr",
            Detection::with_detail(Status::Enabled, SRC, "/dev/cpu/0/msr readable"),
        ));

        arch_capabilities(&msr, &mut out);
        feature_control(&msr, &mut out);
        vmx_capabilities(&msr, &mut out);
        thermal_and_power(&msr, &mut out);
        misc(&msr, &mut out);
        out
    }
}

/// A single CPU's MSR file. `pread` keeps reads stateless and `&self`.
struct Msr(File);

impl Msr {
    fn open(cpu: u32) -> io::Result<Msr> {
        File::open(format!("/dev/cpu/{cpu}/msr")).map(Msr)
    }

    /// Read one 64-bit MSR. `Err(EIO)` means the register `#GP`'d (not implemented).
    fn read(&self, msr: u32) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.0.read_exact_at(&mut buf, msr as u64)?;
        Ok(u64::from_le_bytes(buf))
    }
}

fn bit(v: u64, n: u32) -> bool {
    (v >> n) & 1 == 1
}

fn present(cond: bool) -> Status {
    if cond {
        Status::Present
    } else {
        Status::Absent
    }
}

// ---- IA32_ARCH_CAPABILITIES (0x10A) -------------------------------------------------

fn arch_capabilities(msr: &Msr, out: &mut Vec<(&'static str, Detection)>) {
    let Ok(v) = msr.read(0x10A) else { return };
    // (id, bit) — bit positions per Intel SDM / arch/x86/include/asm/msr-index.h.
    let bits = [
        ("rdcl_no", 0),
        ("eibrs", 1),
        ("rsba", 2),
        ("ssb_no", 4),
        ("mds_no", 5),
        ("if_pschange_no", 6),
        ("tsx_ctrl", 7),
        ("taa_no", 8),
        ("misc_package_ctls", 10),
        ("fb_clear", 17),
        ("rrsba", 19),
        ("bhi_no", 20),
        ("pbrsb_no", 24),
        ("gds_no", 26),
        ("rfds_no", 27),
    ];
    for (id, b) in bits {
        let detail = format!("IA32_ARCH_CAPABILITIES[{b}] (value {v:#x})");
        out.push((id, Detection::with_detail(present(bit(v, b)), SRC, detail)));
    }
}

// ---- IA32_FEATURE_CONTROL (0x3A) ----------------------------------------------------

fn feature_control(msr: &Msr, out: &mut Vec<(&'static str, Detection)>) {
    let Ok(v) = msr.read(0x3A) else { return };
    let locked = bit(v, 0);
    let vmx_out = bit(v, 2);
    let vmx_in = bit(v, 1);

    out.push((
        "feature_control_locked",
        Detection::with_detail(
            if locked {
                Status::Enabled
            } else {
                Status::Disabled
            },
            SRC,
            if locked {
                "locked by firmware"
            } else {
                "unlocked"
            },
        ),
    ));

    // VMX enablement is authoritative here: firmware can lock it off even when the
    // silicon supports it. Aggregates onto the cpuid/procfs `vmx` capability.
    let vmx = if !locked {
        Detection::with_detail(Status::Present, SRC, "FEATURE_CONTROL unlocked")
    } else if vmx_out {
        Detection::with_detail(Status::Enabled, SRC, "locked; VMX enabled outside SMX")
    } else if vmx_in {
        Detection::with_detail(Status::Enabled, SRC, "locked; VMX enabled (SMX only)")
    } else {
        Detection::with_detail(Status::Disabled, SRC, "locked; VMX disabled in firmware")
    };
    out.push(("vmx", vmx));

    // Only assert SGX enablement when actually enabled — a clear bit may just mean the
    // silicon lacks SGX, which cpuid already reports.
    if bit(v, 18) {
        out.push((
            "sgx",
            Detection::with_detail(Status::Enabled, SRC, "FEATURE_CONTROL SGX enabled"),
        ));
    }
    if bit(v, 17) {
        out.push((
            "sgx_lc",
            Detection::with_detail(Status::Enabled, SRC, "SGX launch control enabled"),
        ));
    }
}

// ---- VMX capability MSRs (0x481 / 0x48B / 0x48C) ------------------------------------

fn vmx_capabilities(msr: &Msr, out: &mut Vec<(&'static str, Detection)>) {
    // IA32_VMX_BASIC (0x480) only reads when VMX is supported; use it as the gate so we
    // don't #GP on non-VMX parts.
    if msr.read(0x480).is_err() {
        return;
    }

    // Secondary processor-based controls (0x48B): a control is *available* when its bit
    // is set in the allowed-1 (high) dword.
    if let Ok(v) = msr.read(0x48B) {
        let avail = |b: u32| present(bit(v, 32 + b));
        out.push((
            "ept",
            Detection::with_detail(avail(1), SRC, "VMX_PROCBASED_CTLS2[1]"),
        ));
        out.push((
            "vpid",
            Detection::with_detail(avail(5), SRC, "VMX_PROCBASED_CTLS2[5]"),
        ));
        out.push((
            "unrestricted_guest",
            Detection::with_detail(avail(7), SRC, "VMX_PROCBASED_CTLS2[7]"),
        ));
        out.push((
            "apicv",
            Detection::with_detail(avail(9), SRC, "virtual-interrupt delivery"),
        ));
        out.push((
            "vmcs_shadow",
            Detection::with_detail(avail(14), SRC, "VMX_PROCBASED_CTLS2[14]"),
        ));
    }

    // Pin-based controls (0x481): posted interrupts = allowed-1 bit 7.
    if let Ok(v) = msr.read(0x481) {
        out.push((
            "posted_intr",
            Detection::with_detail(present(bit(v, 32 + 7)), SRC, "VMX_PINBASED_CTLS[7]"),
        ));
    }

    // EPT/VPID capabilities (0x48C).
    if let Ok(v) = msr.read(0x48C) {
        out.push((
            "ept_ad",
            Detection::with_detail(present(bit(v, 21)), SRC, "VMX_EPT_VPID_CAP[21]"),
        ));
        out.push((
            "ept_1gb",
            Detection::with_detail(present(bit(v, 17)), SRC, "VMX_EPT_VPID_CAP[17]"),
        ));
    }
}

// ---- Thermal & RAPL (0x1A2 / 0x606 / 0x610 / 0x614) --------------------------------

fn thermal_and_power(msr: &Msr, out: &mut Vec<(&'static str, Detection)>) {
    if let Ok(v) = msr.read(0x1A2) {
        let tjmax = (v >> 16) & 0xff;
        out.push((
            "tjmax",
            Detection::with_detail(Status::Present, SRC, format!("{tjmax} °C")),
        ));
    }

    // RAPL power unit (0x606): power unit = 1 / 2^(bits[3:0]) watts.
    if let Ok(units) = msr.read(0x606) {
        let power_w = 1.0 / (1u64 << (units & 0xf)) as f64;
        if let Ok(v) = msr.read(0x614) {
            let tdp = (v & 0x7fff) as f64 * power_w;
            out.push((
                "pkg_tdp",
                Detection::with_detail(Status::Present, SRC, format!("{tdp:.0} W")),
            ));
        }
        if let Ok(v) = msr.read(0x610) {
            let pl1 = (v & 0x7fff) as f64 * power_w;
            let pl2 = ((v >> 32) & 0x7fff) as f64 * power_w;
            out.push((
                "pkg_power_limit",
                Detection::with_detail(
                    Status::Present,
                    SRC,
                    format!("PL1 {pl1:.0} W, PL2 {pl2:.0} W"),
                ),
            ));
        }
    }
}

// ---- Misc (0x34 SMI count, 0x13A Boot Guard) ---------------------------------------

fn misc(msr: &Msr, out: &mut Vec<(&'static str, Detection)>) {
    if let Ok(v) = msr.read(0x34) {
        let count = v & 0xffff_ffff;
        out.push((
            "smi_count",
            Detection::with_detail(Status::Present, SRC, format!("{count} SMIs")),
        ));
    }
    if let Ok(v) = msr.read(0x13A) {
        out.push((
            "boot_guard",
            Detection::with_detail(Status::Present, SRC, format!("SACM_INFO = {v:#x}")),
        ));
    }
}
