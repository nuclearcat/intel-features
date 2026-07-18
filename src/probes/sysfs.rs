//! Linux sysfs, procfs, and device-node runtime-state probe.

use std::io;
use std::path::Path;

use crate::model::Status;
use crate::probes::{finding_detail, Context, Findings, Probe, ProbeResult};

const SRC: &str = "linux-sysfs";
const FEATURES: &[&str] = &[
    "smt",
    "kvm",
    "tpm",
    "intel_pstate",
    "turbo",
    "intel_idle",
    "rapl",
    "resctrl",
    "ipmi",
    "bluetooth",
    "sgx",
];

pub struct SysfsProbe;

impl Probe for SysfsProbe {
    fn name(&self) -> &'static str {
        SRC
    }
    fn feature_ids(&self) -> Vec<&'static str> {
        FEATURES.to_vec()
    }

    fn detect(&self, ctx: &Context) -> ProbeResult {
        let mut out = Vec::new();
        detect_smt(ctx, &mut out);
        detect_kvm(ctx, &mut out);
        detect_tpm(ctx, &mut out);
        detect_pstate(ctx, &mut out);
        detect_idle(ctx, &mut out);
        detect_rapl(ctx, &mut out);
        detect_resctrl(ctx, &mut out);
        detect_nodes(ctx, &mut out);
        Ok(out)
    }
}

fn read_trim(ctx: &Context, path: &str) -> io::Result<String> {
    ctx.reader
        .read_to_string(Path::new(path))
        .map(|s| s.trim().to_string())
}

fn path_state(ctx: &Context, path: &str) -> Result<bool, io::Error> {
    match ctx.reader.metadata(Path::new(path)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn detect_smt(ctx: &Context, out: &mut Findings) {
    let path = "/sys/devices/system/cpu/smt/active";
    let (status, detail) = match read_trim(ctx, path) {
        Ok(v) if v == "1" => (Status::Enabled, "smt/active=1".into()),
        Ok(v) if v == "0" => (Status::Disabled, "smt/active=0".into()),
        Ok(v) => (Status::Unknown, format!("malformed smt/active={v:?}")),
        Err(e) => (Status::Unknown, format!("cannot inspect smt/active: {e}")),
    };
    out.push(finding_detail(SRC, "smt", status, detail));
}

fn detect_kvm(ctx: &Context, out: &mut Findings) {
    let path = Path::new("/dev/kvm");
    let det = match ctx.reader.metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            finding_detail(SRC, "kvm", Status::Absent, "/dev/kvm absent")
        }
        Err(e) => finding_detail(
            SRC,
            "kvm",
            Status::Unknown,
            format!("cannot inspect /dev/kvm: {e}"),
        ),
        Ok(_) => match ctx.reader.open_device(path, true) {
            Ok(()) => finding_detail(SRC, "kvm", Status::Enabled, "/dev/kvm openable"),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => finding_detail(
                SRC,
                "kvm",
                Status::Present,
                "/dev/kvm present but not permitted",
            ),
            Err(e) => finding_detail(
                SRC,
                "kvm",
                Status::Unknown,
                format!("/dev/kvm open failed: {e}"),
            ),
        },
    };
    out.push(det);
}

fn detect_tpm(ctx: &Context, out: &mut Findings) {
    let states = ["/sys/class/tpm/tpm0", "/dev/tpm0"].map(|p| path_state(ctx, p));
    let (status, detail) = if states.iter().any(|s| matches!(s, Ok(true))) {
        (Status::Present, "tpm0 device present".to_string())
    } else if states.iter().all(|s| matches!(s, Ok(false))) {
        (Status::Absent, "no tpm0 device".to_string())
    } else {
        (
            Status::Unknown,
            "cannot fully inspect TPM interfaces".to_string(),
        )
    };
    out.push(finding_detail(SRC, "tpm", status, detail));
}

fn detect_pstate(ctx: &Context, out: &mut Findings) {
    let driver_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver";
    match read_trim(ctx, driver_path) {
        Ok(driver) => {
            let governor =
                read_trim(ctx, "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").ok();
            let detail = governor.map_or_else(
                || format!("driver={driver}"),
                |g| format!("driver={driver}, governor={g}"),
            );
            out.push(finding_detail(
                SRC,
                "intel_pstate",
                if driver == "intel_pstate" {
                    Status::Enabled
                } else {
                    Status::Absent
                },
                detail,
            ));
        }
        Err(e) => out.push(finding_detail(
            SRC,
            "intel_pstate",
            Status::Unknown,
            format!("cannot inspect cpufreq driver: {e}"),
        )),
    }

    // intel_pstate mode is intentionally not treated as HWP enablement. IA32_PM_ENABLE
    // is the authoritative runtime source for HWP.
    match read_trim(ctx, "/sys/devices/system/cpu/intel_pstate/no_turbo") {
        Ok(v) if v == "0" => out.push(finding_detail(SRC, "turbo", Status::Enabled, "no_turbo=0")),
        Ok(v) if v == "1" => out.push(finding_detail(
            SRC,
            "turbo",
            Status::Disabled,
            "no_turbo=1 (turbo off)",
        )),
        Ok(v) => out.push(finding_detail(
            SRC,
            "turbo",
            Status::Unknown,
            format!("malformed no_turbo={v:?}"),
        )),
        Err(e) => out.push(finding_detail(
            SRC,
            "turbo",
            Status::Unknown,
            format!("cannot inspect turbo state: {e}"),
        )),
    }
}

fn detect_idle(ctx: &Context, out: &mut Findings) {
    let driver = match read_trim(ctx, "/sys/devices/system/cpu/cpuidle/current_driver") {
        Ok(driver) => driver,
        Err(e) => {
            out.push(finding_detail(
                SRC,
                "intel_idle",
                Status::Unknown,
                format!("cannot inspect cpuidle: {e}"),
            ));
            return;
        }
    };
    let mut states = Vec::new();
    for i in 0..16 {
        match read_trim(
            ctx,
            &format!("/sys/devices/system/cpu/cpu0/cpuidle/state{i}/name"),
        ) {
            Ok(name) => states.push(name),
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(_) => {
                out.push(finding_detail(
                    SRC,
                    "intel_idle",
                    Status::Unknown,
                    "cpuidle state enumeration incomplete",
                ));
                return;
            }
        }
    }
    out.push(finding_detail(
        SRC,
        "intel_idle",
        if driver == "intel_idle" {
            Status::Enabled
        } else {
            Status::Absent
        },
        format!("driver={driver}, states: {}", states.join(" ")),
    ));
}

fn detect_rapl(ctx: &Context, out: &mut Findings) {
    let root = Path::new("/sys/class/powercap");
    let entries = match ctx.reader.read_dir(root) {
        Ok(entries) => entries,
        Err(e) => {
            out.push(finding_detail(
                SRC,
                "rapl",
                Status::Unknown,
                format!("cannot inspect powercap: {e}"),
            ));
            return;
        }
    };
    let mut domains = Vec::new();
    let mut complete = true;
    for entry in entries {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        if !entry.file_name.starts_with("intel-rapl:") {
            continue;
        }
        match ctx.reader.read_to_string(&entry.path.join("name")) {
            Ok(name) => domains.push(name.trim().to_string()),
            Err(_) => complete = false,
        }
    }
    let (status, detail) = if !complete {
        (
            Status::Unknown,
            "powercap enumeration incomplete".to_string(),
        )
    } else if domains.is_empty() {
        (Status::Absent, "no intel-rapl powercap domains".to_string())
    } else {
        (Status::Enabled, format!("domains: {}", domains.join(", ")))
    };
    out.push(finding_detail(SRC, "rapl", status, detail));
}

fn detect_resctrl(ctx: &Context, out: &mut Findings) {
    let info = path_state(ctx, "/sys/fs/resctrl/info");
    let root = path_state(ctx, "/sys/fs/resctrl");
    let (status, detail) = match (info, root) {
        (Ok(true), _) => (Status::Enabled, "mounted at /sys/fs/resctrl"),
        (Ok(false), Ok(true)) => (Status::Present, "present but not mounted"),
        (Ok(false), Ok(false)) => (Status::Absent, "no /sys/fs/resctrl"),
        _ => (Status::Unknown, "cannot inspect resctrl"),
    };
    out.push(finding_detail(SRC, "resctrl", status, detail));
}

fn detect_nodes(ctx: &Context, out: &mut Findings) {
    let ipmi = ["/dev/ipmi0", "/dev/ipmi/0"].map(|p| path_state(ctx, p));
    let (status, detail) = if ipmi.iter().any(|s| matches!(s, Ok(true))) {
        (Status::Enabled, "IPMI device present")
    } else if ipmi.iter().all(|s| matches!(s, Ok(false))) {
        (Status::Absent, "no IPMI device")
    } else {
        (Status::Unknown, "cannot fully inspect IPMI devices")
    };
    out.push(finding_detail(SRC, "ipmi", status, detail));

    match ctx.reader.read_dir(Path::new("/sys/class/bluetooth")) {
        Ok(entries) if entries.iter().any(Result::is_err) => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Unknown,
            "bluetooth enumeration incomplete",
        )),
        Ok(entries) if entries.is_empty() => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Absent,
            "no bluetooth hci",
        )),
        Ok(_) => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Enabled,
            "hci device present",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Absent,
            "no bluetooth class",
        )),
        Err(e) => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Unknown,
            format!("cannot inspect bluetooth: {e}"),
        )),
    }

    match path_state(ctx, "/dev/sgx_enclave") {
        Ok(true) => out.push(finding_detail(
            SRC,
            "sgx",
            Status::Enabled,
            "/dev/sgx_enclave present",
        )),
        Ok(false) => {}
        Err(e) => out.push(finding_detail(
            SRC,
            "sgx",
            Status::Unknown,
            format!("cannot inspect SGX device: {e}"),
        )),
    }
}
