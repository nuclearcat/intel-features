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
    "intel_uncore_freq",
    "acpi_cppc",
    "umwait_control",
    "rapl",
    "resctrl",
    "ipmi",
    "itco_wdt",
    "bluetooth",
    "sgx",
    "edac",
    "memory_ecc",
    "memory_dimms",
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
        detect_uncore_freq(ctx, &mut out);
        detect_cppc(ctx, &mut out);
        detect_umwait(ctx, &mut out);
        detect_rapl(ctx, &mut out);
        detect_resctrl(ctx, &mut out);
        detect_edac(ctx, &mut out);
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
        let ver = read_trim(ctx, "/sys/class/tpm/tpm0/tpm_version_major")
            .ok()
            .filter(|v| !v.is_empty());
        let detail = match ver {
            Some(v) => format!("tpm0 device present (TPM {v}.0)"),
            None => "tpm0 device present".to_string(),
        };
        (Status::Present, detail)
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

fn detect_uncore_freq(ctx: &Context, out: &mut Findings) {
    let root = Path::new("/sys/devices/system/cpu/intel_uncore_frequency");
    let entries = match ctx.reader.read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (status, detail) = match path_state(ctx, "/sys/devices/system/cpu") {
                Ok(true) => (Status::Absent, "no intel_uncore_frequency".to_string()),
                _ => (
                    Status::Unknown,
                    "cannot inspect /sys/devices/system/cpu".to_string(),
                ),
            };
            out.push(finding_detail(SRC, "intel_uncore_freq", status, detail));
            return;
        }
        Err(e) => {
            out.push(finding_detail(
                SRC,
                "intel_uncore_freq",
                Status::Unknown,
                format!("cannot inspect intel_uncore_frequency: {e}"),
            ));
            return;
        }
    };

    let mut domains = Vec::new();
    for entry in entries.into_iter().flatten() {
        if entry.file_name.starts_with("package_") || entry.file_name.starts_with("uncore") {
            domains.push(entry);
        }
    }
    domains.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    if domains.is_empty() {
        out.push(finding_detail(
            SRC,
            "intel_uncore_freq",
            Status::Absent,
            "no uncore frequency domains",
        ));
        return;
    }

    let first = &domains[0].path;
    let min_mhz = ctx
        .reader
        .read_to_string(&first.join("min_freq_khz"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|khz| khz / 1000);
    let max_mhz = ctx
        .reader
        .read_to_string(&first.join("max_freq_khz"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|khz| khz / 1000);
    let detail = match (min_mhz, max_mhz) {
        (Some(min), Some(max)) => {
            format!("{} domain(s), {min}–{max} MHz", domains.len())
        }
        _ => format!("{} domain(s)", domains.len()),
    };
    out.push(finding_detail(
        SRC,
        "intel_uncore_freq",
        Status::Enabled,
        detail,
    ));
}

fn detect_cppc(ctx: &Context, out: &mut Findings) {
    let cppc = "/sys/devices/system/cpu/cpu0/acpi_cppc";
    let (status, detail) = match path_state(ctx, cppc) {
        Ok(true) => {
            let highest = read_trim(ctx, "/sys/devices/system/cpu/cpu0/acpi_cppc/highest_perf")
                .ok()
                .filter(|v| !v.is_empty());
            let detail = match highest {
                Some(h) => format!("cpu0/acpi_cppc (highest_perf={h})"),
                None => "cpu0/acpi_cppc present".to_string(),
            };
            (Status::Present, detail)
        }
        Ok(false) => match path_state(ctx, "/sys/devices/system/cpu/cpu0") {
            Ok(true) => (Status::Absent, "no cpu0/acpi_cppc".to_string()),
            _ => (Status::Unknown, "cannot inspect cpu0 sysfs".to_string()),
        },
        Err(e) => (Status::Unknown, format!("cannot inspect acpi_cppc: {e}")),
    };
    out.push(finding_detail(SRC, "acpi_cppc", status, detail));
}

fn detect_umwait(ctx: &Context, out: &mut Findings) {
    let dir = "/sys/devices/system/cpu/umwait_control";
    let (status, detail) = match path_state(ctx, dir) {
        Ok(true) => {
            let c02 = read_trim(ctx, "/sys/devices/system/cpu/umwait_control/enable_c02").ok();
            let max_time = read_trim(ctx, "/sys/devices/system/cpu/umwait_control/max_time").ok();
            let suffix = max_time
                .as_deref()
                .map_or_else(String::new, |t| format!(", max_time={t}"));
            match c02.as_deref() {
                Some("1") => (Status::Enabled, format!("enable_c02=1{suffix}")),
                Some("0") => (
                    Status::Disabled,
                    format!("enable_c02=0 (C0.2 disabled){suffix}"),
                ),
                _ => (Status::Present, format!("umwait_control present{suffix}")),
            }
        }
        Ok(false) => match path_state(ctx, "/sys/devices/system/cpu") {
            Ok(true) => (Status::Absent, "no umwait_control".to_string()),
            _ => (Status::Unknown, "cannot inspect cpu sysfs".to_string()),
        },
        Err(e) => (
            Status::Unknown,
            format!("cannot inspect umwait_control: {e}"),
        ),
    };
    out.push(finding_detail(SRC, "umwait_control", status, detail));
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
        let is_msr_rapl = entry.file_name.starts_with("intel-rapl:");
        let is_mmio_rapl = entry.file_name.starts_with("intel-rapl-mmio:");
        if !is_msr_rapl && !is_mmio_rapl {
            continue;
        }
        match ctx.reader.read_to_string(&entry.path.join("name")) {
            Ok(name) => {
                let name = name.trim();
                if is_mmio_rapl {
                    domains.push(format!("{name} (mmio)"));
                } else {
                    domains.push(name.to_string());
                }
            }
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

fn detect_edac(ctx: &Context, out: &mut Findings) {
    let root = Path::new("/sys/devices/system/edac/mc");
    let entries = match ctx.reader.read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (status, detail) = match path_state(ctx, "/sys/devices/system") {
                Ok(true) => (Status::Absent, "no /sys/devices/system/edac/mc".to_string()),
                _ => (Status::Unknown, "cannot inspect edac sysfs".to_string()),
            };
            out.push(finding_detail(SRC, "edac", status, detail));
            return;
        }
        Err(e) => {
            let msg = format!("cannot inspect EDAC controllers: {e}");
            out.push(finding_detail(SRC, "edac", Status::Unknown, msg.clone()));
            out.push(finding_detail(
                SRC,
                "memory_ecc",
                Status::Unknown,
                msg.clone(),
            ));
            out.push(finding_detail(SRC, "memory_dimms", Status::Unknown, msg));
            return;
        }
    };

    let mut mcs = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            out.push(finding_detail(
                SRC,
                "edac",
                Status::Unknown,
                "EDAC controller enumeration incomplete",
            ));
            return;
        };
        if entry.file_name.starts_with("mc") {
            mcs.push(entry);
        }
    }
    mcs.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    if mcs.is_empty() {
        out.push(finding_detail(
            SRC,
            "edac",
            Status::Absent,
            "no active EDAC memory controllers",
        ));
        return;
    }

    let mut mc_names = Vec::new();
    let mut dimms = Vec::new();
    let mut ecc_modes = Vec::new();
    for mc in &mcs {
        let name = ctx
            .reader
            .read_to_string(&mc.path.join("mc_name"))
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| mc.file_name.clone());
        mc_names.push(name);

        let Ok(sub_entries) = ctx.reader.read_dir(&mc.path) else {
            continue;
        };
        let mut sub_dirs: Vec<_> = sub_entries
            .into_iter()
            .flatten()
            .filter(|e| e.file_name.starts_with("dimm") || e.file_name.starts_with("rank"))
            .collect();
        sub_dirs.sort_by(|a, b| a.file_name.cmp(&b.file_name));

        for dimm in sub_dirs {
            let size_mb = ctx
                .reader
                .read_to_string(&dimm.path.join("size"))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0);
            if size_mb == 0 {
                continue;
            }
            let mem_type = ctx
                .reader
                .read_to_string(&dimm.path.join("dimm_mem_type"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "RAM".to_string());
            if let Ok(mode) = ctx.reader.read_to_string(&dimm.path.join("dimm_edac_mode")) {
                let mode = mode.trim();
                if !mode.is_empty() && !ecc_modes.iter().any(|m| m == mode) {
                    ecc_modes.push(mode.to_string());
                }
            }
            let size_str = if size_mb >= 1024 && size_mb % 1024 == 0 {
                format!("{} GB", size_mb / 1024)
            } else {
                format!("{size_mb} MB")
            };
            dimms.push(format!("{size_str} {mem_type}"));
        }
    }

    let mode_suffix = if ecc_modes.is_empty() {
        String::new()
    } else {
        format!(" ({})", ecc_modes.join(", "))
    };
    out.push(finding_detail(
        SRC,
        "edac",
        Status::Enabled,
        format!("{}{mode_suffix}", mc_names.join(", ")),
    ));

    if !ecc_modes.is_empty() {
        let active_ecc = ecc_modes.iter().any(|m| !m.eq_ignore_ascii_case("none"));
        out.push(finding_detail(
            SRC,
            "memory_ecc",
            if active_ecc {
                Status::Enabled
            } else {
                Status::Absent
            },
            format!("EDAC mode: {}", ecc_modes.join(", ")),
        ));
    }
    if !dimms.is_empty() {
        out.push(finding_detail(
            SRC,
            "memory_dimms",
            Status::Present,
            format!("{} populated (EDAC): {}", dimms.len(), dimms.join(", ")),
        ));
    }
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

    let wdt_dir = "/sys/bus/platform/devices/iTCO_wdt";
    let (wdt_status, wdt_detail) = match path_state(ctx, wdt_dir) {
        Ok(true) => match ctx.reader.read_link(Path::new(&format!("{wdt_dir}/driver"))) {
            Ok(drv) => {
                let drv_name = drv
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "iTCO_wdt".to_string());
                (Status::Enabled, format!("iTCO_wdt, driver {drv_name}"))
            }
            Err(_) => (Status::Present, "iTCO_wdt platform device".to_string()),
        },
        Ok(false) => match path_state(ctx, "/sys/bus/platform/devices") {
            Ok(true) => (Status::Absent, "no iTCO_wdt device".to_string()),
            _ => (Status::Unknown, "cannot inspect platform bus".to_string()),
        },
        Err(e) => (Status::Unknown, format!("cannot inspect iTCO_wdt: {e}")),
    };
    out.push(finding_detail(SRC, "itco_wdt", wdt_status, wdt_detail));

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
