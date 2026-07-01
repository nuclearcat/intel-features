//! Linux sysfs / procfs / devnode probe.
//!
//! Where CPUID reports *silicon capability*, this probe reports *runtime state* the
//! kernel exposes without root: whether SMT is actually on, whether KVM is usable,
//! whether a TPM device is present. For SMT in particular this produces a second
//! detection on the same feature as CPUID — demonstrating the Present-vs-Enabled
//! distinction that is central to the tool's model.

use std::path::Path;

use crate::model::{Detection, Status};
use crate::probes::{Context, Probe};

pub struct SysfsProbe;

impl Probe for SysfsProbe {
    fn name(&self) -> &'static str {
        "linux-sysfs"
    }

    fn detect(&self, _ctx: &Context) -> Vec<(&'static str, Detection)> {
        let mut out = Vec::new();
        detect_smt(&mut out);
        detect_kvm(&mut out);
        detect_tpm(&mut out);
        detect_pstate(&mut out);
        detect_idle(&mut out);
        detect_rapl(&mut out);
        detect_resctrl(&mut out);
        out
    }
}

/// Read a sysfs file, trimmed. `None` if absent/unreadable.
fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// SMT enabled/disabled from `/sys/devices/system/cpu/smt/active`.
fn detect_smt(out: &mut Vec<(&'static str, Detection)>) {
    const PATH: &str = "/sys/devices/system/cpu/smt/active";
    match std::fs::read_to_string(PATH) {
        Ok(s) => {
            let det = match s.trim() {
                "1" => Detection::with_detail(Status::Enabled, "linux-sysfs", "smt/active=1"),
                "0" => Detection::with_detail(Status::Disabled, "linux-sysfs", "smt/active=0"),
                other => Detection::with_detail(
                    Status::Unknown,
                    "linux-sysfs",
                    format!("smt/active={other:?}"),
                ),
            };
            out.push(("smt", det));
        }
        Err(_) => {
            // Node absent → kernel without SMT control, or no SMT-capable CPU.
            out.push((
                "smt",
                Detection::with_detail(Status::Unknown, "linux-sysfs", "smt/active absent"),
            ));
        }
    }
}

/// KVM usability: `/dev/kvm` present (and, if we have access, openable).
fn detect_kvm(out: &mut Vec<(&'static str, Detection)>) {
    const PATH: &str = "/dev/kvm";
    if !Path::new(PATH).exists() {
        out.push((
            "kvm",
            Detection::with_detail(Status::Absent, "linux-sysfs", "/dev/kvm absent"),
        ));
        return;
    }
    let det = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PATH)
    {
        Ok(_) => Detection::with_detail(Status::Enabled, "linux-sysfs", "/dev/kvm openable"),
        Err(e) => Detection::with_detail(
            Status::Present,
            "linux-sysfs",
            format!("/dev/kvm present, open failed: {}", e.kind()),
        ),
    };
    out.push(("kvm", det));
}

/// TPM device presence via `/sys/class/tpm/tpm0` or `/dev/tpm0`.
fn detect_tpm(out: &mut Vec<(&'static str, Detection)>) {
    let present = Path::new("/sys/class/tpm/tpm0").exists() || Path::new("/dev/tpm0").exists();
    let det = if present {
        Detection::with_detail(Status::Present, "linux-sysfs", "tpm0 device present")
    } else {
        Detection::with_detail(Status::Absent, "linux-sysfs", "no tpm0 device")
    };
    out.push(("tpm", det));
}

/// P-state driver, and the runtime enabled/disabled state of HWP and Turbo. The turbo
/// and hwp detections aggregate onto the same features as CPUID's silicon capability,
/// giving the Present-vs-Enabled distinction.
fn detect_pstate(out: &mut Vec<(&'static str, Detection)>) {
    let driver = read_trim("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver");
    let governor = read_trim("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");

    if let Some(drv) = &driver {
        let is_pstate = drv == "intel_pstate";
        let detail = match &governor {
            Some(g) => format!("driver={drv}, governor={g}"),
            None => format!("driver={drv}"),
        };
        let status = if is_pstate {
            Status::Enabled
        } else {
            Status::Absent
        };
        out.push((
            "intel_pstate",
            Detection::with_detail(status, "linux-sysfs", detail),
        ));
    }

    // HWP is active when intel_pstate runs in "active" mode.
    if let Some(status) = read_trim("/sys/devices/system/cpu/intel_pstate/status") {
        let det = match status.as_str() {
            "active" => {
                Detection::with_detail(Status::Enabled, "linux-sysfs", "intel_pstate active (HWP)")
            }
            other => Detection::with_detail(
                Status::Present,
                "linux-sysfs",
                format!("intel_pstate mode: {other}"),
            ),
        };
        out.push(("hwp", det));
    }

    // Turbo: no_turbo=1 means turbo is disabled.
    if let Some(no_turbo) = read_trim("/sys/devices/system/cpu/intel_pstate/no_turbo") {
        let det = match no_turbo.as_str() {
            "0" => Detection::with_detail(Status::Enabled, "linux-sysfs", "no_turbo=0"),
            "1" => {
                Detection::with_detail(Status::Disabled, "linux-sysfs", "no_turbo=1 (turbo off)")
            }
            other => {
                Detection::with_detail(Status::Unknown, "linux-sysfs", format!("no_turbo={other}"))
            }
        };
        out.push(("turbo", det));
    }
}

/// C-state idle driver, with the available C-state names in the detail.
fn detect_idle(out: &mut Vec<(&'static str, Detection)>) {
    let Some(driver) = read_trim("/sys/devices/system/cpu/cpuidle/current_driver") else {
        return;
    };
    let mut states = Vec::new();
    for i in 0..16 {
        match read_trim(&format!(
            "/sys/devices/system/cpu/cpu0/cpuidle/state{i}/name"
        )) {
            Some(name) => states.push(name),
            None => break,
        }
    }
    let detail = format!("driver={driver}, states: {}", states.join(" "));
    let status = if driver == "intel_idle" {
        Status::Enabled
    } else {
        Status::Absent
    };
    out.push((
        "intel_idle",
        Detection::with_detail(status, "linux-sysfs", detail),
    ));
}

/// RAPL power domains under `/sys/class/powercap`.
fn detect_rapl(out: &mut Vec<(&'static str, Detection)>) {
    let mut domains = Vec::new();
    for i in 0..8 {
        match read_trim(&format!("/sys/class/powercap/intel-rapl:{i}/name")) {
            Some(name) => domains.push(name),
            None => break,
        }
    }
    let det = if domains.is_empty() {
        Detection::with_detail(
            Status::Absent,
            "linux-sysfs",
            "no intel-rapl powercap domains",
        )
    } else {
        Detection::with_detail(
            Status::Enabled,
            "linux-sysfs",
            format!("domains: {}", domains.join(", ")),
        )
    };
    out.push(("rapl", det));
}

/// resctrl filesystem: mounted and usable when `/sys/fs/resctrl/info` exists.
fn detect_resctrl(out: &mut Vec<(&'static str, Detection)>) {
    let det = if Path::new("/sys/fs/resctrl/info").exists() {
        Detection::with_detail(Status::Enabled, "linux-sysfs", "mounted at /sys/fs/resctrl")
    } else if Path::new("/sys/fs/resctrl").exists() {
        Detection::with_detail(Status::Present, "linux-sysfs", "present but not mounted")
    } else {
        Detection::with_detail(Status::Absent, "linux-sysfs", "no /sys/fs/resctrl")
    };
    out.push(("resctrl", det));
}
