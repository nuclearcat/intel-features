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
        out
    }
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
