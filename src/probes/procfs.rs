//! `/proc/cpuinfo` probe — the kernel's view, for cross-checking CPUID.
//!
//! For every catalog feature that declares a `cpuinfo_flag`, this probe reports whether
//! the kernel advertises that flag. Aggregated alongside the CPUID detection, this makes
//! silicon-vs-kernel disparities visible: if CPUID says `present` but the kernel flag is
//! missing, the feature was likely masked or disabled by firmware/microcode (or the
//! kernel predates the flag). The disparity summary in the report keys off exactly this.

use std::collections::HashSet;

use crate::catalog;
use crate::model::{Detection, Status};
use crate::probes::{Context, Probe};

pub struct ProcfsProbe;

impl Probe for ProcfsProbe {
    fn name(&self) -> &'static str {
        "procfs"
    }

    fn detect(&self, _ctx: &Context) -> Vec<(&'static str, Detection)> {
        let flags = match read_flags() {
            Some(f) => f,
            None => return Vec::new(),
        };
        let mut out = Vec::new();
        for def in catalog::FEATURES {
            let Some(flag) = def.cpuinfo_flag else {
                continue;
            };
            let (status, detail) = if flags.contains(flag) {
                (Status::Present, format!("/proc/cpuinfo flag '{flag}'"))
            } else {
                (Status::Absent, format!("no '{flag}' flag in /proc/cpuinfo"))
            };
            out.push((def.id, Detection::with_detail(status, "procfs", detail)));
        }
        out
    }
}

/// Read the `flags` set from the first processor block of `/proc/cpuinfo`.
///
/// The kernel presents the same flag set on every logical CPU (it exposes the common
/// supported set), so the first block is representative.
fn read_flags() -> Option<HashSet<String>> {
    let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("flags") {
            if let Some((_, list)) = rest.split_once(':') {
                return Some(list.split_whitespace().map(str::to_string).collect());
            }
        }
    }
    None
}
