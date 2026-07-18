//! `/proc/cpuinfo` probe — the kernel's view, for cross-checking CPUID.
//!
//! For every catalog feature that declares a `cpuinfo_flag`, this probe reports whether
//! the kernel advertises that flag. Aggregated alongside the CPUID detection, this makes
//! silicon-vs-kernel disparities visible: if CPUID says `present` but the kernel flag is
//! missing, the feature was likely masked or disabled by firmware/microcode (or the
//! kernel predates the flag). The disparity summary in the report keys off exactly this.

use std::collections::HashSet;
use std::path::Path;

use crate::catalog;
use crate::model::Status;
use crate::probes::{finding_detail, unavailable, Context, Probe, ProbeResult};

pub struct ProcfsProbe;

impl Probe for ProcfsProbe {
    fn name(&self) -> &'static str {
        "procfs"
    }

    fn feature_ids(&self) -> Vec<&'static str> {
        catalog::FEATURES
            .iter()
            .filter(|def| def.cpuinfo_flag.is_some())
            .map(|def| def.id)
            .collect()
    }

    fn detect(&self, ctx: &Context) -> ProbeResult {
        let ids: Vec<_> = catalog::FEATURES
            .iter()
            .filter(|def| def.cpuinfo_flag.is_some())
            .map(|def| def.id)
            .collect();
        let flags = match read_flags(ctx) {
            Ok(flags) => flags,
            Err(reason) => return Ok(unavailable(self.name(), &ids, reason)),
        };
        let mut out = Vec::new();
        for def in catalog::FEATURES {
            let Some(flag) = def.cpuinfo_flag else {
                continue;
            };
            let (status, detail) = if flags.all.contains(flag) {
                (
                    Status::Present,
                    format!("/proc/cpuinfo flag '{flag}' on all {} CPUs", flags.cpus),
                )
            } else if flags.any.contains(flag) {
                let count = flags.counts.get(flag).copied().unwrap_or(0);
                (
                    Status::Present,
                    format!(
                        "/proc/cpuinfo flag '{flag}' asymmetric: {count}/{} CPUs",
                        flags.cpus
                    ),
                )
            } else {
                (
                    Status::Absent,
                    format!("no '{flag}' flag on any of {} CPUs", flags.cpus),
                )
            };
            out.push(finding_detail(self.name(), def.id, status, detail));
        }
        Ok(out)
    }
}

struct CpuFlags {
    cpus: usize,
    all: HashSet<String>,
    any: HashSet<String>,
    counts: std::collections::HashMap<String, usize>,
}

fn read_flags(ctx: &Context) -> Result<CpuFlags, String> {
    let text = ctx
        .reader
        .read_to_string(Path::new("/proc/cpuinfo"))
        .map_err(|e| format!("cannot inspect /proc/cpuinfo: {e}"))?;
    let mut blocks = Vec::new();
    for block in text.split("\n\n") {
        let has_processor = block.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(key, _)| key.trim() == "processor")
        });
        if !has_processor {
            continue;
        }
        let flags = block
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == "flags").then(|| {
                    value
                        .split_whitespace()
                        .map(str::to_string)
                        .collect::<HashSet<_>>()
                })
            })
            .ok_or_else(|| "malformed /proc/cpuinfo: processor block lacks flags".to_string())?;
        blocks.push(flags);
    }
    if blocks.is_empty() {
        return Err("malformed /proc/cpuinfo: no processor blocks".to_string());
    }
    let mut counts = std::collections::HashMap::new();
    for flags in &blocks {
        for flag in flags {
            *counts.entry(flag.clone()).or_insert(0) += 1;
        }
    }
    let any = counts.keys().cloned().collect();
    let all = counts
        .iter()
        .filter(|(_, count)| **count == blocks.len())
        .map(|(flag, _)| flag.clone())
        .collect();
    Ok(CpuFlags {
        cpus: blocks.len(),
        all,
        any,
        counts,
    })
}
