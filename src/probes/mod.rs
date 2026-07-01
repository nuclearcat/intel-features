//! Probe infrastructure.
//!
//! A [`Probe`] is one *detection mechanism* (CPUID, MSR, sysfs, PCI, ACPI, …). Each
//! probe inspects the running system and emits `(feature_id, Detection)` pairs. The
//! reporter aggregates every probe's findings per feature. This is the modularity
//! axis of the whole tool: adding a mechanism means adding a `Probe`, and adding a
//! feature means adding a catalog entry plus teaching some probe to emit it.

pub mod cpuid;
pub mod procfs;
pub mod sysfs;

use crate::model::{Detection, Privilege};

/// Runtime context handed to every probe: effective privilege plus (later) caches
/// of expensive shared reads.
#[derive(Debug, Clone)]
pub struct Context {
    pub privilege: Privilege,
}

impl Context {
    /// Build the context by inspecting the current process.
    pub fn detect() -> Self {
        Context {
            privilege: effective_privilege(),
        }
    }

    pub fn is_root(&self) -> bool {
        self.privilege == Privilege::Root
    }
}

/// A single detection mechanism.
pub trait Probe {
    /// Stable, short mechanism name (also used as `Detection::source`).
    fn name(&self) -> &'static str;

    /// Inspect the system and return findings keyed by catalog feature id.
    ///
    /// A probe that cannot run (missing interface, insufficient privilege) should
    /// return findings with [`Status::Unknown`](crate::model::Status::Unknown) and a
    /// reason, or simply return nothing for features it does not cover.
    fn detect(&self, ctx: &Context) -> Vec<(&'static str, Detection)>;
}

/// The set of probes enabled in this build, in run order.
pub fn all() -> Vec<Box<dyn Probe>> {
    vec![
        Box::new(cpuid::CpuidProbe),
        Box::new(procfs::ProcfsProbe),
        Box::new(sysfs::SysfsProbe),
    ]
}

/// Determine the effective privilege by reading the effective UID from
/// `/proc/self/status` (dependency-free; Linux-specific). Defaults to `User`.
fn effective_privilege() -> Privilege {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            // Format: "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(euid) = rest.split_whitespace().nth(1) {
                    if euid == "0" {
                        return Privilege::Root;
                    }
                }
            }
        }
    }
    Privilege::User
}
