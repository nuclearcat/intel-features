//! ACPI firmware-table probe (no root).
//!
//! The *presence* of a table in `/sys/firmware/acpi/tables/` is readable without root
//! and is itself informative: DMAR ⇒ the platform supports VT-d, NFIT ⇒ persistent
//! memory, CEDT ⇒ CXL, LPIT ⇒ low-power S0 idle, and so on. Table *contents* need root
//! and are left to later milestones; here we combine presence with a couple of live
//! sysfs signals (`/sys/class/iommu`, `/sys/power/mem_sleep`) to tell "supported" from
//! "active".

use std::collections::HashSet;

use crate::model::{Detection, Status};
use crate::probes::{Context, Probe};

const SRC: &str = "acpi";
const TABLES: &str = "/sys/firmware/acpi/tables";

pub struct AcpiProbe;

impl Probe for AcpiProbe {
    fn name(&self) -> &'static str {
        SRC
    }

    fn detect(&self, _ctx: &Context) -> Vec<(&'static str, Detection)> {
        let tables = table_signatures();
        let mut out = Vec::new();
        let has = |sig: &str| tables.contains(sig);

        // VT-d: DMAR table = platform support; /sys/class/iommu = active.
        let iommu_active = dir_nonempty("/sys/class/iommu");
        out.push((
            "vt_d",
            if iommu_active {
                Detection::with_detail(Status::Enabled, SRC, "ACPI DMAR + /sys/class/iommu active")
            } else if has("DMAR") {
                Detection::with_detail(Status::Present, SRC, "ACPI DMAR table (IOMMU not active)")
            } else {
                Detection::with_detail(Status::Absent, SRC, "no ACPI DMAR table")
            },
        ));

        // S0ix: LPIT table and/or s2idle offered by the kernel.
        let s2idle = std::fs::read_to_string("/sys/power/mem_sleep")
            .map(|s| s.contains("s2idle"))
            .unwrap_or(false);
        out.push((
            "s0ix",
            if s2idle {
                Detection::with_detail(Status::Enabled, SRC, "s2idle in /sys/power/mem_sleep")
            } else if has("LPIT") {
                Detection::with_detail(Status::Present, SRC, "ACPI LPIT table")
            } else {
                Detection::with_detail(Status::Absent, SRC, "no LPIT / s2idle")
            },
        ));

        // Pure table-presence signals: (feature, signature).
        for (feature, sig) in [
            ("pmem", "NFIT"),
            ("cxl", "CEDT"),
            ("hmat", "HMAT"),
            ("hpet", "HPET"),
            ("numa", "SRAT"),
            ("wsmt", "WSMT"),
        ] {
            let det = if has(sig) {
                Detection::with_detail(Status::Present, SRC, format!("ACPI {sig} table"))
            } else {
                Detection::with_detail(Status::Absent, SRC, format!("no ACPI {sig} table"))
            };
            out.push((feature, det));
        }

        // TPM 2.0: the TPM2 table names the version; enriches the tpm capability.
        if has("TPM2") {
            out.push((
                "tpm",
                Detection::with_detail(Status::Present, SRC, "TPM 2.0 (ACPI TPM2 table)"),
            ));
        }
        out
    }
}

/// Uppercase table signatures present (file names, sans the numeric SSDT suffixes we
/// don't care about).
fn table_signatures() -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(entries) = std::fs::read_dir(TABLES) {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                set.insert(name.to_ascii_uppercase());
            }
        }
    }
    set
}

fn dir_nonempty(path: &str) -> bool {
    std::fs::read_dir(path)
        .map(|mut d| d.any(|e| e.is_ok()))
        .unwrap_or(false)
}
