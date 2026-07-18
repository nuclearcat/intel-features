//! ACPI firmware-table probe (no root).
//!
//! The *presence* of a table in `/sys/firmware/acpi/tables/` is readable without root
//! and is itself informative: DMAR ⇒ the platform supports VT-d, NFIT ⇒ persistent
//! memory, CEDT ⇒ CXL, LPIT ⇒ low-power S0 idle, and so on. Table *contents* need root
//! and are left to later milestones; here we combine presence with a couple of live
//! sysfs signals (`/sys/class/iommu`, `/sys/power/mem_sleep`) to tell "supported" from
//! "active".

use std::collections::HashSet;
use std::path::Path;

use crate::model::{Detection, Status};
use crate::probes::{unavailable, Context, Probe, ProbeResult};

const SRC: &str = "acpi";
const TABLES: &str = "/sys/firmware/acpi/tables";
const FEATURES: &[&str] = &[
    "vt_d", "s0ix", "pmem", "cxl", "hmat", "hpet", "numa", "wsmt", "tpm",
];

pub struct AcpiProbe;

impl Probe for AcpiProbe {
    fn name(&self) -> &'static str {
        SRC
    }

    fn feature_ids(&self) -> Vec<&'static str> {
        FEATURES.to_vec()
    }

    fn detect(&self, ctx: &Context) -> ProbeResult {
        let (tables, complete) = match table_signatures(ctx) {
            Ok(value) => value,
            Err(reason) => return Ok(unavailable(self.name(), FEATURES, reason)),
        };
        let mut out = Vec::new();
        let has = |sig: &str| tables.contains(sig);

        // VT-d: DMAR table = platform support; /sys/class/iommu = active.
        let iommu_active = dir_nonempty(ctx, "/sys/class/iommu").unwrap_or(false);
        out.push((
            "vt_d",
            if iommu_active {
                Detection::with_detail(Status::Enabled, SRC, "ACPI DMAR + /sys/class/iommu active")
            } else if has("DMAR") {
                Detection::with_detail(Status::Present, SRC, "ACPI DMAR table (IOMMU not active)")
            } else if complete {
                Detection::with_detail(Status::Absent, SRC, "no ACPI DMAR table")
            } else {
                Detection::with_detail(
                    Status::Unknown,
                    SRC,
                    "ACPI table enumeration was incomplete",
                )
            },
        ));

        // S0ix: LPIT table and/or s2idle offered by the kernel.
        let s2idle = ctx
            .reader
            .read_to_string(Path::new("/sys/power/mem_sleep"))
            .map(|s| s.contains("s2idle"))
            .ok();
        out.push((
            "s0ix",
            if s2idle == Some(true) {
                Detection::with_detail(Status::Enabled, SRC, "s2idle in /sys/power/mem_sleep")
            } else if has("LPIT") {
                Detection::with_detail(Status::Present, SRC, "ACPI LPIT table")
            } else if complete && s2idle == Some(false) {
                Detection::with_detail(Status::Absent, SRC, "no LPIT / s2idle")
            } else {
                Detection::with_detail(
                    Status::Unknown,
                    SRC,
                    "ACPI or mem_sleep inspection incomplete",
                )
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
            } else if complete {
                Detection::with_detail(Status::Absent, SRC, format!("no ACPI {sig} table"))
            } else {
                Detection::with_detail(
                    Status::Unknown,
                    SRC,
                    "ACPI table enumeration was incomplete",
                )
            };
            out.push((feature, det));
        }

        // TPM 2.0: the TPM2 table names the version; enriches the tpm capability.
        if has("TPM2") {
            out.push((
                "tpm",
                Detection::with_detail(Status::Present, SRC, "TPM 2.0 (ACPI TPM2 table)"),
            ));
        } else {
            out.push((
                "tpm",
                Detection::with_detail(
                    if complete {
                        Status::Absent
                    } else {
                        Status::Unknown
                    },
                    SRC,
                    if complete {
                        "no ACPI TPM2 table"
                    } else {
                        "ACPI table enumeration was incomplete"
                    },
                ),
            ));
        }
        Ok(out)
    }
}

/// Uppercase table signatures present (file names, sans the numeric SSDT suffixes we
/// don't care about).
fn table_signatures(ctx: &Context) -> Result<(HashSet<String>, bool), String> {
    let mut set = HashSet::new();
    let entries = ctx
        .reader
        .read_dir(Path::new(TABLES))
        .map_err(|e| format!("cannot inspect ACPI tables: {e}"))?;
    let mut complete = true;
    for entry in entries {
        match entry {
            Ok(entry) => {
                set.insert(entry.file_name.to_ascii_uppercase());
            }
            Err(_) => complete = false,
        }
    }
    Ok((set, complete))
}

fn dir_nonempty(ctx: &Context, path: &str) -> Result<bool, String> {
    let entries = ctx
        .reader
        .read_dir(Path::new(path))
        .map_err(|e| e.to_string())?;
    if entries.iter().any(Result::is_err) {
        return Err("partial directory enumeration".into());
    }
    Ok(!entries.is_empty())
}
