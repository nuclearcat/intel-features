//! CPU vulnerability / mitigation probe.
//!
//! Reads `/sys/devices/system/cpu/vulnerabilities/*`, one file per known transient-
//! execution (and related) issue. Each file holds a human status string; this probe
//! maps it onto the shared status model where, for a *mitigation*, `Enabled` means the
//! machine is protected (not affected, or a mitigation is active) and `Disabled` means
//! it is exposed (`Vulnerable`).
//!
//! The directory is enumerated dynamically. Files matching a catalog id are reported
//! individually; any file the catalog does not yet know about is collected under
//! `vuln_other` so a newer kernel's additions surface rather than vanish.

use std::collections::HashSet;

use crate::catalog;
use crate::model::{Category, Detection, Status};
use crate::probes::{Context, Probe};

const DIR: &str = "/sys/devices/system/cpu/vulnerabilities";

pub struct VulnProbe;

impl Probe for VulnProbe {
    fn name(&self) -> &'static str {
        "linux-vuln"
    }

    fn detect(&self, _ctx: &Context) -> Vec<(&'static str, Detection)> {
        let entries = match std::fs::read_dir(DIR) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        // Catalog ids in the Vulnerabilities category (minus the catch-all) are the
        // filenames we recognise.
        let known: HashSet<&'static str> = catalog::FEATURES
            .iter()
            .filter(|f| f.category == Category::Vulnerabilities && f.id != "vuln_other")
            .map(|f| f.id)
            .collect();

        let mut out = Vec::new();
        let mut unknown: Vec<String> = Vec::new();

        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().into_owned();
            let status_text = match std::fs::read_to_string(entry.path()) {
                Ok(s) => s.trim().to_string(),
                Err(_) => continue,
            };
            match known.get(fname.as_str()) {
                Some(&id) => out.push((id, classify(&status_text))),
                None => unknown.push(format!("{fname} = {status_text}")),
            }
        }

        if !unknown.is_empty() {
            unknown.sort();
            out.push((
                "vuln_other",
                Detection::with_detail(Status::Unknown, "linux-vuln", unknown.join("; ")),
            ));
        }
        out
    }
}

/// Map a kernel vulnerability status string onto the status model.
fn classify(text: &str) -> Detection {
    // Compare case-insensitively on the leading keyword.
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("not affected") {
        Detection::with_detail(Status::Enabled, "linux-vuln", "not affected")
    } else if lower.starts_with("mitigation") {
        // Keep the specific mitigation, dropping the "Mitigation: " prefix.
        let detail = text.split_once(':').map(|(_, m)| m.trim()).unwrap_or(text);
        Detection::with_detail(
            Status::Enabled,
            "linux-vuln",
            format!("mitigated: {detail}"),
        )
    } else if lower.starts_with("vulnerable") {
        Detection::with_detail(Status::Disabled, "linux-vuln", text.to_string())
    } else {
        Detection::with_detail(Status::Unknown, "linux-vuln", text.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_affected_is_enabled() {
        assert_eq!(classify("Not affected").status, Status::Enabled);
    }

    #[test]
    fn mitigation_is_enabled_and_keeps_detail() {
        let d = classify("Mitigation: Enhanced IBRS");
        assert_eq!(d.status, Status::Enabled);
        assert_eq!(d.detail.as_deref(), Some("mitigated: Enhanced IBRS"));
    }

    #[test]
    fn vulnerable_is_disabled() {
        let d = classify("Vulnerable: No microcode");
        assert_eq!(d.status, Status::Disabled);
        assert_eq!(d.detail.as_deref(), Some("Vulnerable: No microcode"));
    }

    #[test]
    fn unrecognised_is_unknown() {
        assert_eq!(
            classify("Processor vulnerable; something").status,
            Status::Unknown
        );
    }
}
