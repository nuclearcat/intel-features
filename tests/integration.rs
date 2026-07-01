//! End-to-end tests over the public library API. These are hardware-independent
//! except `real_probes_do_not_panic`, which just exercises the read-only probes.

use std::collections::HashMap;

use intel_features::catalog;
use intel_features::model::{Category, Detection, Privilege, Status};
use intel_features::probes::{self, Context};
use intel_features::report::Report;

/// Every catalog feature id must be unique — probes key detections by id, so a
/// collision would silently merge two features.
#[test]
fn catalog_ids_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for f in catalog::FEATURES {
        assert!(!f.id.is_empty(), "empty id for {}", f.name);
        assert!(seen.insert(f.id), "duplicate feature id: {}", f.id);
    }
}

/// Every catalog category is covered by the display order, and every feature lands
/// in exactly one category bucket.
#[test]
fn build_covers_every_feature() {
    let report = Report::build(HashMap::new(), None, Privilege::User);
    assert_eq!(report.categories.len(), Category::ORDER.len());
    let total: usize = report.categories.iter().map(|c| c.features.len()).sum();
    assert_eq!(total, catalog::FEATURES.len());
}

/// With no detections, every feature is Unknown.
#[test]
fn empty_results_are_all_unknown() {
    let report = Report::build(HashMap::new(), None, Privilege::User);
    for cat in &report.categories {
        for f in &cat.features {
            assert_eq!(f.status, Status::Unknown, "{} should be unknown", f.id);
            assert!(f.detections.is_empty());
        }
    }
}

/// The headline status is the highest-ranked detection: a firmware/OS `Disabled`
/// outranks a silicon `Present`. This is the core aggregation contract.
#[test]
fn headline_prefers_higher_rank() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "smt",
        vec![
            Detection::new(Status::Present, "cpuid"),
            Detection::new(Status::Disabled, "linux-sysfs"),
        ],
    );
    let report = Report::build(results, None, Privilege::User);
    let smt = find(&report, "smt");
    assert_eq!(smt.status, Status::Disabled);
    assert_eq!(smt.detections.len(), 2);
}

/// Detections keyed by an unknown id are dropped, not surfaced as phantom features.
#[test]
fn unknown_ids_are_ignored() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "not_a_real_feature",
        vec![Detection::new(Status::Present, "cpuid")],
    );
    let report = Report::build(results, None, Privilege::User);
    for cat in &report.categories {
        for f in &cat.features {
            assert_ne!(f.id, "not_a_real_feature");
        }
    }
}

/// CPUID-present + kernel-flag-absent must raise a disparity note.
#[test]
fn disparity_cpuid_present_kernel_absent() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "aes",
        vec![
            Detection::new(Status::Present, "cpuid"),
            Detection::new(Status::Absent, "procfs"),
        ],
    );
    let report = Report::build(results, None, Privilege::User);
    assert_eq!(report.notes.len(), 1);
    assert!(
        report.notes[0].contains("AES-NI"),
        "note was: {}",
        report.notes[0]
    );
}

/// CPUID-absent + kernel-flag-present points at a decode gap in our probe.
#[test]
fn disparity_kernel_present_cpuid_absent() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "aes",
        vec![
            Detection::new(Status::Absent, "cpuid"),
            Detection::new(Status::Present, "procfs"),
        ],
    );
    let report = Report::build(results, None, Privilege::User);
    assert_eq!(report.notes.len(), 1);
    assert!(
        report.notes[0].contains("decode gap"),
        "note was: {}",
        report.notes[0]
    );
}

/// Agreement between CPUID and the kernel must produce no note.
#[test]
fn no_disparity_when_sources_agree() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "aes",
        vec![
            Detection::new(Status::Present, "cpuid"),
            Detection::new(Status::Present, "procfs"),
        ],
    );
    let report = Report::build(results, None, Privilege::User);
    assert!(report.notes.is_empty());
}

/// Kernel-flag names in the catalog must be well-formed (lowercase, no whitespace).
#[test]
fn cpuinfo_flags_are_well_formed() {
    for f in catalog::FEATURES {
        if let Some(flag) = f.cpuinfo_flag {
            assert!(!flag.is_empty(), "{} has empty flag", f.id);
            assert!(
                flag.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "malformed flag {flag:?} for {}",
                f.id
            );
        }
    }
}

#[test]
fn json_output_is_produced() {
    let report = Report::build(HashMap::new(), None, Privilege::Root);
    let json = report.to_json();
    assert!(json.contains("\"tool\": \"intel-features\""));
    assert!(json.contains("\"privilege\": \"root\""));
}

/// The real probes are read-only; running them must never panic regardless of host.
#[test]
fn real_probes_do_not_panic() {
    let ctx = Context::detect();
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    for probe in probes::all() {
        for (id, det) in probe.detect(&ctx) {
            results.entry(id).or_default().push(det);
        }
    }
    let report = Report::build(results, probes::cpuid::identity(), ctx.privilege);
    // Text rendering must also not panic.
    let _ = report.render_text(intel_features::report::TextOptions {
        color: false,
        verbose: true,
        hide_absent: false,
    });
}

fn find<'a>(report: &'a Report, id: &str) -> &'a intel_features::report::FeatureReport {
    report
        .categories
        .iter()
        .flat_map(|c| &c.features)
        .find(|f| f.id == id)
        .unwrap_or_else(|| panic!("feature {id} not found"))
}
