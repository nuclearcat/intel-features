//! Aggregation and rendering.
//!
//! Takes the per-feature detections gathered from all probes, folds them against the
//! catalog into a [`Report`], and renders it as grouped colorized text or JSON.

use std::collections::HashMap;
use std::fmt;

use serde::Serialize;

use crate::catalog;
use crate::model::{Category, ClassExpectation, Detection, Privilege, Status};
use crate::probes::cpuid::Identity;
use crate::probes::firmware::SystemInfo;

/// Per-feature rolled-up result.
#[derive(Debug, Serialize)]
pub struct FeatureReport {
    pub id: &'static str,
    pub name: &'static str,
    pub category: Category,
    pub description: &'static str,
    /// Headline status: the highest-ranked detection (see [`Status::rank`]).
    pub status: Status,
    /// Relationship to the recognized CPU family/model class, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_expectation: Option<ClassExpectation>,
    /// A warning derived from status, cross-probe evidence, and class expectation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attention: Option<FeatureAttention>,
    /// Every probe's finding for this feature, in probe run order.
    pub detections: Vec<Detection>,
    /// Render the winning detection's detail inline instead of the probe names.
    #[serde(skip)]
    pub inline_detail: bool,
}

/// Why a feature deserves attention beyond its literal probe status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureAttention {
    /// Silicon reports the feature but the kernel does not expose it.
    Masked,
    /// The feature belongs to the class but is absent on this machine.
    ExpectedMissing,
    /// The feature belongs to the class but is explicitly disabled.
    ExpectedDisabled,
    /// Some members/configurations of the class offer it, but it is absent here.
    PossibleMissing,
    /// Some members/configurations of the class offer it, but it is disabled here.
    PossibleDisabled,
}

#[derive(Debug, Serialize)]
pub struct CategoryReport {
    pub category: Category,
    pub title: &'static str,
    pub features: Vec<FeatureReport>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub privilege: Privilege,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemInfo>,
    pub categories: Vec<CategoryReport>,
    /// Silicon-vs-kernel disparities found by cross-checking CPUID against
    /// `/proc/cpuinfo` (see [`disparity_note`]).
    pub notes: Vec<String>,
}

/// Rendering knobs for text output.
#[derive(Debug, Clone, Copy)]
pub struct TextOptions {
    pub color: bool,
    /// Show each probe's status + detail line under the feature.
    pub verbose: bool,
    /// Hide features whose headline status is `Absent`.
    pub hide_absent: bool,
}

impl Report {
    /// Fold probe results against the catalog.
    pub fn build(
        results: HashMap<&'static str, Vec<Detection>>,
        identity: Option<Identity>,
        system: Option<SystemInfo>,
        privilege: Privilege,
    ) -> Report {
        Self::try_build(results, identity, system, privilege)
            .expect("probe emitted an unknown feature id")
    }

    pub fn try_build(
        mut results: HashMap<&'static str, Vec<Detection>>,
        identity: Option<Identity>,
        system: Option<SystemInfo>,
        privilege: Privilege,
    ) -> Result<Report, ReportError> {
        if let Some(id) = results.keys().find(|id| catalog::find(id).is_none()) {
            return Err(ReportError::UnknownFeatureId(id));
        }
        let mut categories = Vec::new();
        let mut notes = Vec::new();
        for &cat in Category::ORDER {
            let mut features = Vec::new();
            for def in catalog::FEATURES.iter().filter(|f| f.category == cat) {
                let detections = results.remove(def.id).unwrap_or_default();
                let enabled = detections.iter().any(|d| d.status == Status::Enabled);
                let disabled = detections.iter().any(|d| d.status == Status::Disabled);
                let status = if enabled && disabled {
                    notes.push(format!(
                        "{}: conflicting enabled and disabled detections; headline set to unknown",
                        def.name
                    ));
                    Status::Unknown
                } else {
                    detections
                        .iter()
                        .map(|d| d.status)
                        .max_by_key(|s| s.rank())
                        .unwrap_or(Status::Unknown)
                };
                if let Some(note) = disparity_note(def.name, &detections) {
                    notes.push(note);
                }
                let class_expectation = identity.as_ref().and_then(|id| {
                    crate::cpu_db::feature_expectation(&id.vendor, id.family, id.model, def.id)
                });
                let attention = feature_attention(status, &detections, class_expectation);
                features.push(FeatureReport {
                    id: def.id,
                    name: def.name,
                    category: def.category,
                    description: def.description,
                    status,
                    class_expectation,
                    attention,
                    detections,
                    inline_detail: def.inline_detail,
                });
            }
            categories.push(CategoryReport {
                category: cat,
                title: cat.title(),
                features,
            });
        }
        Ok(Report {
            tool: "intel-features",
            version: env!("CARGO_PKG_VERSION"),
            privilege,
            identity,
            system,
            categories,
            notes,
        })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serializes")
    }

    pub fn render_text(&self, opts: TextOptions) -> String {
        let mut s = String::new();
        self.render_banner(&mut s, opts);
        for cat in &self.categories {
            let visible: Vec<&FeatureReport> = cat
                .features
                .iter()
                .filter(|f| {
                    if !opts.hide_absent {
                        return true;
                    }
                    // Default view hides absent features and ones no probe covered
                    // ("not probed"); `--all` shows everything.
                    (f.status != Status::Absent && !f.detections.is_empty())
                        || matches!(
                            f.attention,
                            Some(
                                FeatureAttention::ExpectedMissing
                                    | FeatureAttention::PossibleMissing
                            )
                        )
                })
                .collect();
            if visible.is_empty() {
                continue;
            }
            s.push('\n');
            s.push_str(&bold(cat.title, opts.color));
            s.push('\n');
            s.push_str(&dim(
                "    Feature                 Status    Evidence                 Purpose / notable instructions\n",
                opts.color,
            ));
            for f in visible {
                render_feature(&mut s, f, opts);
            }
        }
        if !self.notes.is_empty() {
            s.push('\n');
            s.push_str(&bold("Notes", opts.color));
            s.push('\n');
            for note in &self.notes {
                s.push_str(&format!("  {} {}\n", colorize("!", "33", opts.color), note));
            }
        }
        s
    }

    fn render_banner(&self, s: &mut String, opts: TextOptions) {
        s.push_str(&bold(
            &format!("{} {}", self.tool, self.version),
            opts.color,
        ));
        s.push('\n');
        match &self.identity {
            Some(id) => {
                let brand = if id.brand.is_empty() {
                    "(unknown)"
                } else {
                    &id.brand
                };
                s.push_str(&format!("  CPU:       {brand}\n"));
                s.push_str(&format!(
                    "  Vendor:    {}   family {:#x} model {:#x} stepping {}\n",
                    id.vendor, id.family, id.model, id.stepping
                ));
                if let Some(model) = id.model_info {
                    s.push_str(&format!(
                        "  Generation: {} — {} ({})\n",
                        model.codename, model.generation, model.segment
                    ));
                }
                let topo = if id.hybrid {
                    format!(
                        "{} logical, hybrid: {} P-core(s) + {} E-core(s)",
                        id.logical_cpus, id.p_cores, id.e_cores
                    )
                } else {
                    format!("{} logical CPU(s)", id.logical_cpus)
                };
                s.push_str(&format!("  Topology:  {topo}\n"));
                if let Some(channels) = id.max_memory_channels {
                    s.push_str(&format!(
                        "  Memory:    up to {channels} channels per CPU socket\n"
                    ));
                }
                if let Some(mc) = &id.microcode {
                    s.push_str(&format!("  Microcode: {mc}\n"));
                }
            }
            None => s.push_str("  CPU:       (CPUID unavailable on this architecture)\n"),
        }
        if let Some(sys) = &self.system {
            let product = [sys.vendor.as_str(), sys.product.as_str()]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            if !product.is_empty() {
                s.push_str(&format!("  System:    {product}  (board {})\n", sys.board));
            }
            if let Some(chipset) = &sys.chipset {
                s.push_str(&format!(
                    "  Chipset:   {}  (PCI {:04x}:{:04x} at {})\n",
                    chipset.name, chipset.vendor_id, chipset.device_id, chipset.address
                ));
            }
            if !sys.bios_version.is_empty() {
                s.push_str(&format!(
                    "  BIOS:      {} {}  ({})\n",
                    sys.bios_vendor, sys.bios_version, sys.bios_date
                ));
            }
        }
        let priv_note = match self.privilege {
            Privilege::Root => {
                "root (availability still depends on host interfaces and namespaces)"
            }
            Privilege::User => "user (MSR access may report Unknown)",
        };
        s.push_str(&format!("  Privilege: {priv_note}\n"));
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReportError {
    UnknownFeatureId(&'static str),
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFeatureId(id) => write!(f, "unknown feature id {id:?}"),
        }
    }
}

impl std::error::Error for ReportError {}

fn render_feature(s: &mut String, f: &FeatureReport, opts: TextOptions) {
    let (glyph_text, label_text, color) = feature_visual(f);
    let glyph = colorize(glyph_text, color, opts.color);
    // For vulnerabilities the mitigation string is the point, so show it inline; for
    // everything else the contributing probe names are the useful trailing hint.
    let trailing = if matches!(
        f.attention,
        Some(
            FeatureAttention::ExpectedMissing
                | FeatureAttention::ExpectedDisabled
                | FeatureAttention::PossibleMissing
                | FeatureAttention::PossibleDisabled
        )
    ) {
        let level = match f.class_expectation {
            Some(ClassExpectation::Expected) => "expected",
            Some(ClassExpectation::Possible) => "possible",
            None => "class hint",
        };
        format!("{level} for CPU class")
    } else if f.attention == Some(FeatureAttention::Masked) {
        "CPUID vs procfs".to_string()
    } else if f.detections.is_empty() {
        "not probed".to_string()
    } else if f.inline_detail {
        f.detections
            .iter()
            .max_by_key(|d| d.status.rank())
            .and_then(|d| d.detail.clone())
            .unwrap_or_default()
    } else {
        f.detections
            .iter()
            .map(|d| d.source)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let label = colorize(&format!("{label_text:<9}"), color, opts.color);
    let evidence = format!("{trailing:<24}");
    s.push_str(&format!(
        "  {} {:<22} {} {} {}\n",
        glyph,
        f.name,
        label,
        dim(&evidence, opts.color),
        f.description,
    ));
    if opts.verbose {
        for d in &f.detections {
            let detail = d.detail.as_deref().unwrap_or("");
            s.push_str(&dim(
                &format!("      └ {}: {} {}\n", d.source, d.status.label(), detail),
                opts.color,
            ));
        }
    }
}

fn feature_visual(f: &FeatureReport) -> (&'static str, &'static str, &'static str) {
    match f.attention {
        Some(FeatureAttention::Masked) => ("!", "masked", "31"),
        Some(FeatureAttention::ExpectedMissing) => ("!", "missing", "31"),
        Some(FeatureAttention::ExpectedDisabled) => ("✗", "disabled", "31"),
        Some(FeatureAttention::PossibleMissing) => ("!", "missing", "33"),
        Some(FeatureAttention::PossibleDisabled) => ("✗", "disabled", "33"),
        None => (f.status.glyph(), f.status.label(), f.status.color()),
    }
}

fn feature_attention(
    status: Status,
    detections: &[Detection],
    class_expectation: Option<ClassExpectation>,
) -> Option<FeatureAttention> {
    let cpuid_present = detections
        .iter()
        .any(|d| d.source == "cpuid" && matches!(d.status, Status::Present | Status::Enabled));
    let procfs_absent = detections
        .iter()
        .any(|d| d.source == "procfs" && d.status == Status::Absent);
    if cpuid_present && procfs_absent {
        return Some(FeatureAttention::Masked);
    }

    match (class_expectation, status) {
        (Some(ClassExpectation::Expected), Status::Absent) => {
            Some(FeatureAttention::ExpectedMissing)
        }
        (Some(ClassExpectation::Expected), Status::Disabled) => {
            Some(FeatureAttention::ExpectedDisabled)
        }
        (Some(ClassExpectation::Possible), Status::Absent) => {
            Some(FeatureAttention::PossibleMissing)
        }
        (Some(ClassExpectation::Possible), Status::Disabled) => {
            Some(FeatureAttention::PossibleDisabled)
        }
        _ => None,
    }
}

/// Compare the CPUID and procfs findings for one feature and, if they disagree in a
/// meaningful way, produce a note. Two directions matter:
///
/// * CPUID present but kernel flag absent → the feature exists in silicon but the kernel
///   does not advertise it: masked/disabled by firmware or microcode, or a kernel too old
///   to name the flag.
/// * CPUID absent but kernel flag present → the CPUID decode missed something the kernel
///   sees. This points at a gap in *our* probe and is worth surfacing.
fn disparity_note(name: &str, detections: &[Detection]) -> Option<String> {
    let status_of = |src: &str| {
        detections
            .iter()
            .find(|d| d.source == src)
            .map(|d| d.status)
    };
    let cpuid = status_of("cpuid")?;
    let procfs = status_of("procfs")?;
    let present = |s: Status| matches!(s, Status::Present | Status::Enabled);
    if present(cpuid) && procfs == Status::Absent {
        Some(format!(
            "{name}: CPUID reports present, but absent from /proc/cpuinfo \
             (masked/firmware-disabled, or kernel too old)"
        ))
    } else if cpuid == Status::Absent && present(procfs) {
        Some(format!(
            "{name}: present in /proc/cpuinfo but CPUID probe reports absent \
             (CPUID decode gap — please report)"
        ))
    } else {
        None
    }
}

// ---- tiny ANSI helpers (no external crate) ------------------------------------------

fn colorize(text: &str, code: &str, on: bool) -> String {
    if on {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn bold(text: &str, on: bool) -> String {
    colorize(text, "1", on)
}

fn dim(text: &str, on: bool) -> String {
    colorize(text, "2", on)
}
