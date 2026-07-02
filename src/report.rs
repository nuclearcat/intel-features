//! Aggregation and rendering.
//!
//! Takes the per-feature detections gathered from all probes, folds them against the
//! catalog into a [`Report`], and renders it as grouped colorized text or JSON.

use std::collections::HashMap;

use serde::Serialize;

use crate::catalog;
use crate::model::{Category, Detection, Privilege, Status};
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
    /// Every probe's finding for this feature, in probe run order.
    pub detections: Vec<Detection>,
    /// Render the winning detection's detail inline instead of the probe names.
    #[serde(skip)]
    pub inline_detail: bool,
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
        mut results: HashMap<&'static str, Vec<Detection>>,
        identity: Option<Identity>,
        system: Option<SystemInfo>,
        privilege: Privilege,
    ) -> Report {
        let mut categories = Vec::new();
        let mut notes = Vec::new();
        for &cat in Category::ORDER {
            let mut features = Vec::new();
            for def in catalog::FEATURES.iter().filter(|f| f.category == cat) {
                let detections = results.remove(def.id).unwrap_or_default();
                let status = detections
                    .iter()
                    .map(|d| d.status)
                    .max_by_key(|s| s.rank())
                    .unwrap_or(Status::Unknown);
                if let Some(note) = disparity_note(def.name, &detections) {
                    notes.push(note);
                }
                features.push(FeatureReport {
                    id: def.id,
                    name: def.name,
                    category: def.category,
                    description: def.description,
                    status,
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
        Report {
            tool: "intel-features",
            version: env!("CARGO_PKG_VERSION"),
            privilege,
            identity,
            system,
            categories,
            notes,
        }
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
                    f.status != Status::Absent && !f.detections.is_empty()
                })
                .collect();
            if visible.is_empty() {
                continue;
            }
            s.push('\n');
            s.push_str(&bold(cat.title, opts.color));
            s.push('\n');
            for f in visible {
                render_feature(&mut s, f, opts);
            }
        }
        if !self.notes.is_empty() {
            s.push('\n');
            s.push_str(&bold("Cross-check (CPUID vs kernel)", opts.color));
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
                let topo = if id.hybrid {
                    format!(
                        "{} logical, hybrid: {} P-core(s) + {} E-core(s)",
                        id.logical_cpus, id.p_cores, id.e_cores
                    )
                } else {
                    format!("{} logical CPU(s)", id.logical_cpus)
                };
                s.push_str(&format!("  Topology:  {topo}\n"));
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
            if !sys.bios_version.is_empty() {
                s.push_str(&format!(
                    "  BIOS:      {} {}  ({})\n",
                    sys.bios_vendor, sys.bios_version, sys.bios_date
                ));
            }
        }
        let priv_note = match self.privilege {
            Privilege::Root => "root (all probes available)",
            Privilege::User => "user (MSR/PCI-config probes will report Unknown)",
        };
        s.push_str(&format!("  Privilege: {priv_note}\n"));
    }
}

fn render_feature(s: &mut String, f: &FeatureReport, opts: TextOptions) {
    let glyph = colorize(f.status.glyph(), f.status.color(), opts.color);
    // For vulnerabilities the mitigation string is the point, so show it inline; for
    // everything else the contributing probe names are the useful trailing hint.
    let trailing = if f.detections.is_empty() {
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
    let label = colorize(
        &format!("{:<9}", f.status.label()),
        f.status.color(),
        opts.color,
    );
    s.push_str(&format!(
        "  {} {:<22} {} {}\n",
        glyph,
        f.name,
        label,
        dim(&trailing, opts.color)
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
