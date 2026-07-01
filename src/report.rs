//! Aggregation and rendering.
//!
//! Takes the per-feature detections gathered from all probes, folds them against the
//! catalog into a [`Report`], and renders it as grouped colorized text or JSON.

use std::collections::HashMap;

use serde::Serialize;

use crate::catalog;
use crate::model::{Category, Detection, Privilege, Status};
use crate::probes::cpuid::Identity;

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
    pub categories: Vec<CategoryReport>,
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
        privilege: Privilege,
    ) -> Report {
        let mut categories = Vec::new();
        for &cat in Category::ORDER {
            let mut features = Vec::new();
            for def in catalog::FEATURES.iter().filter(|f| f.category == cat) {
                let detections = results.remove(def.id).unwrap_or_default();
                let status = detections
                    .iter()
                    .map(|d| d.status)
                    .max_by_key(|s| s.rank())
                    .unwrap_or(Status::Unknown);
                features.push(FeatureReport {
                    id: def.id,
                    name: def.name,
                    category: def.category,
                    description: def.description,
                    status,
                    detections,
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
            categories,
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
                .filter(|f| !(opts.hide_absent && f.status == Status::Absent))
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
            }
            None => s.push_str("  CPU:       (CPUID unavailable on this architecture)\n"),
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
    let sources = if f.detections.is_empty() {
        "not probed".to_string()
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
        dim(&sources, opts.color)
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
