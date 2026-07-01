//! Core data model shared by every probe and the reporter.
//!
//! The central idea: "the silicon supports X", "the firmware/BIOS enabled X", and
//! "the OS is using X" are *different* answers. A single [`Feature`] can therefore
//! collect several [`Detection`]s from different [`Probe`](crate::probes::Probe)s,
//! each reporting from its own vantage point.

use serde::Serialize;

/// Outcome of a single probe looking at a single feature.
///
/// Precedence (see [`Status::rank`]) decides the *headline* status when a feature
/// has several detections: an explicit `Enabled`/`Disabled` (a firmware/OS fact)
/// outranks a bare `Present` (a silicon fact), which outranks `Absent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Present in silicon *and* actively turned on.
    Enabled,
    /// Present in silicon but turned off (firmware/OS/microcode).
    Disabled,
    /// Capability exists; enablement not determined by this probe.
    Present,
    /// Capability does not exist.
    Absent,
    /// Could not be determined (insufficient privilege, missing interface, …).
    Unknown,
}

impl Status {
    /// Higher rank = more authoritative / more informative for the headline.
    pub fn rank(self) -> u8 {
        match self {
            Status::Enabled => 5,
            Status::Disabled => 4,
            Status::Present => 3,
            Status::Absent => 2,
            Status::Unknown => 1,
        }
    }

    /// Short human label.
    pub fn label(self) -> &'static str {
        match self {
            Status::Enabled => "enabled",
            Status::Disabled => "disabled",
            Status::Present => "present",
            Status::Absent => "absent",
            Status::Unknown => "unknown",
        }
    }

    /// Glyph used in text output.
    pub fn glyph(self) -> &'static str {
        match self {
            Status::Enabled => "✓",
            Status::Disabled => "✗",
            Status::Present => "•",
            Status::Absent => "·",
            Status::Unknown => "?",
        }
    }

    /// ANSI SGR color code (foreground) for text output.
    pub fn color(self) -> &'static str {
        match self {
            Status::Enabled => "32",  // green
            Status::Present => "36",  // cyan
            Status::Disabled => "33", // yellow
            Status::Absent => "90",   // bright black / grey
            Status::Unknown => "90",  // grey
        }
    }
}

/// One probe's finding about one feature.
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub status: Status,
    /// Name of the probe/mechanism that produced this finding (e.g. `"cpuid"`).
    pub source: &'static str,
    /// Optional human note: how it was found, or why it is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Detection {
    pub fn new(status: Status, source: &'static str) -> Self {
        Detection {
            status,
            source,
            detail: None,
        }
    }

    pub fn with_detail(status: Status, source: &'static str, detail: impl Into<String>) -> Self {
        Detection {
            status,
            source,
            detail: Some(detail.into()),
        }
    }
}

/// Privilege required by a probe / feature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    /// Ring 3, no special access (CPUID, most of sysfs/procfs).
    User,
    /// Needs root (MSRs, some PCI config space, TXT public space, …).
    Root,
}

/// Top-level grouping for the report. Ordering here is display ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Isa,
    Security,
    Virtualization,
    Power,
    Topology,
    Firmware,
}

impl Category {
    /// Display order.
    pub const ORDER: &'static [Category] = &[
        Category::Isa,
        Category::Security,
        Category::Virtualization,
        Category::Power,
        Category::Topology,
        Category::Firmware,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Category::Isa => "Instruction Set Extensions",
            Category::Security => "Security",
            Category::Virtualization => "Virtualization",
            Category::Power => "Power & Thermal",
            Category::Topology => "Topology",
            Category::Firmware => "Platform & Firmware",
        }
    }
}

/// Static definition of a feature the tool knows how to look for.
///
/// This is metadata only — the actual answer comes from probes at runtime,
/// keyed by [`FeatureDef::id`].
#[derive(Debug, Clone, Copy, Serialize)]
pub struct FeatureDef {
    /// Stable machine-readable id, e.g. `"avx2"`. Probes emit detections keyed by this.
    pub id: &'static str,
    /// Human display name, e.g. `"AVX2"`.
    pub name: &'static str,
    pub category: Category,
    /// One-line description of what the feature is / why it matters.
    pub description: &'static str,
    /// Minimum privilege needed to *fully* determine this feature.
    pub min_privilege: Privilege,
}
