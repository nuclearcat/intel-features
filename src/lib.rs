//! `intel-features` — an independent modular detector for Intel® processor and platform features.
//!
//! See `PLAN.md` for the full architecture and roadmap. The short version:
//!
//! * [`catalog`] is the static list of features the tool knows about.
//! * [`probes`] holds one module per *detection mechanism* (CPUID, sysfs, …). Each
//!   emits [`Detection`](model::Detection)s keyed by catalog feature id.
//! * [`report`] folds all detections against the catalog and renders the result.
//!
//! The design separates three questions that are usually conflated: does the silicon
//! support a feature, did firmware enable it, and is the OS using it. Each is a
//! separate detection; the reporter shows all that apply.

pub mod catalog;
pub mod cpu_db;
pub mod model;
pub mod probes;
pub mod report;
