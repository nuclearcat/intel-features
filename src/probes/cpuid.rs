//! CPUID probe — the zero-privilege workhorse (M1).
//!
//! Uses the `raw-cpuid` crate for the bulk of leaf decoding, plus a few direct
//! `std::arch` leaf reads for bits `raw-cpuid` does not expose (SERIALIZE, MOVDIR*,
//! CET-IBT, FSRM, hybrid, arch-LBR, core type).
//!
//! CPUID is executed **per logical core** (pinned via `sched_setaffinity`) so hybrid
//! asymmetries are visible: a feature present only on P-cores is reported `Present`
//! with an "asymmetric" note, since software cannot rely on it uniformly. The scan
//! runs once and is memoized; both [`identity`] and the [`Probe`] impl read from it.

use crate::cpu_db::{self, CpuModelInfo};
use crate::model::{Detection, Status};
use crate::probes::{unavailable, Context, Probe, ProbeResult};
use std::collections::HashSet;
use std::path::Path;

/// CPU identity + topology summary, shown as the report banner.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Identity {
    pub vendor: String,
    pub brand: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    /// Codename, marketing generation, and segment from the family/model database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_info: Option<CpuModelInfo>,
    pub logical_cpus: usize,
    pub hybrid: bool,
    pub p_cores: usize,
    pub e_cores: usize,
    /// Loaded microcode revision (from sysfs), e.g. `"0x11b"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub microcode: Option<String>,
    /// Maximum memory channels supported by one processor socket for recognized,
    /// unambiguous family/model groups. This is not an active/populated count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_memory_channels: Option<u8>,
}

pub struct CpuidProbe;

const FEATURES: &[&str] = &[
    "adx",
    "aes",
    "amx_bf16",
    "amx_int8",
    "amx_tile",
    "arat",
    "arch_lbr",
    "arch_perfmon",
    "avx",
    "avx10",
    "avx2",
    "avx512bf16",
    "avx512bitalg",
    "avx512bw",
    "avx512cd",
    "avx512dq",
    "avx512f",
    "avx512fp16",
    "avx512ifma",
    "avx512vbmi",
    "avx512vbmi2",
    "avx512vl",
    "avx512vnni",
    "avx512vp2intersect",
    "avx512vpopcntdq",
    "avx_ifma",
    "avx_ne_convert",
    "avx_vnni",
    "avx_vnni_int16",
    "avx_vnni_int8",
    "bmi1",
    "bmi2",
    "bts",
    "cat_l2",
    "cat_l3",
    "cdp_l3",
    "cet_ibt",
    "cet_ss",
    "cet_sss",
    "clflushopt",
    "clwb",
    "cmpxchg16b",
    "cmt",
    "dts",
    "eist",
    "epb",
    "f16c",
    "fma",
    "fsgsbase",
    "fsrm",
    "gfni",
    "hdc",
    "hle",
    "hreset",
    "htt",
    "hwp",
    "hwp_activity_window",
    "hwp_epp",
    "hwp_notification",
    "hwp_package",
    "hybrid",
    "hypervisor",
    "intel_pt",
    "lam",
    "lzcnt",
    "mba",
    "mbm_local",
    "mbm_total",
    "monitor",
    "movbe",
    "movdir64b",
    "movdiri",
    "mpx",
    "nx",
    "ospke",
    "pclmulqdq",
    "pdcm",
    "pku",
    "pln",
    "popcnt",
    "prefetchi",
    "ptm",
    "ptwrite",
    "rdpid",
    "rdrand",
    "rdseed",
    "rdt_a",
    "rdt_m",
    "rtm",
    "serialize",
    "sgx",
    "sgx_lc",
    "sha",
    "smap",
    "smep",
    "smx",
    "sse",
    "sse2",
    "sse3",
    "sse4_1",
    "sse4_2",
    "ssse3",
    "tm2",
    "tme",
    "tsc_deadline",
    "turbo",
    "turbo3",
    "umip",
    "vaes",
    "vmx",
    "vpclmulqdq",
    "waitpkg",
    "x2apic",
    "xsave",
    "xsavec",
    "xsaveopt",
    "xsaves",
];

impl Probe for CpuidProbe {
    fn name(&self) -> &'static str {
        "cpuid"
    }

    fn feature_ids(&self) -> Vec<&'static str> {
        FEATURES.to_vec()
    }

    fn detect(&self, ctx: &Context) -> ProbeResult {
        let scan = run_scan(ctx);
        if scan.detections.is_empty() {
            Ok(unavailable(
                self.name(),
                FEATURES,
                "no eligible logical CPU could be scanned",
            ))
        } else {
            Ok(scan.detections)
        }
    }
}

/// CPU identity banner, if determinable on this architecture.
pub fn identity() -> Option<Identity> {
    identity_with(&Context::detect())
}

pub fn identity_with(ctx: &Context) -> Option<Identity> {
    run_scan(ctx).identity
}

/// Per-architecture core type as reported by CPUID leaf 0x1A.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CoreType {
    Performance,
    Efficiency,
    Other,
}

impl CoreType {
    fn short(self) -> &'static str {
        match self {
            CoreType::Performance => "P",
            CoreType::Efficiency => "E",
            CoreType::Other => "?",
        }
    }
}

/// Result of the whole scan: identity plus the aggregated per-feature detections.
struct Scan {
    identity: Option<Identity>,
    detections: Vec<(&'static str, Detection)>,
}

// =====================================================================================
// x86-64 implementation
// =====================================================================================

#[cfg(target_arch = "x86_64")]
fn run_scan(ctx: &Context) -> Scan {
    let cpus = eligible_cpus(ctx);
    let cores: Vec<CoreScan> = cpus
        .iter()
        .filter_map(|&cpu| scan_pinned(cpu, ctx.clone()))
        .collect();
    if cores.is_empty() {
        return Scan {
            identity: None,
            detections: Vec::new(),
        };
    }
    let identity = build_identity(&cores, ctx);
    let detections = aggregate(&cores);
    Scan {
        identity: Some(identity),
        detections,
    }
}

/// One core's findings: its type and the full feature boolean vector (with leaf tags).
struct CoreScan {
    logical_cpu: u32,
    core_type: CoreType,
    physical_key: Option<u64>,
    feats: Vec<(&'static str, bool, &'static str)>,
    ident: CoreIdent,
}

struct CoreIdent {
    vendor: String,
    brand: String,
    family: u32,
    model: u32,
    stepping: u32,
}

#[cfg(target_arch = "x86_64")]
mod raw {
    use core::arch::x86_64::__cpuid_count;

    /// Raw CPUID read on the current core. `__cpuid_count` is safe on x86-64.
    pub fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
        let r = __cpuid_count(leaf, sub);
        (r.eax, r.ebx, r.ecx, r.edx)
    }

    pub fn bit(v: u32, n: u32) -> bool {
        (v >> n) & 1 == 1
    }
}

/// Pin a fresh thread to `cpu`, scan there, return the result. Returns `None` if the
/// core could not be pinned (e.g. it went offline between enumeration and scan).
#[cfg(target_arch = "x86_64")]
fn scan_pinned(cpu: u32, ctx: Context) -> Option<CoreScan> {
    std::thread::Builder::new()
        .name(format!("cpuid-scan-{cpu}"))
        .spawn(move || {
            if !pin_to(cpu) {
                return None;
            }
            Some(scan_core(cpu, &ctx))
        })
        .ok()?
        .join()
        .ok()?
}

/// Bind the current thread to a single logical CPU.
#[cfg(target_arch = "x86_64")]
fn pin_to(cpu: u32) -> bool {
    let word_bits = usize::BITS as usize;
    let words = cpu as usize / word_bits + 1;
    let mut mask = vec![0usize; words];
    mask[cpu as usize / word_bits] |= 1usize << (cpu as usize % word_bits);
    // SAFETY: the pointer addresses `words * size_of::<usize>()` initialized bytes.
    unsafe {
        libc::sched_setaffinity(
            0,
            std::mem::size_of_val(mask.as_slice()),
            mask.as_ptr().cast(),
        ) == 0
    }
}

/// Decode every catalog-relevant feature on the current core.
#[cfg(target_arch = "x86_64")]
fn scan_core(logical_cpu: u32, ctx: &Context) -> CoreScan {
    use raw::{bit, cpuid};
    let id = raw_cpuid::CpuId::new();
    let max_basic = cpuid(0, 0).0;

    let mut feats: Vec<(&'static str, bool, &'static str)> = Vec::new();
    let mut push =
        |name: &'static str, cond: bool, leaf: &'static str| feats.push((name, cond, leaf));

    // ---- Leaf 1: legacy features ----------------------------------------------------
    let fi = id.get_feature_info();
    let f = |g: fn(&raw_cpuid::FeatureInfo) -> bool| fi.as_ref().map(g).unwrap_or(false);
    push("sse", f(|i| i.has_sse()), "leaf 1");
    push("sse2", f(|i| i.has_sse2()), "leaf 1");
    push("sse3", f(|i| i.has_sse3()), "leaf 1");
    push("ssse3", f(|i| i.has_ssse3()), "leaf 1");
    push("sse4_1", f(|i| i.has_sse41()), "leaf 1");
    push("sse4_2", f(|i| i.has_sse42()), "leaf 1");
    push("avx", f(|i| i.has_avx()), "leaf 1");
    push("fma", f(|i| i.has_fma()), "leaf 1");
    push("f16c", f(|i| i.has_f16c()), "leaf 1");
    push("popcnt", f(|i| i.has_popcnt()), "leaf 1");
    push("movbe", f(|i| i.has_movbe()), "leaf 1");
    push("aes", f(|i| i.has_aesni()), "leaf 1");
    push("pclmulqdq", f(|i| i.has_pclmulqdq()), "leaf 1");
    push("rdrand", f(|i| i.has_rdrand()), "leaf 1");
    push("cmpxchg16b", f(|i| i.has_cmpxchg16b()), "leaf 1");
    push("xsave", f(|i| i.has_xsave()), "leaf 1");
    push("monitor", f(|i| i.has_monitor_mwait()), "leaf 1");
    push("vmx", f(|i| i.has_vmx()), "leaf 1");
    push("smx", f(|i| i.has_smx()), "leaf 1");
    push("eist", f(|i| i.has_eist()), "leaf 1");
    push("tm2", f(|i| i.has_tm2()), "leaf 1");
    push("x2apic", f(|i| i.has_x2apic()), "leaf 1");
    push("htt", f(|i| i.has_htt()), "leaf 1");
    push("hypervisor", f(|i| i.has_hypervisor()), "leaf 1");
    push("tsc_deadline", f(|i| i.has_tsc_deadline()), "leaf 1");
    push("pdcm", f(|i| i.has_pdcm()), "leaf 1");
    push("bts", f(|i| i.has_ds()), "leaf 1 (DS)");

    // ---- Leaf 7/0: extended features ------------------------------------------------
    let ef = id.get_extended_feature_info();
    let e = |g: fn(&raw_cpuid::ExtendedFeatures) -> bool| ef.as_ref().map(g).unwrap_or(false);
    push("avx2", e(|i| i.has_avx2()), "leaf 7");
    push("bmi1", e(|i| i.has_bmi1()), "leaf 7");
    push("bmi2", e(|i| i.has_bmi2()), "leaf 7");
    push("adx", e(|i| i.has_adx()), "leaf 7");
    push("fsgsbase", e(|i| i.has_fsgsbase()), "leaf 7");
    push("smep", e(|i| i.has_smep()), "leaf 7");
    push("smap", e(|i| i.has_smap()), "leaf 7");
    push("umip", e(|i| i.has_umip()), "leaf 7");
    push("pku", e(|i| i.has_pku()), "leaf 7");
    push("ospke", e(|i| i.has_ospke()), "leaf 7");
    push("avx512f", e(|i| i.has_avx512f()), "leaf 7");
    push("avx512cd", e(|i| i.has_avx512cd()), "leaf 7");
    push("avx512vl", e(|i| i.has_avx512vl()), "leaf 7");
    push("avx512dq", e(|i| i.has_avx512dq()), "leaf 7");
    push("avx512bw", e(|i| i.has_avx512bw()), "leaf 7");
    push("avx512ifma", e(|i| i.has_avx512_ifma()), "leaf 7");
    push("avx512vbmi", e(|i| i.has_avx512vbmi()), "leaf 7");
    push("avx512vbmi2", e(|i| i.has_avx512vbmi2()), "leaf 7");
    push("avx512vnni", e(|i| i.has_avx512vnni()), "leaf 7");
    push("avx512bitalg", e(|i| i.has_avx512bitalg()), "leaf 7");
    push("avx512vpopcntdq", e(|i| i.has_avx512vpopcntdq()), "leaf 7");
    push(
        "avx512vp2intersect",
        e(|i| i.has_avx512_vp2intersect()),
        "leaf 7",
    );
    push("avx512bf16", e(|i| i.has_avx512_bf16()), "leaf 7");
    push("avx512fp16", e(|i| i.has_avx512_fp16()), "leaf 7");
    push("avx10", e(|i| i.has_avx10()), "leaf 7");
    push("avx_vnni", e(|i| i.has_avx_vnni()), "leaf 7");
    push("avx_vnni_int8", e(|i| i.has_avx_vnni_int8()), "leaf 7");
    push("avx_vnni_int16", e(|i| i.has_avx_vnni_int16()), "leaf 7");
    push("avx_ifma", e(|i| i.has_avx_ifma()), "leaf 7");
    push("avx_ne_convert", e(|i| i.has_avx_ne_convert()), "leaf 7");
    push("amx_tile", e(|i| i.has_amx_tile()), "leaf 7");
    push("amx_int8", e(|i| i.has_amx_int8()), "leaf 7");
    push("amx_bf16", e(|i| i.has_amx_bf16()), "leaf 7");
    push("sha", e(|i| i.has_sha()), "leaf 7");
    push("vaes", e(|i| i.has_vaes()), "leaf 7");
    push("vpclmulqdq", e(|i| i.has_vpclmulqdq()), "leaf 7");
    push("gfni", e(|i| i.has_gfni()), "leaf 7");
    push("rdseed", e(|i| i.has_rdseed()), "leaf 7");
    push("rtm", e(|i| i.has_rtm()), "leaf 7");
    push("hle", e(|i| i.has_hle()), "leaf 7");
    push("clflushopt", e(|i| i.has_clflushopt()), "leaf 7");
    push("clwb", e(|i| i.has_clwb()), "leaf 7");
    push("waitpkg", e(|i| i.has_waitpkg()), "leaf 7");
    push("hreset", e(|i| i.has_hreset()), "leaf 7");
    push("prefetchi", e(|i| i.has_prefetchi()), "leaf 7");
    push("rdpid", e(|i| i.has_rdpid()), "leaf 7");
    push("cet_ss", e(|i| i.has_cet_ss()), "leaf 7");
    push("cet_sss", e(|i| i.has_cet_sss()), "leaf 7");
    push("mpx", e(|i| i.has_mpx()), "leaf 7");
    push("sgx", e(|i| i.has_sgx()), "leaf 7");
    push("sgx_lc", e(|i| i.has_sgx_lc()), "leaf 7");
    push("tme", e(|i| i.has_tme_en()), "leaf 7");
    push("lam", e(|i| i.has_lam()), "leaf 7");
    push("intel_pt", e(|i| i.has_processor_trace()), "leaf 7");
    push("rdt_m", e(|i| i.has_rdtm()), "leaf 7");
    push("rdt_a", e(|i| i.has_rdta()), "leaf 7");

    // Leaf 7 bits raw-cpuid does not expose — read directly.
    let (_, _, l7c, l7d) = cpuid(7, 0);
    push("movdiri", bit(l7c, 27), "leaf 7:ECX[27]");
    push("movdir64b", bit(l7c, 28), "leaf 7:ECX[28]");
    push("fsrm", bit(l7d, 4), "leaf 7:EDX[4]");
    push("serialize", bit(l7d, 14), "leaf 7:EDX[14]");
    push("hybrid", bit(l7d, 15), "leaf 7:EDX[15]");
    push("arch_lbr", bit(l7d, 19), "leaf 7:EDX[19]");
    push("cet_ibt", bit(l7d, 20), "leaf 7:EDX[20]");

    // ---- Leaf 6: thermal & power ----------------------------------------------------
    let tp = id.get_thermal_power_info();
    let t = |g: fn(&raw_cpuid::ThermalPowerInfo) -> bool| tp.as_ref().map(g).unwrap_or(false);
    push("hwp", t(|i| i.has_hwp()), "leaf 6");
    push(
        "hwp_notification",
        t(|i| i.has_hwp_notification()),
        "leaf 6",
    );
    push(
        "hwp_epp",
        t(|i| i.has_hwp_energy_performance_preference()),
        "leaf 6",
    );
    push(
        "hwp_activity_window",
        t(|i| i.has_hwp_activity_window()),
        "leaf 6",
    );
    push(
        "hwp_package",
        t(|i| i.has_hwp_package_level_request()),
        "leaf 6",
    );
    push("turbo", t(|i| i.has_turbo_boost()), "leaf 6");
    push("turbo3", t(|i| i.has_turbo_boost3()), "leaf 6");
    push("arat", t(|i| i.has_arat()), "leaf 6");
    push("hdc", t(|i| i.has_hdc()), "leaf 6");
    push("dts", t(|i| i.has_dts()), "leaf 6");
    push("ptm", t(|i| i.has_ptm()), "leaf 6");
    push("epb", t(|i| i.has_energy_bias_pref()), "leaf 6");
    push("pln", t(|i| i.has_pln()), "leaf 6");

    // ---- Leaf 0xD: XSAVE sub-features ----------------------------------------------
    let xs = id.get_extended_state_info();
    push(
        "xsaveopt",
        xs.as_ref().map(|i| i.has_xsaveopt()).unwrap_or(false),
        "leaf 0xD",
    );
    push(
        "xsavec",
        xs.as_ref().map(|i| i.has_xsavec()).unwrap_or(false),
        "leaf 0xD",
    );
    push(
        "xsaves",
        xs.as_ref().map(|i| i.has_xsaves_xrstors()).unwrap_or(false),
        "leaf 0xD",
    );

    // ---- Extended leaf 0x80000001 --------------------------------------------------
    let epi = id.get_extended_processor_and_feature_identifiers();
    push(
        "nx",
        epi.as_ref()
            .map(|i| i.has_execute_disable())
            .unwrap_or(false),
        "ext leaf 1",
    );
    push(
        "lzcnt",
        epi.as_ref().map(|i| i.has_lzcnt()).unwrap_or(false),
        "ext leaf 1",
    );

    // ---- Leaf 0xA: architectural PMU ------------------------------------------------
    let perfmon = id
        .get_performance_monitoring_info()
        .map(|p| p.version_id() >= 1)
        .unwrap_or(false);
    push("arch_perfmon", perfmon, "leaf 0xA");

    // ---- Leaf 0x14: processor trace details ----------------------------------------
    let ptwrite = id
        .get_processor_trace_info()
        .map(|p| p.has_ptwrite())
        .unwrap_or(false);
    push("ptwrite", ptwrite, "leaf 0x14");

    // ---- Leaf 0xF/0x10: RDT monitoring & allocation --------------------------------
    let mon = id.get_rdt_monitoring_info();
    let l3mon = mon.as_ref().and_then(|m| m.l3_monitoring());
    push(
        "cmt",
        l3mon
            .as_ref()
            .map(|l| l.has_occupancy_monitoring())
            .unwrap_or(false),
        "leaf 0xF",
    );
    push(
        "mbm_local",
        l3mon
            .as_ref()
            .map(|l| l.has_local_bandwidth_monitoring())
            .unwrap_or(false),
        "leaf 0xF",
    );
    push(
        "mbm_total",
        l3mon
            .as_ref()
            .map(|l| l.has_total_bandwidth_monitoring())
            .unwrap_or(false),
        "leaf 0xF",
    );
    let alloc = id.get_rdt_allocation_info();
    push(
        "cat_l3",
        alloc.as_ref().map(|a| a.has_l3_cat()).unwrap_or(false),
        "leaf 0x10",
    );
    push(
        "cat_l2",
        alloc.as_ref().map(|a| a.has_l2_cat()).unwrap_or(false),
        "leaf 0x10",
    );
    push(
        "mba",
        alloc
            .as_ref()
            .map(|a| a.has_memory_bandwidth_allocation())
            .unwrap_or(false),
        "leaf 0x10",
    );
    let cdp = alloc
        .as_ref()
        .and_then(|a| a.l3_cat())
        .map(|c| c.has_code_data_prioritization());
    push("cdp_l3", cdp.unwrap_or(false), "leaf 0x10");

    // ---- Core type (leaf 0x1A) ------------------------------------------------------
    let core_type = if max_basic >= 0x1a {
        // CPUID.1AH:EAX[31:24] core type: 0x40 = Intel Core (P), 0x20 = Intel Atom (E).
        match cpuid(0x1A, 0).0 >> 24 {
            0x40 => CoreType::Performance,
            0x20 => CoreType::Efficiency,
            _ => CoreType::Other,
        }
    } else {
        CoreType::Other
    };

    let ident = {
        let vendor = id
            .get_vendor_info()
            .map(|v| v.as_str().to_string())
            .unwrap_or_default();
        let brand = id
            .get_processor_brand_string()
            .map(|b| b.as_str().trim().to_string())
            .unwrap_or_default();
        let (family, model, stepping) = fi
            .as_ref()
            .map(|i| {
                (
                    i.family_id() as u32,
                    i.model_id() as u32,
                    i.stepping_id() as u32,
                )
            })
            .unwrap_or((0, 0, 0));
        CoreIdent {
            vendor,
            brand,
            family,
            model,
            stepping,
        }
    };

    CoreScan {
        logical_cpu,
        core_type,
        physical_key: physical_core_key(logical_cpu, max_basic, ctx),
        feats,
        ident,
    }
}

/// Fold per-core scans into one detection per feature. A feature present on every core
/// is `Present`; on a subset, `Present` with an asymmetry note; on none, `Absent`.
#[cfg(target_arch = "x86_64")]
fn aggregate(cores: &[CoreScan]) -> Vec<(&'static str, Detection)> {
    let total = cores.len();
    // Feature order and leaf tags come from the boot core.
    let template = &cores[0].feats;
    let mut out = Vec::with_capacity(template.len());

    for (idx, &(id, _, leaf)) in template.iter().enumerate() {
        let present_types: Vec<CoreType> = cores
            .iter()
            .filter(|c| c.feats.get(idx).map(|f| f.1).unwrap_or(false))
            .map(|c| c.core_type)
            .collect();
        let count = present_types.len();

        let det = if count == total {
            Detection::with_detail(Status::Present, "cpuid", leaf)
        } else if count == 0 {
            Detection::with_detail(Status::Absent, "cpuid", leaf)
        } else {
            let types = summarize_types(&present_types);
            Detection::with_detail(
                Status::Present,
                "cpuid",
                format!("{leaf}; asymmetric: {count}/{total} cores ({types})"),
            )
        };
        out.push((id, det));
    }
    out
}

/// Human summary of which core types carry an asymmetric feature.
#[cfg(target_arch = "x86_64")]
fn summarize_types(types: &[CoreType]) -> String {
    let p = types
        .iter()
        .filter(|t| **t == CoreType::Performance)
        .count();
    let e = types.iter().filter(|t| **t == CoreType::Efficiency).count();
    match (p, e) {
        (p, 0) if p > 0 => "P-cores only".to_string(),
        (0, e) if e > 0 => "E-cores only".to_string(),
        _ => types.iter().map(|t| t.short()).collect::<Vec<_>>().join(""),
    }
}

#[cfg(target_arch = "x86_64")]
fn build_identity(cores: &[CoreScan], ctx: &Context) -> Identity {
    let ci = cores.first().map(|c| &c.ident);
    let (p_cores, e_cores) = physical_counts(cores);
    // Hybrid if the leaf-7 bit was set (recorded as a feature) or core types differ.
    let hybrid = cores
        .iter()
        .any(|c| c.feats.iter().any(|(id, v, _)| *id == "hybrid" && *v))
        || (p_cores > 0 && e_cores > 0);
    let microcode = read_microcode(ctx);
    match ci {
        Some(ci) => Identity {
            vendor: ci.vendor.clone(),
            brand: ci.brand.clone(),
            family: ci.family,
            model: ci.model,
            stepping: ci.stepping,
            model_info: cpu_db::lookup(&ci.vendor, ci.family, ci.model),
            logical_cpus: cores.len(),
            hybrid,
            p_cores,
            e_cores,
            microcode,
            max_memory_channels: cpu_db::max_memory_channels(&ci.vendor, ci.family, ci.model),
        },
        None => unreachable!("identity requires at least one successful scan"),
    }
}

#[cfg(target_arch = "x86_64")]
fn physical_counts(cores: &[CoreScan]) -> (usize, usize) {
    let physical: HashSet<(CoreType, u64)> = cores
        .iter()
        .map(|core| {
            let key = core
                .physical_key
                .unwrap_or(0x8000_0000_0000_0000 | u64::from(core.logical_cpu));
            (core.core_type, key)
        })
        .collect();
    let p_cores = physical
        .iter()
        .filter(|(kind, _)| *kind == CoreType::Performance)
        .count();
    let e_cores = physical
        .iter()
        .filter(|(kind, _)| *kind == CoreType::Efficiency)
        .count();
    (p_cores, e_cores)
}

/// Loaded microcode revision from sysfs (falls back to `/proc/cpuinfo`).
#[cfg(target_arch = "x86_64")]
fn read_microcode(ctx: &Context) -> Option<String> {
    if let Ok(v) = ctx
        .reader
        .read_to_string(Path::new("/sys/devices/system/cpu/cpu0/microcode/version"))
    {
        return Some(v.trim().to_string());
    }
    let info = ctx.reader.read_to_string(Path::new("/proc/cpuinfo")).ok()?;
    for line in info.lines() {
        if let Some(rest) = line.strip_prefix("microcode") {
            if let Some((_, v)) = rest.split_once(':') {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn physical_core_key(cpu: u32, max_basic: u32, ctx: &Context) -> Option<u64> {
    let leaf = if max_basic >= 0x1f {
        Some(0x1f)
    } else if max_basic >= 0x0b {
        Some(0x0b)
    } else {
        None
    };
    if let Some(leaf) = leaf {
        let mut smt_shift = None;
        let mut x2apic = None;
        for subleaf in 0..32 {
            let (eax, ebx, ecx, edx) = raw::cpuid(leaf, subleaf);
            if ebx == 0 {
                break;
            }
            x2apic = Some(edx);
            if (ecx >> 8) & 0xff == 1 {
                smt_shift = Some(eax & 0x1f);
            }
        }
        if let (Some(id), Some(shift)) = (x2apic, smt_shift) {
            return Some(u64::from(id >> shift));
        }
    }
    let base = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
    let package = ctx
        .reader
        .read_to_string(Path::new(&format!("{base}/physical_package_id")))
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    let core = ctx
        .reader
        .read_to_string(Path::new(&format!("{base}/core_id")))
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    Some((u64::from(package) << 32) | u64::from(core))
}

/// Parse Linux CPU-list syntax such as `0-3,8-11`.
#[cfg(target_arch = "x86_64")]
fn parse_cpu_list(text: &str) -> Option<Vec<u32>> {
    let mut cpus = Vec::new();
    for part in text.trim().split(',').filter(|s| !s.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?);
                if a > b {
                    return None;
                }
                cpus.extend(a..=b);
            }
            None => {
                cpus.push(part.parse::<u32>().ok()?);
            }
        }
    }
    (!cpus.is_empty()).then_some(cpus)
}

#[cfg(target_arch = "x86_64")]
fn eligible_cpus(ctx: &Context) -> Vec<u32> {
    let allowed_text = ctx
        .reader
        .read_to_string(Path::new("/proc/self/status"))
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("Cpus_allowed_list:")
                    .map(str::trim)
                    .map(str::to_string)
            })
        });
    let online_text = ctx
        .reader
        .read_to_string(Path::new("/sys/devices/system/cpu/online"))
        .ok();
    let Some(allowed) = allowed_text.as_deref().and_then(parse_cpu_list) else {
        return Vec::new();
    };
    let Some(online) = online_text.as_deref().and_then(parse_cpu_list) else {
        return Vec::new();
    };
    let online: HashSet<_> = online.into_iter().collect();
    allowed
        .into_iter()
        .filter(|cpu| online.contains(cpu))
        .collect()
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    fn core(cpu: u32, kind: CoreType, key: Option<u64>) -> CoreScan {
        CoreScan {
            logical_cpu: cpu,
            core_type: kind,
            physical_key: key,
            feats: Vec::new(),
            ident: CoreIdent {
                vendor: String::new(),
                brand: String::new(),
                family: 0,
                model: 0,
                stepping: 0,
            },
        }
    }

    #[test]
    fn cpu_list_supports_sparse_and_high_ids() {
        assert_eq!(
            parse_cpu_list("2-3,1024,4096"),
            Some(vec![2, 3, 1024, 4096])
        );
        assert_eq!(parse_cpu_list("4-2"), None);
        assert_eq!(parse_cpu_list("garbage"), None);
    }

    #[test]
    fn smt_siblings_are_counted_as_one_physical_core() {
        let cores = vec![
            core(2, CoreType::Performance, Some(10)),
            core(6, CoreType::Performance, Some(10)),
            core(9, CoreType::Efficiency, Some(11)),
        ];
        assert_eq!(physical_counts(&cores), (1, 1));
    }

    #[test]
    fn missing_topology_key_does_not_merge_logical_cpus() {
        let cores = vec![
            core(1024, CoreType::Performance, None),
            core(4096, CoreType::Performance, None),
        ];
        assert_eq!(physical_counts(&cores), (2, 0));
    }
}

// =====================================================================================
// Non-x86 fallback
// =====================================================================================

#[cfg(not(target_arch = "x86_64"))]
fn run_scan(_ctx: &Context) -> Scan {
    Scan {
        identity: None,
        detections: Vec::new(),
    }
}
