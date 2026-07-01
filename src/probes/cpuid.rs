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

use crate::model::{Detection, Status};
use crate::probes::{Context, Probe};

/// CPU identity + topology summary, shown as the report banner.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Identity {
    pub vendor: String,
    pub brand: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub logical_cpus: usize,
    pub hybrid: bool,
    pub p_cores: usize,
    pub e_cores: usize,
}

pub struct CpuidProbe;

impl Probe for CpuidProbe {
    fn name(&self) -> &'static str {
        "cpuid"
    }

    fn detect(&self, _ctx: &Context) -> Vec<(&'static str, Detection)> {
        scan().detections.clone()
    }
}

/// CPU identity banner, if determinable on this architecture.
pub fn identity() -> Option<Identity> {
    scan().identity.clone()
}

/// Per-architecture core type as reported by CPUID leaf 0x1A.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Memoized scan — CPUID does not change during a run.
fn scan() -> &'static Scan {
    use std::sync::OnceLock;
    static SCAN: OnceLock<Scan> = OnceLock::new();
    SCAN.get_or_init(run_scan)
}

// =====================================================================================
// x86-64 implementation
// =====================================================================================

#[cfg(target_arch = "x86_64")]
fn run_scan() -> Scan {
    let cpus = online_cpus();
    let cores: Vec<CoreScan> = cpus.iter().filter_map(|&c| scan_pinned(c)).collect();
    if cores.is_empty() {
        return Scan {
            identity: None,
            detections: Vec::new(),
        };
    }
    let identity = build_identity(&cores);
    let detections = aggregate(&cores);
    Scan {
        identity: Some(identity),
        detections,
    }
}

/// One core's findings: its type and the full feature boolean vector (with leaf tags).
struct CoreScan {
    core_type: CoreType,
    feats: Vec<(&'static str, bool, &'static str)>,
    // Identity fields, filled from the boot core only.
    ident: Option<CoreIdent>,
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
fn scan_pinned(cpu: u32) -> Option<CoreScan> {
    std::thread::Builder::new()
        .name(format!("cpuid-scan-{cpu}"))
        .spawn(move || {
            if !pin_to(cpu) {
                return None;
            }
            Some(scan_core(cpu == 0))
        })
        .ok()?
        .join()
        .ok()?
}

/// Bind the current thread to a single logical CPU.
#[cfg(target_arch = "x86_64")]
fn pin_to(cpu: u32) -> bool {
    // SAFETY: zeroed cpu_set_t is valid; we pass its true size to the kernel.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu as usize, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    }
}

/// Decode every catalog-relevant feature on the current core.
#[cfg(target_arch = "x86_64")]
fn scan_core(is_boot: bool) -> CoreScan {
    use raw::{bit, cpuid};
    let id = raw_cpuid::CpuId::new();

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
    let core_type = if id.get_extended_feature_info().map(|_| ()).is_some() {
        // CPUID.1AH:EAX[31:24] core type: 0x40 = Intel Core (P), 0x20 = Intel Atom (E).
        match cpuid(0x1A, 0).0 >> 24 {
            0x40 => CoreType::Performance,
            0x20 => CoreType::Efficiency,
            _ => CoreType::Other,
        }
    } else {
        CoreType::Other
    };

    let ident = if is_boot {
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
        Some(CoreIdent {
            vendor,
            brand,
            family,
            model,
            stepping,
        })
    } else {
        None
    };

    CoreScan {
        core_type,
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
fn build_identity(cores: &[CoreScan]) -> Identity {
    let ci = cores.iter().find_map(|c| c.ident.as_ref());
    let p_cores = cores
        .iter()
        .filter(|c| c.core_type == CoreType::Performance)
        .count();
    let e_cores = cores
        .iter()
        .filter(|c| c.core_type == CoreType::Efficiency)
        .count();
    // Hybrid if the leaf-7 bit was set (recorded as a feature) or core types differ.
    let hybrid = cores
        .iter()
        .any(|c| c.feats.iter().any(|(id, v, _)| *id == "hybrid" && *v))
        || (p_cores > 0 && e_cores > 0);
    match ci {
        Some(ci) => Identity {
            vendor: ci.vendor.clone(),
            brand: ci.brand.clone(),
            family: ci.family,
            model: ci.model,
            stepping: ci.stepping,
            logical_cpus: cores.len(),
            hybrid,
            p_cores,
            e_cores,
        },
        None => Identity {
            vendor: String::new(),
            brand: String::new(),
            family: 0,
            model: 0,
            stepping: 0,
            logical_cpus: cores.len(),
            hybrid,
            p_cores,
            e_cores,
        },
    }
}

/// Parse `/sys/devices/system/cpu/online` (e.g. `"0-3,8-11"`). Falls back to `[0]`.
#[cfg(target_arch = "x86_64")]
fn online_cpus() -> Vec<u32> {
    let text = std::fs::read_to_string("/sys/devices/system/cpu/online").unwrap_or_default();
    let mut cpus = Vec::new();
    for part in text.trim().split(',').filter(|s| !s.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                    cpus.extend(a..=b);
                }
            }
            None => {
                if let Ok(n) = part.parse::<u32>() {
                    cpus.push(n);
                }
            }
        }
    }
    if cpus.is_empty() {
        cpus.push(0);
    }
    cpus
}

// =====================================================================================
// Non-x86 fallback
// =====================================================================================

#[cfg(not(target_arch = "x86_64"))]
fn run_scan() -> Scan {
    Scan {
        identity: None,
        detections: Vec::new(),
    }
}
