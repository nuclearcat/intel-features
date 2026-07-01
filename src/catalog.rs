//! The feature registry: the static list of features the tool knows about.
//!
//! M1 expands this to comprehensive CPUID-detectable coverage across the ISA,
//! security, virtualization, power, topology, performance-monitoring and RDT
//! categories. Features carry an optional `/proc/cpuinfo` flag name so the procfs
//! probe can corroborate CPUID and the reporter can flag silicon-vs-kernel
//! disparities.
//!
//! `def(...)` = no kernel flag; `defk(..., flag)` = with a known `/proc/cpuinfo` flag.

use crate::model::{Category, FeatureDef, Privilege};

use Category::*;
use Privilege::User;

/// All features known to the tool, in no particular order (the reporter groups
/// and orders them by [`Category`]). `#[rustfmt::skip]` keeps this dense table
/// one-feature-per-line rather than exploding each `defk(...)` across five lines.
#[rustfmt::skip]
pub const FEATURES: &[FeatureDef] = &[
    // ================= Instruction Set Extensions ===================================
    defk("sse", "SSE", Isa, "128-bit SIMD", "sse"),
    defk("sse2", "SSE2", Isa, "128-bit SIMD (x86-64 baseline)", "sse2"),
    defk("sse3", "SSE3", Isa, "SIMD3", "pni"),
    defk("ssse3", "SSSE3", Isa, "Supplemental SSE3", "ssse3"),
    defk("sse4_1", "SSE4.1", Isa, "SIMD4.1", "sse4_1"),
    defk("sse4_2", "SSE4.2", Isa, "String/text SIMD + CRC32", "sse4_2"),
    defk("avx", "AVX", Isa, "256-bit FP SIMD", "avx"),
    defk("avx2", "AVX2", Isa, "256-bit integer SIMD", "avx2"),
    defk("fma", "FMA3", Isa, "Fused multiply-add", "fma"),
    defk("f16c", "F16C", Isa, "Half-precision float conversion", "f16c"),
    // AVX-512 family
    defk("avx512f", "AVX-512F", Isa, "512-bit SIMD foundation", "avx512f"),
    defk("avx512cd", "AVX-512CD", Isa, "Conflict detection", "avx512cd"),
    defk("avx512vl", "AVX-512VL", Isa, "Vector length extensions", "avx512vl"),
    defk("avx512dq", "AVX-512DQ", Isa, "Doubleword/quadword", "avx512dq"),
    defk("avx512bw", "AVX-512BW", Isa, "Byte/word", "avx512bw"),
    defk("avx512ifma", "AVX-512IFMA", Isa, "Integer FMA", "avx512ifma"),
    defk("avx512vbmi", "AVX-512VBMI", Isa, "Vector byte manipulation", "avx512vbmi"),
    defk("avx512vbmi2", "AVX-512VBMI2", Isa, "Vector byte manipulation 2", "avx512_vbmi2"),
    defk("avx512vnni", "AVX-512VNNI", Isa, "Vector neural-net instructions", "avx512_vnni"),
    defk("avx512bitalg", "AVX-512BITALG", Isa, "Bit algorithms", "avx512_bitalg"),
    defk("avx512vpopcntdq", "AVX-512VPOPCNTDQ", Isa, "Vector popcount", "avx512_vpopcntdq"),
    def("avx512vp2intersect", "AVX-512VP2INTERSECT", Isa, "Vector pair intersection"),
    def("avx512bf16", "AVX-512BF16", Isa, "bfloat16"),
    def("avx512fp16", "AVX-512FP16", Isa, "IEEE half-precision"),
    def("avx10", "AVX10", Isa, "Unified AVX successor ISA"),
    // AVX-VNNI / VEX-form new ISA
    defk("avx_vnni", "AVX-VNNI", Isa, "VEX-encoded VNNI", "avx_vnni"),
    def("avx_vnni_int8", "AVX-VNNI-INT8", Isa, "VEX VNNI int8"),
    def("avx_vnni_int16", "AVX-VNNI-INT16", Isa, "VEX VNNI int16"),
    def("avx_ifma", "AVX-IFMA", Isa, "VEX integer FMA"),
    def("avx_ne_convert", "AVX-NE-CONVERT", Isa, "VEX no-exception convert"),
    // AMX
    def("amx_tile", "AMX-TILE", Isa, "Tile architecture"),
    def("amx_int8", "AMX-INT8", Isa, "Tile int8 matmul"),
    def("amx_bf16", "AMX-BF16", Isa, "Tile bfloat16 matmul"),
    // Bit-manip / integer
    defk("popcnt", "POPCNT", Isa, "Population count", "popcnt"),
    defk("lzcnt", "LZCNT/ABM", Isa, "Leading-zero count", "abm"),
    defk("bmi1", "BMI1", Isa, "Bit-manipulation 1", "bmi1"),
    defk("bmi2", "BMI2", Isa, "Bit-manipulation 2", "bmi2"),
    defk("adx", "ADX", Isa, "Multi-precision add-carry", "adx"),
    defk("movbe", "MOVBE", Isa, "Big-endian move", "movbe"),
    // Crypto
    defk("aes", "AES-NI", Isa, "Hardware AES", "aes"),
    defk("vaes", "VAES", Isa, "Vector AES", "vaes"),
    defk("pclmulqdq", "PCLMULQDQ", Isa, "Carry-less multiply", "pclmulqdq"),
    defk("vpclmulqdq", "VPCLMULQDQ", Isa, "Vector carry-less multiply", "vpclmulqdq"),
    defk("sha", "SHA-NI", Isa, "Hardware SHA-1/256", "sha_ni"),
    defk("gfni", "GFNI", Isa, "Galois-field new instructions", "gfni"),
    // RNG
    defk("rdrand", "RDRAND", Isa, "On-chip DRBG", "rdrand"),
    defk("rdseed", "RDSEED", Isa, "On-chip entropy source", "rdseed"),
    // TSX
    defk("rtm", "RTM (TSX)", Isa, "Restricted transactional memory", "rtm"),
    defk("hle", "HLE (TSX)", Isa, "Hardware lock elision (deprecated)", "hle"),
    // Memory/streaming
    defk("clflushopt", "CLFLUSHOPT", Isa, "Optimized cache-line flush", "clflushopt"),
    defk("clwb", "CLWB", Isa, "Cache-line write-back", "clwb"),
    defk("movdiri", "MOVDIRI", Isa, "Direct-store doubleword", "movdiri"),
    defk("movdir64b", "MOVDIR64B", Isa, "64-byte direct store", "movdir64b"),
    defk("serialize", "SERIALIZE", Isa, "Serializing instruction", "serialize"),
    defk("waitpkg", "WAITPKG", Isa, "UMONITOR/UMWAIT/TPAUSE", "waitpkg"),
    def("hreset", "HRESET", Isa, "History reset (Thread Director)"),
    def("prefetchi", "PREFETCHI", Isa, "Code prefetch to L2"),
    defk("fsrm", "FSRM", Isa, "Fast short REP MOVSB", "fsrm"),
    defk("rdpid", "RDPID", Isa, "Read processor ID", "rdpid"),
    defk("cmpxchg16b", "CMPXCHG16B", Isa, "128-bit compare-exchange", "cx16"),
    defk("fsgsbase", "FSGSBASE", Isa, "User FS/GS base access", "fsgsbase"),
    // XSAVE family
    defk("xsave", "XSAVE", Isa, "Extended state save/restore", "xsave"),
    defk("xsaveopt", "XSAVEOPT", Isa, "Optimized XSAVE", "xsaveopt"),
    defk("xsavec", "XSAVEC", Isa, "Compacted XSAVE", "xsavec"),
    defk("xsaves", "XSAVES", Isa, "Supervisor XSAVE", "xsaves"),
    // ================= Security ======================================================
    defk("nx", "NX / XD", Security, "No-execute page protection", "nx"),
    defk("smep", "SMEP", Security, "Supervisor-mode exec prevention", "smep"),
    defk("smap", "SMAP", Security, "Supervisor-mode access prevention", "smap"),
    defk("umip", "UMIP", Security, "User-mode instruction prevention", "umip"),
    defk("pku", "PKU", Security, "User-mode protection keys", "pku"),
    defk("ospke", "OSPKE", Security, "OS-enabled protection keys", "ospke"),
    defk("cet_ss", "CET Shadow Stack", Security, "Return-address protection", "user_shstk"),
    defk("cet_ibt", "CET-IBT", Security, "Indirect branch tracking", "ibt"),
    def("cet_sss", "CET SSS", Security, "Supervisor shadow-stack safe"),
    defk("mpx", "MPX", Security, "Memory protection extensions (removed)", "mpx"),
    defk("sgx", "SGX", Security, "Software Guard Extensions", "sgx"),
    def("sgx_lc", "SGX Launch Control", Security, "Flexible launch control"),
    def("tme", "TME", Security, "Total Memory Encryption"),
    defk("lam", "LAM", Security, "Linear Address Masking", "lam"),
    defk("tpm", "TPM", Security, "Trusted Platform Module device present", ""),
    // ================= CPU Vulnerabilities & Mitigations =============================
    // ids are the kernel filenames under /sys/devices/system/cpu/vulnerabilities/.
    // The vulns probe enumerates that directory; any file with no entry here is
    // collected under `vuln_other` rather than silently dropped.
    defv("meltdown", "Meltdown", Vulnerabilities, "Rogue data cache load (CVE-2017-5754)"),
    defv("spectre_v1", "Spectre v1", Vulnerabilities, "Bounds-check bypass"),
    defv("spectre_v2", "Spectre v2", Vulnerabilities, "Branch-target injection"),
    defv("spec_store_bypass", "Spectre v4 (SSB)", Vulnerabilities, "Speculative store bypass"),
    defv("l1tf", "L1TF", Vulnerabilities, "L1 Terminal Fault / Foreshadow"),
    defv("mds", "MDS", Vulnerabilities, "Microarchitectural Data Sampling"),
    defv("tsx_async_abort", "TAA", Vulnerabilities, "TSX Asynchronous Abort"),
    defv("itlb_multihit", "iTLB Multihit", Vulnerabilities, "Instruction-TLB multihit"),
    defv("srbds", "SRBDS", Vulnerabilities, "Special Register Buffer Data Sampling"),
    defv("mmio_stale_data", "MMIO Stale Data", Vulnerabilities, "Processor MMIO stale data"),
    defv("retbleed", "Retbleed", Vulnerabilities, "Return-stack-buffer underflow"),
    defv("gather_data_sampling", "GDS (Downfall)", Vulnerabilities, "Gather Data Sampling"),
    defv("reg_file_data_sampling", "RFDS", Vulnerabilities, "Register File Data Sampling"),
    defv("spec_rstack_overflow", "SRSO", Vulnerabilities, "Speculative return-stack overflow"),
    defv("indirect_target_selection", "ITS", Vulnerabilities, "Indirect Target Selection"),
    defv("ghostwrite", "GhostWrite", Vulnerabilities, "Architectural write vulnerability"),
    defv("old_microcode", "Old Microcode", Vulnerabilities, "Running outdated microcode"),
    defv("tsa", "TSA", Vulnerabilities, "Transient Scheduler Attack"),
    defv("vmscape", "VMScape", Vulnerabilities, "Guest→host branch-predictor leak"),
    defv("vuln_other", "Other (uncatalogued)", Vulnerabilities, "Kernel-listed vulns not yet in catalog"),
    // ============ Architectural Capabilities (IA32_ARCH_CAPABILITIES, MSR 0x10A) =====
    // Present = the CPU declares this bit. Most *_NO bits mean "immune to X".
    def("rdcl_no", "RDCL_NO", ArchCaps, "Immune to Meltdown (rogue data cache load)"),
    def("eibrs", "IBRS_ALL / eIBRS", ArchCaps, "Enhanced IBRS (always-on branch restriction)"),
    def("rsba", "RSBA", ArchCaps, "Retpoline-susceptible RSB behaviour"),
    def("ssb_no", "SSB_NO", ArchCaps, "Immune to Spectre-v4 (speculative store bypass)"),
    def("mds_no", "MDS_NO", ArchCaps, "Immune to MDS"),
    def("if_pschange_no", "IF_PSCHANGE_MC_NO", ArchCaps, "No MCE on page-size change"),
    def("tsx_ctrl", "TSX_CTRL", ArchCaps, "TSX control MSR (0x122) available"),
    def("taa_no", "TAA_NO", ArchCaps, "Immune to TSX Async Abort"),
    def("misc_package_ctls", "MISC_PACKAGE_CTLS", ArchCaps, "MSR 0x1AA available"),
    def("fb_clear", "FB_CLEAR", ArchCaps, "Fill-buffer clear (VERW) supported"),
    def("rrsba", "RRSBA", ArchCaps, "Restricted RSB alternate behaviour"),
    def("bhi_no", "BHI_NO", ArchCaps, "Immune to Branch History Injection"),
    def("pbrsb_no", "PBRSB_NO", ArchCaps, "Immune to Post-barrier RSB predictions"),
    def("gds_no", "GDS_NO", ArchCaps, "Immune to Gather Data Sampling (Downfall)"),
    def("rfds_no", "RFDS_NO", ArchCaps, "Immune to Register File Data Sampling"),
    // ================= Virtualization ================================================
    defk("vmx", "VT-x (VMX)", Virtualization, "Hardware virtualization", "vmx"),
    defk("smx", "SMX (TXT)", Virtualization, "Safer Mode Extensions", "smx"),
    defk("hypervisor", "Running under hypervisor", Virtualization, "Guest/VM detection", "hypervisor"),
    def("kvm", "KVM usable", Virtualization, "/dev/kvm present and openable"),
    // VMX capability MSRs (0x481/0x48B/0x48C) — some also named by the kernel.
    defk("ept", "EPT", Virtualization, "Extended Page Tables (2nd-level address translation)", "ept"),
    defk("vpid", "VPID", Virtualization, "Virtual-processor IDs (tagged TLB)", "vpid"),
    defk("ept_ad", "EPT A/D", Virtualization, "EPT accessed/dirty bits", "ept_ad"),
    def("ept_1gb", "EPT 1GB pages", Virtualization, "1 GiB EPT mappings"),
    def("unrestricted_guest", "Unrestricted Guest", Virtualization, "Real-mode/unpaged guest execution"),
    def("apicv", "APICv", Virtualization, "Virtual-interrupt delivery"),
    def("posted_intr", "Posted Interrupts", Virtualization, "Direct interrupt posting to guest"),
    def("vmcs_shadow", "VMCS Shadowing", Virtualization, "Nested-VMX VMREAD/VMWRITE without exit"),
    // ================= Power & Thermal ===============================================
    defk("eist", "Enhanced SpeedStep", Power, "Software P-state control", "est"),
    defk("hwp", "HWP / Speed Shift", Power, "Hardware-managed P-states", "hwp"),
    defk("hwp_notification", "HWP Notification", Power, "Interrupt on HWP change", "hwp_notify"),
    defk("hwp_epp", "HWP EPP", Power, "Energy/perf preference", "hwp_epp"),
    defk("hwp_activity_window", "HWP Activity Window", Power, "HWP window hint", "hwp_act_window"),
    defk("hwp_package", "HWP Package Request", Power, "Package-level HWP", "hwp_pkg_req"),
    defk("turbo", "Turbo Boost", Power, "Opportunistic frequency boost", "ida"),
    def("turbo3", "Turbo Boost Max 3.0", Power, "Favored-core boost"),
    defk("arat", "ARAT", Power, "Always-running APIC timer", "arat"),
    defk("hdc", "HDC", Power, "Hardware Duty Cycling", "hdc"),
    defk("dts", "Digital Thermal Sensor", Power, "On-die thermal sensor", "dts"),
    defk("ptm", "Package Thermal Mgmt", Power, "Package-level thermal", "pts"),
    defk("epb", "Energy Perf Bias", Power, "IA32_ENERGY_PERF_BIAS", "epb"),
    defk("tm2", "Thermal Monitor 2", Power, "TM2 throttling", "tm2"),
    defk("pln", "Power Limit Notification", Power, "PLN interrupt", "pln"),
    // Runtime driver/state (sysfs)
    def("intel_pstate", "intel_pstate driver", Power, "P-state governor driver active"),
    def("intel_idle", "intel_idle driver", Power, "C-state idle driver active"),
    def("rapl", "RAPL powercap", Power, "Running Average Power Limit domains exposed"),
    // MSR-derived values (root)
    defv("tjmax", "TjMax", Power, "Thermal throttle temperature (MSR 0x1A2)"),
    defv("pkg_tdp", "Package TDP", Power, "Thermal design power (MSR 0x614)"),
    defv("pkg_power_limit", "Package Power Limit", Power, "RAPL PL1/PL2 (MSR 0x610)"),
    defv("smi_count", "SMI Count", Power, "System Management Interrupts seen (MSR 0x34)"),
    // ================= Topology ======================================================
    defk("x2apic", "x2APIC", Topology, "Extended APIC addressing", "x2apic"),
    defk("htt", "HTT (multi-logical)", Topology, "Multiple logical CPUs/package", "ht"),
    def("hybrid", "Hybrid cores", Topology, "P-core / E-core hybrid topology"),
    def("smt", "SMT / Hyper-Threading", Topology, "Simultaneous multithreading"),
    defk("invariant_tsc", "Invariant TSC", Topology, "Constant-rate TSC", "constant_tsc"),
    defk("tsc_deadline", "TSC-Deadline Timer", Topology, "One-shot APIC deadline", "tsc_deadline_timer"),
    defk("monitor", "MONITOR/MWAIT", Topology, "Address-monitor wait", "monitor"),
    // ================= Performance Monitoring & Trace ================================
    defk("arch_perfmon", "Arch PerfMon", Perf, "Architectural PMU", "arch_perfmon"),
    defk("pdcm", "PDCM", Perf, "Perf/debug capabilities MSR", "pdcm"),
    defk("pebs", "PEBS", Perf, "Precise event-based sampling", "pebs"),
    defk("bts", "BTS", Perf, "Branch trace store", "bts"),
    defk("intel_pt", "Intel PT", Perf, "Processor Trace", "intel_pt"),
    defk("arch_lbr", "Arch LBR", Perf, "Architectural last-branch records", "arch_lbr"),
    def("ptwrite", "PTWRITE", Perf, "Write to PT stream"),
    // ================= Resource Director Technology ==================================
    defk("rdt_m", "RDT Monitoring", Rdt, "Cache/bandwidth monitoring (leaf 0xF)", "cqm"),
    def("cmt", "CMT", Rdt, "Cache occupancy (L3) monitoring"),
    def("mbm_local", "MBM Local", Rdt, "Local memory-bandwidth monitoring"),
    def("mbm_total", "MBM Total", Rdt, "Total memory-bandwidth monitoring"),
    defk("rdt_a", "RDT Allocation", Rdt, "Cache/bandwidth allocation (leaf 0x10)", "rdt_a"),
    def("cat_l3", "L3 CAT", Rdt, "L3 cache allocation"),
    def("cat_l2", "L2 CAT", Rdt, "L2 cache allocation"),
    def("cdp_l3", "L3 CDP", Rdt, "L3 code/data prioritization"),
    def("mba", "MBA", Rdt, "Memory-bandwidth allocation"),
    def("resctrl", "resctrl mounted", Rdt, "/sys/fs/resctrl available for use"),
    // ================= Platform & Firmware ===========================================
    def("msr", "MSR access", Firmware, "/dev/cpu/*/msr readable (root + msr module)"),
    def("feature_control_locked", "IA32_FEATURE_CONTROL lock", Firmware, "Feature-control MSR locked by firmware"),
    defv("boot_guard", "Boot Guard (SACM info)", Firmware, "MSR 0x13A readable (ACM/verified-boot state)"),
];

/// Feature with no kernel-flag mapping.
const fn def(
    id: &'static str,
    name: &'static str,
    category: Category,
    description: &'static str,
) -> FeatureDef {
    FeatureDef {
        id,
        name,
        category,
        description,
        min_privilege: User,
        cpuinfo_flag: None,
        inline_detail: false,
    }
}

/// Value/detail feature: the reporter shows the detection's detail inline (a value or
/// a mitigation string) rather than the probe names.
const fn defv(
    id: &'static str,
    name: &'static str,
    category: Category,
    description: &'static str,
) -> FeatureDef {
    FeatureDef {
        inline_detail: true,
        ..def(id, name, category, description)
    }
}

/// Feature with a known `/proc/cpuinfo` flag. An empty `flag` means "the feature has
/// no CPUID/flag mapping at all" (e.g. `tpm`, detected purely via device nodes) and is
/// treated as no mapping.
const fn defk(
    id: &'static str,
    name: &'static str,
    category: Category,
    description: &'static str,
    flag: &'static str,
) -> FeatureDef {
    let cpuinfo_flag = if flag.is_empty() { None } else { Some(flag) };
    FeatureDef {
        id,
        name,
        category,
        description,
        min_privilege: User,
        cpuinfo_flag,
        inline_detail: false,
    }
}

/// Look up a feature definition by id.
pub fn find(id: &str) -> Option<&'static FeatureDef> {
    FEATURES.iter().find(|f| f.id == id)
}
