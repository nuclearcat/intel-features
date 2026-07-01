//! The feature registry: the static list of features the tool knows about.
//!
//! M0 ships a representative subset spanning several categories so the end-to-end
//! pipeline (probe → aggregate → report) is exercised for real. Later milestones
//! grow this list to match `PLAN.md`'s catalog; the probes are what determine how
//! much of it can actually be answered.

use crate::model::{Category, FeatureDef, Privilege};

use Category::*;
use Privilege::User;

/// All features known to the tool, in no particular order (the reporter groups
/// and orders them by [`Category`]).
pub const FEATURES: &[FeatureDef] = &[
    // ---- Instruction Set Extensions -------------------------------------------------
    def("sse2", "SSE2", Isa, "128-bit SIMD (baseline for x86-64)"),
    def("sse4_2", "SSE4.2", Isa, "String/text SIMD + CRC32"),
    def("avx", "AVX", Isa, "256-bit floating-point SIMD"),
    def("avx2", "AVX2", Isa, "256-bit integer SIMD"),
    def("fma", "FMA3", Isa, "Fused multiply-add"),
    def("f16c", "F16C", Isa, "Half-precision float conversion"),
    def("avx512f", "AVX-512F", Isa, "512-bit SIMD foundation"),
    def("bmi1", "BMI1", Isa, "Bit-manipulation instructions 1"),
    def("bmi2", "BMI2", Isa, "Bit-manipulation instructions 2"),
    def("popcnt", "POPCNT", Isa, "Population count"),
    def("movbe", "MOVBE", Isa, "Big-endian move"),
    def("aes", "AES-NI", Isa, "Hardware AES acceleration"),
    def(
        "pclmulqdq",
        "PCLMULQDQ",
        Isa,
        "Carry-less multiply (GCM, CRC)",
    ),
    def("sha", "SHA-NI", Isa, "Hardware SHA-1/SHA-256"),
    def("rdrand", "RDRAND", Isa, "On-chip DRBG random numbers"),
    def("rdseed", "RDSEED", Isa, "On-chip entropy source"),
    def(
        "waitpkg",
        "WAITPKG",
        Isa,
        "UMONITOR/UMWAIT/TPAUSE user wait",
    ),
    def(
        "movdir64b",
        "MOVDIR64B",
        Isa,
        "64-byte direct store (accelerator doorbells)",
    ),
    def("serialize", "SERIALIZE", Isa, "Serializing instruction"),
    // ---- Security -------------------------------------------------------------------
    def("nx", "NX / XD", Security, "No-execute page protection"),
    def(
        "smep",
        "SMEP",
        Security,
        "Supervisor-mode execution prevention",
    ),
    def(
        "smap",
        "SMAP",
        Security,
        "Supervisor-mode access prevention",
    ),
    def("umip", "UMIP", Security, "User-mode instruction prevention"),
    def("pku", "PKU", Security, "User-mode protection keys"),
    def("cet_ibt", "CET-IBT", Security, "Indirect branch tracking"),
    def(
        "tpm",
        "TPM",
        Security,
        "Trusted Platform Module device present",
    ),
    // ---- Virtualization -------------------------------------------------------------
    def(
        "vmx",
        "VT-x (VMX)",
        Virtualization,
        "Hardware virtualization",
    ),
    def(
        "hypervisor",
        "Running under hypervisor",
        Virtualization,
        "Guest/VM detection",
    ),
    def(
        "kvm",
        "KVM usable",
        Virtualization,
        "/dev/kvm present and openable",
    ),
    // ---- Power & Thermal ------------------------------------------------------------
    def(
        "hwp",
        "HWP / Speed Shift",
        Power,
        "Hardware-managed P-states",
    ),
    def("arat", "ARAT", Power, "Always-running APIC timer"),
    // ---- Topology -------------------------------------------------------------------
    def("x2apic", "x2APIC", Topology, "Extended APIC addressing"),
    def(
        "hybrid",
        "Hybrid cores",
        Topology,
        "P-core / E-core hybrid topology",
    ),
    def(
        "smt",
        "SMT / Hyper-Threading",
        Topology,
        "Simultaneous multithreading",
    ),
];

/// Const helper so the table above stays terse. All M0 features are `User`-privilege.
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
    }
}

/// Look up a feature definition by id.
pub fn find(id: &str) -> Option<&'static FeatureDef> {
    FEATURES.iter().find(|f| f.id == id)
}
