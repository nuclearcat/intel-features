//! CPUID probe — the zero-privilege workhorse.
//!
//! M0 decodes a representative subset of leaves using `std::arch` intrinsics directly
//! (no external crate). M1 replaces the hand-decoding with the `raw-cpuid` crate and
//! grows coverage to the full ISA/security/virtualization catalog.
//!
//! CPUID reports *silicon capability*. Whether a capability is actually enabled by
//! firmware/OS is a separate question answered by other probes (MSR, sysfs); those
//! detections are aggregated per feature alongside this one.

use crate::model::{Detection, Status};
use crate::probes::{Context, Probe};

/// CPU identity, shown as the report banner.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Identity {
    pub vendor: String,
    pub brand: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
}

pub struct CpuidProbe;

impl Probe for CpuidProbe {
    fn name(&self) -> &'static str {
        "cpuid"
    }

    fn detect(&self, _ctx: &Context) -> Vec<(&'static str, Detection)> {
        detect_impl()
    }
}

// =====================================================================================
// x86-64 implementation
// =====================================================================================

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::*;
    use core::arch::x86_64::__cpuid_count;

    /// Raw CPUID leaf/subleaf read. `__cpuid_count` is safe on x86-64 (CPUID is
    /// unconditionally available there).
    fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
        let r = __cpuid_count(leaf, sub);
        (r.eax, r.ebx, r.ecx, r.edx)
    }

    fn max_leaf() -> u32 {
        cpuid(0, 0).0
    }

    fn max_ext_leaf() -> u32 {
        cpuid(0x8000_0000, 0).0
    }

    fn bit(v: u32, n: u32) -> bool {
        (v >> n) & 1 == 1
    }

    pub fn identity() -> Option<Identity> {
        let (_, ebx, ecx, edx) = cpuid(0, 0);
        let mut vendor = Vec::with_capacity(12);
        vendor.extend_from_slice(&ebx.to_le_bytes());
        vendor.extend_from_slice(&edx.to_le_bytes());
        vendor.extend_from_slice(&ecx.to_le_bytes());
        let vendor = String::from_utf8_lossy(&vendor).trim().to_string();

        let (eax1, ..) = cpuid(1, 0);
        let base_family = (eax1 >> 8) & 0xf;
        let ext_family = (eax1 >> 20) & 0xff;
        let base_model = (eax1 >> 4) & 0xf;
        let ext_model = (eax1 >> 16) & 0xf;
        let stepping = eax1 & 0xf;
        let family = if base_family == 0xf {
            base_family + ext_family
        } else {
            base_family
        };
        let model = if base_family == 0x6 || base_family == 0xf {
            (ext_model << 4) | base_model
        } else {
            base_model
        };

        let brand = brand_string().unwrap_or_default();

        Some(Identity {
            vendor,
            brand,
            family,
            model,
            stepping,
        })
    }

    fn brand_string() -> Option<String> {
        if max_ext_leaf() < 0x8000_0004 {
            return None;
        }
        let mut bytes = Vec::with_capacity(48);
        for leaf in 0x8000_0002u32..=0x8000_0004 {
            let (a, b, c, d) = cpuid(leaf, 0);
            for reg in [a, b, c, d] {
                bytes.extend_from_slice(&reg.to_le_bytes());
            }
        }
        // Brand string is NUL-terminated and often left-padded with spaces.
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(String::from_utf8_lossy(&bytes[..end]).trim().to_string())
    }

    pub fn detect() -> Vec<(&'static str, Detection)> {
        let mut out = Vec::new();
        let maxl = max_leaf();

        // ---- Leaf 1: legacy feature flags ------------------------------------------
        let (_, _, ecx1, edx1) = cpuid(1, 0);
        emit(&mut out, "sse2", bit(edx1, 26), "CPUID.01H:EDX[26]");
        emit(&mut out, "sse4_2", bit(ecx1, 20), "CPUID.01H:ECX[20]");
        emit(&mut out, "avx", bit(ecx1, 28), "CPUID.01H:ECX[28]");
        emit(&mut out, "fma", bit(ecx1, 12), "CPUID.01H:ECX[12]");
        emit(&mut out, "f16c", bit(ecx1, 29), "CPUID.01H:ECX[29]");
        emit(&mut out, "popcnt", bit(ecx1, 23), "CPUID.01H:ECX[23]");
        emit(&mut out, "movbe", bit(ecx1, 22), "CPUID.01H:ECX[22]");
        emit(&mut out, "aes", bit(ecx1, 25), "CPUID.01H:ECX[25]");
        emit(&mut out, "pclmulqdq", bit(ecx1, 1), "CPUID.01H:ECX[1]");
        emit(&mut out, "rdrand", bit(ecx1, 30), "CPUID.01H:ECX[30]");
        emit(&mut out, "vmx", bit(ecx1, 5), "CPUID.01H:ECX[5]");
        emit(&mut out, "x2apic", bit(ecx1, 21), "CPUID.01H:ECX[21]");

        // SMT capability: HTT bit (leaf 1). sysfs reports enabled/disabled state.
        emit(&mut out, "smt", bit(edx1, 28), "CPUID.01H:EDX[28] (HTT)");

        // Hypervisor-present bit: if set we are (almost certainly) a guest.
        out.push((
            "hypervisor",
            Detection::with_detail(
                if bit(ecx1, 31) {
                    Status::Present
                } else {
                    Status::Absent
                },
                "cpuid",
                "CPUID.01H:ECX[31]",
            ),
        ));

        // ---- Leaf 7/0: extended feature flags --------------------------------------
        if maxl >= 7 {
            let (_, ebx7, ecx7, edx7) = cpuid(7, 0);
            emit(&mut out, "avx2", bit(ebx7, 5), "CPUID.07H:EBX[5]");
            emit(&mut out, "bmi1", bit(ebx7, 3), "CPUID.07H:EBX[3]");
            emit(&mut out, "bmi2", bit(ebx7, 8), "CPUID.07H:EBX[8]");
            emit(&mut out, "smep", bit(ebx7, 7), "CPUID.07H:EBX[7]");
            emit(&mut out, "smap", bit(ebx7, 20), "CPUID.07H:EBX[20]");
            emit(&mut out, "rdseed", bit(ebx7, 18), "CPUID.07H:EBX[18]");
            emit(&mut out, "sha", bit(ebx7, 29), "CPUID.07H:EBX[29]");
            emit(&mut out, "avx512f", bit(ebx7, 16), "CPUID.07H:EBX[16]");
            emit(&mut out, "umip", bit(ecx7, 2), "CPUID.07H:ECX[2]");
            emit(&mut out, "pku", bit(ecx7, 3), "CPUID.07H:ECX[3]");
            emit(&mut out, "waitpkg", bit(ecx7, 5), "CPUID.07H:ECX[5]");
            emit(&mut out, "movdir64b", bit(ecx7, 28), "CPUID.07H:ECX[28]");
            emit(&mut out, "cet_ibt", bit(edx7, 20), "CPUID.07H:EDX[20]");
            emit(&mut out, "serialize", bit(edx7, 14), "CPUID.07H:EDX[14]");
            emit(&mut out, "hybrid", bit(edx7, 15), "CPUID.07H:EDX[15]");
        } else {
            for id in [
                "avx2",
                "bmi1",
                "bmi2",
                "smep",
                "smap",
                "rdseed",
                "sha",
                "avx512f",
                "umip",
                "pku",
                "waitpkg",
                "movdir64b",
                "cet_ibt",
                "serialize",
                "hybrid",
            ] {
                out.push((
                    id,
                    Detection::with_detail(Status::Unknown, "cpuid", "leaf 7 unavailable"),
                ));
            }
        }

        // ---- Leaf 6: thermal & power management ------------------------------------
        if maxl >= 6 {
            let (eax6, ..) = cpuid(6, 0);
            emit(&mut out, "hwp", bit(eax6, 7), "CPUID.06H:EAX[7]");
            emit(&mut out, "arat", bit(eax6, 2), "CPUID.06H:EAX[2]");
        } else {
            for id in ["hwp", "arat"] {
                out.push((
                    id,
                    Detection::with_detail(Status::Unknown, "cpuid", "leaf 6 unavailable"),
                ));
            }
        }

        // ---- Extended leaf 0x80000001: NX ------------------------------------------
        if max_ext_leaf() >= 0x8000_0001 {
            let (.., edxe) = cpuid(0x8000_0001, 0);
            emit(&mut out, "nx", bit(edxe, 20), "CPUID.80000001H:EDX[20]");
        } else {
            out.push((
                "nx",
                Detection::with_detail(Status::Unknown, "cpuid", "ext leaf unavailable"),
            ));
        }

        out
    }

    /// Push a Present/Absent detection for a silicon capability bit.
    fn emit(
        out: &mut Vec<(&'static str, Detection)>,
        id: &'static str,
        present: bool,
        detail: &'static str,
    ) {
        let status = if present {
            Status::Present
        } else {
            Status::Absent
        };
        out.push((id, Detection::with_detail(status, "cpuid", detail)));
    }
}

// =====================================================================================
// Non-x86 fallback
// =====================================================================================

#[cfg(not(target_arch = "x86_64"))]
mod imp {
    use super::*;

    pub fn identity() -> Option<Identity> {
        None
    }

    pub fn detect() -> Vec<(&'static str, Detection)> {
        // CPUID does not exist off x86; leave everything to other probes / Unknown.
        Vec::new()
    }
}

/// CPU identity banner, if determinable on this architecture.
pub fn identity() -> Option<Identity> {
    imp::identity()
}

fn detect_impl() -> Vec<(&'static str, Detection)> {
    imp::detect()
}
