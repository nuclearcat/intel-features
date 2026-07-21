//! Intel CPUID display-family/model database.
//!
//! Model numbers identify a processor family, not necessarily one retail generation.
//! Intel occasionally reuses a model across refreshes, so ambiguous entries deliberately
//! use ranges rather than guessing from the brand string or stepping.

use serde::Serialize;

use crate::model::ClassExpectation;

/// Human-friendly identification for an Intel CPUID family/model pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CpuModelInfo {
    /// Intel platform or product-family codename.
    pub codename: &'static str,
    /// Marketing generation when it can be stated without guessing.
    pub generation: &'static str,
    /// Broad market segment represented by this CPUID model.
    pub segment: &'static str,
}

const fn info(
    codename: &'static str,
    generation: &'static str,
    segment: &'static str,
) -> CpuModelInfo {
    CpuModelInfo {
        codename,
        generation,
        segment,
    }
}

/// Look up a CPU by CPUID vendor, display family, and display model.
///
/// Only `GenuineIntel` is classified. Unknown and future model IDs return `None` so
/// callers never present a speculative generation as fact.
pub fn lookup(vendor: &str, family: u32, model: u32) -> Option<CpuModelInfo> {
    if vendor != "GenuineIntel" {
        return None;
    }

    let found = match (family, model) {
        // Core / Xeon big-core lineage.
        (6, 0x1a | 0x1e | 0x1f | 0x2e) => {
            info("Nehalem", "1st Gen Core / Xeon 5500–7500", "client/server")
        }
        (6, 0x25 | 0x2c | 0x2f) => info("Westmere", "1st Gen Core / Xeon 5600–E7", "client/server"),
        (6, 0x2a) => info("Sandy Bridge", "2nd Gen Core", "client"),
        (6, 0x2d) => info("Sandy Bridge-EP", "Xeon E5 v1", "server"),
        (6, 0x3a) => info("Ivy Bridge", "3rd Gen Core", "client"),
        (6, 0x3e) => info("Ivy Bridge-EP", "Xeon E5 v2", "server"),
        (6, 0x3c | 0x45 | 0x46) => info("Haswell", "4th Gen Core", "client"),
        (6, 0x3f) => info("Haswell-EP", "Xeon E5 v3", "server"),
        (6, 0x3d | 0x47) => info("Broadwell", "5th Gen Core", "client"),
        (6, 0x4f) => info("Broadwell-EP", "Xeon E5 v4", "server"),
        (6, 0x56) => info("Broadwell-DE", "Xeon D-1500", "server/embedded"),
        (6, 0x4e | 0x5e) => info("Skylake", "6th Gen Core", "client"),
        (6, 0x55) => info("Skylake-SP family", "1st–3rd Gen Xeon Scalable", "server"),
        (6, 0x8e) => info(
            "Kaby/Coffee/Whiskey Lake",
            "7th–8th Gen Core",
            "mobile client",
        ),
        (6, 0x9e) => info("Kaby/Coffee Lake", "7th–9th Gen Core", "client"),
        (6, 0xa5) => info("Comet Lake", "10th Gen Core", "client"),
        (6, 0xa6) => info("Comet Lake-U", "10th Gen Core", "mobile client"),
        (6, 0x66) => info("Cannon Lake", "8th Gen Core", "mobile client"),
        (6, 0x7d | 0x7e) => info("Ice Lake", "10th Gen Core", "mobile client"),
        (6, 0x6a) => info("Ice Lake-SP", "3rd Gen Xeon Scalable", "server"),
        (6, 0x6c) => info("Ice Lake-D", "Xeon D-1700/2700", "server/embedded"),
        (6, 0xa7) => info("Rocket Lake", "11th Gen Core", "client"),
        (6, 0x8c | 0x8d) => info("Tiger Lake", "11th Gen Core", "mobile client"),
        (6, 0x8f) => info("Sapphire Rapids", "4th Gen Xeon Scalable", "server"),
        (6, 0xcf) => info("Emerald Rapids", "5th Gen Xeon Scalable", "server"),
        (6, 0xad) => info("Granite Rapids", "6th Gen Xeon Scalable", "server"),
        (6, 0xae) => info("Granite Rapids-D", "Xeon 6 SoC", "server/embedded"),
        (6, 0xd7) => info("Bartlett Lake", "Raptor Cove family", "client/embedded"),

        // Hybrid client lineage.
        (6, 0x8a) => info(
            "Lakefield",
            "Core with Intel Hybrid Technology",
            "mobile client",
        ),
        (6, 0x97 | 0x9a) => info("Alder Lake", "12th Gen Core", "client"),
        (6, 0xb7 | 0xba | 0xbf) => info("Raptor Lake", "13th–14th Gen Core", "client"),
        (6, 0xaa | 0xac) => info("Meteor Lake", "Core Ultra Series 1", "mobile client"),
        (6, 0xb5 | 0xc5 | 0xc6) => info("Arrow Lake", "Core Ultra Series 2", "client"),
        (6, 0xbd) => info("Lunar Lake", "Core Ultra Series 2", "mobile client"),
        (6, 0xcc | 0xe5) => info("Panther Lake", "Core Ultra Series 3", "mobile client"),

        // Atom, low-power, and many-core families.
        (6, 0x1c | 0x26) => info("Bonnell", "Atom Bonnell", "low-power/embedded"),
        (6, 0x27 | 0x35 | 0x36) => info("Saltwell", "Atom Saltwell", "low-power/embedded"),
        (6, 0x37 | 0x4a | 0x4d | 0x5a) => {
            info("Silvermont", "Atom Silvermont", "low-power/embedded")
        }
        (6, 0x4c | 0x75) => info("Airmont", "Atom Airmont", "low-power/embedded"),
        (6, 0x5c | 0x5f) => info("Goldmont", "Atom Goldmont", "low-power/embedded"),
        (6, 0x7a) => info("Goldmont Plus", "Atom Goldmont Plus", "low-power/embedded"),
        (6, 0x86 | 0x96 | 0x9c) => info("Tremont", "Atom Tremont", "low-power/embedded"),
        (6, 0xbe) => info(
            "Alder Lake-N",
            "Intel Processor N-series",
            "low-power client",
        ),
        (6, 0xaf) => info("Sierra Forest", "Xeon 6 E-core", "server"),
        (6, 0xb6) => info("Grand Ridge", "Atom Crestmont", "network/embedded"),
        (6, 0xdd) => info("Clearwater Forest", "Xeon E-core", "server"),
        (6, 0x57) => info("Knights Landing", "Xeon Phi x200", "many-core"),
        (6, 0x85) => info("Knights Mill", "Xeon Phi 72x5", "many-core"),

        // Intel moved beyond display family 6 for these newer lineages.
        (18, 0x01 | 0x03) => info("Nova Lake", "Nova Lake family", "client"),
        (19, 0x01) => info("Diamond Rapids", "Diamond Rapids Xeon", "server"),
        _ => return None,
    };
    Some(found)
}

/// Maximum memory channels provided by one processor socket for CPU families where
/// the family/model ID gives an unambiguous answer.
///
/// This is a silicon limit, not a count of populated or currently active channels.
/// Ambiguous family/model groups deliberately return `None` rather than guessing.
pub fn max_memory_channels(vendor: &str, family: u32, model: u32) -> Option<u8> {
    if vendor != "GenuineIntel" {
        return None;
    }

    match (family, model) {
        // Xeon E5 generations use four channels per socket.
        (6, 0x2d | 0x3e | 0x3f | 0x4f) => Some(4),
        // The Skylake-SP CPUID model is shared by the first three Xeon Scalable
        // generations; all three retain six channels per socket.
        (6, 0x55) => Some(6),
        // Ice Lake-SP through Emerald Rapids Xeon Scalable families.
        (6, 0x6a | 0x8f | 0xcf) => Some(8),

        // Conventional Core client memory controllers expose two channels. Avoid
        // assigning a value to mobile/SoC families whose 32-bit subchannels make
        // the marketing channel count easy to misinterpret.
        (6, 0x2a | 0x3a | 0x3c | 0x45 | 0x46 | 0x3d | 0x47)
        | (6, 0x4e | 0x5e | 0x9e | 0xa5 | 0xa7)
        | (6, 0x97 | 0xb7 | 0xba | 0xbf | 0xb5 | 0xc5 | 0xc6 | 0xd7) => Some(2),
        _ => None,
    }
}

/// Return a conservative class-level expectation for a feature.
///
/// These hints are intentionally much smaller than the feature catalog. They cover
/// only capabilities that are well associated with a family/model class. In
/// particular, `Possible` means that the feature is offered by some SKU or platform
/// configuration in the class; it does not mean the current SKU was sold with it.
pub fn feature_expectation(
    vendor: &str,
    family: u32,
    model: u32,
    feature: &str,
) -> Option<ClassExpectation> {
    let model_info = lookup(vendor, family, model)?;

    // Core Ultra is explicitly a CPU + GPU + NPU product class. A missing NPU on
    // these recognized model families is stronger than an ordinary optional-device
    // hint and can point to firmware masking or incomplete enumeration.
    let core_ultra =
        family == 6 && matches!(model, 0xaa | 0xac | 0xb5 | 0xbd | 0xc5 | 0xc6 | 0xcc | 0xe5);
    if core_ultra && feature == "npu" {
        return Some(ClassExpectation::Expected);
    }

    // Integrated graphics exists on many, but not every, client SKU (for example,
    // desktop F SKUs are a notable exception), so absence is advisory only.
    if model_info.segment.contains("client") && feature == "igpu" {
        return Some(ClassExpectation::Possible);
    }

    // Mobile client platforms commonly offer these integrated connectivity and
    // low-power capabilities, but system-vendor routing and SKU choices vary.
    if model_info.segment == "mobile client"
        && matches!(feature, "wifi" | "bluetooth" | "thunderbolt" | "s0ix")
    {
        return Some(ClassExpectation::Possible);
    }

    // These client generations have platform/SKU configurations with VMD and/or a
    // Gaussian & Neural Accelerator. Keep the hint optional because both vary.
    let recent_client = family == 6
        && matches!(
            model,
            0x8c | 0x8d
                | 0x97
                | 0x9a
                | 0xb7
                | 0xba
                | 0xbf
                | 0xaa
                | 0xac
                | 0xb5
                | 0xbd
                | 0xc5
                | 0xc6
                | 0xcc
                | 0xe5
        );
    if recent_client && matches!(feature, "vmd" | "gna") {
        return Some(ClassExpectation::Possible);
    }

    // Server systems can legitimately omit these at the board or deployment level,
    // but their absence is useful to call out rather than bury among inapplicable ISA
    // extensions.
    if model_info.segment.contains("server") && matches!(feature, "ipmi" | "memory_ecc" | "numa") {
        return Some(ClassExpectation::Possible);
    }

    // Fourth-generation Xeon Scalable and newer families offer a selection of
    // accelerator and CXL configurations. Engine counts and enablement are SKU- and
    // firmware-dependent, hence `Possible` rather than `Expected`.
    let accelerator_xeon = matches!((family, model), (6, 0x8f | 0xcf | 0xad | 0xae) | (19, 0x01));
    if accelerator_xeon && matches!(feature, "dsa" | "iaa" | "qat" | "dlb" | "cxl" | "hmat") {
        return Some(ClassExpectation::Possible);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_modern_client_cpu() {
        let cpu = lookup("GenuineIntel", 6, 0xc6).unwrap();
        assert_eq!(cpu.codename, "Arrow Lake");
        assert_eq!(cpu.generation, "Core Ultra Series 2");
    }

    #[test]
    fn shared_model_is_reported_as_a_range() {
        let cpu = lookup("GenuineIntel", 6, 0x55).unwrap();
        assert_eq!(cpu.generation, "1st–3rd Gen Xeon Scalable");
        assert_eq!(max_memory_channels("GenuineIntel", 6, 0x55), Some(6));
    }

    #[test]
    fn refuses_unknown_or_non_intel_cpu() {
        assert_eq!(lookup("GenuineIntel", 6, 0xfe), None);
        assert_eq!(lookup("AuthenticAMD", 6, 0x97), None);
        assert_eq!(max_memory_channels("GenuineIntel", 6, 0xfe), None);
        assert_eq!(max_memory_channels("AuthenticAMD", 6, 0x55), None);
    }

    #[test]
    fn class_expectations_are_conservative_and_intel_only() {
        assert_eq!(
            feature_expectation("GenuineIntel", 6, 0xc6, "npu"),
            Some(ClassExpectation::Expected)
        );
        assert_eq!(
            feature_expectation("GenuineIntel", 6, 0xc6, "igpu"),
            Some(ClassExpectation::Possible)
        );
        assert_eq!(feature_expectation("GenuineIntel", 6, 0x3c, "npu"), None);
        assert_eq!(feature_expectation("AuthenticAMD", 6, 0xc6, "npu"), None);
    }
}
