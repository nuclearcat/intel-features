//! PCI device probe (no root).
//!
//! Scans `/sys/bus/pci/devices/*` for Intel (vendor 0x8086) devices and matches them
//! against a rule table to identify the chipset, accelerators and integrated devices.
//! A device is `Enabled` when a kernel driver is bound to it, else `Present` (silicon
//! there but unclaimed). Matching is by PCI class, by specific device id, or by bound
//! driver name — whichever is most reliable for that feature — and a few features add a
//! corroborating `/dev` or sysfs node to the detail.

use std::path::Path;

use crate::model::{Detection, Status};
use crate::probes::{unavailable, Context, Probe, ProbeResult};

const SRC: &str = "pci";
const INTEL: u32 = 0x8086;

pub struct PciProbe;

/// Chipset identity obtained from the Intel ISA/LPC/eSPI bridge actually enumerated
/// on the PCI bus.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChipsetInfo {
    pub name: String,
    pub vendor_id: u16,
    pub device_id: u16,
    pub address: String,
}

/// Return the motherboard chipset/PCH when Linux exposes its Intel LPC/eSPI bridge.
/// The descriptive name comes from the host's pci.ids database when available, with
/// a small built-in fallback for C620-series server chipsets.
pub fn chipset_info_with(ctx: &Context) -> Option<ChipsetInfo> {
    let (mut devices, _) = scan_intel_devices(ctx).ok()?;
    devices.sort_by(|a, b| a.address.cmp(&b.address));
    let device = devices
        .iter()
        .find(|device| device.class_hi == 0x06 && device.subclass == 0x01)?;
    Some(ChipsetInfo {
        name: pci_device_name(ctx, device.device)
            .unwrap_or_else(|| "Intel chipset (unrecognized model)".to_string()),
        vendor_id: INTEL as u16,
        device_id: device.device,
        address: device.address.clone(),
    })
}

impl Probe for PciProbe {
    fn name(&self) -> &'static str {
        SRC
    }

    fn feature_ids(&self) -> Vec<&'static str> {
        PCI_FEATURES.to_vec()
    }

    fn detect(&self, ctx: &Context) -> ProbeResult {
        let (devices, complete) = match scan_intel_devices(ctx) {
            Ok(result) => result,
            Err(reason) => return Ok(unavailable(self.name(), PCI_FEATURES, reason)),
        };
        Ok(RULES
            .iter()
            .map(|rule| (rule.feature, evaluate(rule, &devices, complete, ctx)))
            .collect())
    }
}

/// One Intel PCI device, reduced to the fields we match on.
struct PciDevice {
    address: String,
    device: u16,
    class_hi: u8,
    subclass: u8,
    driver: Option<String>,
    driver_known: bool,
}

/// A feature's match criteria. A device matches if *any* criterion matches: its class
/// (subclass `0xff` = any), its device id, or its bound driver.
struct Rule {
    feature: &'static str,
    class: Option<(u8, u8)>,
    devices: &'static [u16],
    drivers: &'static [&'static str],
    /// Corroborating node appended to the detail when present.
    node: Option<&'static str>,
}

#[rustfmt::skip]
const RULES: &[Rule] = &[
    // On-SoC accelerators & engines
    Rule { feature: "igpu", class: Some((0x03, 0xff)), devices: &[], drivers: &["i915", "xe"], node: None },
    Rule { feature: "npu",  class: Some((0x12, 0xff)), devices: &[0xad1d, 0x7d1d, 0x643e, 0xb03e], drivers: &["intel_vpu"], node: Some("/dev/accel/accel0") },
    Rule { feature: "gna",  class: None, devices: &[0x5a11, 0x8a11, 0x9a11, 0x4511, 0x51e4, 0x54e4], drivers: &["intel_gna"], node: None },
    Rule { feature: "dsa",  class: None, devices: &[0x0b25], drivers: &[], node: None },
    Rule { feature: "iaa",  class: None, devices: &[0x0cfe], drivers: &[], node: None },
    Rule { feature: "qat",  class: None, devices: &[0x4940, 0x4942, 0x4944, 0x4946, 0x37c8, 0x19e2, 0x0435], drivers: &["4xxx", "qat_4xxx", "c6xx", "dh895xcc"], node: None },
    Rule { feature: "dlb",  class: None, devices: &[0x2710, 0x2711], drivers: &["dlb2"], node: None },
    // Chipset & platform devices
    Rule { feature: "pch",         class: Some((0x06, 0x01)), devices: &[], drivers: &[], node: None },
    Rule { feature: "csme",        class: Some((0x07, 0x80)), devices: &[], drivers: &["mei_me"], node: Some("/dev/mei0") },
    Rule { feature: "ethernet",    class: Some((0x02, 0x00)), devices: &[], drivers: &["igc", "e1000e", "igb", "ixgbe", "i40e", "ice"], node: None },
    Rule { feature: "wifi",        class: Some((0x02, 0x80)), devices: &[], drivers: &["iwlwifi"], node: None },
    Rule { feature: "audio",       class: Some((0x04, 0x03)), devices: &[], drivers: &[], node: None },
    Rule { feature: "smbus",       class: Some((0x0c, 0x05)), devices: &[], drivers: &["i801_smbus"], node: None },
    Rule { feature: "spi_flash",   class: None, devices: &[], drivers: &["intel-spi"], node: None },
    Rule { feature: "thunderbolt", class: None, devices: &[], drivers: &["thunderbolt"], node: Some("/sys/bus/thunderbolt") },
    Rule { feature: "vmd",         class: None, devices: &[0x9a0b, 0x467f, 0xa77f, 0x7d0b, 0xad0b, 0xb60b], drivers: &["vmd"], node: None },
];

const PCI_FEATURES: &[&str] = &[
    "igpu",
    "npu",
    "gna",
    "dsa",
    "iaa",
    "qat",
    "dlb",
    "pch",
    "csme",
    "ethernet",
    "wifi",
    "audio",
    "smbus",
    "spi_flash",
    "thunderbolt",
    "vmd",
];

fn evaluate(rule: &Rule, devices: &[PciDevice], complete: bool, ctx: &Context) -> Detection {
    let matched: Vec<&PciDevice> = devices.iter().filter(|d| matches(d, rule)).collect();
    if matched.is_empty() {
        return Detection::with_detail(
            if complete {
                Status::Absent
            } else {
                Status::Unknown
            },
            SRC,
            if complete {
                "no matching Intel PCI device"
            } else {
                "PCI enumeration incomplete; an unreadable device could match"
            },
        );
    }
    // Prefer a driver-bound instance so the headline reflects "in use".
    let best = matched
        .iter()
        .find(|d| d.driver.is_some())
        .copied()
        .unwrap_or(matched[0]);
    let status = if best.driver.is_some() {
        Status::Enabled
    } else if !best.driver_known {
        Status::Unknown
    } else {
        Status::Present
    };

    let mut detail = if rule.feature == "pch" {
        match pci_device_name(ctx, best.device) {
            Some(name) => format!("{name} (PCI 8086:{:04x})", best.device),
            None => format!("Intel chipset (PCI 8086:{:04x})", best.device),
        }
    } else {
        format!("dev {:#06x}", best.device)
    };
    if let Some(drv) = &best.driver {
        detail.push_str(&format!(", driver {drv}"));
    }
    if matched.len() > 1 {
        detail.push_str(&format!(" (+{} more)", matched.len() - 1));
    }
    if let Some(node) = rule.node {
        if ctx.reader.exists(Path::new(node)) {
            detail.push_str(&format!("; {node}"));
        }
    }
    Detection::with_detail(status, SRC, detail)
}

fn matches(dev: &PciDevice, rule: &Rule) -> bool {
    if let Some((class, sub)) = rule.class {
        if dev.class_hi == class && (sub == 0xff || dev.subclass == sub) {
            return true;
        }
    }
    if rule.devices.contains(&dev.device) {
        return true;
    }
    if let Some(drv) = &dev.driver {
        if rule.drivers.contains(&drv.as_str()) {
            return true;
        }
    }
    false
}

fn scan_intel_devices(ctx: &Context) -> Result<(Vec<PciDevice>, bool), String> {
    let mut out = Vec::new();
    let entries = ctx
        .reader
        .read_dir(Path::new("/sys/bus/pci/devices"))
        .map_err(|e| format!("cannot inspect PCI devices: {e}"))?;
    let mut complete = true;
    for entry in entries {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        let path = entry.path;
        let vendor = match read_hex(ctx, &path.join("vendor")) {
            Ok(vendor) => vendor,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        if vendor != INTEL {
            continue;
        }
        let (device, class) = match (
            read_hex(ctx, &path.join("device")),
            read_hex(ctx, &path.join("class")),
        ) {
            (Ok(device), Ok(class)) => (device as u16, class),
            _ => {
                complete = false;
                continue;
            }
        };
        let (driver, driver_known) = match ctx.reader.read_link(&path.join("driver")) {
            Ok(path) => (
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
                true,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, true),
            Err(_) => {
                complete = false;
                (None, false)
            }
        };
        out.push(PciDevice {
            address: entry.file_name,
            device,
            class_hi: ((class >> 16) & 0xff) as u8,
            subclass: ((class >> 8) & 0xff) as u8,
            driver,
            driver_known,
        });
    }
    Ok((out, complete))
}

const PCI_ID_DATABASES: &[&str] = &[
    "/usr/share/hwdata/pci.ids",
    "/usr/share/misc/pci.ids",
    "/usr/share/pci.ids",
];

fn pci_device_name(ctx: &Context, device: u16) -> Option<String> {
    for path in PCI_ID_DATABASES {
        if let Ok(data) = ctx.reader.read_to_string(Path::new(path)) {
            if let Some(name) = parse_pci_ids_name(&data, INTEL as u16, device) {
                return Some(name);
            }
        }
    }
    c620_fallback_name(device).map(str::to_string)
}

/// Parse a top-level device entry from the standard pci.ids text format. Subsystem
/// entries start with two tabs and are intentionally ignored.
fn parse_pci_ids_name(data: &str, vendor: u16, device: u16) -> Option<String> {
    let mut in_vendor = false;
    for line in data.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with('\t') {
            let mut fields = line.split_whitespace();
            in_vendor = fields
                .next()
                .and_then(|id| u16::from_str_radix(id, 16).ok())
                == Some(vendor);
            continue;
        }
        if !in_vendor || line.starts_with("\t\t") {
            continue;
        }
        let line = line.trim_start_matches('\t');
        let Some((id, name)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if u16::from_str_radix(id, 16).ok() == Some(device) {
            let name = name.trim();
            return (!name.is_empty()).then(|| name.to_string());
        }
    }
    None
}

fn c620_fallback_name(device: u16) -> Option<&'static str> {
    match device {
        0xa1c1 => Some("C621 Series Chipset LPC/eSPI Controller"),
        0xa1c2 => Some("C622 Series Chipset LPC/eSPI Controller"),
        0xa1c3 => Some("C624 Series Chipset LPC/eSPI Controller"),
        0xa1c4 => Some("C625 Series Chipset LPC/eSPI Controller"),
        0xa1c5 => Some("C626 Series Chipset LPC/eSPI Controller"),
        0xa1c6 => Some("C627 Series Chipset LPC/eSPI Controller"),
        0xa1c7 => Some("C628 Series Chipset LPC/eSPI Controller"),
        _ => None,
    }
}

/// Read a `0x…`-formatted sysfs hex file.
fn read_hex(ctx: &Context, path: &Path) -> Result<u32, String> {
    let s = ctx.reader.read_to_string(path).map_err(|e| e.to_string())?;
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(class_hi: u8, subclass: u8, device: u16, driver: Option<&str>) -> PciDevice {
        PciDevice {
            address: "0000:00:1f.0".to_string(),
            device,
            class_hi,
            subclass,
            driver: driver.map(str::to_string),
            driver_known: true,
        }
    }

    fn rule(feature: &str) -> &'static Rule {
        RULES.iter().find(|r| r.feature == feature).unwrap()
    }

    #[test]
    fn class_match_ignores_subclass_when_0xff() {
        // igpu matches any display-class (0x03) device regardless of subclass.
        assert!(matches(&dev(0x03, 0x80, 0x1234, None), rule("igpu")));
    }

    #[test]
    fn subclass_must_match_when_specified() {
        // ethernet is class 0x02 subclass 0x00; a wifi (0x02/0x80) must not match it.
        assert!(matches(&dev(0x02, 0x00, 0x125c, None), rule("ethernet")));
        assert!(!matches(&dev(0x02, 0x80, 0x272b, None), rule("ethernet")));
    }

    #[test]
    fn device_id_match() {
        assert!(matches(&dev(0x08, 0x00, 0x0b25, None), rule("dsa")));
        assert!(!matches(&dev(0x08, 0x00, 0x9999, None), rule("dsa")));
    }

    #[test]
    fn driver_name_match() {
        assert!(matches(
            &dev(0x02, 0x00, 0x1, Some("igc")),
            rule("ethernet")
        ));
    }

    #[test]
    fn evaluate_enabled_prefers_driver_bound() {
        let devs = vec![
            dev(0x03, 0x00, 0x1, None),
            dev(0x03, 0x00, 0x2, Some("i915")),
        ];
        let ctx = Context::detect();
        let d = evaluate(rule("igpu"), &devs, true, &ctx);
        assert_eq!(d.status, Status::Enabled);
        assert!(d.detail.unwrap().contains("i915"));
    }

    #[test]
    fn evaluate_absent_when_no_match() {
        let ctx = Context::detect();
        assert_eq!(
            evaluate(rule("vmd"), &[], true, &ctx).status,
            Status::Absent
        );
    }

    #[test]
    fn parses_intel_device_but_not_subsystem_names() {
        let ids = "8086  Intel Corporation\n\ta1c3  C624 Series Chipset LPC/eSPI Controller\n\t\t1234 5678  Board subsystem\n8087  Other vendor\n\ta1c3  Wrong device\n";
        assert_eq!(
            parse_pci_ids_name(ids, 0x8086, 0xa1c3).as_deref(),
            Some("C624 Series Chipset LPC/eSPI Controller")
        );
        assert_eq!(parse_pci_ids_name(ids, 0x8086, 0x5678), None);
    }

    #[test]
    fn c620_fallback_identifies_example_chipset() {
        assert_eq!(
            c620_fallback_name(0xa1c3),
            Some("C624 Series Chipset LPC/eSPI Controller")
        );
    }
}
