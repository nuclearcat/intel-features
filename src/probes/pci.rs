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
use crate::probes::{Context, Probe};

const SRC: &str = "pci";
const INTEL: u32 = 0x8086;

pub struct PciProbe;

impl Probe for PciProbe {
    fn name(&self) -> &'static str {
        SRC
    }

    fn detect(&self, _ctx: &Context) -> Vec<(&'static str, Detection)> {
        let devices = scan_intel_devices();
        RULES
            .iter()
            .map(|rule| (rule.feature, evaluate(rule, &devices)))
            .collect()
    }
}

/// One Intel PCI device, reduced to the fields we match on.
struct PciDevice {
    device: u16,
    class_hi: u8,
    subclass: u8,
    driver: Option<String>,
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

fn evaluate(rule: &Rule, devices: &[PciDevice]) -> Detection {
    let matched: Vec<&PciDevice> = devices.iter().filter(|d| matches(d, rule)).collect();
    if matched.is_empty() {
        return Detection::with_detail(Status::Absent, SRC, "no matching Intel PCI device");
    }
    // Prefer a driver-bound instance so the headline reflects "in use".
    let best = matched
        .iter()
        .find(|d| d.driver.is_some())
        .copied()
        .unwrap_or(matched[0]);
    let status = if best.driver.is_some() {
        Status::Enabled
    } else {
        Status::Present
    };

    let mut detail = format!("dev {:#06x}", best.device);
    if let Some(drv) = &best.driver {
        detail.push_str(&format!(", driver {drv}"));
    }
    if matched.len() > 1 {
        detail.push_str(&format!(" (+{} more)", matched.len() - 1));
    }
    if let Some(node) = rule.node {
        if Path::new(node).exists() {
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

fn scan_intel_devices() -> Vec<PciDevice> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/bus/pci/devices") else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if read_hex(&path.join("vendor")) != Some(INTEL) {
            continue;
        }
        let device = read_hex(&path.join("device")).unwrap_or(0) as u16;
        let class = read_hex(&path.join("class")).unwrap_or(0);
        let driver = std::fs::read_link(path.join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        out.push(PciDevice {
            device,
            class_hi: ((class >> 16) & 0xff) as u8,
            subclass: ((class >> 8) & 0xff) as u8,
            driver,
        });
    }
    out
}

/// Read a `0x…`-formatted sysfs hex file.
fn read_hex(path: &Path) -> Option<u32> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(class_hi: u8, subclass: u8, device: u16, driver: Option<&str>) -> PciDevice {
        PciDevice {
            device,
            class_hi,
            subclass,
            driver: driver.map(str::to_string),
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
        let d = evaluate(rule("igpu"), &devs);
        assert_eq!(d.status, Status::Enabled);
        assert!(d.detail.unwrap().contains("i915"));
    }

    #[test]
    fn evaluate_absent_when_no_match() {
        assert_eq!(evaluate(rule("vmd"), &[]).status, Status::Absent);
    }
}
