//! UEFI + SMBIOS/DMI probe.
//!
//! Three firmware sources, each tagged with its own detection source:
//! * `efi` — `/sys/firmware/efi` presence, `SecureBoot`/`SetupMode` efivars, ESRT.
//! * `dmi` — board/BIOS identity (world-readable `/sys/class/dmi/id/*`) for the banner,
//!   plus the SMBIOS structure table (`/sys/firmware/dmi/tables/DMI`, root) for memory
//!   ECC (type 16) and installed DIMMs (type 17).

use std::path::Path;

use crate::model::{Detection, Status};
use crate::probes::{Context, Probe};

pub struct FirmwareProbe;

impl Probe for FirmwareProbe {
    fn name(&self) -> &'static str {
        "firmware"
    }

    fn detect(&self, _ctx: &Context) -> Vec<(&'static str, Detection)> {
        let mut out = Vec::new();
        efi(&mut out);
        smbios_memory(&mut out);
        out
    }
}

/// Board / BIOS identity for the report banner (all world-readable DMI id fields).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemInfo {
    pub vendor: String,
    pub product: String,
    pub board: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
}

pub fn system_info() -> Option<SystemInfo> {
    let id = |f: &str| dmi_id(f).unwrap_or_default();
    let vendor = id("sys_vendor");
    let product = id("product_name");
    let board = id("board_name");
    let bios_version = id("bios_version");
    if vendor.is_empty() && product.is_empty() && bios_version.is_empty() {
        return None;
    }
    Some(SystemInfo {
        vendor,
        product,
        board,
        bios_vendor: id("bios_vendor"),
        bios_version,
        bios_date: id("bios_date"),
    })
}

fn dmi_id(field: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/dmi/id/{field}"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ---- EFI -----------------------------------------------------------------------------

fn efi(out: &mut Vec<(&'static str, Detection)>) {
    let uefi = Path::new("/sys/firmware/efi").exists();
    out.push((
        "uefi_boot",
        if uefi {
            Detection::with_detail(Status::Enabled, "efi", "booted via UEFI")
        } else {
            Detection::with_detail(Status::Absent, "efi", "legacy BIOS boot")
        },
    ));
    if !uefi {
        return;
    }

    // Secure Boot / Setup Mode efivars: 4-byte attribute prefix then a 1-byte value.
    match efivar_byte("SecureBoot-") {
        Some(1) => out.push((
            "secure_boot",
            Detection::with_detail(Status::Enabled, "efi", "SecureBoot=1"),
        )),
        Some(0) => out.push((
            "secure_boot",
            Detection::with_detail(Status::Disabled, "efi", "SecureBoot=0"),
        )),
        Some(v) => out.push((
            "secure_boot",
            Detection::with_detail(Status::Unknown, "efi", format!("SecureBoot={v}")),
        )),
        None => {}
    }
    match efivar_byte("SetupMode-") {
        Some(1) => out.push((
            "setup_mode",
            Detection::with_detail(Status::Enabled, "efi", "setup mode (keys not enrolled)"),
        )),
        Some(0) => out.push((
            "setup_mode",
            Detection::with_detail(Status::Disabled, "efi", "user mode (keys enrolled)"),
        )),
        _ => {}
    }

    let esrt = Path::new("/sys/firmware/efi/esrt").exists();
    out.push((
        "esrt",
        if esrt {
            Detection::with_detail(Status::Enabled, "efi", "ESRT present (capsule/fwupd)")
        } else {
            Detection::with_detail(Status::Absent, "efi", "no ESRT")
        },
    ));
}

/// Read the 1-byte value of a global efivar by name prefix (the GUID suffix varies).
fn efivar_byte(prefix: &str) -> Option<u8> {
    let dir = std::fs::read_dir("/sys/firmware/efi/efivars").ok()?;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) {
            let bytes = std::fs::read(entry.path()).ok()?;
            // [attr:4][data...]; the boolean vars carry a single data byte.
            return bytes.get(4).copied();
        }
    }
    None
}

// ---- SMBIOS memory (root) ------------------------------------------------------------

fn smbios_memory(out: &mut Vec<(&'static str, Detection)>) {
    let Ok(buf) = std::fs::read("/sys/firmware/dmi/tables/DMI") else {
        return; // needs root; left "not probed" otherwise
    };
    let mut ecc: Option<&'static str> = None;
    let mut dimms: Vec<String> = Vec::new();

    for s in SmbiosIter::new(&buf) {
        match s.stype {
            16 => ecc = Some(ecc_kind(s.byte(0x06))),
            17 => {
                if let Some(d) = dimm_summary(&s) {
                    dimms.push(d);
                }
            }
            _ => {}
        }
    }

    if let Some(kind) = ecc {
        let status = if kind == "None" {
            Status::Absent
        } else {
            Status::Present
        };
        out.push(("memory_ecc", Detection::with_detail(status, "dmi", kind)));
    }
    if !dimms.is_empty() {
        let detail = format!("{} populated: {}", dimms.len(), dimms.join(", "));
        out.push((
            "memory_dimms",
            Detection::with_detail(Status::Present, "dmi", detail),
        ));
    }
}

fn ecc_kind(v: u8) -> &'static str {
    match v {
        0x04 => "Parity",
        0x05 => "Single-bit ECC",
        0x06 => "Multi-bit ECC",
        0x07 => "CRC",
        _ => "None",
    }
}

/// Summarise a populated type-17 DIMM as e.g. "16 GB LPDDR5-8533".
fn dimm_summary(s: &Structure) -> Option<String> {
    let size_raw = s.word(0x0C);
    if size_raw == 0 || size_raw == 0xFFFF {
        return None; // empty or unknown slot
    }
    let mb = if size_raw == 0x7FFF {
        s.dword(0x1C) // extended size, in MB
    } else if size_raw & 0x8000 != 0 {
        (size_raw & 0x7FFF) as u32 / 1024 // value is in KB
    } else {
        size_raw as u32
    };
    let size = if mb >= 1024 {
        format!("{} GB", mb / 1024)
    } else {
        format!("{mb} MB")
    };
    let mem_type = mem_type(s.byte(0x12));
    let speed = s.word(0x15);
    if speed != 0 && speed != 0xFFFF {
        Some(format!("{size} {mem_type}-{speed}"))
    } else {
        Some(format!("{size} {mem_type}"))
    }
}

fn mem_type(v: u8) -> &'static str {
    match v {
        0x18 => "DDR3",
        0x1A => "DDR4",
        0x1E => "LPDDR",
        0x1F => "LPDDR2",
        0x20 => "LPDDR3",
        0x21 => "LPDDR4",
        0x22 => "DDR5",
        0x23 => "LPDDR5",
        _ => "RAM",
    }
}

// ---- Minimal SMBIOS structure walker -------------------------------------------------

struct Structure<'a> {
    stype: u8,
    formatted: &'a [u8],
}

impl Structure<'_> {
    fn byte(&self, off: usize) -> u8 {
        self.formatted.get(off).copied().unwrap_or(0)
    }
    fn word(&self, off: usize) -> u16 {
        u16::from_le_bytes([self.byte(off), self.byte(off + 1)])
    }
    fn dword(&self, off: usize) -> u32 {
        u32::from_le_bytes([
            self.byte(off),
            self.byte(off + 1),
            self.byte(off + 2),
            self.byte(off + 3),
        ])
    }
}

/// Iterates SMBIOS structures: each is a formatted area of `length` bytes followed by a
/// double-NUL-terminated string set.
struct SmbiosIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SmbiosIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        SmbiosIter { buf, pos: 0 }
    }
}

impl<'a> Iterator for SmbiosIter<'a> {
    type Item = Structure<'a>;

    fn next(&mut self) -> Option<Structure<'a>> {
        let buf = self.buf;
        if self.pos + 4 > buf.len() {
            return None;
        }
        let stype = buf[self.pos];
        let length = buf[self.pos + 1] as usize;
        if length < 4 || self.pos + length > buf.len() {
            return None;
        }
        let formatted = &buf[self.pos..self.pos + length];
        if stype == 127 {
            return None; // end-of-table
        }
        // Skip past the string set: bytes after the formatted area until a 00 00 pair.
        let mut p = self.pos + length;
        while p + 1 < buf.len() && !(buf[p] == 0 && buf[p + 1] == 0) {
            p += 1;
        }
        self.pos = p + 2;
        Some(Structure { stype, formatted })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a type-17 formatted area with size (MB), memory type and speed set.
    fn type17(size_mb: u16, mem_type: u8, speed: u16) -> Vec<u8> {
        let mut f = vec![0u8; 0x18];
        f[0] = 17;
        f[1] = 0x18;
        f[0x0C..0x0E].copy_from_slice(&size_mb.to_le_bytes());
        f[0x12] = mem_type;
        f[0x15..0x17].copy_from_slice(&speed.to_le_bytes());
        f
    }

    #[test]
    fn dimm_summary_formats_gb_and_speed() {
        let f = type17(16384, 0x22, 6400);
        let s = Structure {
            stype: 17,
            formatted: &f,
        };
        assert_eq!(dimm_summary(&s).as_deref(), Some("16 GB DDR5-6400"));
    }

    #[test]
    fn empty_slot_is_skipped() {
        let f = type17(0, 0x22, 0);
        let s = Structure {
            stype: 17,
            formatted: &f,
        };
        assert_eq!(dimm_summary(&s), None);
    }

    #[test]
    fn smbios_iter_walks_structures_and_strings() {
        // Two structures: type 17 (with a trailing string) then the type-127 terminator.
        let mut buf = type17(8192, 0x1A, 3200);
        buf.extend_from_slice(b"DIMM_A\0\0"); // string set, double-NUL terminated
        buf.extend_from_slice(&[127, 4, 0, 0, 0, 0]); // end-of-table + empty strings
        let types: Vec<u8> = SmbiosIter::new(&buf).map(|s| s.stype).collect();
        assert_eq!(types, vec![17]); // 127 terminates iteration
    }
}
