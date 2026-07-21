//! Separate EFI and SMBIOS/DMI probes, preserving their public source names.

use std::io;
use std::path::Path;

use crate::model::Privilege;
use crate::model::{Detection, Status};
use crate::probes::ContextOptions;
use crate::probes::{
    finding_detail, unavailable, Context, Findings, HostMsrAccess, HostSystemReader, Probe,
    ProbeResult,
};
use std::sync::Arc;

const EFI_FEATURES: &[&str] = &["uefi_boot", "secure_boot", "setup_mode", "esrt"];
const DMI_FEATURES: &[&str] = &["memory_ecc", "memory_dimms"];

pub struct EfiProbe;
pub struct DmiProbe;

impl Probe for EfiProbe {
    fn name(&self) -> &'static str {
        "efi"
    }
    fn feature_ids(&self) -> Vec<&'static str> {
        EFI_FEATURES.to_vec()
    }
    fn detect(&self, ctx: &Context) -> ProbeResult {
        Ok(efi(ctx))
    }
}

impl Probe for DmiProbe {
    fn name(&self) -> &'static str {
        "dmi"
    }
    fn feature_ids(&self) -> Vec<&'static str> {
        DMI_FEATURES.to_vec()
    }
    fn detect(&self, ctx: &Context) -> ProbeResult {
        Ok(smbios_memory(ctx))
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemInfo {
    pub vendor: String,
    pub product: String,
    pub board: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chipset: Option<crate::probes::pci::ChipsetInfo>,
}

pub fn system_info() -> Option<SystemInfo> {
    let reader = Arc::new(HostSystemReader);
    let ctx = Context::new(
        Privilege::User,
        reader,
        Arc::new(HostMsrAccess),
        ContextOptions::default(),
    );
    system_info_with(&ctx)
}

pub fn system_info_with(ctx: &Context) -> Option<SystemInfo> {
    let id = |field: &str| dmi_id(ctx, field).unwrap_or_default();
    let vendor = id("sys_vendor");
    let product = id("product_name");
    let board = id("board_name");
    let bios_version = id("bios_version");
    let chipset = crate::probes::pci::chipset_info_with(ctx);
    if vendor.is_empty() && product.is_empty() && bios_version.is_empty() && chipset.is_none() {
        return None;
    }
    Some(SystemInfo {
        vendor,
        product,
        board,
        bios_vendor: id("bios_vendor"),
        bios_version,
        bios_date: id("bios_date"),
        chipset,
    })
}

fn dmi_id(ctx: &Context, field: &str) -> Option<String> {
    ctx.reader
        .read_to_string(Path::new(&format!("/sys/class/dmi/id/{field}")))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn efi(ctx: &Context) -> Findings {
    const ROOT: &str = "/sys/firmware/efi";
    match ctx.reader.metadata(Path::new(ROOT)) {
        Err(error) => {
            return unavailable(
                "efi",
                EFI_FEATURES,
                format!("cannot establish EFI boot state: {error}"),
            )
        }
        Ok(metadata) if !metadata.is_dir => {
            return unavailable("efi", EFI_FEATURES, "EFI interface is not a directory")
        }
        Ok(_) => {}
    }
    let mut out = vec![finding_detail(
        "efi",
        "uefi_boot",
        Status::Enabled,
        "booted via UEFI",
    )];
    out.push(efi_boolean(ctx, "SecureBoot-", "secure_boot", "SecureBoot"));
    out.push(efi_boolean(ctx, "SetupMode-", "setup_mode", "SetupMode"));
    let esrt = match ctx.reader.metadata(Path::new("/sys/firmware/efi/esrt")) {
        Ok(_) => finding_detail(
            "efi",
            "esrt",
            Status::Enabled,
            "ESRT present (capsule/fwupd)",
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            finding_detail("efi", "esrt", Status::Absent, "no ESRT")
        }
        Err(e) => finding_detail(
            "efi",
            "esrt",
            Status::Unknown,
            format!("cannot inspect ESRT: {e}"),
        ),
    };
    out.push(esrt);
    out
}

fn efi_boolean(
    ctx: &Context,
    prefix: &str,
    id: &'static str,
    label: &str,
) -> (&'static str, Detection) {
    let entries = match ctx.reader.read_dir(Path::new("/sys/firmware/efi/efivars")) {
        Ok(entries) => entries,
        Err(e) => {
            return finding_detail(
                "efi",
                id,
                Status::Unknown,
                format!("cannot inspect efivars: {e}"),
            )
        }
    };
    let mut complete = true;
    for entry in entries {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        if !entry.file_name.starts_with(prefix) {
            continue;
        }
        return match ctx.reader.read(&entry.path) {
            Ok(bytes) if bytes.get(4) == Some(&1) => {
                finding_detail("efi", id, Status::Enabled, format!("{label}=1"))
            }
            Ok(bytes) if bytes.get(4) == Some(&0) => {
                finding_detail("efi", id, Status::Disabled, format!("{label}=0"))
            }
            Ok(_) => finding_detail(
                "efi",
                id,
                Status::Unknown,
                format!("malformed {label} efivar"),
            ),
            Err(e) => finding_detail(
                "efi",
                id,
                Status::Unknown,
                format!("cannot read {label}: {e}"),
            ),
        };
    }
    finding_detail(
        "efi",
        id,
        Status::Unknown,
        if complete {
            format!("{label} efivar absent")
        } else {
            "efivar enumeration incomplete".to_string()
        },
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EccState {
    None,
    Ecc,
    Unknown,
}

fn smbios_memory(ctx: &Context) -> Findings {
    let buf = match ctx.reader.read(Path::new("/sys/firmware/dmi/tables/DMI")) {
        Ok(buf) => buf,
        Err(e) => {
            return unavailable(
                "dmi",
                DMI_FEATURES,
                format!("cannot inspect SMBIOS table: {e}"),
            )
        }
    };
    let structures = match parse_structures(&buf) {
        Ok(structures) => structures,
        Err(reason) => return unavailable("dmi", DMI_FEATURES, reason),
    };
    let mut ecc = Vec::new();
    let mut dimms = Vec::new();
    let mut dimm_malformed = false;
    for structure in structures {
        match structure.stype {
            16 => ecc.push(ecc_state(structure.byte(0x06))),
            17 => {
                if structure.formatted.len() < 0x17 {
                    dimm_malformed = true;
                    continue;
                }
                if let Some(summary) = dimm_summary(&structure) {
                    dimms.push(summary);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    if ecc.is_empty() {
        out.push(finding_detail(
            "dmi",
            "memory_ecc",
            Status::Unknown,
            "no SMBIOS type 16 memory array",
        ));
    } else {
        let has_none = ecc.contains(&EccState::None);
        let has_ecc = ecc.contains(&EccState::Ecc);
        let has_unknown = ecc.contains(&EccState::Unknown);
        let (status, detail) = if has_unknown || (has_none && has_ecc) {
            (
                Status::Unknown,
                "memory arrays have unknown or conflicting ECC modes",
            )
        } else if has_ecc {
            (Status::Present, "ECC-capable memory array(s)")
        } else {
            (Status::Absent, "SMBIOS reports no ECC")
        };
        out.push(finding_detail("dmi", "memory_ecc", status, detail));
    }
    if dimm_malformed {
        out.push(finding_detail(
            "dmi",
            "memory_dimms",
            Status::Unknown,
            "malformed SMBIOS type 17 structure",
        ));
    } else if dimms.is_empty() {
        out.push(finding_detail(
            "dmi",
            "memory_dimms",
            Status::Absent,
            "no populated SMBIOS type 17 devices",
        ));
    } else {
        out.push(finding_detail(
            "dmi",
            "memory_dimms",
            Status::Present,
            format!("{} populated: {}", dimms.len(), dimms.join(", ")),
        ));
    }
    out
}

fn ecc_state(value: u8) -> EccState {
    match value {
        0x03 => EccState::None,
        0x04..=0x07 => EccState::Ecc,
        _ => EccState::Unknown,
    }
}

fn dimm_summary(s: &Structure<'_>) -> Option<String> {
    let size_raw = s.word(0x0c)?;
    if size_raw == 0 || size_raw == 0xffff {
        return None;
    }
    let mb = if size_raw == 0x7fff {
        s.dword(0x1c)?
    } else if size_raw & 0x8000 != 0 {
        u32::from(size_raw & 0x7fff) / 1024
    } else {
        u32::from(size_raw)
    };
    let size = if mb >= 1024 {
        format!("{} GB", mb / 1024)
    } else {
        format!("{mb} MB")
    };
    let memory_type = mem_type(s.byte(0x12));
    let speed = s.word(0x15).unwrap_or(0);
    Some(if speed != 0 && speed != 0xffff {
        format!("{size} {memory_type}-{speed}")
    } else {
        format!("{size} {memory_type}")
    })
}

fn mem_type(value: u8) -> &'static str {
    match value {
        0x18 => "DDR3",
        0x1a => "DDR4",
        0x1e => "LPDDR",
        0x1f => "LPDDR2",
        0x20 => "LPDDR3",
        0x21 => "LPDDR4",
        0x22 => "DDR5",
        0x23 => "LPDDR5",
        _ => "RAM",
    }
}

struct Structure<'a> {
    stype: u8,
    formatted: &'a [u8],
}
impl Structure<'_> {
    fn byte(&self, offset: usize) -> u8 {
        self.formatted.get(offset).copied().unwrap_or(0)
    }
    fn word(&self, offset: usize) -> Option<u16> {
        Some(u16::from_le_bytes([
            *self.formatted.get(offset)?,
            *self.formatted.get(offset + 1)?,
        ]))
    }
    fn dword(&self, offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes([
            *self.formatted.get(offset)?,
            *self.formatted.get(offset + 1)?,
            *self.formatted.get(offset + 2)?,
            *self.formatted.get(offset + 3)?,
        ]))
    }
}

fn parse_structures(buf: &[u8]) -> Result<Vec<Structure<'_>>, String> {
    let mut structures = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        if pos + 4 > buf.len() {
            return Err("malformed SMBIOS header".into());
        }
        let stype = buf[pos];
        let length = usize::from(buf[pos + 1]);
        if length < 4 || pos + length > buf.len() {
            return Err("malformed SMBIOS structure length".into());
        }
        if stype == 127 {
            return Ok(structures);
        }
        let formatted = &buf[pos..pos + length];
        let mut end = pos + length;
        while end + 1 < buf.len() && !(buf[end] == 0 && buf[end + 1] == 0) {
            end += 1;
        }
        if end + 1 >= buf.len() {
            return Err("unterminated SMBIOS string table".into());
        }
        structures.push(Structure { stype, formatted });
        pos = end + 2;
    }
    Ok(structures)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type17(size_mb: u16, memory_type: u8, speed: u16) -> Vec<u8> {
        let mut f = vec![0; 0x18];
        f[0] = 17;
        f[1] = 0x18;
        f[0x0c..0x0e].copy_from_slice(&size_mb.to_le_bytes());
        f[0x12] = memory_type;
        f[0x15..0x17].copy_from_slice(&speed.to_le_bytes());
        f
    }

    #[test]
    fn ecc_decode_is_conservative() {
        assert!(matches!(ecc_state(0x03), EccState::None));
        for v in 0x04..=0x07 {
            assert!(matches!(ecc_state(v), EccState::Ecc));
        }
        for v in [0, 1, 2, 8, 0xff] {
            assert!(matches!(ecc_state(v), EccState::Unknown));
        }
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
    fn malformed_table_is_rejected() {
        assert!(parse_structures(&[17, 24, 0, 0]).is_err());
    }
}
