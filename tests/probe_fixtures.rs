use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use intel_features::model::{Privilege, Status};
use intel_features::probes::acpi::AcpiProbe;
use intel_features::probes::firmware::{DmiProbe, EfiProbe};
use intel_features::probes::msr::MsrProbe;
use intel_features::probes::pci::PciProbe;
use intel_features::probes::procfs::ProcfsProbe;
use intel_features::probes::sysfs::SysfsProbe;
use intel_features::probes::{
    Context, ContextOptions, DirEntry, MsrAccess, Probe, SystemMetadata, SystemReader,
};

#[derive(Default)]
struct MemoryReader {
    files: HashMap<PathBuf, Vec<u8>>,
    dirs: HashMap<PathBuf, Vec<Result<String, io::ErrorKind>>>,
    denied: HashSet<PathBuf>,
    links: HashMap<PathBuf, PathBuf>,
    openable: HashSet<PathBuf>,
}

impl MemoryReader {
    fn file(mut self, path: &str, value: impl AsRef<[u8]>) -> Self {
        self.files.insert(path.into(), value.as_ref().to_vec());
        self
    }
    fn dir(mut self, path: &str, entries: &[&str]) -> Self {
        self.dirs.insert(
            path.into(),
            entries.iter().map(|name| Ok((*name).to_string())).collect(),
        );
        self
    }
    fn partial_dir(mut self, path: &str) -> Self {
        self.dirs
            .insert(path.into(), vec![Err(io::ErrorKind::PermissionDenied)]);
        self
    }
    fn openable(mut self, path: &str) -> Self {
        self.openable.insert(path.into());
        self
    }
}

impl SystemReader for MemoryReader {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<io::Result<DirEntry>>> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.dirs
            .get(path)
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| match entry {
                        Ok(name) => Ok(DirEntry {
                            path: path.join(name),
                            file_name: name.clone(),
                        }),
                        Err(kind) => Err(io::Error::from(*kind)),
                    })
                    .collect()
            })
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
    fn metadata(&self, path: &Path) -> io::Result<SystemMetadata> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        if self.dirs.contains_key(path) {
            Ok(SystemMetadata { is_dir: true })
        } else if self.files.contains_key(path) || self.openable.contains(path) {
            Ok(SystemMetadata { is_dir: false })
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        self.links
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
    fn open_device(&self, path: &Path, _read_write: bool) -> io::Result<()> {
        if self.openable.contains(path) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
}

#[derive(Default)]
struct FakeMsr {
    values: HashMap<u32, Result<u64, io::ErrorKind>>,
    loads: Mutex<usize>,
}

impl MsrAccess for FakeMsr {
    fn read(&self, _cpu: u32, register: u32) -> io::Result<u64> {
        self.values.get(&register).map_or_else(
            || Err(io::Error::from(io::ErrorKind::Other)),
            |value| match value {
                Ok(value) => Ok(*value),
                Err(kind) => Err(io::Error::from(*kind)),
            },
        )
    }
    fn load_module(&self) -> Result<(), String> {
        *self.loads.lock().unwrap() += 1;
        Ok(())
    }
}

fn context(reader: MemoryReader) -> Context {
    Context::new(
        Privilege::User,
        Arc::new(reader),
        Arc::new(FakeMsr::default()),
        ContextOptions::default(),
    )
}

fn status(findings: &intel_features::probes::Findings, id: &str) -> Status {
    findings
        .iter()
        .find(|(found, _)| *found == id)
        .unwrap_or_else(|| panic!("missing {id}"))
        .1
        .status
}

#[test]
fn acpi_unavailable_differs_from_inspected_and_absent() {
    let missing = AcpiProbe.detect(&context(MemoryReader::default())).unwrap();
    assert_eq!(status(&missing, "cxl"), Status::Unknown);
    let empty = AcpiProbe
        .detect(&context(
            MemoryReader::default().dir("/sys/firmware/acpi/tables", &[]),
        ))
        .unwrap();
    assert_eq!(status(&empty, "cxl"), Status::Absent);
}

#[test]
fn partial_pci_enumeration_cannot_prove_absence() {
    let partial = PciProbe
        .detect(&context(
            MemoryReader::default().partial_dir("/sys/bus/pci/devices"),
        ))
        .unwrap();
    assert_eq!(status(&partial, "igpu"), Status::Unknown);
    let empty = PciProbe
        .detect(&context(
            MemoryReader::default().dir("/sys/bus/pci/devices", &[]),
        ))
        .unwrap();
    assert_eq!(status(&empty, "igpu"), Status::Absent);
}

#[test]
fn procfs_reports_asymmetric_flags_across_all_blocks() {
    let cpuinfo = "processor : 0\nflags : sse avx2\n\nprocessor : 1\nflags : sse\n";
    let findings = ProcfsProbe
        .detect(&context(
            MemoryReader::default().file("/proc/cpuinfo", cpuinfo),
        ))
        .unwrap();
    let avx2 = findings.iter().find(|(id, _)| *id == "avx2").unwrap();
    assert_eq!(avx2.1.status, Status::Present);
    assert!(avx2.1.detail.as_deref().unwrap().contains("1/2 CPUs"));
    assert_eq!(status(&findings, "sse"), Status::Present);
}

#[test]
fn malformed_cpuinfo_is_unknown_not_absent() {
    let findings = ProcfsProbe
        .detect(&context(
            MemoryReader::default().file("/proc/cpuinfo", "processor : 0\n"),
        ))
        .unwrap();
    assert_eq!(status(&findings, "avx2"), Status::Unknown);
}

#[test]
fn missing_efi_interface_does_not_claim_legacy_bios() {
    let findings = EfiProbe.detect(&context(MemoryReader::default())).unwrap();
    assert_eq!(status(&findings, "uefi_boot"), Status::Unknown);
}

#[test]
fn confirmed_efi_with_missing_esrt_is_absent() {
    let reader = MemoryReader::default()
        .dir("/sys/firmware/efi", &[])
        .dir("/sys/firmware/efi/efivars", &[]);
    let findings = EfiProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "uefi_boot"), Status::Enabled);
    assert_eq!(status(&findings, "esrt"), Status::Absent);
}

fn smbios_type16(ecc: u8) -> Vec<u8> {
    let mut data = vec![0; 0x0f];
    data[0] = 16;
    data[1] = 0x0f;
    data[6] = ecc;
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(&[127, 4, 0, 0, 0, 0]);
    data
}

#[test]
fn smbios_ecc_none_and_unknown_are_distinct() {
    let none = DmiProbe
        .detect(&context(
            MemoryReader::default().file("/sys/firmware/dmi/tables/DMI", smbios_type16(3)),
        ))
        .unwrap();
    assert_eq!(status(&none, "memory_ecc"), Status::Absent);
    let unknown = DmiProbe
        .detect(&context(
            MemoryReader::default().file("/sys/firmware/dmi/tables/DMI", smbios_type16(2)),
        ))
        .unwrap();
    assert_eq!(status(&unknown, "memory_ecc"), Status::Unknown);
}

#[test]
fn intel_pstate_does_not_assert_hwp() {
    let reader = MemoryReader::default()
        .file(
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver",
            "intel_pstate",
        )
        .file("/sys/devices/system/cpu/intel_pstate/status", "active");
    let findings = SysfsProbe.detect(&context(reader)).unwrap();
    assert!(!findings.iter().any(|(id, _)| *id == "hwp"));
}

#[test]
fn hwp_state_comes_from_pm_enable_msr() {
    for (value, expected) in [(1, Status::Enabled), (0, Status::Disabled)] {
        let reader = MemoryReader::default().openable("/dev/cpu/0/msr");
        let mut msr = FakeMsr::default();
        msr.values.insert(0x770, Ok(value));
        let ctx = Context::new(
            Privilege::Root,
            Arc::new(reader),
            Arc::new(msr),
            ContextOptions::default(),
        );
        let findings = MsrProbe.detect(&ctx).unwrap();
        assert_eq!(status(&findings, "hwp"), expected);
    }
}

#[test]
fn module_loading_requires_explicit_root_opt_in_and_runs_once() {
    let msr = Arc::new(FakeMsr::default());
    let no_opt = Context::new(
        Privilege::Root,
        Arc::new(MemoryReader::default()),
        msr.clone(),
        ContextOptions::default(),
    );
    MsrProbe.detect(&no_opt).unwrap();
    assert_eq!(*msr.loads.lock().unwrap(), 0);

    let user_opt = Context::new(
        Privilege::User,
        Arc::new(MemoryReader::default()),
        msr.clone(),
        ContextOptions {
            load_msr_module: true,
        },
    );
    MsrProbe.detect(&user_opt).unwrap();
    assert_eq!(*msr.loads.lock().unwrap(), 0);

    let root_opt = Context::new(
        Privilege::Root,
        Arc::new(MemoryReader::default()),
        msr.clone(),
        ContextOptions {
            load_msr_module: true,
        },
    );
    MsrProbe.detect(&root_opt).unwrap();
    MsrProbe.detect(&root_opt).unwrap();
    assert_eq!(*msr.loads.lock().unwrap(), 1);
}
