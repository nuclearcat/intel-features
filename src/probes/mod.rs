//! Probe infrastructure and injectable host interfaces.

pub mod acpi;
pub mod cpuid;
pub mod firmware;
pub mod msr;
pub mod pci;
pub mod procfs;
pub mod sysfs;
pub mod vulns;

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::model::{Detection, Privilege, Status};

pub type Findings = Vec<(&'static str, Detection)>;
pub type ProbeResult = Result<Findings, ProbeError>;

#[derive(Debug)]
pub struct ProbeError(pub String);

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProbeError {}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub path: PathBuf,
    pub file_name: String,
}

#[derive(Debug, Clone, Copy)]
pub struct SystemMetadata {
    pub is_dir: bool,
}

/// Read-only filesystem operations used by probes. Tests can provide an in-memory tree.
pub trait SystemReader: Send + Sync {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn read_dir(&self, path: &Path) -> io::Result<Vec<io::Result<DirEntry>>>;
    fn metadata(&self, path: &Path) -> io::Result<SystemMetadata>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
    fn open_device(&self, path: &Path, read_write: bool) -> io::Result<()>;

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        String::from_utf8(self.read(path)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn exists(&self, path: &Path) -> bool {
        self.metadata(path).is_ok()
    }
}

#[derive(Debug, Default)]
pub struct HostSystemReader;

impl SystemReader for HostSystemReader {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<io::Result<DirEntry>>> {
        Ok(fs::read_dir(path)?
            .map(|entry| {
                entry.map(|entry| DirEntry {
                    path: entry.path(),
                    file_name: entry.file_name().to_string_lossy().into_owned(),
                })
            })
            .collect())
    }

    fn metadata(&self, path: &Path) -> io::Result<SystemMetadata> {
        fs::metadata(path).map(|metadata| SystemMetadata {
            is_dir: metadata.is_dir(),
        })
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        fs::read_link(path)
    }

    fn open_device(&self, path: &Path, read_write: bool) -> io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(read_write);
        options.open(path).map(drop)
    }
}

/// MSR reads and the optional module-loading operation are isolated from filesystem I/O.
pub trait MsrAccess: Send + Sync {
    fn read(&self, cpu: u32, register: u32) -> io::Result<u64>;
    fn load_module(&self) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct HostMsrAccess;

impl MsrAccess for HostMsrAccess {
    fn read(&self, cpu: u32, register: u32) -> io::Result<u64> {
        let file = fs::File::open(format!("/dev/cpu/{cpu}/msr"))?;
        let mut buf = [0; 8];
        file.read_exact_at(&mut buf, u64::from(register))?;
        Ok(u64::from_le_bytes(buf))
    }

    fn load_module(&self) -> Result<(), String> {
        let mut last = "modprobe not found".to_string();
        for program in ["modprobe", "/sbin/modprobe", "/usr/sbin/modprobe"] {
            match Command::new(program).arg("msr").status() {
                Ok(status) if status.success() => return Ok(()),
                Ok(status) => last = format!("`{program} msr` exited {status}"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => last = format!("`{program}`: {error}"),
            }
        }
        Err(last)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ContextOptions {
    pub load_msr_module: bool,
}

#[derive(Clone)]
pub struct Context {
    pub privilege: Privilege,
    pub reader: Arc<dyn SystemReader>,
    pub msr: Arc<dyn MsrAccess>,
    pub options: ContextOptions,
    module_load_tried: Arc<AtomicBool>,
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("privilege", &self.privilege)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl Context {
    pub fn detect() -> Self {
        Self::with_options(ContextOptions::default())
    }

    pub fn with_options(options: ContextOptions) -> Self {
        let reader: Arc<dyn SystemReader> = Arc::new(HostSystemReader);
        let privilege = effective_privilege(reader.as_ref());
        Self::new(privilege, reader, Arc::new(HostMsrAccess), options)
    }

    pub fn new(
        privilege: Privilege,
        reader: Arc<dyn SystemReader>,
        msr: Arc<dyn MsrAccess>,
        options: ContextOptions,
    ) -> Self {
        Self {
            privilege,
            reader,
            msr,
            options,
            module_load_tried: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_root(&self) -> bool {
        self.privilege == Privilege::Root
    }

    pub(crate) fn try_mark_module_load(&self) -> bool {
        !self.module_load_tried.swap(true, Ordering::SeqCst)
    }
}

pub trait Probe {
    fn name(&self) -> &'static str;
    fn feature_ids(&self) -> Vec<&'static str>;
    fn detect(&self, ctx: &Context) -> ProbeResult;
}

pub fn finding(
    source: &'static str,
    id: &'static str,
    status: Status,
) -> (&'static str, Detection) {
    (id, Detection::new(status, source))
}

pub fn finding_detail(
    source: &'static str,
    id: &'static str,
    status: Status,
    detail: impl Into<String>,
) -> (&'static str, Detection) {
    (id, Detection::with_detail(status, source, detail))
}

pub fn unavailable(
    source: &'static str,
    ids: &[&'static str],
    reason: impl fmt::Display,
) -> Findings {
    let reason = reason.to_string();
    ids.iter()
        .map(|&id| finding_detail(source, id, Status::Unknown, reason.clone()))
        .collect()
}

pub fn all() -> Vec<Box<dyn Probe>> {
    vec![
        Box::new(cpuid::CpuidProbe),
        Box::new(procfs::ProcfsProbe),
        Box::new(sysfs::SysfsProbe),
        Box::new(vulns::VulnProbe),
        Box::new(msr::MsrProbe),
        Box::new(pci::PciProbe),
        Box::new(acpi::AcpiProbe),
        Box::new(firmware::EfiProbe),
        Box::new(firmware::DmiProbe),
    ]
}

fn effective_privilege(reader: &dyn SystemReader) -> Privilege {
    let Ok(status) = reader.read_to_string(Path::new("/proc/self/status")) else {
        return Privilege::User;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .filter(|euid| *euid == "0")
        .map_or(Privilege::User, |_| Privilege::Root)
}
