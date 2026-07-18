# intel-features

A modular, read-only detector for Intel® processor and platform features. It reports not just
*whether* a feature exists, but — where determinable — whether firmware enabled it and
whether the OS is using it. These are separate questions and the tool keeps them separate.

See [`PLAN.md`](PLAN.md) for the full feature catalog and roadmap.

## Status

Milestones **M0**–**M5** are complete. The catalog covers ~205 features across ISA,
security, CPU vulnerabilities, architectural capabilities, virtualization, power,
topology, performance-monitoring, RDT, on-SoC accelerators, chipset/platform devices and
firmware. Nine source-authoritative probes run today:

* **cpuid** — `raw-cpuid` plus direct leaf reads for bits it doesn't expose, executed
  **per logical core** (pinned via `sched_setaffinity`) so hybrid P/E asymmetries are
  reported. CPUs are taken from the process affinity allowance intersected with the
  online set. The banner shows physical P/E core counts (deduplicated from topology),
  successfully scanned logical CPUs, microcode revision, and a conservative
  family/model lookup for the Intel processor codename, product generation, and market segment.
* **procfs** — reads `/proc/cpuinfo` flags to corroborate CPUID; the reporter prints a
  cross-check section for any silicon-vs-kernel disparity.
* **linux-sysfs** — runtime state: SMT, `/dev/kvm`, TPM, intel_pstate/turbo,
  intel_idle C-states, RAPL powercap domains, resctrl mount.
* **linux-vuln** — `/sys/.../vulnerabilities/*`, reporting mitigated/not-affected vs
  vulnerable with the kernel's mitigation string inline.
* **msr** *(root)* — read-only `/dev/cpu/0/msr`: IA32_ARCH_CAPABILITIES immunities,
  FEATURE_CONTROL (VMX enable/lock), VMX capability MSRs (EPT/VPID/APICv/…),
  HWP enablement from `IA32_PM_ENABLE`, TjMax/TDP/power limits, SMI count, Boot Guard.
  Missing or inaccessible MSR devices produce explicit `unknown` findings.
* **pci** — scans `/sys/bus/pci/devices` for Intel devices: chipset (PCH), iGPU, NPU,
  accelerators (DSA/IAA/QAT/DLB/GNA), CSME, NIC, Wi-Fi, audio, SMBus, SPI flash,
  Thunderbolt, VMD — matched by class / device-id / driver, enabled when a driver is bound.
* **acpi** — `/sys/firmware/acpi/tables` presence: VT-d (DMAR), S0ix (LPIT/s2idle),
  persistent memory (NFIT), CXL (CEDT), HMAT, HPET, NUMA (SRAT), WSMT, TPM 2.0.
* **efi** — UEFI boot, Secure Boot / Setup Mode, and ESRT.
* **dmi** — board/BIOS identity in the banner and SMBIOS memory ECC + installed DIMMs.

Later milestones: M6 = MEI protocol / TXT / Boot Guard decode / server extras (CXL, SST).
Target platform is Linux/x86-64.

## Build & run

```sh
cargo build --release
./target/release/intel-features            # grouped, colorized text
./target/release/intel-features --json     # machine-readable
./target/release/intel-features --all -v   # include absent features, show every probe
sudo ./target/release/intel-features --load-msr-module # explicitly allow modprobe msr
```

Options: `--json/-j`, `--verbose/-v`, `--all/-a` (show absent), `--no-color`,
`--load-msr-module`, `--help/-h`, `--version/-V`.

Runs unprivileged and does not mutate the host by default. `--load-msr-module` permits
one `modprobe msr` attempt only when the effective UID is root and the device is missing.
Root does not guarantee access: containers, namespaces, lockdown, mount policy, device
cgroups, and firmware can hide interfaces. Missing, unreadable, malformed, or partially
enumerated authoritative interfaces are reported conservatively as `unknown`; `absent`
means the parent interface was successfully inspected and no match was found.

## Architecture

The modularity axis is the **detection mechanism**, because that is what actually varies:

```
model      — Status / Detection / Category / FeatureDef / Privilege
catalog    — the static registry of known features (id, name, category, description)
probes/    — one module per mechanism, each emitting (feature_id, Detection) pairs
  cpuid    — the CPUID instruction, per-core (ring 3, always available)
  procfs   — /proc/cpuinfo kernel flags (cross-check against CPUID)
  sysfs    — /sys, /dev runtime state (SMT, /dev/kvm, TPM, pstate, RAPL, …)
  vulns    — /sys/.../vulnerabilities/* mitigation status
  msr      — /dev/cpu/0/msr, read-only (root); degrades gracefully otherwise
  pci      — /sys/bus/pci Intel devices (chipset, accelerators, NIC, iGPU, …)
  acpi     — /sys/firmware/acpi/tables presence (VT-d, S0ix, pmem, CXL, …)
  efi      — UEFI boot state, Secure Boot/Setup Mode, ESRT
  dmi      — SMBIOS/DMI board, BIOS, ECC, and memory devices
report     — folds all detections against the catalog; renders text or JSON
```

A `Detection` carries a `Status` — `Present` (silicon), `Enabled`/`Disabled`
(firmware/OS), `Absent`, or `Unknown` — plus its source probe and a traceability note
(e.g. `CPUID.07H:EBX[5]`). A feature can collect several detections; the headline status
is the most informative non-conflicting one. Simultaneous `Enabled` and `Disabled`
findings produce an `Unknown` headline plus a conflict note while retaining both findings.
Asymmetric CPU flags are reported with per-CPU counts instead of trusting CPU 0.

Adding a **feature**: add a `FeatureDef` to `catalog.rs` and teach a probe to emit its id.
Adding a **mechanism**: implement the `Probe` trait and register it in `probes::all()`.

> Note: `PLAN.md` M0 called for a multi-crate workspace. This ships as a single crate with
> the same module boundaries — promoting to a workspace is deferred until probes acquire
> divergent heavy dependencies, at which point the split is mechanical.

## License

MIT OR Apache-2.0.

## Trademarks and affiliation

This is an independent, third-party project. It is not affiliated with, endorsed by, or
sponsored by Intel Corporation. Intel trademarks are used only to identify the processors,
platforms, and technologies the tool inspects. The project does not use the Intel logo.

Intel, the Intel logo, Intel Core, Intel SpeedStep, Intel Xeon, Intel Atom, Intel Optane,
Thunderbolt, and other Intel marks are trademarks of Intel Corporation or its subsidiaries.
Other names and brands may be claimed as the property of others. See
[`TRADEMARKS.md`](TRADEMARKS.md) for usage details and official references.
