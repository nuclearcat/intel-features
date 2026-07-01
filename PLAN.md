# IntelFeatures — Intel CPU & Platform Feature Detection Tool

A modular CLI tool that detects the presence (and where possible, the enabled/disabled
state) of Intel processor and motherboard/platform features.

**Language:** Rust (recommended — the `raw-cpuid` crate already decodes the entire CPUID
leaf zoo, memory safety for parsing firmware tables, trivial modularity via traits, single
static binary). C is a fallback if we want zero dependencies.

**Target OS:** Linux first (sysfs/procfs/dev interfaces). Architecture should keep
OS-specific probing behind the detector trait so other OSes can come later.

**Key design principle:** every feature is detected by one or more *probe backends*, and
"CPU supports it", "firmware/BIOS enabled it", and "OS is using it" are three different
answers. The tool should report all that apply (e.g. VT-d: CPUID says nothing — DMAR ACPI
table says supported, kernel cmdline says enabled).

---

## Architecture

```
core
 ├── FeatureRegistry     — static list of all known features + metadata
 ├── Detector trait      — probe(&self, ctx) -> Detection { Present, Absent, Enabled, Disabled, Unknown(reason) }
 ├── Report              — text / JSON output
 └── probes/             — one module per detection mechanism
      ├── cpuid          — CPUID instruction (ring 3, always available)
      ├── msr            — /dev/cpu/*/msr (root, msr module)
      ├── sysfs_cpu      — /sys/devices/system/cpu/** (vulnerabilities, pm, caps)
      ├── procfs         — /proc/cpuinfo flags, /proc/interrupts
      ├── pci            — /sys/bus/pci config space & device IDs
      ├── acpi           — /sys/firmware/acpi/tables (DMAR, TPM2, NFIT, HMAT, SRAT…)
      ├── smbios         — /sys/class/dmi/id + SMBIOS table parsing
      ├── efi            — /sys/firmware/efi/efivars (SecureBoot, etc.)
      ├── devnode        — presence of /dev/tpm0, /dev/mei0, /dev/sgx_enclave…
      └── kmod           — loaded drivers as corroborating evidence
```

Each feature entry declares: name, category, short description, probe(s) to use, and
minimum privilege required. Run unprivileged → report what's detectable; note which
features need root/msr.

---

## Feature Catalog

### 1. Instruction Set Extensions (probe: cpuid, /proc/cpuinfo cross-check)

- [ ] Baseline SIMD: SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2
- [ ] AVX, AVX2, F16C, FMA3
- [ ] AVX-512 subfeatures: F, CD, VL, DQ, BW, IFMA, VBMI, VBMI2, VNNI, BITALG,
      VPOPCNTDQ, VP2INTERSECT, BF16, FP16, (deprecated: ER, PF, 4VNNIW, 4FMAPS)
- [ ] AVX10 (version + vector lengths, leaf 0x24)
- [ ] AVX-VNNI, AVX-VNNI-INT8/INT16, AVX-IFMA, AVX-NE-CONVERT (Alder Lake+ VEX variants)
- [ ] AMX: TILE, INT8, BF16, FP16, COMPLEX (+ palette info via leaf 0x1D/0x1E)
- [ ] Bit manipulation: POPCNT, LZCNT, BMI1, BMI2, ADX, MOVBE
- [ ] Crypto: AES-NI, VAES, PCLMULQDQ, VPCLMULQDQ, SHA-NI, SHA-512, SM3, SM4,
      Key Locker (AESKLE)
- [ ] Random: RDRAND, RDSEED
- [ ] TSX: HLE (dead), RTM, RTM_ALWAYS_ABORT, TSXLDTRK; TSX force-abort MSR state
- [ ] Memory/streaming: CLFLUSHOPT, CLWB, CLDEMOTE, MOVDIRI, MOVDIR64B, ENQCMD,
      PREFETCHW, PREFETCHIT0/1, SERIALIZE
- [ ] Wait/monitor: MONITOR/MWAIT, WAITPKG (UMONITOR/UMWAIT/TPAUSE)
- [ ] HRESET (history reset, for Thread Director)
- [ ] FRED (Flexible Return and Event Delivery), LKGS
- [ ] APX (Advanced Performance Extensions — new GPRs, if/when exposed)
- [ ] XSAVE family: XSAVE, XSAVEOPT, XSAVEC, XSAVES, XFD; enabled XCR0 state components
- [ ] Legacy check: x87, MMX, CMPXCHG16B, LAHF/SAHF in 64-bit

### 2. Security Features — CPU (probe: cpuid, msr, sysfs)

- [ ] NX/XD bit
- [ ] SMEP, SMAP, UMIP
- [ ] CET: Shadow Stack (SHSTK), Indirect Branch Tracking (IBT); kernel/user enablement
- [ ] Protection keys: PKU (user), PKS (supervisor)
- [ ] LASS (Linear Address Space Separation)
- [ ] LAM (Linear Address Masking)
- [ ] SGX: SGX1/SGX2, launch control (FLC), EPC size & sections (leaf 0x12),
      deprecation status; /dev/sgx_enclave presence
- [ ] TDX: guest-side detection (CPUID leaf 0x21), host-side (MSR/SEAM), TDX module version
- [ ] TME / TME-MT (Total Memory Encryption, multi-key), MKTME key count (MSR 0x981/0x982)
- [ ] Key Locker (feature + backup MSR state)
- [ ] MPX (deprecated — detect and flag as removed)
- [ ] Speculation controls present: IBRS/IBPB, STIBP, SSBD, eIBRS (IA32_ARCH_CAPABILITIES),
      RRSBA, BHI_CTRL, PSFD
- [ ] IA32_ARCH_CAPABILITIES decode: RDCL_NO, IBRS_ALL, RSBA, SKIP_L1DFL_VMENTRY,
      SSB_NO, MDS_NO, TAA_NO, TSX_CTRL, MISC_PACKAGE_CTLS, ENERGY_FILTERING_CTL,
      DOITM, SBDR_SSDP_NO, FBSDP_NO, PSDP_NO, FB_CLEAR, GDS_NO, RFDS_NO …
- [ ] Vulnerability/mitigation status: /sys/devices/system/cpu/vulnerabilities/*
      (Meltdown, Spectre v1/v2, L1TF, MDS, TAA, SRBDS, MMIO stale data, Retbleed,
      Downfall/GDS, SRSO n/a, RFDS, BHI, ITS, …)
- [ ] Microcode revision (per-core, flag mismatches) + comparison hooks for "current" DB

### 3. Virtualization (probe: cpuid, msr IA32_VMX_*, acpi, sysfs)

- [ ] VMX present; enabled/locked state (IA32_FEATURE_CONTROL MSR 0x3A)
- [ ] SMX (Safer Mode Extensions / TXT GETSEC)
- [ ] VMX capabilities: EPT, EPT 1G/2M pages, EPT A/D bits, VPID, unrestricted guest,
      APIC virtualization (APICv), posted interrupts, VMCS shadowing, PML,
      mode-based execute control (MBEC), SPP, TSC scaling, PT in VMX, IPI virtualization
- [ ] VT-d (IOMMU): ACPI DMAR table presence, /sys/class/iommu, interrupt remapping,
      posted interrupts, scalable mode (SVM/PASID), enabled on kernel cmdline
- [ ] Shared Virtual Memory / PASID support on devices
- [ ] KVM usability check: /dev/kvm present & openable
- [ ] Am-I-a-guest detection: hypervisor bit, hypervisor vendor leaf (KVM/Hyper-V/VMware/Xen)

### 4. Power, Thermal & Frequency Management (probe: cpuid leaf 6, msr, sysfs)

- [ ] Enhanced SpeedStep (EIST)
- [ ] Speed Shift / HWP (base, notification, activity window, EPP, package-level, PECI override)
- [ ] Turbo Boost 2.0 (presence + enabled bit MSR 0x1A0), turbo ratio limits per core count
- [ ] Turbo Boost Max 3.0 / favored cores (ITBM), preferred core ordering
- [ ] Thermal: digital thermal sensor, package thermal, TjMax (MSR 0x1A2), PROCHOT,
      thermal throttle status/log, PTM
- [ ] RAPL power domains: PKG, PP0 (cores), PP1 (uncore/gfx), DRAM, PSYS; power limits
      PL1/PL2 (+PL4), energy units; powercap sysfs cross-check
- [ ] C-states: supported MWAIT sub-states (leaf 5), enabled C-states via sysfs cpuidle,
      package C-state limit MSR (0xE2)
- [ ] S0ix / Low Power Idle (ACPI FADT LOW_POWER_S0 flag), Modern Standby capability,
      substate residency counters (pmc_core)
- [ ] Energy Perf Bias (IA32_ENERGY_PERF_BIAS)
- [ ] Hardware Duty Cycling (HDC)
- [ ] Thermal Velocity Boost / dynamic tuning hints (where exposed)
- [ ] Running Average Power Limit lock status, undervolt interface (MSR 0x150) responds
      or locked (informational — flag Plundervolt-era lock)
- [ ] Intel SST (Speed Select, servers): SST-PP (perf profiles), SST-BF (base freq),
      SST-TF (turbo freq), SST-CP (core power) — via intel-speed-select mailbox/sysfs

### 5. Hybrid Architecture & Topology (probe: cpuid leaf 0x1A/0xB/0x1F, sysfs)

- [ ] Hybrid flag; per-core type enumeration (P-core / E-core / LP E-core), core counts
- [ ] Thread Director / HFI (Hardware Feedback Interface, leaf 6 bits; HFI table via kernel)
- [ ] Topology: packages, dies, tiles, modules, cores, SMT/Hyper-Threading state
- [ ] Cache topology & sizes (leaf 4), inclusive/exclusive, ways; cache IDs
- [ ] TSC: invariant TSC, TSC frequency enumeration (leaf 0x15/0x16), TSC deadline timer,
      always-running APIC timer (ARAT)
- [ ] x2APIC support & enabled state
- [ ] NUMA nodes, Sub-NUMA Clustering (SNC) detection heuristic
- [ ] CLX/Cluster-on-die style configs (servers), UPI link count (server, PCI probing)

### 6. Performance Monitoring, Debug & Trace (probe: cpuid 0xA/0x14, msr, sysfs)

- [ ] PMU: architectural version, #GP counters, #fixed counters, width, events supported
- [ ] PEBS (+ adaptive PEBS), PDist
- [ ] LBR: legacy vs Architectural LBR (leaf 0x1C), depth
- [ ] Intel PT (Processor Trace): leaf 0x14 subfeatures (PSB, ToPA, multi-range, PTWRITE),
      /sys/bus/event_source/devices/intel_pt
- [ ] BTS (Branch Trace Store)
- [ ] PMU metrics / TMA (PERF_METRICS MSR support on Ice Lake+)
- [ ] Precise TSC / PTWRITE
- [ ] Uncore PMU presence (per-model, via perf sysfs)
- [ ] SMI counter (MSR 0x34) readable — report SMI count

### 7. Resource Director Technology — RDT (probe: cpuid 0xF/0x10, resctrl)

- [ ] Monitoring: CMT (cache occupancy), MBM local/total (+ MBM counters width)
- [ ] Allocation: L3 CAT, L2 CAT, CDP (code/data prioritization) L2/L3, MBA
      (memory bandwidth allocation), MBA thermal throttling
- [ ] resctrl filesystem mounted / usable

### 8. On-SoC Accelerators (probe: cpuid, pci device IDs, devnode, kmod)

- [ ] Intel DSA (Data Streaming Accelerator) — PCI 8086:0b25 etc., idxd driver
- [ ] Intel IAA (In-Memory Analytics Accelerator) — idxd
- [ ] Intel QAT (QuickAssist: crypto/compression) — PCI IDs, qat drivers, VF support
- [ ] Intel DLB (Dynamic Load Balancer)
- [ ] GNA (Gaussian & Neural Accelerator, client)
- [ ] NPU / VPU (Meteor Lake+ AI engine, intel_vpu driver)
- [ ] IPU (image processing unit, client)
- [ ] Integrated GPU: generation, EUs/Xe cores, GuC/HuC firmware loaded, SR-IOV or
      GVT-g capability, Quick Sync (media engines)

### 9. Management Engine & Platform Firmware Security (probe: pci, devnode/MEI, msr, acpi, efi)

- [ ] ME/CSME presence: MEI PCI device (8086:xxxx), /dev/mei0; ME firmware version via
      MEI MKHI; ME operational state (normal / disabled / HAP bit hint)
- [ ] AMT / vPro provisioning state (via MEI), LMS presence
- [ ] Intel PTT (firmware TPM) vs discrete TPM: /dev/tpm0, TPM2 ACPI table,
      manufacturer string (INTC = PTT)
- [ ] Intel TXT: SMX cpuid, TXT public space (0xFED30000) readable, ACM/SINIT status,
      TPM + TXT combination viability
- [ ] Boot Guard: MSR 0x13A (BOOT_GUARD_SACM_INFO) decode — measured/verified boot,
      profile, ACM present
- [ ] BIOS Guard (PFAT) — MSR/platform hint
- [ ] SPS vs consumer ME (server platform services) discrimination
- [ ] SPI flash descriptor lock / BIOS write protection: BIOS_CNTL / BC register via PCI,
      PR registers (best effort, chipsec-like read)
- [ ] SMM_CODE_CHK / SMM protections advertised
- [ ] UEFI Secure Boot state (efivars SecureBoot/SetupMode), UEFI vs legacy CSM boot
- [ ] Firmware update via capsule/fwupd supported (ESRT table present)
- [ ] IA32_FEATURE_CONTROL lock bit state

### 10. Chipset / Motherboard / Platform (probe: pci, smbios, acpi, sysfs)

- [ ] Chipset/PCH identification (LPC/eSPI bridge device ID → PCH family name)
- [ ] Board identity: vendor/model/BIOS version/date (DMI) — context for the report
- [ ] Memory: channels populated, DIMM types/speeds (DMI type 17), ECC supported &
      enabled (DMI type 16 + EDAC sysfs), XMP-capable hint (JEDEC vs running speed)
- [ ] Optane / NVDIMM / persistent memory: NFIT ACPI table, ndctl regions
- [ ] VMD (Volume Management Device) enabled — PCI 8086:9a0b etc.
- [ ] RST / SATA mode (AHCI vs RAID/RST), NVMe remapping detection
- [ ] Thunderbolt / USB4: PCI + /sys/bus/thunderbolt, security level, retimer info
- [ ] PCIe: max gen per root port, ASPM states, Resizable BAR enabled on GPU(s),
      SR-IOV capable devices inventory, ATS/ACS support (relevant to IOMMU isolation)
- [ ] Integrated Ethernet (I219/I225/I226/X710…): identify + IPsec/PTP offload hints
- [ ] Wi-Fi (Intel CNVi vs discrete), Bluetooth
- [ ] HD Audio / Smart Sound Technology (SST/AVS DSP)
- [ ] ISH (Integrated Sensor Hub)
- [ ] GPIO / pinctrl controller exposure
- [ ] Watchdog: iTCO presence & state
- [ ] SMBus controller + accessibility
- [ ] eSPI vs LPC generation hint
- [ ] HPET present/enabled
- [ ] Legacy: serial/parallel port controllers (Super I/O via DMI/kernel)

### 11. Server / Datacenter Specific (probe: pci, msr, acpi, ipmi)

- [ ] IPMI BMC presence (ipmi_si, /dev/ipmi0, DMI type 38), interface type
- [ ] PECI accessibility (peci driver, Icelake+)
- [ ] Node Manager / DCMI via IPMI
- [ ] RAS: machine check banks count, CMCI, MCA recovery (SRAR/SRAO), eMCA gen2,
      ADDDC/patrol scrub hints (EDAC), PPR (post-package repair) hint
- [ ] UPI/QPI topology (multi-socket)
- [ ] CXL: ACPI CEDT table, /sys/bus/cxl, device inventory, CXL 1.1/2.0 type
- [ ] HBM presence (Xeon Max), memory tiering / HMAT table
- [ ] SGX EPC total on server (large-EPC platforms)
- [ ] Crystal Ridge / Optane PMem modes (Memory Mode vs App Direct) if present

### 12. Meta / Cross-cutting checks

- [ ] CPU identity: family/model/stepping, brand string, codename mapping table,
      market segment guess (client/server/embedded)
- [ ] Feature *disparity* report: CPUID says present but kernel flag missing (or vice
      versa) → usually firmware disabled or kernel too old — flag it
- [ ] Per-core consistency: run CPUID probes on every core, flag asymmetries beyond
      expected hybrid differences
- [ ] "Locked by firmware" report: FEATURE_CONTROL, TSX_CTRL, turbo disable bits,
      overclocking lock (MSR 0x194 hint), undervolt lock

---

## Tasks / Milestones

### M0 — Scaffolding  ✅ DONE
- [x] `cargo init` + module layout (`model`, `catalog`, `probes/*`, `report`, `cli`).
      NOTE: shipped as a single crate rather than a multi-crate workspace — same module
      boundaries, workspace split deferred until probes need divergent heavy deps.
- [x] Define `FeatureDef`, `Detection` (Enabled/Disabled/Present/Absent/Unknown + source
      + detail), `Status::rank` headline precedence, `Probe` trait, `Privilege` model
      (euid-based, degrades to `unknown` without root)
- [x] Output: human text (grouped by category, colorized, `-v` per-probe detail,
      `-a` show-absent) + `--json` (serde, validated)
- [x] CI: GitHub Actions (fmt + clippy -D warnings + build + test); 7 integration tests;
      verified on an Intel Core Ultra 9 275HX (Arrow Lake HX)
- Two working probes: `cpuid` (std intrinsics, ~33 features) + `linux-sysfs` (SMT state,
  /dev/kvm, TPM). SMT is detected by both, exercising the Present-vs-Enabled model.

### M1 — CPUID probe (biggest bang, zero privileges)  ✅ DONE
- [x] Integrated `raw-cpuid` for the bulk of leaf decoding + direct `std::arch` reads
      for bits it does not expose (SERIALIZE, MOVDIR*, CET-IBT, FSRM, hybrid, arch-LBR,
      core type). Catalog grown to ~110 CPUID-detectable features across sections 1–7
      (ISA, security, virtualization, power, topology, perfmon, RDT).
- [x] Per-core CPUID via `sched_setaffinity` (pinned thread per online CPU). Aggregates
      to the common subset; features present on only some cores are flagged
      "asymmetric: N/M cores (P-cores only / E-cores only)". Topology banner reports
      hybrid P/E core counts (leaf 0x1A; note: 0x40=Core/P, 0x20=Atom/E — verified
      against kernel `cpu_capacity`, initial mapping was inverted and fixed).
- [x] Cross-check against `/proc/cpuinfo`: new `procfs` probe corroborates each mapped
      feature; reporter emits a "Cross-check" section for silicon-vs-kernel disparities
      in both directions (firmware-masked, or a gap in our own decode).
- Verified on Core Ultra 9 275HX: 122 features (85 present), 8P+16E detected, SMT
  disabled (cpuid HTT + sysfs active=0), 0 disparities (CPUID agrees with kernel across
  ~80 mapped flags). 11 tests, fmt+clippy clean.
- NOTE: target is Linux/x86-64 (per-core scan uses `sched_setaffinity`, topology reads
  `/sys/.../online`). Non-x86 compiles but reports nothing from CPUID.

### M2 — sysfs/procfs probe  ✅ DONE
- [x] Vulnerabilities/mitigations: new `linux-vuln` probe enumerates
      `/sys/devices/system/cpu/vulnerabilities/*` dynamically (20 catalogued +
      `vuln_other` catch-all so newer-kernel entries surface). Maps kernel strings to
      Enabled=protected (not affected / mitigated, with the mitigation text shown inline)
      / Disabled=vulnerable. New "CPU Vulnerabilities & Mitigations" category.
- [x] cpufreq/HWP + turbo runtime state, C-state idle driver, RAPL powercap domains,
      resctrl mount state — added to `linux-sysfs`. Turbo and HWP aggregate onto their
      CPUID silicon-capability entries (Present→Enabled/Disabled via intel_pstate
      no_turbo/status). New features: intel_pstate, intel_idle, rapl (Power), resctrl (Rdt).
- [x] Microcode revision in the banner (sysfs, falls back to /proc/cpuinfo).
- Default view now also hides "not probed" features (no probe covered them); `--all`
  still shows them. Verified on 275HX / kernel 6.17: 146 features, 0 vulnerable,
  turbo+HWP+RAPL+intel_idle enabled, microcode 0x11b. 15 tests, fmt+clippy clean.

### M3 — MSR probe (root)  ✅ DONE
- [x] Read-only MSR layer: `pread` on `/dev/cpu/0/msr`, never writes. Without root or
      the msr module it emits one `msr: disabled` status line and leaves MSR-only
      features "not probed" (hidden by default). A specific MSR that #GP's (EIO) is
      skipped, not fatal. VMX-cap reads gated behind IA32_VMX_BASIC to avoid #GP spam
      (verified: 0 "unchecked MSR" dmesg lines).
- [x] IA32_ARCH_CAPABILITIES (0x10A) → new "Architectural Capabilities" category
      (RDCL_NO, eIBRS, MDS_NO, TAA_NO, BHI_NO, PBRSB_NO, GDS_NO, RFDS_NO, …) — these
      cross-validate the vulnerabilities section. IA32_FEATURE_CONTROL (0x3A) →
      VMX enabled/disabled/locked (aggregates onto cpuid/procfs `vmx`), lock state,
      SGX enable. VMX capability MSRs (0x481/0x48B/0x48C) → EPT, VPID, EPT A/D,
      EPT 1GB, unrestricted guest, APICv, posted interrupts, VMCS shadowing. Thermal
      /RAPL (0x1A2/0x606/0x610/0x614) → TjMax, package TDP, PL1/PL2 (shown inline).
      SMI count (0x34), Boot Guard SACM info (0x13A). TME/MKTME deferred (needs the
      0x981/0x982 key-count decode — small follow-up).
- [x] Reporter gained an `inline_detail` feature flag (replaces the vulnerability
      category special-case): value features like TjMax/TDP and mitigation strings
      render their detail inline instead of probe names.
- Verified as root on 275HX: 176 features, 5 probes, 11 arch-cap immunities present,
      TjMax 105°C, TDP 55W, PL1 165W/PL2 210W, VMX enabled, 0 disparities. 17 tests.

### M4 — PCI + device probes
- [ ] PCI scan via sysfs; device-ID tables for PCH, MEI, QAT/DSA/IAA/DLB, VMD,
      Thunderbolt, NICs, iGPU
- [ ] devnode + kmod corroboration (tpm0, mei0, sgx, kvm, ipmi0)

### M5 — Firmware tables
- [ ] ACPI: DMAR, TPM2, NFIT, CEDT, HMAT, FADT flags (S0ix)
- [ ] SMBIOS/DMI parsing (types 0, 1, 2, 16, 17, 38)
- [ ] EFI vars: SecureBoot/SetupMode; ESRT

### M6 — Advanced / niche
- [ ] MEI protocol client (ME version, AMT state)
- [ ] TXT public space read, Boot Guard full decode
- [ ] Server extras: IPMI, CXL, SST mailbox
- [ ] Codename/generation database + "expected features for this SKU" diffing

### M7 — Polish
- [ ] `--explain <feature>` (what it is, why it matters, how it was detected)
- [ ] Machine-readable schema stability, exit codes for scripting
- [ ] Snapshot/compare mode (diff two runs — e.g. before/after BIOS update)
- [ ] Docs + example outputs

---

## Non-goals (for now)
- Writing to MSRs or any state modification — strictly read-only tool
- Windows/macOS support (keep abstractions clean, but don't implement)
- AMD support (structure the catalog so it could be added, but out of scope)
- Exploit/PoC-style checks — we report mitigation *status* only, from kernel/MSR data
