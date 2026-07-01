# intel-features

A modular, read-only detector for Intel CPU and platform features. It reports not just
*whether* a feature exists, but — where determinable — whether firmware enabled it and
whether the OS is using it. These are separate questions and the tool keeps them separate.

See [`PLAN.md`](PLAN.md) for the full feature catalog and roadmap.

## Status

Milestones **M0** (scaffolding) and **M1** (CPUID) are complete. The catalog covers ~110
CPUID-detectable features across ISA, security, virtualization, power, topology,
performance-monitoring and RDT. Three probes run today:

* **cpuid** — `raw-cpuid` plus direct leaf reads for bits it doesn't expose, executed
  **per logical core** (pinned via `sched_setaffinity`) so hybrid P/E asymmetries are
  reported. The banner shows P/E core counts.
* **procfs** — reads `/proc/cpuinfo` flags to corroborate CPUID; the reporter prints a
  cross-check section for any silicon-vs-kernel disparity.
* **linux-sysfs** — runtime state (SMT enabled, `/dev/kvm`, TPM).

Later milestones: M2 = more sysfs/procfs (vulnerabilities, cpufreq, RAPL), M3 = MSRs
(root), M4 = PCI/device probes, M5 = firmware tables. Target platform is Linux/x86-64.

## Build & run

```sh
cargo build --release
./target/release/intel-features            # grouped, colorized text
./target/release/intel-features --json     # machine-readable
./target/release/intel-features --all -v   # include absent features, show every probe
```

Options: `--json/-j`, `--verbose/-v`, `--all/-a` (show absent), `--no-color`,
`--help/-h`, `--version/-V`.

Runs unprivileged. Probes that need root (MSRs, some PCI config space) are not yet
implemented; when they are, they degrade to `unknown` rather than failing.

## Architecture

The modularity axis is the **detection mechanism**, because that is what actually varies:

```
model      — Status / Detection / Category / FeatureDef / Privilege
catalog    — the static registry of known features (id, name, category, description)
probes/    — one module per mechanism, each emitting (feature_id, Detection) pairs
  cpuid    — the CPUID instruction, per-core (ring 3, always available)
  procfs   — /proc/cpuinfo kernel flags (cross-check against CPUID)
  sysfs    — /sys, /dev runtime state (SMT enabled, /dev/kvm, TPM, …)
report     — folds all detections against the catalog; renders text or JSON
```

A `Detection` carries a `Status` — `Present` (silicon), `Enabled`/`Disabled`
(firmware/OS), `Absent`, or `Unknown` — plus its source probe and a traceability note
(e.g. `CPUID.07H:EBX[5]`). A feature can collect several detections; the headline status
is the most informative one (an `Enabled`/`Disabled` fact outranks a bare `Present`).

Adding a **feature**: add a `FeatureDef` to `catalog.rs` and teach a probe to emit its id.
Adding a **mechanism**: implement the `Probe` trait and register it in `probes::all()`.

> Note: `PLAN.md` M0 called for a multi-crate workspace. This ships as a single crate with
> the same module boundaries — promoting to a workspace is deferred until probes acquire
> divergent heavy dependencies, at which point the split is mechanical.

## License

MIT OR Apache-2.0.
