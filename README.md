# intel-features

A modular, read-only detector for Intel CPU and platform features. It reports not just
*whether* a feature exists, but — where determinable — whether firmware enabled it and
whether the OS is using it. These are separate questions and the tool keeps them separate.

See [`PLAN.md`](PLAN.md) for the full feature catalog and roadmap.

## Status

Milestone **M0** (scaffolding) is complete: the end-to-end pipeline works with two probes
(CPUID and a Linux sysfs/devnode probe) over a representative subset of the catalog.
Coverage grows in later milestones (M1 = full CPUID via `raw-cpuid`, M2 = sysfs/procfs,
M3 = MSRs, …).

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
  cpuid    — the CPUID instruction (ring 3, always available)
  sysfs    — /sys, /proc, /dev runtime state (SMT enabled, /dev/kvm, TPM, …)
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
