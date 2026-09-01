# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Linux desktop application.** The interface now draws on Linux and ships as a `.tar.gz` alongside the macOS and Windows builds. Verified on Linux ARM64 on 2026-09-01: built native, window drawn, six catalogued agents detected, state directory written. Where no Vulkan or GL driver is present the toolkit falls back to software rendering and the interface is unaffected.

### Changed

- **Interface redesign.** The console is rebuilt around a host-posture header, a single agent inventory table, and a panel rail for investigation. `docs/UI-DESIGN-SYSTEM.md` records the tokens and the rules.

### Removed

- **The Tauri directory.** `app/src-tauri` held no source, only build output, and had been superseded by the native interface in `crates/topgent-ui`.

## [0.1.0] - 2026-08-28

First public release. Ships the command-line tool for macOS, Windows, and Linux.

### Added

- **Agent inventory.** Nineteen agent-family definitions, matched on executable identity and, where defined, installation path. Definitions are data in `agent-families.json`.
- **Three access states.** Declared, observed, and currently reachable resources are reported independently. Reachability is established by testing whether a path could be opened, without opening it.
- **Risk factors.** Twenty-one factors, each carrying points, evidence, remedy, and a MITRE ATLAS technique. Factor data is stored in `topgent-policy/data/`.
- **Blast radius.** Resources and invocable agents reachable after compromise of a given process.
- **Network history.** Endpoints, exposed listeners, private-network peers, and cloud metadata access, retained for seven days and keyed by process identity.
- **Process-tree analysis.** Children, known offensive tooling, and process fan-out.
- **Append-only journal.** Grade changes recorded with exact process identity. Escalations notify; reductions are retained without an alarm.
- **Sensor health.** `topgent doctor` reports `unsupported`, `permission_required`, and `degraded` per sensor and per platform.
- **Guarded termination.** `topgent stop` revalidates `(PID, process start time)` immediately before signalling. Protected process sets are maintained per platform.
- **CycloneDX AI-BOM export.** JSON and self-contained HTML. Metadata only, with an explicit redaction statement.
- **CI policy check.** `topgent policy check` returns a distinct exit code when required detection coverage is unavailable.
- **Optional sensors.** Linux Audit filesystem, network, and DNS event collectors. Windows Security log filesystem events and Filtering Platform connection attempts. Windows DNS Client name resolution.

### Platform support

| | macOS | Windows | Linux |
|---|:---:|:---:|:---:|
| Command-line tool | ✓ | ✓ | ✓ |
| Desktop application | ✓ unsigned `.dmg` | ✓ unsigned `.zip` | not shipped |

The Linux desktop build is withheld. Tauri renders its Linux window through GTK3, whose Rust bindings carry thirteen open advisories with no available upgrade path. See `ROADMAP.md`.

### Fixed

- **Windows on ARM.** The x86_64 build runs under emulation but enumerates no processes, so every sensor reported available while producing no facts. A native `aarch64-pc-windows-msvc` build is shipped and verified: two fixture agents at catalogued paths are detected and classified. The process library moves from sysinfo 0.33 to 0.39.6.

### Security

- Binaries are not code-signed. Verify against `SHA256SUMS`.
- Dependencies, secrets, and static analysis are scanned on every push and weekly by `scripts/scan.sh` and `cargo deny`.
- Sensor binaries are resolved to operating-system-owned paths. A tool found only on `PATH` is refused.

### Known limits

Documented in `THREAT-MODEL.md` and the Limits section of `README.md`. No pre-execution blocking on macOS or Windows, no per-extension attribution within a shared editor process, and no telemetry the platform does not supply.

[Unreleased]: https://github.com/farikonsec/topgent/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/farikonsec/topgent/releases/tag/v0.1.0
