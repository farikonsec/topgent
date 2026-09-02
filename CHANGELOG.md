# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **A credential that was opened still read "never touched".** Reachability names a file `~/.aws/credentials` and the filesystem sensor names it `/home/you/.aws/credentials`. The fold keyed resources by the string it was given, so one file became two and `CREDENTIAL_ACCESS` could not fire for anything under a home directory.
- **Nothing protected the init process off Windows.** `topgent stop 1` offered to terminate systemd or launchd behind an ordinary confirmation. Pid 1 is now refused everywhere, along with `systemd`, `init`, `launchd`, `kthreadd` and `kernel_task` by name.
- **A watchlist rule written as an absolute home path never matched.** It was accepted, reported `ok`, and silently scored nothing. Rules now normalise to the same key the graph uses.
- **`AGENT_CHAIN` could not fire.** It scored on `invokes`, which only `Claim::InvokesAgent` fills, and no collector emitted one. The config collector now reads an execute grant naming another agent as a second hop.

## [0.2.1] - 2026-09-01

### Fixed

- **Scan header printed a hardcoded `0.1.0`.** `--version` reported the build version, the header did not. Both now read `CARGO_PKG_VERSION`. Regression tests added.

## [0.2.0] - 2026-09-01

### Added

- **Linux desktop application.** The interface now draws on Linux and ships as a `.tar.gz` alongside the macOS and Windows builds. Verified on Linux ARM64 on 2026-09-01: built native, window drawn, six catalogued agents detected, state directory written. Where no Vulkan or GL driver is present the toolkit falls back to software rendering and the interface is unaffected.

- **`topgent --version`.** The command-line tool reported the version in every document it wrote and had no way to be asked directly.

### Fixed

- **An unreadable colour crashed the interface.** The palette loader checked a colour was six bytes and then split it every two, so six bytes of multi-byte text halved a character and panicked. The settings file is one anyone can edit.
- **A permission rule naming no path became a grant.** `Bash()` parsed to the tool `Bash` and an empty argument, and was recorded as a grant over `""`. It is now refused; a bare `Bash` still means every path.
- **No application icon on any platform.** Nothing embedded a Windows resource, the macOS bundle named no `CFBundleIconFile`, and no window icon was set.
- **Empty notification bodies on Windows.** The toast indexed a WinRT node list with `[1]`, which PowerShell cannot do, so every notification shipped a title and nothing else.
- **The declared minimum Rust was wrong.** Five places promised 1.88 while `sysinfo` requires 1.95.

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

[Unreleased]: https://github.com/farikonsec/topgent/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/farikonsec/topgent/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/farikonsec/topgent/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/farikonsec/topgent/releases/tag/v0.1.0
