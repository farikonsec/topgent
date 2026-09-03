# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-09-03

Written against three operating systems rather than one. Every number below was
measured on macOS, Kali and Windows 11, and five of the entries are defects the
laboratory found that no amount of reading the code would have.

The theme is not new capability. It is the ability to say precisely what the
capability is, and four of the five defects were the same shape: a correct
refusal to answer rendering as an absence, which reads as good news.

### Fixed

- **An owner macOS would not state was displayed as root.** macOS does not disclose the owning uid of another account's process to an unprivileged reader. The typed owner handled that correctly and went to unknown; the string a person reads fell back through a `unwrap_or(0)` and printed `0`, so a process Topgent could learn nothing about appeared as the most privileged account on the machine. It now reads `unknown`, and a uid with no name still prints as its number.
- **macOS missed every agent installed by a package manager.** npm, Homebrew and pipx install a link in a `bin` directory pointing at the real file. Linux reports the resolved target; macOS reports the link. A family requiring path provenance therefore matched on Linux and never on macOS. The process table now canonicalises the executable path before matching. Proven by launching one binary two ways: through the link, invisible; by its target, detected at once.
- **A journal writer no longer gives up on a lock nobody holds.** The record lock borrowed its staleness from the sweep lock at thirty seconds while waiting only about one, so a writer killed mid-record silenced every other writer and they reported contention that was not there. Staleness is now two seconds, the wait is wall-clock and longer than it, and the backoff carries jitter so eight contenders stop convoying.
- **`include_unrecognised` no longer disables the same-family relaunch check.** Written as `flag || (family && !relaunch)`, widening the net also switched off a correctness filter, and a fixture that spawns copies of itself came back as three agents where there was one.

### Added

- **A risk band for what was never evaluated.** An agent owned by another account was graded `LOW` with a score of zero, which reads as *this agent is safe* and means *nobody looked at it*. Fact schema 3 adds `SubjectNotEvaluated` so a collector can state that it skipped a subject and why; `Grade::NotEvaluated` sits below `LOW`, carries zero pips, and is unreachable from any score. Verified on all three platforms, through three different owner-resolution paths: Linux uid, Windows SID, macOS.
- **Collectors declare what they cannot answer.** Reachability now states that it answers only for agents owned by the account Topgent runs as, only over the declared inventory, and only against the permission model. On Windows it says something stronger and more useful: there is no access check in this build, so no reachability finding can ever be raised, and **a Windows score is not comparable with a Linux or macOS one**. File access states that a read performed by an agent's short-lived child is attributed to that child and disappears with it, and that the kernel's dropped-event counter needs privilege Topgent does not take.
- **A kernel event is not a table lookup.** `MatchBasis::KernelEvent` for an audit record naming the process the kernel attributed a syscall to as it happened. Calling that an exact tuple match would claim a search that never took place.
- **What a sweep costs.** Wall time and resident growth, measured through the same process table Topgent uses for the agents. About 300ms and eight megabytes on macOS; **five seconds on Windows**, which is what holds its short-lived-process recall at zero. CPU time is deliberately absent: a portable figure needs two samples, and one sample would be an invention.
- **A shared editor host says what it is.** A VS Code plugin host with three agent extensions loaded rendered as `LOW 0 -`. Topgent declines to say *which* extension caused a host-level event, correctly, and that refusal had become saying nothing at all. The row now reads *3 agent extensions active in a shared editor host*.
- **A normative definition for every word a finding uses.** `docs/NORMATIVE-CLAIMS.md` fixes what running, owner, started, reachable, visible connection, evidence, and complete are allowed to mean, what establishes each and what does not, and the eighteen worked examples two implementers must agree on. Attribution quality and collection coverage are separate dimensions and both travel with every claim; `exact` beside `snapshot_only` is the common case and does not mean complete.
- **A build check that refuses an unsupported claim.** `topgent-lab::overclaim` scans the README, threat model, changelog, and the user-facing crates for reserved strong claims with no quality or coverage beside them, for banned phrases, for integrity described as proof of truth, and for uncalibrated percentages. Twenty findings on first run; the two real ones were reworded, the rest were rules that were too broad.
- **Evidence records with content addresses.** The new `topgent-evidence` crate binds each observation to a host, boot, sensor instance, and sequence, and addresses it by the digest of a canonical encoding that has no maps, no floats, and no escaping. Claims name the rule that drew them, every record for and against, and their own quality and coverage; one that hides a contradiction or names no evidence is refused at construction.
- **A socket fact now says how its owner was matched.** Fact schema 2 added a `MatchBasis` to `SocketOpen`: `exact_tuple`, `wildcard_local`, `listener`, or `unreported`. A tool that lists a process's own sockets names an owner without ever searching a table, so today's collector reports `unreported` and the claim it supports is `Weak` with the reason attached. Only a complete four-tuple matched to a live process may be claimed as `Exact`, and no socket attribution may claim completeness at all.
- **A journal writer no longer gives up on a lock nobody holds.** The record lock borrowed its staleness from the sweep lock at thirty seconds while waiting only about one, so a writer killed mid-record silenced every other writer and they reported contention that was not there. Staleness is now two seconds, the wait is wall-clock and longer than it, and the backoff carries jitter so eight contenders stop convoying. Found by a Windows CI runner slow enough to expose it.
- **A measured answer to what the collectors miss.** `topgent lab benchmark` runs a fixture whose behaviour is known exactly and scores the collectors against it. On macOS, unprivileged: every resident process seen, no short-lived process seen at all, and no fixture process classified as an agent. That is the snapshot method working as specified, and the number is the point. The fixture and the scorer are separate binaries so they cannot share a bug, and the fixture records what it did from its own return values rather than from a second sweep.
- **Structural zeros are explained rather than printed.** Three metrics read zero because descendant enumeration and socket attribution run only for recognised agents, and reachability covers the declared inventory only. The report names each reason on every run. A benchmark that printed a bare `0.0%` beside a metric the tool does not attempt would be inventing a failure.
- **A hash chain, Ed25519 checkpoints, and key rotation.** Each record occupies one position in one sensor instance's chain, and each position commits to the one before. A checkpoint signs the head, which covers everything before it. Rotations are signed by the key stepping down, so authority cannot be minted by anyone holding a bundle. The chain is separate from the record on purpose: a record is content-addressed, and folding its position into its id would give the same observation two ids in two exports.
- **`topgent-verify`, an offline verifier that depends on nothing that produced the bundle.** No collectors, no policy, no renderer, no interface. Three outcomes rather than two: intact, intact with holes, broken. A partial disclosure and a sensor that dropped records look identical, so the middle outcome exists rather than being folded into a pass. Every failure names what was expected and what was found, and every pass prints what it did not establish.
- **`docs/EVIDENCE-BUNDLE-FORMAT.md` and a pinned interoperability fixture.** Enough to write a second implementation, plus the bytes and expected values to check it against. A verifier that links the producing crate shares its bugs; the fixture is what stops that. Writing it found one: two signed structures wrote a domain tag their readers never consumed.
- **`topgent evidence explain <claim-id> --bundle PATH`.** Walks a statement down to the records behind it, reading nothing but the bundle file. `verify` recomputes every id and resolves every reference. Both refuse a bundle holding a duplicate address, a dangling reference, or a record that could not have been collected. `verify` takes the key the caller holds, or `--self` for internal consistency, which it labels as establishing no origin.

## [0.3.0] - 2026-09-02

Six gaps between what Topgent stated and what it had proved, from an external
assessment of 0.2.1. Five of the six remove a claim rather than add a capability:
the tool now knows less and says so accurately.

### Changed

- **Reachability asks the kernel instead of calling `stat`.** `stat` needs the execute bit on the parent directory and nothing on the file, so a mode-000 credential stated fine and could not be opened. `faccessat` with `AT_EACCESS` answers the real question, access-control lists included, and the file is still never opened. Every reachable resource now carries its evidence: `account_readable` where the kernel answered, `path_resolves` where only the path could be established. The answer is about the account, not the process, and the wording says so.
- **Windows reachability degrades rather than overclaiming.** There is no `AccessCheck` in this build, so a reachable path there means the path resolves. A real implementation upgrades it later instead of restoring it.
- **An agent needs a process observation plus a recognised family or a verified editor extension.** <!-- overclaim-ok: verified names the extension-id allowlist check, not a finding quality --> With audit sensors live, an unrelated shell that opened a watched file arrived in the inventory with a risk score of its own. On a lab host the inventory went from twenty rows to one. Refused facts are retained with the identity they were about.
- **Configuration is attributed only to processes this account owns.** Another user's Claude was reported with this user's declared permissions, model and grants. Ownership is compared as a typed value, uid on Unix and SID on Windows, resolved rather than assumed.
- **Sensor trust is a reported state, not a boolean.** A binary was trusted because a file existed at an accepted path, and `/usr/local/bin` and `/opt/homebrew/bin` are user-owned on most developer machines. The resolved path is canonicalised and the file and every parent are checked for owner and writability. A Homebrew Docker client reports `user_managed`.
- **Policy health is reported.** Absent, valid with a digest, recovered from a last-known-good copy, or malformed. Writes replace the file atomically. Nothing overwrites a policy it could not read.

### Fixed

- **An empty coverage array passed `--require-coverage`.** `all()` on an empty array is true, so a truncated or crafted report opened the CI gate. The exact rule catalogue is validated: every rule once, no unknowns, valid state and verification. A malformed table is an input error rather than incomplete coverage.
- **A JSON array parsed as a policy with every weight at zero.** Serde fills a struct from a sequence positionally, so `[[0]]` scored every agent on the host at zero, silently. Found by the `config` fuzz target.
- **The journal lost records under concurrent writes.** Every writer named its scratch file by process id alone, so two writers inside one process collided and one lost. Read-modify-write now runs under an exclusive lock.
- **Reachability was empty on Windows after the ownership change.** The sweep leaves the owner unstated there because a security identifier costs a query per process, and an unstated owner matches nothing. Ownership is resolved before it is compared.
- **A sensor path was reported with the Windows extended-length prefix.**

### Interface

- The reachable column says `path only` where readability was not established.
- The health panel names the policy file when the rules in force are not the operator's, and lists the binaries the sensors run with the trust state of each.

## [0.2.2] - 2026-09-02

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

- **Linux desktop application.** The interface now draws on Linux and ships as a `.tar.gz` alongside the macOS and Windows builds. Verified on Linux ARM64 on 2026-09-01: built native, window drawn, six catalogued agents detected, state directory written. <!-- overclaim-ok: verified describes a lab run of the build, with its evidence listed --> Where no Vulkan or GL driver is present the toolkit falls back to software rendering and the interface is unaffected.

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

- **Windows on ARM.** The x86_64 build runs under emulation but enumerates no processes, so every sensor reported available while producing no facts. A native `aarch64-pc-windows-msvc` build is shipped and verified <!-- overclaim-ok: verified describes a lab run of the build, with its evidence listed -->: two fixture agents at catalogued paths are detected and classified. The process library moves from sysinfo 0.33 to 0.39.6.

### Security

- Binaries are not code-signed. Verify against `SHA256SUMS`.
- Dependencies, secrets, and static analysis are scanned on every push and weekly by `scripts/scan.sh` and `cargo deny`.
- Sensor binaries are resolved to operating-system-owned paths. A tool found only on `PATH` is refused.

### Known limits

Documented in `THREAT-MODEL.md` and the Limits section of `README.md`. No pre-execution blocking on macOS or Windows, no per-extension attribution within a shared editor process, and no telemetry the platform does not supply.

[Unreleased]: https://github.com/farikonsec/topgent/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/farikonsec/topgent/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/farikonsec/topgent/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/farikonsec/topgent/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/farikonsec/topgent/releases/tag/v0.1.0
