# Threat model

What Topgent defends against, what it does not, and why. This document states limits. A capability absent here is absent from the product.

## 1. Scope

Topgent is an unprivileged local process. It enumerates AI agent processes running under the invoking user, records their reachable and observed resources, scores risk from deterministic rules, journals state changes, and can terminate a verified process.

It has no server, no account, and no listening socket. The desktop application communicates with the core in-process.

**In scope:** the Topgent binaries, the desktop application, the report and journal on disk, the policy file, and the collectors that read operating-system state.

**Out of scope:** the security of the agents themselves, the models they call, the networks they traverse, and the operating system.

## 2. Assets

| Asset | Location | Exposure if compromised |
|---|---|---|
| Report and journal | `~/.config/topgent/`, user-readable | Discloses which agents run, what they reached, and host paths |
| Policy file | `~/.config/topgent/policy.json` | Modification suppresses findings |
| Topgent binary | Install path | Execution as the user |
| Signature and factor data | Compiled into the binary | Not writable at runtime |

Topgent stores no credentials, no prompts, no file contents, and no packet payloads. The schema has no field for them.

## 3. Adversaries

| Adversary | Capability assumed | Position |
|---|---|---|
| A misbehaving agent | Full user privileges. Reads and writes anything the user can. Spawns processes. Opens sockets. | The primary case. Topgent exists to report on it. |
| An agent aware of Topgent | The above, plus knowledge of Topgent's detection rules, which are open source. | Assumed. Detection rules are public by design. |
| A local unprivileged process | User privileges, not an agent. | Equivalent to the above. |
| A privileged local attacker | Root or Administrator. | **Out of scope.** A privileged attacker can modify the kernel, the binary, and the journal. No unprivileged monitor defends against this. |
| A network attacker | Traffic interception and modification. | **Out of scope.** Topgent opens no port and initiates no connection except optional DNS reverse lookups. |

## 4. Threats and mitigations

### T1. An agent renames its executable to evade detection

**Mitigation, partial.** Families with provenance markers require the installation path to corroborate the name. A binary named `codex` outside a known install path does not match.

**Residual risk.** Families without markers match on basename alone. Those cells are unmarked in the README table. A definition can also be evaded by installing at an unknown path, which reports as `unrecognised` rather than as a false identity.

### T2. An agent modifies the policy file to lower its own score

**Mitigation, partial.** Modification of Topgent's own configuration by an agent raises `SELF_TAMPERING`. The paths that trigger it are recognised in Rust, not in data, so a data file cannot remove them.

A policy that cannot be read is not silently replaced by defaults. Four states are reported: absent, valid with a SHA-256 digest of the bytes loaded, recovered from a last-known-good copy, and malformed with nothing behind it. Only the last withholds the operator's rules, and it fails the CI gate closed. Writes replace the file atomically, so a crash or a second writer cannot leave half a policy.

**Residual risk.** An agent that stops Topgent before modifying the file leaves no finding. Topgent is not a tamper-proof agent and does not claim to be.

### T3. An agent substitutes a sensor binary on `PATH`

**Mitigation.** Sensor tools are resolved to an absolute path in an operating-system-owned location. A tool found only on `PATH` is refused rather than executed. The resolved path is canonicalised, and the file and every directory above it are checked for owner and writability, so a symlink from an accepted location into a user-writable one is refused. Attestations are journaled with first-seen, last-seen, and change time.

Trust is reported as a state rather than a verdict: `system_trusted`, `user_managed`, `unverified`, `rejected`, `missing`. A Homebrew Docker client is `user_managed`, because the account being watched can replace it.

**Residual risk.** Ownership and writability are not a signature. Package provenance and code signing are not checked. On Windows there is no `AccessCheck` in this build, so every present binary reports `unverified` rather than a trust level nobody established. Collectors that shell out remain the largest attack surface in the product; replacing them with library calls is tracked work.

### T4. PID reuse causes activity to be attributed to the wrong process

**Mitigation.** Identity is `(PID, process start time)` everywhere: journal keys, network history, activity events, and the termination path. A reused PID is a stopped run and a started run, never a grade change.

### T5. Guarded termination stops the wrong process

**Mitigation.** The exact identity is revalidated immediately before the signal is sent. Protected process sets are maintained per platform. Ownership is typed per platform, so an owner the system will not state matches nothing.

### T6. A finding is fabricated by feeding the collector false telemetry

**Mitigation, partial.** Facts carry provenance and confidence. Attribution requires a live PID whose start time precedes the observation, within the current collection window.

**Residual risk.** A process able to write to a log a collector reads can inject records. This is why an unreadable executable reports `unexamined` rather than `unrecognised`: the two are different claims.

### T7. Topgent discloses host detail through its own output

**Mitigation.** Connector URLs are stripped of user information, query, and fragment before entering the inventory. The AI-BOM export carries a redaction statement. `SECURITY.md` and `CONTRIBUTING.md` ask reporters to redact before submitting output.

**Residual risk.** A report shared without redaction describes the host in detail. Topgent does not redact on the user's behalf at display time.

### T8. A supply-chain compromise reaches users through a release

**Mitigation, partial.** Releases are built by CI from a tagged commit, with checksums published alongside. Dependencies are scanned on every push and weekly. Licence and advisory policy is enforced by `cargo-deny`.

**Residual risk.** Binaries are **not code-signed**. Verification depends on the user checking `SHA256SUMS`. Signing is tracked in the roadmap.

### T9. A reachability finding claims more than was established

**Mitigation.** Reachability asks the kernel through `faccessat` with `AT_EACCESS`, so access-control lists are included and a file that stats but cannot be opened is not reported. Every reachable resource carries the evidence behind it: `account_readable` where the kernel answered, `path_resolves` where only the path could be established. The file is never opened.

**Residual risk.** The answer is about the **account**, not the process. Two processes under one owner can differ in supplementary groups, capabilities, namespaces, mandatory access control, seccomp, a macOS sandbox profile, a container filesystem view or a chroot. Topgent scores `SANDBOX_ESCAPE` and therefore does not pretend otherwise: process confinement is not evaluated. On Windows there is no `AccessCheck` in this build, so reachability degrades to `path_resolves` and never claims readability. Resolving the pathname can itself touch a remote or automounted path.

### T10. An unrelated process is reported as an agent

**Mitigation.** The filesystem, network-event and DNS collectors build their maps from every visible process, so being seen doing something is not enough. An identity becomes an agent only with a process observation plus either a recognised family or a verified active editor extension. Everything else is retained as refused, with the identity it was about, so an attribution defect stays findable.

**Residual risk.** A binary installed at a path the catalogue knows is recognised on that evidence. Detection is executable provenance, not code identity.

## 5. Non-goals

Topgent does not prevent action, decrypt traffic, read content, run privileged, or defend against an attacker who already holds root. It reports what an unprivileged process can observe, and states when it cannot observe something.

A sensor that cannot work reports `unsupported`, `permission_required`, or `degraded`. A green row never indicates coverage the platform did not provide, and the CI gate validates the whole rule catalogue rather than whatever coverage a report happens to carry.

Configuration is attributed only to agent processes owned by the invoking account. An agent running as another user, or one whose owner the platform will not state, is listed without its declared permissions rather than borrowing someone else's.
