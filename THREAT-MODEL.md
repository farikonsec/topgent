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

**Residual risk.** An agent that stops Topgent before modifying the file leaves no finding. Topgent is not a tamper-proof agent and does not claim to be.

### T3. An agent substitutes a sensor binary on `PATH`

**Mitigation.** Sensor tools are resolved to an absolute path in an operating-system-owned location. A tool found only on `PATH` is refused rather than executed. Attestations are journaled with first-seen, last-seen, and change time.

**Residual risk.** Collectors that shell out remain the largest attack surface in the product. Replacing them with library calls is tracked work.

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

## 5. Non-goals

Topgent does not prevent action, decrypt traffic, read content, run privileged, or defend against an attacker who already holds root. It reports what an unprivileged process can observe, and states when it cannot observe something.

A sensor that cannot work reports `unsupported`, `permission_required`, or `degraded`. A green row never indicates coverage the platform did not provide.
