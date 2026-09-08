<div align="center">

<img src="assets/icon.png" width="120" alt="Topgent">

# Topgent

**`top` for AI agents. See what they can reach, and stop rogue agents.**

[![CI](https://github.com/farikonsec/topgent/actions/workflows/ci.yml/badge.svg)](https://github.com/farikonsec/topgent/actions/workflows/ci.yml)
[![Security](https://github.com/farikonsec/topgent/actions/workflows/security.yml/badge.svg)](https://github.com/farikonsec/topgent/actions/workflows/security.yml)
[![Fuzz](https://github.com/farikonsec/topgent/actions/workflows/fuzz.yml/badge.svg)](https://github.com/farikonsec/topgent/actions/workflows/fuzz.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.95%2B-orange)](https://www.rust-lang.org)

[Install](#install) · [Use](#use) · [Agents](#agents) · [Packet capture](#packet-capture) · [Limits](#limits) · [Roadmap](ROADMAP.md)

</div>

---

Topgent lists the AI agents running on your machine and shows what each one can
reach, what it has connected to, and which model it is using. It scores each
agent, records grade changes, and can terminate one after re-checking its
identity at the moment of the kill.

Everything runs locally. Detection and scoring are deterministic rules.

<div align="center">
<img src="assets/screenshots/01-agents.png" width="100%" alt="Agent inventory and grades">
</div>

## What it shows

- **Detection checks the executable.** A matching process name is not enough:
  the path must also match a marker a real installer leaves, so a file called
  `codex` in `~/Downloads` is ignored.
- **Three kinds of access, kept apart.** What the agent declares, what it was
  seen doing, and what its account can currently read. Each carries its
  evidence: `account_readable` where the kernel answered, `path_resolves` where
  only the path could be established.
- **Risk with a reason.** Every point of score names its factor, its evidence,
  the MITRE ATLAS technique, and what a compromise would reach.
- **Network history.** Endpoints, listeners, private-network peers and cloud
  metadata access for seven days, with the country and announcing network of
  each address, resolved from a table compiled into the binary.
- **The model each agent is running,** read from the agent's own session files,
  config and command line.
- **Sensor coverage.** `topgent doctor` reports which sensors are unsupported,
  need permission, or are degraded, so an empty result is distinguishable from a
  clean one.
- **Guarded stop.** Revalidates `(PID, start time)` immediately before
  signalling.
- **Exports.** The session and a CycloneDX AI-BOM, as JSON or as a
  self-contained HTML file with a stated redaction level.

Topgent collects metadata. It does not read prompts, responses, file contents or
packet payloads, and it does not decrypt TLS.

<div align="center">
<img src="assets/screenshots/06-capture-and-models.png" width="100%" alt="Packet capture on, the model each agent is using, and the event log">
<img src="assets/screenshots/02-risk-and-blast-radius.png" width="100%" alt="Risk factors and blast radius">
</div>

## Agents

Nineteen families are defined:

Claude Code, Codex CLI, Gemini CLI, Qwen Code, Kimi Code CLI, OpenHands, Aider,
Goose, OpenCode, Amp, Ollama, Cursor, Windsurf, LM Studio, GitHub Copilot Chat,
ChatGPT for VS Code, Cline, Roo Code, Continue.

Most require provenance: the executable path must match an installer marker
before the process is reported. Symlinks are resolved first, because package
managers install a link in `bin/` and on macOS that link is what the process
reports.

Cline, Roo Code and Continue share one editor process. Topgent reports the
process and its active extensions, without attributing activity to a single
extension.

Definitions live in
[`agent-families.json`](crates/topgent-collect/data/agent-families.json). Adding
one means adding a fixture that matches and a decoy that must not.

Models are matched from a second catalogue covering ten providers — Anthropic,
OpenAI, Google, Meta, Alibaba, DeepSeek, Mistral, xAI, Zhipu and Moonshot. A
model named on the command line is recorded as observed; one read from a config
file is recorded as declared, because the file says what was asked for. An agent
whose model cannot be established shows no model.

## Packet capture

Packet capture is optional and turned off until you enable it, and granted
separately on each platform. It shows what a socket listing cannot see: UDP
peers, ICMP, connections that open and close between two sweeps, and traffic
volume per endpoint.

| Platform | Needs | How |
|---|---|---|
| Linux | `CAP_NET_RAW` on the helper | `sudo setcap cap_net_raw,cap_net_admin+eip ./topgent-capture` |
| macOS | Read access to `/dev/bpf*` | The `ChmodBPF` helper shipped with Wireshark |
| Windows | The Npcap driver | Npcap's own signed installer |

Topgent does not install any driver and does not change any permission for you.

A helper process, `topgent-capture`, holds the capability for the privileged
part. It reads frames, prints them, and exits when its parent goes away.

Packet capture reads network headers only. The buffer holds the front of each
frame and the kernel discards the rest, so no payload reaches the process.

Packets carry no process id on any operating system, so Topgent takes the local
port off the packet and asks the socket table who holds it. Frames with no
matching socket are counted and reported as unattributed.

## Install

Every link downloads from the [latest
release](https://github.com/farikonsec/topgent/releases/latest) and stays
correct as new ones ship.

| Platform | Command line | Desktop app |
|---|---|---|
| 🍎 **macOS** 12+ | [Apple silicon][cli-mac-arm] · [Intel][cli-mac-x64] | [Apple silicon][dmg-arm] · [Intel][dmg-x64] |
| 🪟 **Windows** 10/11, Server 2022+ | [ARM64][cli-win-arm] · [x64][cli-win-x64] | [ARM64][app-win-arm] · [x64][app-win-x64] |
| 🐧 **Linux** | [x86-64][cli-lin-x64] | [ARM64][app-lin-arm] · [x86-64][app-lin-x64] |

[cli-mac-arm]: https://github.com/farikonsec/topgent/releases/latest/download/topgent-aarch64-apple-darwin.tar.gz
[cli-mac-x64]: https://github.com/farikonsec/topgent/releases/latest/download/topgent-x86_64-apple-darwin.tar.gz
[cli-win-arm]: https://github.com/farikonsec/topgent/releases/latest/download/topgent-aarch64-pc-windows-msvc.zip
[cli-win-x64]: https://github.com/farikonsec/topgent/releases/latest/download/topgent-x86_64-pc-windows-msvc.zip
[cli-lin-x64]: https://github.com/farikonsec/topgent/releases/latest/download/topgent-x86_64-unknown-linux-gnu.tar.gz
[dmg-arm]: https://github.com/farikonsec/topgent/releases/latest/download/Topgent-macos-aarch64.dmg
[dmg-x64]: https://github.com/farikonsec/topgent/releases/latest/download/Topgent-macos-x86_64.dmg
[app-win-arm]: https://github.com/farikonsec/topgent/releases/latest/download/Topgent-windows-aarch64.zip
[app-win-x64]: https://github.com/farikonsec/topgent/releases/latest/download/Topgent-windows-x86_64.zip
[app-lin-arm]: https://github.com/farikonsec/topgent/releases/latest/download/Topgent-linux-aarch64.tar.gz
[app-lin-x64]: https://github.com/farikonsec/topgent/releases/latest/download/Topgent-linux-x86_64.tar.gz

```sh
shasum -a 256 -c SHA256SUMS     # SHA256SUMS ships with every release
tar -xzf topgent-*.tar.gz && ./topgent
```

<table>
<tr>
<td width="50%"><img src="assets/screenshots/05-macos.png" width="100%" alt="The interface on macOS, in the host's light theme"></td>
<td width="50%"><img src="assets/screenshots/05-linux.png" width="100%" alt="The same interface on Linux, in the host's dark theme"></td>
</tr>
<tr>
<td align="center"><sub>macOS 26.6, Apple silicon</sub></td>
<td align="center"><sub>Linux ARM64, Kali 2026.1</sub></td>
</tr>
</table>

### From source

Rust 1.95 or later.

```sh
git clone https://github.com/farikonsec/topgent && cd topgent
cargo build --release && ./target/release/topgent
```

On Windows the build needs the [Npcap SDK](https://npcap.com/#download) for
headers and import libraries. Unzip it and point the linker at it:

```powershell
$env:LIB = "$HOME\npcap-sdk\Lib\ARM64;" + $env:LIB   # or Lib\x64
cargo build --release
```

The SDK is a build dependency, not the driver. The resulting binary runs on a
machine with no capture driver and reports capture as unsupported until Npcap is
installed.

### Unsigned binaries

Releases are not code-signed yet; certificates are tracked in the roadmap.

- **macOS app.** First launch says the developer cannot be verified. **System
  Settings** → **Privacy & Security** → **Open Anyway**. Once only.
- **macOS command line.** Browser downloads carry a quarantine flag, and a
  quarantined binary produces no output and never exits. Run `xattr -d
  com.apple.quarantine ./topgent` before the first run. A binary already blocked
  once stays blocked, so extract the archive again first. Downloads via `curl`,
  `gh` or `git` are not quarantined.
- **Windows.** SmartScreen warns on first run: **More info** → **Run anyway**.
- **Windows on ARM.** Use the `aarch64` archive. The x64 build runs under
  emulation but enumerates no processes, so it finds no agents.
- **Linux app.** Extract and run `./Topgent`; it needs a graphical session.
  `install-desktop-entry.sh` in the archive adds it to the application menu
  under `~/.local`.

## Use

```sh
topgent                # current inventory
topgent --watch        # continuous collection
topgent doctor         # sensor capability and status
topgent events         # state-change journal
topgent stop <pid>     # guarded termination
```

Run `topgent doctor` first. It tells you which sensors are working.

In CI:

```sh
topgent --json > topgent-report.json
topgent policy check --input topgent-report.json --threshold high --require-coverage
```

| Exit | Meaning |
|---:|---|
| `0` | policy passes |
| `1` | policy violations |
| `2` | invalid input |
| `3` | required detection coverage unavailable |

AI-BOM export:

```sh
topgent export cyclonedx --output topgent.cdx.json
topgent export cyclonedx --format html --output topgent-aibom.html
```

## Limits

Topgent runs unprivileged, which costs coverage:

- **Short-lived processes are missed.** A process that starts and exits between
  two sweeps is never seen. Measured on all three platforms: every resident
  process found, none of the short-lived ones.
- **Windows reachability is unavailable.** There is no `AccessCheck` in this
  build, so every Windows answer is `path_resolves` and no reachability finding
  can be raised. A Windows score is lower than a Linux one for the same agent
  because the evidence is missing.
- **Port scans have no named process.** The connections are refused, so no
  socket exists to attribute them through. The traffic is reported against the
  host probed and marked unattributed.
- **Confinement is not evaluated.** Reachability answers for the account.
  Namespaces, containers, chroots and macOS sandbox profiles are not applied, so
  a confined process may be unable to read a path reported readable.
- **Agents owned by another account** are graded `NOT EVALUATED` with the
  reason attached. They are never scored as clean.
- **Dropped events are not counted.** The kernel holds that counter and reading
  it needs privilege Topgent does not take, so completeness is never claimed.

Adversaries, assets and residual risk are in
[`THREAT-MODEL.md`](THREAT-MODEL.md).

## Architecture

Eleven library crates, a CLI, an offline verifier and a desktop app exchange
immutable, attributed `Fact` records. The core is a pure function of its input:
equivalent facts produce equivalent graphs. Risk policy is data in
[`topgent-policy/data/`](crates/topgent-policy/data/); the finding vocabulary is
a Rust enum, so policy data cannot invent a finding type.

Evidence records are content-addressed and chained, and checkpoints are
Ed25519-signed. `topgent-verify` checks a bundle offline against a key you
already hold, and depends on nothing that produced the bundle.
`topgent evidence explain <claim-id>` walks a finding down to the records behind
it, naming the rule and version that drew it.

## Verification

CI runs on macOS, Linux and Windows, against current stable Rust and the
documented 1.95 minimum. [`scripts/scan.sh`](scripts/scan.sh) runs trufflehog,
gitleaks, osv-scanner and semgrep on every push and weekly. Fuzz targets cover
every parser that reads input Topgent did not write.

CI validates builds and tests. Sensor behaviour is checked by live runs against
real agents on disposable hosts. Tests are synthetic and never open
credentials.

## Contributing

New agent detection needs a fixture that matches and a decoy that must not. New
collectors need the full adapter suite and a live run. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

Report vulnerabilities through the **Security** tab, **Report a vulnerability**.
Reports are visible only to maintainers. See [`SECURITY.md`](SECURITY.md).
Anything else, open an [issue](https://github.com/farikonsec/topgent/issues).

## Licence

Apache-2.0. Copyright 2026 Hadosec. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE).

---

<div align="center"><sub>

`ai security` · `agent monitoring` · `llm security` · `claude code` · `codex` ·
`cursor` · `mcp` · `edr` · `blast radius` · `cyclonedx` · `ai-bom` · `rust` ·
`local-first` · `devsecops`

</sub></div>
