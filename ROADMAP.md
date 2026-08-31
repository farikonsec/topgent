# Roadmap

Current capability and planned work. Entries are marked complete only after verification against a real agent on a real host.

## Current capability

| | macOS | Windows | Linux |
|---|:---:|:---:|:---:|
| Command-line tool | ✓ | ✓ | ✓ |
| Desktop application | ✓ unsigned | ✓ unsigned | planned |
| Agent and asset inventory | ✓ | ✓ | ✓ |
| Declared, observed, and reachable access | ✓ | ✓ | ✓ |
| Risk factors, blast radius, event journal | ✓ | ✓ | ✓ |
| Network history and metadata rules | ✓ | ✓ | ✓ |
| Guarded termination | ✓ | ✓ | ✓ |
| CycloneDX AI-BOM and CI policy check | ✓ | ✓ | ✓ |
| Filesystem events | | ✓ | ✓ |
| Connection lifecycle and DNS | | partial | ✓ |

Version 0.1.0 targets Apple silicon and Intel on macOS, x86-64 and ARM64 on Windows, and x86-64 on Linux. Additional architectures are added after verification on a host of that architecture.

## Next

- **Code-signing certificates.** The macOS application ships ad-hoc signed. Gatekeeper reports an unverified developer on first launch and the user approves it once in System Settings. A Developer ID certificate removes that step. The Windows application ships unpacked and unsigned. SmartScreen warns on first launch.

- **Linux desktop build.** Tauri renders its Linux window through GTK3. The gtk-rs GTK3 bindings were last released in December 2024 and carry thirteen open advisories. No published Tauri v2 release avoids them. CI re-evaluates this dependency weekly.

- **Additional verified agents.** Nineteen agent families are defined. Each requires a verified installation per platform. Unmarked cells in the README table indicate unverified platforms, not unsupported ones.

- **Package manager distribution.** Homebrew, `.deb`, and winget.

- **`ARCHITECTURE.md`.** A description of the fact vocabulary, the fold, and the projection, for readers modifying the core.

## Requires a privileged sensor

Topgent runs unprivileged. The following are unavailable at that privilege level. Each is reported as a sensor boundary rather than inferred from adjacent data.

| Capability | Constraint |
|---|---|
| Pre-execution blocking on macOS and Windows | No interception point exists at this privilege level. Linux supports it through fanotify with a privileged helper, which is not implemented. |
| Completed-connection duration on Windows | The Security log records no teardown event. Only the kernel network provider records one. |
| DNS query names on Linux | Linux Audit does not expose the queried name as a structured field. |
| Per-extension attribution in a shared editor process | No unprivileged sensor distinguishes concurrent extensions within one process. |

## Out of scope

Prompt capture, file-content collection, TLS decryption, cloud accounts, and fleet management are out of scope. Topgent reads data the operating system already exposes to an unprivileged process.

---

Open an issue for use cases not covered here.
