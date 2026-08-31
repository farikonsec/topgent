# Contributing

Topgent is a security tool. Changes require evidence and an explicit statement of what that evidence does not establish.

## Setup

Requires Rust 1.88 or later. No other dependency for the command-line tool.

```sh
git clone https://github.com/farikonsec/topgent && cd topgent
cargo test --workspace
```

The desktop application is a workspace member and builds with everything else.

```sh
cargo run -p topgent-ui
```

The browser viewer is a development surface, not a shipped component. It serves the same report over loopback, which is useful for inspecting one without a desktop.

```sh
cargo build && node viewer/serve.mjs
```

## Pre-submission checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
./scripts/scan.sh
```

CI runs these on macOS, Linux, and Windows, plus the Rust 1.88 minimum. Conditional compilation means a platform-specific defect is invisible to the other two platforms.

## Adding an agent definition

Agent-family definitions are data in [`crates/topgent-collect/data/agent-families.json`](crates/topgent-collect/data/agent-families.json). Adding a product is a data change, not a collector change.

A definition requires:

1. **A fixture.** The executable path from a real installation.
2. **A decoy that must not match.** Typically a binary with the correct name at an incorrect path. A process name is not an identity. A scorer that promotes any process named `claude` can be bypassed by naming.
3. **Path markers**, where the product installs at a predictable location. A definition without them matches on basename alone. The catalogue records this distinction.

Submissions without a decoy will be returned. The `cursor` definition previously matched an Apple text-caret helper on every macOS host. A decoy detects that class of error.

## Adding a sensor or risk factor

Risk factors are data in [`crates/topgent-policy/data/risk-factors.json`](crates/topgent-policy/data/risk-factors.json), including points, description, remedy, and ATLAS mapping. The `FactorCode` enum remains in Rust. Policy data cannot introduce a finding type.

A detector requires positive, negative, threshold, and malformed-input tests. It must define behaviour when its sensor is unavailable. `unsupported`, `permission_required`, `degraded`, and a successful empty result are four distinct states and must not be collapsed.

Where a platform does not supply the required evidence, report the boundary. Do not infer the value from adjacent data. A connection that was not observed must remain distinguishable from a connection that terminated.

## Tests

- Lowest deterministic layer first, then integration, then a live run.
- **Fixtures are synthetic.** Tests do not open real credentials, write real persistence locations, or reference real hosts. Use `/Users/testuser` for home directories.
- Every detector requires a negative case.

A passing suite establishes that the code satisfies its tests. It does not establish that the code is connected to a data source. A collector flag once failed to reach the file it configured while every test continued to pass.

## Commit messages

State what changed and what was incorrect before. The commit log is the design record.

## Bug reports

Open an issue with the command executed, the expected result, and the observed result. Redact hostnames, paths, and usernames. Topgent output describes a host in detail and that detail is not required.

For suspected vulnerabilities, do not open an issue. See [`SECURITY.md`](SECURITY.md).

## Licence

Contributions are licensed under Apache-2.0.
