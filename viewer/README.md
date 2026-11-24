# Topgent development viewer

This loopback-only web viewer renders Topgent's live JSON report in a browser.
It is a development and inspection surface; the native desktop application is
the product UI.

Build the CLI into an isolated target directory, then point the viewer at it:

```sh
CARGO_TARGET_DIR="$HOME/.cache/topgent-viewer-target" \
  cargo build -p topgent-cli

TOPGENT_BIN="$HOME/.cache/topgent-viewer-target/debug/topgent" \
  PORT=4174 node viewer/serve.mjs
```

Open <http://127.0.0.1:4174>. Each run of the viewer is one session: it
gives every `topgent` it starts a fresh history directory
(`TOPGENT_SESSION_DIR`) and removes it on stop, so nothing from an earlier
run shows. The server accepts only `localhost` and
`127.0.0.1` Host headers and generates a new mutation token for each run.

The viewer mirrors the native desktop's nine workspaces and the Agents view's
eight investigation tabs. It includes process history, attributed Audit
actions, host and per-agent behaviour findings, the 95-rule live-coverage
catalogue, deployment and policy health, network metadata, response governance,
optional context, assets, and CI policy guidance. The native desktop remains
the wording and information-architecture source of truth.

Run its tests with:

```sh
node --check viewer/serve.mjs
node --test viewer/*.test.mjs
```
