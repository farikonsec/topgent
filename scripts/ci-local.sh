#!/usr/bin/env bash
# Run what continuous integration runs, here, before anything is pushed.
#
#   ./scripts/ci-local.sh              this machine only
#   ./scripts/ci-local.sh --all        this machine, then the lab machines
#
# # Why this exists
#
# Four public build failures in one afternoon, and not one of them was in the
# product. Every one was a difference between what was checked here and what
# the runners actually do:
#
#   * a linker flag that only matters on Windows
#   * a dead-code warning that only appears on Linux
#   * an unnecessary-wrap lint that only fires on Linux, because the other
#     platforms return `None` from the same function
#   * a duplicate key that `yaml.safe_load` accepts and GitHub refuses
#
# Three of those four are lints that are *conditional on the platform*, and
# `cargo check` does not run lints at all. So the rule this script encodes is:
# clippy, on every target, with the same `-D warnings` the workflow uses.
#
# A public repository that is seen fixing its own build all afternoon has told
# every reader something about how carefully it is made. That is the cost this
# is here to avoid.
set -u

cd "$(dirname "$0")/.."
FAILED=()

step() {
  local name=$1
  shift
  if out=$("$@" 2>&1); then
    printf '  %-34s ok\n' "$name"
  else
    printf '  %-34s FAILED\n' "$name"
    printf '%s\n' "$out" | grep -E '^error' -A 4 | head -12 | sed 's/^/      /'
    FAILED+=("$name")
  fi
}

echo
echo "  this machine ($(uname -s))"
step "fmt" cargo fmt --all --check
step "clippy" cargo clippy --workspace --all-targets -- -D warnings
step "test" cargo test --workspace --locked
step "release build" cargo build --workspace --release --locked

# The lints that only fire on another platform are the ones that have actually
# broken the build, so every installed target gets a pass. This is cheap
# compared with finding out from a runner.
for target in $(rustup target list --installed); do
  case "$target" in
  *apple-darwin) continue ;; # the host, already covered above
  esac
  step "clippy ($target)" cargo clippy --workspace --all-targets --target "$target" -- -D warnings
done

# The workflow files themselves, with a parser as strict as GitHub's. A
# duplicate key is accepted by `yaml.safe_load`, silently keeping the last
# value, and refused outright by Actions.
step "workflow yaml" python3 - <<'PY'
import glob
import sys

import yaml


class Strict(yaml.SafeLoader):
    """A loader that refuses a duplicate key rather than keeping the last."""


def no_duplicates(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ValueError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


Strict.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, no_duplicates)

for path in sorted(glob.glob(".github/workflows/*.yml") + glob.glob(".github/actions/*/action.yml")):
    try:
        yaml.load(open(path, encoding="utf-8"), Loader=Strict)
    except Exception as error:  # noqa: BLE001 - the message is the whole point
        print(f"{path}: {error}", file=sys.stderr)
        raise SystemExit(1) from error
PY

echo
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "  all clean"
  echo
  echo "  Before a release, run the same on the lab machines. The steps are in"
  echo "  docs/LAB-ACCESS.md; a Windows runner has no Npcap SDK unless the"
  echo "  workflow puts one there, and that is worth confirming by hand."
  exit 0
fi

echo "  failed: ${FAILED[*]}"
exit 1
