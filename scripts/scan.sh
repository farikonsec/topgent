#!/usr/bin/env bash
# Every scanner the repository is judged by, in one place.
#
# Run it before a release, before opening the repository to anyone, and in CI on
# every push. It is the same four tools whether a human or a runner invokes it,
# because a check that only exists in someone's shell history is a check that
# stops happening.
#
#   ./scripts/scan.sh          run everything, fail on any finding
#   ./scripts/scan.sh --report print findings without failing
#
# Install locally with:
#   brew install trufflehog gitleaks osv-scanner semgrep
set -uo pipefail

cd "$(dirname "$0")/.."
REPORT_ONLY=0
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --report) REPORT_ONLY=1 ;;
    # CI runs one tool per job so each gets its own pass or fail, but the
    # invocation stays here so the runner and the desk cannot drift apart.
    --only) ONLY="${2:-}"; shift ;;
    *) ;;
  esac
  shift
done
FAILED=()
MISSING=()

have() { command -v "$1" >/dev/null 2>&1; }

run() {
  local name=$1 tool=$2
  shift 2
  [ -n "$ONLY" ] && [ "$ONLY" != "$tool" ] && return
  if ! have "$tool"; then
    MISSING+=("$name ($tool)")
    printf '\n──── %s: SKIPPED, %s is not installed\n' "$name" "$tool"
    return
  fi
  printf '\n──── %s\n' "$name"
  if "$@"; then
    printf '     clean\n'
  else
    FAILED+=("$name")
    printf '     FINDINGS\n'
  fi
}

# Secrets. Two tools rather than one: they use different detector sets, and the
# cost of a second pass is seconds against the cost of a published credential.
run "trufflehog (secrets)" trufflehog \
  trufflehog filesystem . --results=verified,unknown --fail --no-update \
    --exclude-paths=.trufflehog-exclude

run "gitleaks (secrets, incl. history)" gitleaks \
  gitleaks detect --no-banner --redact

# Dependency advisories. One lock file since the desktop application moved into
# the workspace. Accepted findings live in osv-scanner.toml, which is currently
# empty.
run "osv-scanner (dependencies)" osv-scanner \
  osv-scanner scan source \
    --config=osv-scanner.toml \
    --lockfile=Cargo.lock

# Static analysis. --error makes a finding a non-zero exit; without it semgrep
# reports and returns success, which is not a gate.
run "semgrep (static analysis)" semgrep \
  semgrep --config=p/rust --config=p/security-audit --config=p/secrets \
    --exclude=target --exclude=.git \
    --metrics=off --quiet --error .

printf '\n════ summary\n'
if [ ${#MISSING[@]} -gt 0 ]; then
  printf '  not installed: %s\n' "${MISSING[*]}"
fi
if [ ${#FAILED[@]} -eq 0 ]; then
  printf '  all scanners clean\n'
  exit 0
fi
printf '  findings from: %s\n' "${FAILED[*]}"
[ "$REPORT_ONLY" = 1 ] && exit 0
exit 1
