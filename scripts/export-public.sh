#!/usr/bin/env bash
# Build the public repository from this one.
#
# This repository is the only place work happens. The public repository is a
# product of it, rebuilt by this script, never edited by hand. That is why the
# two cannot drift: there is nothing to keep in sync.
#
#   ./scripts/export-public.sh [destination]     default: ../topgent-public
#
# What comes out is a tree with a fresh, single-commit history. The private
# history stays private, which is the whole point: it holds the machine this
# was built on.
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=$PWD
DEST=${1:-"$(dirname "$PWD")/topgent-public"}

# Internal working documents. Every one is a record of how a thing was proved
# on a lab host we own, written for whoever picks the work up next. A stranger
# reading the repository is not that person, and the records name hosts,
# accounts and validation procedure that are nobody else's business.
#
# They stay in this repository. They do not go out.
EXCLUDE=(
  ".DS_Store" # Finder leaves these everywhere and they are nobody's business.
  "design" # UI mockups as design-canvas artboards. Working material for
           # drawing the interface, referenced by nothing that ships, and of no
           # use to someone reading the code.
  "docs"   # the whole working log: lab records, internal ledgers, planning
           # documents and per-sensor evidence, all written for whoever picks
           # the work up next rather than for someone arriving at the project.
           # ROADMAP.md at the root is the public one. ARCHITECTURE.md and
           # THREAT-MODEL.md get written for the public and then ship.
)

echo "source:      $SRC"
echo "destination: $DEST"
echo

# Build into a staging directory, then move it into place. The destination may
# already be a git repository with a remote, and blowing away its .git would
# lose the connection to the published repository.
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
git ls-files -z | tar --null -T - -cf - | tar -xf - -C "$STAGE"

mkdir -p "$DEST"
# Everything except .git is replaced, so a file deleted here disappears there.
find "$DEST" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -R "$STAGE"/. "$DEST"/

cd "$DEST"
for path in "${EXCLUDE[@]}"; do
  if [ -e "$path" ]; then
    rm -rf "$path"
    echo "  excluded  $path"
  fi
done

# .gitignore mentions paths that do not ship. Drop those lines rather than leave
# a rule for a directory the reader will never see.
python3 - <<'IGNORE'
lines = [l for l in open(".gitignore") if not l.startswith("design/")]
open(".gitignore", "w").writelines(lines)
IGNORE

# A document that stayed behind leaves links pointing at nothing. Rather than
# ship a broken link or edit the private copy, the link is flattened here: the
# text survives, the target goes. The check below then has to come back clean.
python3 - <<'FLATTEN'
import os, re
excluded = ("docs/lab/", "LINUX-TESTING.md", "WINDOWS-SUBROADMAP.md",
            "ROADMAP-PROGRESS.md", "MILESTONE-20-PLAN.md",
            "ACADEMIC-RESEARCH-PLAN.md", "REFACTOR-PLAN.md",
            "AGENT-FAMILY-VALIDATION.md", "lab/")
changed = 0
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d != ".git"]
    for name in (f for f in files if f.endswith(".md")):
        path = os.path.join(root, name)
        text = open(path, encoding="utf-8", errors="replace").read()
        def flatten(m):
            global changed
            label, target = m.group(1), m.group(2)
            if any(e in target for e in excluded):
                changed += 1
                return label
            return m.group(0)
        new = re.sub(r"\[([^\]]+)\]\(([^)]+\.md)\)", flatten, text)
        if new != text:
            open(path, "w", encoding="utf-8").write(new)
print(f"  flattened {changed} link(s) to withheld documents")
FLATTEN

# A link to a document that did not come with us is worse than no link. Links
# resolve relative to the file that holds them, which is why this is python and
# not a grep.
echo
echo "checking for links to excluded documents..."
python3 - <<'CHECK'
import os, re, sys
bad = []
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d != ".git"]
    for name in files:
        if not name.endswith(".md"):
            continue
        path = os.path.join(root, name)
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        for target in re.findall(r"\]\(([^)#]+\.md)\)", text):
            if target.startswith(("http://", "https://")):
                continue
            if not os.path.exists(os.path.normpath(os.path.join(root, target))):
                bad.append(f"{path} -> {target}")
for line in sorted(set(bad)):
    print("  DANGLING ", line)
print("  none" if not bad else f"  {len(set(bad))} broken link(s)")
sys.exit(1 if bad else 0)
CHECK

echo
echo "files: $(find . -type f -not -path './.git/*' | wc -l | tr -d ' ')"
echo
echo "Next: run ./scripts/scan.sh in $DEST, then commit and push."
