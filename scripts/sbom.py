#!/usr/bin/env python3
"""Write a CycloneDX bill of materials for Topgent's own dependencies.

This is not the AI-BOM. That document describes the AI assets Topgent finds on
a host; this one describes what Topgent itself is built from. The two are about
different subjects and must not be conflated in naming, which is why one is
`topgent.cdx.json` and this is `topgent-sbom.cdx.json`.

Read from `Cargo.lock`, which is the only file that says what was actually
built. `cargo metadata` reports what could resolve; the lock file reports what
did.

No dependency. The project refused two crates to colour a table and would not
be consistent adding one to describe itself.
"""

import hashlib
import json
import pathlib
import re
import subprocess
import sys


def packages(lock: str):
    """Every locked package, as name, version, source, and checksum."""
    out = []
    for block in lock.split("[[package]]")[1:]:
        field = lambda key: (m.group(1) if (m := re.search(rf'^{key} = "([^"]*)"', block, re.M)) else None)
        name, version = field("name"), field("version")
        if not name or not version:
            continue
        out.append({
            "name": name,
            "version": version,
            # A package with no source is one of ours, in this workspace.
            "source": field("source"),
            "checksum": field("checksum"),
        })
    return out


def licences(root: pathlib.Path):
    """What each crate declares, from the metadata cargo already holds."""
    try:
        raw = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--all-features"],
            cwd=root, capture_output=True, text=True, timeout=300, check=True,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        # A licence nobody could read is stated as unknown rather than guessed.
        return {}
    meta = json.loads(raw)
    return {
        (p["name"], p["version"]): p.get("license")
        for p in meta.get("packages", [])
    }


def component(pkg, declared):
    """One package as a CycloneDX component."""
    purl = f"pkg:cargo/{pkg['name']}@{pkg['version']}"
    out = {
        "type": "library",
        "bom-ref": purl,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
        # Where it came from. A package with no source is part of this
        # workspace, which is worth saying rather than leaving to be inferred.
        "scope": "required",
        "properties": [{
            "name": "topgent:origin",
            "value": pkg["source"] or "this workspace",
        }],
    }
    if licence := declared.get((pkg["name"], pkg["version"])):
        out["licenses"] = [{"expression": licence}]
    if pkg["checksum"]:
        out["hashes"] = [{"alg": "SHA-256", "content": pkg["checksum"]}]
    return out


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    lock = (root / "Cargo.lock").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', (root / "Cargo.toml").read_text(), re.M)

    found = packages(lock)
    declared = licences(root)
    components = sorted(
        (component(p, declared) for p in found),
        key=lambda c: (c["name"], c["version"]),
    )

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        # Derived from the lock file rather than the clock, so the same input
        # gives the same document. A BOM that differs between two runs of the
        # same commit cannot be compared against the last release.
        "serialNumber": "urn:uuid:" + str_uuid(lock),
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "pkg:cargo/topgent",
                "name": "topgent",
                "version": version.group(1) if version else "unknown",
                "description": "Local inventory and risk assessment for AI agent processes.",
                "licenses": [{"expression": "Apache-2.0"}],
            },
            "tools": {"components": [{
                "type": "application",
                "name": "topgent sbom",
                "version": "1",
            }]},
        },
        "components": components,
    }

    out = root / "topgent-sbom.cdx.json"
    if len(sys.argv) > 1:
        out = pathlib.Path(sys.argv[1])
    out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    workspace = sum(1 for c in components if c["properties"][0]["value"] == "this workspace")
    unlicensed = sum(1 for c in components if "licenses" not in c)
    print(f"{out}")
    print(f"  components:  {len(components)}")
    print(f"  ours:        {workspace}")
    print(f"  third party: {len(components) - workspace}")
    print(f"  no licence stated: {unlicensed}")
    return 0


def str_uuid(seed: str) -> str:
    """A stable identifier for this exact set of dependencies."""
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


if __name__ == "__main__":
    raise SystemExit(main())
