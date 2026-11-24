#!/usr/bin/env python3
"""Generate crates/topgent-behaviour/data/f/catalogue.json from the vendored F rules.

The YAML files are kept verbatim; the engine reads this JSON form so the build
needs no YAML parser. The output is deterministic: files in load order, and
definitions in the order each file declares them.

    python3 scripts/f-catalogue.py          # regenerate
    python3 scripts/f-catalogue.py --check  # fail if catalogue.json is stale

A vendored file whose hash does not match SOURCE.txt is refused: the pin is
the provenance, and a silently edited rule file would break it.
"""
import argparse
import hashlib
import json
import pathlib
import sys

import yaml

DATA = pathlib.Path(__file__).resolve().parent.parent / "crates/topgent-behaviour/data/f"
FILES = ["stable", "incubating", "sandbox"]
COMMIT = "e822409d8a2a28c9719f56ace66e8cadebfd2bc3"


def pinned_hashes():
    pins = {}
    for line in (DATA / "SOURCE.txt").read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) == 64 and parts[1].endswith(".yaml"):
            pins[parts[1][: -len(".yaml")]] = parts[0]
    return pins


def build():
    pins = pinned_hashes()
    catalogue = {"commit": COMMIT, "files": [], "lists": [], "macros": [], "rules": []}
    for name in FILES:
        raw = (DATA / f"{name}.yaml").read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if pins.get(name) != digest:
            sys.exit(f"{name}.yaml does not match its pinned hash in SOURCE.txt")
        catalogue["files"].append({"name": name, "sha256": digest})
        for item in yaml.safe_load(raw):
            if "list" in item:
                catalogue["lists"].append(
                    {"file": name, "name": item["list"], "items": [str(x) for x in item["items"]]}
                )
            elif "macro" in item:
                catalogue["macros"].append(
                    {"file": name, "name": item["macro"], "condition": item["condition"]}
                )
            elif "rule" in item:
                catalogue["rules"].append(
                    {
                        "file": name,
                        "name": item["rule"],
                        "condition": item["condition"],
                        "priority": item["priority"],
                        "tags": [str(t) for t in item.get("tags", [])],
                        "enabled": item.get("enabled", True),
                        "desc": " ".join(str(item.get("desc", "")).split()),
                    }
                )
    return json.dumps(catalogue, indent=1, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = build()
    target = DATA / "catalogue.json"
    if args.check:
        if not target.exists() or target.read_text() != text:
            sys.exit("catalogue.json is stale: run scripts/f-catalogue.py")
        print("catalogue.json is current")
        return
    target.write_text(text)
    print(f"wrote {target}")


if __name__ == "__main__":
    main()
