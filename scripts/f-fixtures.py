#!/usr/bin/env python3
"""Generate per-rule fixtures for all 95 F rules, verified by the reference evaluator.

For every rule:
  * `fires`: an event on which the rule's condition is true;
  * `near_miss`: the same event with one field changed, on which it is false;
  * `corpus`: the firing event with each field in turn made unknown, absent
    or different, plus random events drawn from the rule's own values, each
    with the reference evaluator's verdict (true, false or unknown), for
    differential testing against the Rust engine.

    python3 scripts/f-fixtures.py           # regenerate
    python3 scripts/f-fixtures.py --check   # fail if fixtures.json is stale

A rule for which no firing event can be constructed is an error, not a skip.
"""
import argparse
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import f_reference as ref  # noqa: E402

DATA = pathlib.Path(__file__).resolve().parent.parent / "crates/topgent-behaviour/data/f"
OTHER = "zz_topgent_other"
BRANCH_BUDGET = 20000
CORPUS_PER_RULE = 24


def literals(cons):
    out = []
    for c in cons:
        if c[0] == "cmp":
            out.extend(v for _, v in c[2])
    return out


def meets(value, cons):
    """Whether one field value meets every constraint on that field."""
    for c in cons:
        if c[0] == "exists":
            if (value is not None) != c[1]:
                return False
            continue
        _, op, items, want, name = c
        got = False if value is None else ref.compare(value, op, items, name)
        if got != want:
            return False
    return True


def candidates(cons):
    wanted = [c for c in cons if c[0] == "cmp" and c[3]]
    eq = [v for c in wanted if c[1] in ("=", "in") and c[4] not in ref.NET_FIELDS for _, v in c[2]]
    if eq:
        yield from eq
        return
    prefixes = [v for c in wanted if c[1] == "startswith" for _, v in c[2]]
    prefixes += [v.rstrip("/") + "/x" for c in wanted if c[1] == "pmatch" for _, v in c[2]]
    suffixes = [v for c in wanted if c[1] == "endswith" for _, v in c[2]]
    middles = [v for c in wanted if c[1] in ("contains", "icontains", "intersects") for _, v in c[2]]
    for c in wanted:
        if c[1] in ("bcontains", "bstartswith"):
            for _, v in c[2]:
                try:
                    yield bytes.fromhex(v)
                except ValueError:
                    pass
        if c[4] in ref.NET_FIELDS and c[1] in ("=", "in"):
            for _, v in c[2]:
                try:
                    yield str(next(ref.ipaddress.ip_network(v, strict=False).hosts(), ref.ipaddress.ip_network(v, strict=False).network_address))
                except ValueError:
                    pass
    globs = [v for c in wanted if c[1] == "glob" for _, v in c[2]]
    for g in globs:
        yield g.replace("*", "x").replace("?", "x").replace("[", "").replace("]", "")[:200]
    for p in prefixes or [""]:
        for s in suffixes or [""]:
            for m in [" ".join(middles)] + middles or [""]:
                yield p + m + s
                yield p + "x" + m + "x" + s
    nums = []
    for c in cons:
        if c[0] == "cmp" and c[1] in ("<", "<=", ">", ">=", "=", "!=", "in"):
            for _, v in c[2]:
                try:
                    n = int(v)
                    nums += [n, n - 1, n + 1]
                except ValueError:
                    pass
    yield from (str(n) for n in nums)
    yield from literals(cons)
    yield OTHER
    yield "0"


def synthesize(cons):
    if all(c[0] == "exists" and not c[1] or c[0] == "cmp" and not c[3] for c in cons):
        # Only things that must not hold: prefer a real value that fails them.
        if meets(OTHER, cons):
            return OTHER
        if meets(None, cons):
            return None
    for v in candidates(cons):
        if meets(v, cons):
            return v
    if meets(None, cons):
        return None
    return ...  # unsatisfiable


# Fields Topgent answers only for a host process: one fixed value, or absent.
HOST_VALUES = {}
HOST_ABSENT = set()


def add(cons, k, c):
    new = dict(cons)
    new[k] = cons.get(k, []) + [c]
    if synthesize(new[k]) is ...:
        return None
    return new


def add_restricted(cons, k, c):
    """`add` for a Topgent-only witness: a host-only field must hold its one
    value, or be absent."""
    new = add(cons, k, c)
    if new is None:
        return None
    base = k.split("[")[0]
    if base in HOST_ABSENT and not meets(None, new[k]):
        return None
    if base in HOST_VALUES and not meets(HOST_VALUES[base], new[k]):
        return None
    return new


def satisfy(e, want, cons, budget, allowed=None, host=True):
    """Constraint sets that make `e` equal `want`. With `allowed`, only those
    fields may be set: any other stays unknown, as it is to Topgent."""
    if budget[0] <= 0:
        return
    budget[0] -= 1
    if e[0] in ("cmp", "exists") and allowed is not None and e[1][0] not in allowed:
        return
    tag = e[0]
    if tag == "not":
        yield from satisfy(e[1], not want, cons, budget, allowed, host)
    elif tag in ("and", "or"):
        conj = (tag == "and") == want
        if conj:
            yield from _all(e[1], want, cons, budget, allowed, host)
        else:
            for p in e[1]:
                yield from satisfy(p, want, cons, budget, allowed, host)
    elif tag == "exists":
        adder = add if allowed is None or not host else add_restricted
        new = adder(cons, ref.key(e[1]), ("exists", want))
        if new is not None:
            yield new
    elif tag == "cmp":
        adder = add if allowed is None or not host else add_restricted
        new = adder(cons, ref.key(e[1]), ("cmp", e[2], e[3], want, e[1][0]))
        if new is not None:
            yield new


def _all(parts, want, cons, budget, allowed=None, host=True):
    if not parts:
        yield cons
        return
    for c in satisfy(parts[0], want, cons, budget, allowed, host):
        yield from _all(parts[1:], want, c, budget, allowed, host)


def build(cons, fields, fill, restricted=False):
    event = {}
    for k, cs in cons.items():
        base = k.split("[")[0]
        if restricted and base in HOST_ABSENT:
            v = None
        elif restricted and base in HOST_VALUES:
            v = HOST_VALUES[base]
        else:
            v = synthesize(cs)
        event[k] = v
    for f in fields:
        k = ref.key(f)
        if k not in event:
            if restricted and f[0] in HOST_ABSENT:
                event[k] = None
            elif restricted and f[0] in HOST_VALUES:
                event[k] = HOST_VALUES[f[0]]
            else:
                event[k] = fill
    return event


def all_fields(e, out=None):
    out = [] if out is None else out
    if e[0] in ("and", "or"):
        for p in e[1]:
            all_fields(p, out)
    elif e[0] == "not":
        all_fields(e[1], out)
    elif e[0] in ("cmp", "exists") and e[1] not in out:
        out.append(e[1])
    return out


def firing(expr, allowed=None, host=True):
    """An event on which `expr` is true, using only `allowed` fields. With
    `host`, the event is a host process's: `container.id` is host and the
    container-only fields are absent. Without it, any container."""
    fields = [f for f in all_fields(expr) if allowed is None or f[0] in allowed]
    budget = [BRANCH_BUDGET]
    for cons in satisfy(expr, True, {}, budget, allowed, host):
        for fill in (OTHER, None):
            event = build(cons, fields, fill, restricted=allowed is not None and host)
            if ref.evaluate(expr, event) == ref.TRUE:
                return event
    return None


def topgent_coverage(expr, fires, provided):
    """Whether the rule can fire on the fields Topgent supplies, with an event
    that shows it; otherwise which fields it is waiting for, and whether it
    only ever fires for a process in a container, whose details Topgent does
    not read."""
    event = firing(expr, provided)
    if event is not None:
        return {"fires": encode(event), "needs": [], "container_only": False}
    needs = sorted({k.split("[")[0] for k in fires if k.split("[")[0] not in provided})
    container_only = firing(expr, provided | {"__any_container__"}) is None and (
        any(fires.get(k) not in (None, v) for k, v in HOST_VALUES.items())
        or any(fires.get(k) is not None for k in fires if k.split("[")[0] in HOST_ABSENT)
    )
    return {"fires": None, "needs": needs, "container_only": container_only}


def by_source(rule_name, expr, provided, sources):
    """Whether the rule can fire on each syscall source's fields. A source
    that names containers (the eBPF probe, from each event's own cgroup) can
    also fire a rule inside a container, where the container's image, pod
    and mounts stay unknown."""
    live = {}
    for name, source in sorted(sources.items()):
        if rule_name in source.get("blind_to", {}):
            live[name] = False
            continue
        fields = provided - set(source.get("lacks", []))
        fires = firing(expr, fields) is not None
        if not fires and source.get("names_containers"):
            # HOST_ABSENT says these fields are absent for host processes; it
            # does not make them unavailable inside a container. Runtime
            # context supplies image, privilege, pod, accounts and mounts.
            inside = fields - set(source.get("lacks_in_containers", []))
            event = firing(expr, inside, host=False)
            fires = event is not None and event.get("container.id") not in (None, "host")
        live[name] = fires
    return live


def near_miss(expr, event):
    for k in sorted(event):
        for replacement in (OTHER, None):
            if event[k] == replacement:
                continue
            trial = dict(event)
            trial[k] = replacement
            if ref.evaluate(expr, trial) == ref.FALSE:
                return trial, k
    budget = [BRANCH_BUDGET]
    fields = all_fields(expr)
    for cons in satisfy(expr, False, {}, budget):
        trial = build(cons, fields, OTHER)
        if ref.evaluate(expr, trial) == ref.FALSE:
            return trial, None
    return None, None


def corpus(expr, event, seed):
    """Random events built from the rule's own values, some fields unknown."""
    rng = random.Random(seed)
    pools = {}
    for f in all_fields(expr):
        k = ref.key(f)
        pools.setdefault(k, {OTHER, "", "/x"})
    for leaf in leaves(expr):
        k = ref.key(leaf[1])
        for _, v in leaf[3]:
            pools[k].update({v, v + "/x", "x" + v, v.upper()})
    for k, v in event.items():
        if v is not None:
            pools.setdefault(k, set()).add(v)
    for k in pools:
        pools[k] = sorted(pools[k], key=lambda v: (isinstance(v, bytes), str(v)))
    out = []
    # The boundary: the firing event with one field at a time made unknown,
    # absent or different. This is where a wrong `not` or a lost unknown shows.
    for k in sorted(event):
        for change in ("unknown", None, OTHER):
            e = dict(event)
            if change == "unknown":
                del e[k]
            else:
                e[k] = change
            out.append({"event": e, "expect": ref.evaluate(expr, e)})
    keys = sorted(pools)
    for _ in range(CORPUS_PER_RULE):
        e = {}
        for k in keys:
            roll = rng.random()
            if roll < 0.1:
                continue  # unknown
            if roll < 0.15:
                e[k] = None
            else:
                e[k] = rng.choice(pools[k])
        out.append({"event": e, "expect": ref.evaluate(expr, e)})
    return out


def leaves(e):
    if e[0] in ("and", "or"):
        for p in e[1]:
            yield from leaves(p)
    elif e[0] == "not":
        yield from leaves(e[1])
    elif e[0] == "cmp":
        yield e


# Rules that cannot fire as shipped, and how an operator makes them fire.
# Each is tested with the customisation applied; none is skipped.
CUSTOMISE = {
    "Network Connection outside Local Subnet": {
        "lists": {"namespace_scope_network_only_subnet": ["prod"]},
        "why": "the namespace list ships empty for the operator to fill",
    },
    "Launch Disallowed Container": {
        "macros": {"allowed_containers": "container.image.repository = trusted.example/app"},
        "why": "the allowed-containers macro is a placeholder meant to be replaced",
    },
}


def encode(event):
    return {k: ({"hex": v.hex()} if isinstance(v, bytes) else v) for k, v in event.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = json.loads((DATA / "catalogue.json").read_text())
    vocabulary = json.loads((DATA.parent / "topgent-fields.json").read_text())
    provided = set(vocabulary["fields"])
    sources = {k: v for k, v in vocabulary["sources"].items() if isinstance(v, dict)}
    HOST_VALUES.update(vocabulary["host_only"]["values"])
    HOST_ABSENT.update(vocabulary["host_only"]["absent"])
    cat = ref.Catalogue(data)
    out = {"commit": data["commit"], "rules": []}
    failures = []
    for i, rule in enumerate(data["rules"]):
        custom = CUSTOMISE.get(rule["name"])
        rule_cat = cat.customised(custom.get("lists"), custom.get("macros")) if custom else cat
        expr = rule_cat.resolve(rule)
        fires = firing(expr)
        if fires is None:
            failures.append(rule["name"])
            continue
        miss, changed = near_miss(expr, fires)
        if miss is None:
            failures.append(rule["name"] + " (no near miss)")
            continue
        entry = {
            "name": rule["name"],
            "file": rule["file"],
            "fires": encode(fires),
            "near_miss": encode(miss),
            "changed": changed,
            "corpus": [{"event": encode(c["event"]), "expect": c["expect"]} for c in corpus(expr, fires, i)],
            "topgent": topgent_coverage(expr, fires, provided),
        }
        entry["topgent"]["live_by_source"] = by_source(rule["name"], expr, provided, sources)
        if custom:
            entry["customise"] = custom
            entry["as_shipped_fires"] = ref.evaluate(cat.resolve(rule), fires) == ref.TRUE
        out["rules"].append(entry)
    if failures:
        sys.exit("no fixture for: " + "; ".join(failures))
    text = json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    # The small table the engine embeds: which rules can fire on Topgent's
    # fields, and what each blocked one is waiting for.
    coverage = {"commit": data["commit"], "rules": [
        {"name": r["name"], "live": r["topgent"]["fires"] is not None, "needs": r["topgent"]["needs"],
         "container_only": r["topgent"]["container_only"],
         "live_by_source": r["topgent"]["live_by_source"]}
        for r in out["rules"]
    ]}
    coverage_text = json.dumps(coverage, indent=1, ensure_ascii=False) + "\n"
    target = DATA / "fixtures.json"
    if args.check:
        stale = [f for f, t in ((target, text), (DATA / "coverage.json", coverage_text))
                 if not f.exists() or f.read_text() != t]
        if stale:
            sys.exit(f"{', '.join(f.name for f in stale)} stale: run scripts/f-fixtures.py")
        print("fixtures.json and coverage.json are current")
        return
    target.write_text(text)
    (DATA / "coverage.json").write_text(coverage_text)
    live = sum(1 for r in out["rules"] if r["topgent"]["fires"] is not None)
    per = {s: sum(1 for r in out["rules"] if r["topgent"]["live_by_source"][s]) for s in sources}
    print(f"wrote {len(out['rules'])} rule fixtures to {target}; {live} can fire on Topgent's fields; by source {per}")


if __name__ == "__main__":
    main()
