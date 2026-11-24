"""An independent reference evaluator for the F condition language.

Written separately from the Rust engine, in a different style (a Pratt-style
parser over a flat token list, tuples for the tree), so the two can be checked
against each other. The fixtures in crates/topgent-behaviour/data/f are
generated and verified with this module; the Rust tests then have to agree.

Semantics, which both implementations must share:
  * a field not in the event is UNKNOWN; a field present with value None is
    ABSENT (collected, no value);
  * any comparison on ABSENT is False; `exists` on ABSENT is False;
  * UNKNOWN propagates: not U = U; and: False wins, else U; or: True wins, else U;
  * a list value (every ancestor at once) satisfies a comparison if any element does.
"""
import ipaddress
import re

TRUE, FALSE, UNKNOWN = "true", "false", "unknown"
MISSING = object()
WORD_OPS = {"contains", "icontains", "bcontains", "startswith", "bstartswith",
            "endswith", "glob", "in", "intersects", "pmatch"}
SET_OPS = {"in", "intersects", "pmatch"}
SYMBOLS = {"=": "=", "==": "=", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">="}


class Error(Exception):
    pass


def tokenize(text):
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c in "(),":
            out.append((c, c))
            i += 1
        elif c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(text[j])
                j += 1
            if j >= n:
                raise Error("unterminated quote")
            out.append(("q", "".join(buf)))
            i = j + 1
        elif c in "=!<>":
            sym = c + ("=" if i + 1 < n and text[i + 1] == "=" else "")
            if sym not in SYMBOLS:
                raise Error("bad symbol " + sym)
            out.append(("op", SYMBOLS[sym]))
            i += len(sym)
        else:
            m = re.match(r"[^\s(),\"'=!<>]+", text[i:])
            out.append(("w", m.group(0)))
            i += len(m.group(0))
    return out


def parse(text):
    toks = tokenize(text)
    pos = [0]

    def peek(k=0):
        return toks[pos[0] + k] if pos[0] + k < len(toks) else (None, None)

    def take():
        t = peek()
        pos[0] += 1
        return t

    def expr(depth):
        if depth > 400:
            raise Error("too deep")
        left = conj(depth)
        parts = [left]
        while peek() == ("w", "or"):
            take()
            parts.append(conj(depth))
        return parts[0] if len(parts) == 1 else ("or", parts)

    def conj(depth):
        parts = [unary(depth)]
        while peek() == ("w", "and"):
            take()
            parts.append(unary(depth))
        return parts[0] if len(parts) == 1 else ("and", parts)

    def unary(depth):
        if peek() == ("w", "not"):
            take()
            return ("not", unary(depth + 1))
        kind, val = take()
        if kind == "(":
            e = expr(depth + 1)
            if take()[0] != ")":
                raise Error("missing )")
            return e
        if kind != "w" or val in ("and", "or", "not"):
            raise Error("expected predicate")
        nk, nv = peek()
        if nk == "w" and nv == "exists":
            take()
            return ("exists", field(val))
        if nk == "op" or (nk == "w" and nv in WORD_OPS):
            take()
            op = nv
            if op in SET_OPS:
                if take()[0] != "(":
                    raise Error("expected (")
                items = []
                while True:
                    k, v = take()
                    if k == ")" and items:
                        break
                    if k not in ("w", "q"):
                        raise Error("expected item")
                    items.append((k, v))
                    k, v = take()
                    if k == ")":
                        break
                    if k != ",":
                        raise Error("expected , or )")
                return ("cmp", field(val), op, items)
            k, v = take()
            if k not in ("w", "q"):
                raise Error("expected value")
            return ("cmp", field(val), op, [(k, v)])
        if "." in val:
            raise Error("field without operator")
        return ("macro", val)

    e = expr(0)
    if pos[0] != len(toks):
        raise Error("trailing tokens")
    return e


def field(text):
    if "[" in text:
        base, arg = text.split("[", 1)
        return (base, arg[:-1])
    return (text, None)


class Catalogue:
    ORDER = ["stable", "incubating", "sandbox"]

    def __init__(self, data):
        self.data = data

    def scope(self, file):
        return [file] + [f for f in self.ORDER if f != file]

    def lookup(self, kind, name, file):
        for f in self.scope(file):
            for d in self.data[kind]:
                if d["file"] == f and d["name"] == name:
                    return d
        return None

    def resolve(self, rule):
        return self._inline(parse(rule["condition"]), rule["file"], ())

    def _inline(self, e, file, chain):
        tag = e[0]
        if tag in ("and", "or"):
            return (tag, [self._inline(p, file, chain) for p in e[1]])
        if tag == "not":
            return ("not", self._inline(e[1], file, chain))
        if tag == "macro":
            if e[1] in chain:
                raise Error("macro cycle")
            m = self.lookup("macros", e[1], file)
            if m is None:
                raise Error("unknown macro " + e[1])
            return self._inline(parse(m["condition"]), file, chain + (e[1],))
        if tag == "cmp" and e[2] in SET_OPS:
            out = []
            for item in e[3]:
                out.extend(self._expand(item, file, ()))
            return ("cmp", e[1], e[2], out)
        return e

    def _expand(self, item, file, chain):
        kind, name = item
        if kind == "q":
            return [item]
        lst = self.lookup("lists", name, file)
        if lst is None:
            return [item]
        if name in chain:
            raise Error("list cycle")
        out = []
        for inner in lst["items"]:
            out.extend(self._expand(list_item(inner), file, chain + (name,)))
        return out

    def customised(self, lists=None, macros=None):
        data = {k: [dict(d) for d in v] if isinstance(v, list) else v for k, v in self.data.items()}
        for d in data["lists"]:
            if lists and d["name"] in lists:
                d["items"] = list(lists[d["name"]])
        for d in data["macros"]:
            if macros and d["name"] in macros:
                d["condition"] = macros[d["name"]]
        return Catalogue(data)


def list_item(text):
    """A list item as the condition would read it if written in by hand."""
    try:
        toks = tokenize(text)
    except Error:
        return ("q", text)
    if len(toks) == 1 and toks[0][0] in ("q", "w"):
        return toks[0]
    return ("q", text)


def fields_of(e, out=None):
    out = set() if out is None else out
    if e[0] in ("and", "or"):
        for p in e[1]:
            fields_of(p, out)
    elif e[0] == "not":
        fields_of(e[1], out)
    elif e[0] in ("cmp", "exists"):
        out.add(e[1])
    return out


def _num(a, b):
    try:
        return int(a.strip()), int(b.strip())
    except ValueError:
        return None


def _eq(a, b):
    n = _num(a, b)
    return n[0] == n[1] if n else a == b


def _glob(pattern, text):
    # Translate to a regular expression: * any run, ? one, [..] a class.
    rx, i = "", 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            rx += ".*"
        elif c == "?":
            rx += "."
        elif c == "[":
            j = pattern.find("]", i + 2)
            if j == -1:
                rx += re.escape(c)
            else:
                body = pattern[i + 1:j]
                neg = body[:1] in ("!", "^")
                if neg:
                    body = body[1:]
                rx += "[" + ("^" if neg else "") + body.replace("\\", "\\\\") + "]"
                i = j
        else:
            rx += re.escape(c)
        i += 1
    return re.fullmatch(rx, text, re.S) is not None


def _under(path, prefix):
    if not prefix:
        return False
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + "/")


def _hex(text):
    try:
        return bytes.fromhex(text) if len(text) % 2 == 0 else None
    except ValueError:
        return None


NET_FIELDS = {"fd.net", "fd.cnet", "fd.snet", "fd.lnet", "fd.rnet"}


def _inside(address, network):
    try:
        return ipaddress.ip_address(address.strip()) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def compare(actual, op, items, field_name=None):
    """`actual` is text, or bytes for a field that carries raw bytes."""
    raw = actual if isinstance(actual, bytes) else actual.encode()
    if isinstance(actual, bytes):
        actual = actual.decode("utf-8", "replace")
    vals = [v for _, v in items]
    if field_name in NET_FIELDS and op in ("=", "!=", "in"):
        inside = any(_inside(actual, v) for v in vals)
        return not inside if op == "!=" else inside
    if op == "in":
        return any(_eq(actual, v) for v in vals)
    if op == "intersects":
        return any(t in vals for t in actual.split())
    if op == "pmatch":
        return any(_under(actual, v) for v in vals)
    if len(vals) != 1:
        return False
    v = vals[0]
    if op == "=":
        return _eq(actual, v)
    if op == "!=":
        return not _eq(actual, v)
    if op in ("<", "<=", ">", ">="):
        n = _num(actual, v)
        if not n:
            return False
        a, b = n
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    if op == "contains":
        return v in actual
    if op == "icontains":
        return v.lower() in actual.lower()
    if op == "startswith":
        return actual.startswith(v)
    if op == "endswith":
        return actual.endswith(v)
    if op == "glob":
        return _glob(v, actual)
    if op == "bcontains":
        h = _hex(v)
        return bool(h) and h in raw
    if op == "bstartswith":
        h = _hex(v)
        return h is not None and raw.startswith(h)
    return False


def key(f):
    """How a field is written in a fixture: `proc.aname[2]` or `proc.name`."""
    return f[0] if f[1] is None else f"{f[0]}[{f[1]}]"


def evaluate(e, event):
    tag = e[0]
    if tag == "and":
        res = TRUE
        for p in e[1]:
            r = evaluate(p, event)
            if r == FALSE:
                return FALSE
            if r == UNKNOWN:
                res = UNKNOWN
        return res
    if tag == "or":
        res = FALSE
        for p in e[1]:
            r = evaluate(p, event)
            if r == TRUE:
                return TRUE
            if r == UNKNOWN:
                res = UNKNOWN
        return res
    if tag == "not":
        r = evaluate(e[1], event)
        return {TRUE: FALSE, FALSE: TRUE, UNKNOWN: UNKNOWN}[r]
    if tag == "macro":
        return UNKNOWN
    value = event.get(key(e[1]), MISSING)
    if value is MISSING:
        return UNKNOWN
    if isinstance(value, list):
        # Several values at once (every ancestor): holds if any one does.
        if tag == "exists":
            return TRUE if value else FALSE
        return TRUE if any(compare(v, e[2], e[3], e[1][0]) for v in value) else FALSE
    if tag == "exists":
        return FALSE if value is None else TRUE
    if value is None:
        return FALSE
    return TRUE if compare(value, e[2], e[3], e[1][0]) else FALSE
