"""Helpers for idea 132: the exact key-rule tests with TWO clue letters left out.

Idea 81 left out one of the 24 clue letters at a time. Here two are left out: one from
EASTNORTHEAST and one from BERLINCLOCK (13 x 11 = 143 pairs), or both from one block
(78 + 55 = 133 pairs, kept only where the test still has 9 or more checks).

How the search works. Every rule of the key-rule battery is written as a list of "items". An
item is a value computed from a few clue letters (a key value, a key difference, a key value
minus the fed letter) and a class; the rule holds when all items of a class have the same value
(or a fixed value, for chain addition). Leaving out a clue letter removes every item that uses
it. So for each rule we look for the sets D of at most two clue letters that hit every clash:
find the first two items of one class that disagree; one of their clue letters must be in D;
branch on it (at most two levels). This finds every D exactly, in a handful of scans per rule,
instead of re-running the battery 276 times.

Rules (as kryptos.round11.battery plus idea 104's two hole fixes):
  repeating p = 1..17, sliding p = 1..15, progressive p = 1..12 (key moved on in the cipher-strip
  order, and idea 104's hole: moved on in A-Z / KRYPTOS / M order, 26 index offsets),
  autokey lag 1..6 (plain and cipher feed, fed letter numbered on M, A-Z and KRYPTOS, both signs),
  chain addition (taps t, m <= 6), two stacked repeating keys (exact loop test of idea 104 on the
  22 letters kept, p < q <= QMAX, no pre-filter).

Checks of a rule on D are counted on the 22 letters kept: items kept minus classes kept
(minus 1 for the progressive step, minus 1 more for the index offset of the hole form).
Pairs of positions further apart than the rule's lag are not added when a letter between them
is dropped (sliding uses neighbouring letters only), so the tests are a little weaker than
they could be; the planted answers show they still find the message.
"""
from itertools import combinations

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET as KR
from .idea104_holes import Graph
from .round11 import B1, B2, POS, pmap, streams

N = 24
IB1, IB2 = list(range(13)), list(range(13, 24))
CROSS = [(a, b) for a in IB1 for b in IB2]
SAME1 = list(combinations(IB1, 2))
SAME2 = list(combinations(IB2, 2))
DROPS = CROSS + SAME1 + SAME2                    # 143 + 78 + 55 = 276
BAR_CROSS = 7
BAR_SAME = 9
QMAX = 26
INDEX = {p: i for i, p in enumerate(POS)}


def kind(D):
    a, b = D
    return "cross" if (a < 13) != (b < 13) else ("B1" if a < 13 else "B2")


def bar(D, bar_cross=BAR_CROSS):
    return bar_cross if kind(D) == "cross" else BAR_SAME


def cut(v, D):
    return [x for j, x in enumerate(v) if j not in D]


# ------------------------------------------------------------------ rule templates (positions only)

class Template:
    """One rule shape: items = [(clue indexes used, class)]; target: class value must be 0;
    extra: checks spent on free parameters beyond one value per class."""

    def __init__(self, name, items, target=False, extra=0, mult=1.0):
        self.name, self.items, self.target, self.extra, self.mult = name, items, target, extra, mult
        self.idx = [it[0] for it in items]
        self.cls = [it[1] for it in items]
        self.checks = {}
        for D in DROPS + [()] + [(j,) for j in range(N)]:
            self.checks[D] = self.count(D)
        self._live = {}
        per = {}
        for ix in self.idx:
            for j in set(ix):
                per[j] = per.get(j, 0) + 1
        self.limit = 2 * max(per.values())      # items two dropped letters can remove at most

    def live(self, bar_cross):
        if bar_cross not in self._live:
            self._live[bar_cross] = any(self.checks[D] >= bar(D, bar_cross) for D in DROPS)
        return self._live[bar_cross]

    def count(self, D):
        keep = [c for ix, c in self.items if not any(j in D for j in ix)]
        if self.target:
            return len(keep)
        return len(keep) - len(set(keep)) - self.extra


def _pairs(lag):
    return [(INDEX[i], INDEX[i + lag]) for i in POS if i + lag in INDEX]


def templates():
    out = {}
    for p in range(1, 18):
        out["repeating p=%d" % p] = Template("repeating p=%d" % p, [((j,), POS[j] % p) for j in range(N)])
    for p in range(1, 16):
        out["sliding p=%d" % p] = Template("sliding p=%d" % p, [((a, b), POS[a] % p) for a, b in _pairs(1)])
    for p in range(1, 13):
        out["progressive p=%d" % p] = Template("progressive p=%d" % p, [((j,), POS[j] % p) for j in range(N)], extra=1)
        out["progressive-h p=%d" % p] = Template("progressive-h p=%d" % p, [((j,), POS[j] % p) for j in range(N)],
                                                 extra=2)
    for L in range(1, 7):
        out["autokey lag=%d" % L] = Template("autokey lag=%d" % L, [((a, b), 0) for a, b in _pairs(L)])
    for m in range(2, 7):
        for t in range(1, m):
            items = [((a, INDEX[POS[b] - t], b), 0) for a, b in _pairs(m)]
            out["chain taps %d,%d" % (t, m)] = Template("chain taps %d,%d" % (t, m), items, target=True)
    return out


TPL = templates()


# ------------------------------------------------------------------ exact drop-set finder

def _conflict(vals, idx, cls, D, target):
    """First clash among the items that avoid D: the clue indexes that could remove it, or None."""
    first = {}
    for v, ix, c in zip(vals, idx, cls):
        if D and (D[0] in ix or D[-1] in ix):
            continue
        f = first.get(c)
        if f is None:
            if target and v:
                return ix
            first[c] = (v, ix)
        elif f[0] != v:
            return f[1] + ix
    return None


def minority_ok(vals, tpl):
    """Quick necessary test: the items off their class's most common value (off 0 for a target
    rule) must be few enough for two dropped letters to remove."""
    if tpl.target:
        n = 0
        for v in vals:
            if v:
                n += 1
                if n > tpl.limit:
                    return False
        return True
    cnt = {}
    for v, c in zip(vals, tpl.cls):
        cnt[c, v] = cnt.get((c, v), 0) + 1
    best = {}
    for (c, v), n in cnt.items():
        if n > best.get(c, 0):
            best[c] = n
    return len(vals) - sum(best.values()) <= tpl.limit


def drop_sets(vals, tpl):
    """Every minimal set D of <= 2 clue indexes such that the items avoiding D agree per class."""
    idx, cls, target = tpl.idx, tpl.cls, tpl.target
    if not minority_ok(vals, tpl):
        return []
    c0 = _conflict(vals, idx, cls, (), target)
    if c0 is None:
        return [()]
    out = set()
    for a in set(c0):
        c1 = _conflict(vals, idx, cls, (a,), target)
        if c1 is None:
            out.add((a,))
            continue
        for b in set(c1):
            if b == a:
                continue
            D = (min(a, b), max(a, b))
            if _conflict(vals, idx, cls, D, target) is None:
                out.add(D)
    singles = {d for d in out if len(d) == 1}
    return [d for d in out if len(d) == 1 or not (({(d[0],)} | {(d[1],)}) & singles)]


def bad_classes(vals, cls, limit=2):
    """Quick necessary test for one-letter items: at most `limit` classes may hold two values."""
    first, bad = {}, set()
    for v, c in zip(vals, cls):
        f = first.setdefault(c, v)
        if f != v and c not in bad:
            bad.add(c)
            if len(bad) > limit:
                return False
    return True


def expand(Dmin, tpl, bar_cross=BAR_CROSS, checks=None):
    """[(D, checks)] for the full drop pairs that contain Dmin and keep the bar."""
    out = []
    for D in DROPS:
        if all(j in D for j in Dmin):
            ck = (checks or tpl.checks)[D]
            if ck >= bar(D, bar_cross):
                out.append((D, ck))
    return out


# ------------------------------------------------------------------ the battery on one alphabet

ORDERS = {"AZ": AZ, "KR": KR}
QD = {p: [POS[j] // p for j in range(N)] for p in range(1, 13)}
# clue-index-disjoint same-class pairs per period whose quotient gap t is a unit mod 26: each gives
# the step as (o[b] - o[a]) / t. Two dropped letters touch at most two of them, so the true step is
# given by all but two.
DISJ = {}
for _p in range(1, 13):
    cand = []
    for _a in range(N):
        for _b in range(_a + 1, N):
            if POS[_a] % _p == POS[_b] % _p:
                _t = (POS[_b] - POS[_a]) // _p
                if _t % 2 and _t % 13:
                    cand.append((_t, _a, _b))
    chosen, used = [], set()
    for _t, _a, _b in sorted(cand):
        if _a not in used and _b not in used:
            chosen.append((_a, _b, pow(_t, -1, 26)))
            used |= {_a, _b}
    DISJ[_p] = chosen


# per period: clue indexes grouped by class (classes with most members first), for an early exit
PORD = {}
for _p in range(1, 13):
    _g = {}
    for _j in range(N):
        _g.setdefault(POS[_j] % _p, []).append(_j)
    PORD[_p] = [(_j, POS[_j] % _p, POS[_j] // _p) for _c in sorted(_g, key=lambda c: -len(_g[c])) for _j in _g[_c]]


def prog_ok(o, s, p):
    """Quick necessary test for progressive p, step s on values o: at most two classes clash."""
    first, bad = {}, 0
    for j, c, q in PORD[p]:
        v = (o[j] - s * q) % 26
        f = first.get(c)
        if f is None:
            first[c] = v
        elif f != v:
            first[c] = -1 - v if f >= 0 else f
            if f >= 0:
                bad += 1
                if bad > 2:
                    return False
    return True


def _steps(o, p):
    pairs = DISJ[p]
    if len(pairs) < 3:
        return range(1, 26)
    (a0, b0, i0), (a1, b1, i1), (a2, b2, i2) = pairs[:3]
    out = []
    for x in {(o[b0] - o[a0]) * i0 % 26, (o[b1] - o[a1]) * i1 % 26, (o[b2] - o[a2]) * i2 % 26}:
        if not x:
            continue
        miss = 0
        for a, b, inv in pairs:
            if (o[b] - o[a]) * inv % 26 != x:
                miss += 1
                if miss > 2:
                    break
        else:
            out.append(x)
    return out


def _faces(lay, m):
    a, b = lay.split("/")
    pick = {"M": m, "AZ": AZ, "KR": KR}
    return pick[a], pick[b]


def test_alphabet(name, m, pl, cl, bar_cross=BAR_CROSS, qmax=QMAX, parts=("battery", "hole", "stacked")):
    """[(checks, alphabet, layout, form, rule, D, minimal D, info)] for one keyword alphabet."""
    hits = []
    feeds = [("plain", "M", [m.index(c) for c in pl]), ("cipher", "M", [m.index(c) for c in cl])]
    if "hole" in parts or "akhole" in parts:
        feeds += [(f, on, [ORDERS[on].index(c) for c in letters]) for f, letters in (("plain", pl), ("cipher", cl))
                  for on in ORDERS]
    sfn = stacked_fn(bar_cross, qmax) if "stacked" in parts else None

    def add(tpl, vals, lay, form, rule, info):
        for Dmin in drop_sets(vals, tpl):
            for D, ck in expand(Dmin, tpl, bar_cross):
                hits.append((ck, name, lay, form, rule, D, Dmin, info))

    for lay, form, k, _, _ in streams(m, pl, cl):
        if "battery" in parts:
            for p in range(1, 18):
                t = TPL["repeating p=%d" % p]
                if t.live(bar_cross) and bad_classes(k, t.cls):
                    add(t, k, lay, form, t.name, ("rep", p))
            d1 = [(k[b] - k[a]) % 26 for a, b in _pairs(1)]
            for p in range(1, 16):
                t = TPL["sliding p=%d" % p]
                if t.live(bar_cross):
                    add(t, d1, lay, form, t.name, ("slide", p))
            for p in range(1, 13):
                t = TPL["progressive p=%d" % p]
                if not t.live(bar_cross):
                    continue
                for s in _steps(k, p):
                    if prog_ok(k, s, p):
                        vals = [(v - s * q) % 26 for v, q in zip(k, QD[p])]
                        add(t, vals, lay, form, "%s step=%d" % (t.name, s), ("prog", p, s, None, 0))
            for m_ in range(2, 7):
                for tt in range(1, m_):
                    t = TPL["chain taps %d,%d" % (tt, m_)]
                    if not t.live(bar_cross):
                        continue
                    vals = [(k[x] + k[a] - k[b]) % 26 for (a, x, b) in t.idx]
                    add(t, vals, lay, form, t.name, ("chain", tt, m_))
        for L in range(1, 7):
            t = TPL["autokey lag=%d" % L]
            if not t.live(bar_cross):
                continue
            for feed, on, x in (feeds if "battery" in parts else feeds[2:]):
                for sg in (1, -1):
                    vals = [(k[b] - sg * x[a]) % 26 for a, b in t.idx]
                    add(t, vals, lay, form, "autokey %s lag=%d sign=%+d fed on %s" % (feed, L, sg, on),
                        ("ak", feed, on, L, sg))
        if "hole" in parts or "proghole" in parts:
            cipher = _faces(lay, m)[1]
            for on, order in (("AZ", AZ), ("KR", KR), ("M", m)):
                if order == cipher or (on == "M" and m in (AZ, KR)):
                    continue
                io = {c: i for i, c in enumerate(order)}
                g2 = [io[c] for c in cipher] * 2
                for c in range(26):
                    o = [g2[v + c] for v in k]
                    for p in range(1, 13):
                        t = TPL["progressive-h p=%d" % p]
                        if not t.live(bar_cross):
                            continue
                        for s in _steps(o, p):
                            if prog_ok(o, s, p):
                                vals = [(v - s * q) % 26 for v, q in zip(o, QD[p])]
                                add(t, vals, lay, form, "progressive p=%d step=%d moved on in %s order, offset %d" % (
                                    p, s, on, c), ("prog", p, s, on, c))
        if sfn is not None:
            for D, p, q, ck in sfn(k):
                hits.append((ck, name, lay, form, "two stacked keys p=%d q=%d" % (p, q), D, D, ("st", p, q)))
    return hits


# ------------------------------------------------------------------ two stacked keys, exact, per drop pair

_SFN = {}


def stacked_listing(bar_cross=BAR_CROSS, qmax=QMAX):
    out = []
    for D in DROPS:
        pos = cut(POS, D)
        idx = cut(list(range(N)), D)
        for p in range(2, qmax):
            for q in range(p + 1, qmax + 1):
                if q % p == 0:
                    continue
                g = Graph(pos, p, q)
                if g.n_checks >= bar(D, bar_cross):
                    chk = [(tuple(idx[j] for j in a), tuple(idx[j] for j in b)) for a, b in g.checks]
                    out.append((D, p, q, g.n_checks, chk))
    return out


def _fin(k, entries, out):
    for rest, D, p, q, ck in entries:
        for plus, minus in rest:
            if (sum(k[j] for j in plus) - sum(k[j] for j in minus)) % 26:
                break
        else:
            out.append((D, p, q, ck))


def stacked_fn(bar_cross=BAR_CROSS, qmax=QMAX):
    key = (bar_cross, qmax)
    if key not in _SFN:
        groups = {}
        for D, p, q, ck, chk in stacked_listing(bar_cross, qmax):
            plus, minus = chk[0]
            if min(minus) < min(plus):
                plus, minus = minus, plus
            groups.setdefault((plus, minus), []).append((chk[1:], D, p, q, ck))
        table, src = [], ["def f(k):", "    out = []"]
        for (plus, minus), entries in sorted(groups.items()):
            expr = "+".join("k[%d]" % j for j in plus) + "".join("-k[%d]" % j for j in minus)
            src.append("    if not (%s) %% 26: fin(k, T[%d], out)" % (expr, len(table)))
            table.append(entries)
        src.append("    return out")
        env = {"fin": _fin, "T": table}
        exec("\n".join(src), env)
        _SFN[key] = env["f"]
    return _SFN[key]


# ------------------------------------------------------------------ sizes and chance

def chance(bar_cross=BAR_CROSS, qmax=QMAX, parts=("battery", "hole", "stacked")):
    """{rule family: (tests per key stream, chance passes per key stream)} over all 276 drop pairs."""
    fam = {}
    bat = "battery" in parts
    akh = "hole" in parts or "akhole" in parts
    pgh = "hole" in parts or "proghole" in parts

    def put(f, n, e):
        a, b = fam.get(f, (0, 0.0))
        fam[f] = (a + n, b + e)

    for name, t in TPL.items():
        for D in DROPS:
            ck = t.checks[D]
            ok = ck >= bar(D, bar_cross)
            if name.split()[0] in ("repeating", "sliding", "chain"):
                if bat:
                    put(name.split()[0], int(ok), 26.0 ** -ck if ok else 0)
            elif name.startswith("progressive-h"):
                if pgh:
                    put("progressive (hole)", 2 * 26 * 25 * ok, 2 * 26 * 25 * 26.0 ** -(ck + 2) if ok else 0)
            elif name.startswith("progressive"):
                if bat:
                    put("progressive", 25 * ok, 25 * 26.0 ** -(ck + 1) if ok else 0)
            elif name.startswith("autokey"):
                n = 4 * bat + 8 * akh
                put("autokey", n * ok, n * 26.0 ** -ck if ok else 0)
    if "stacked" in parts:
        for D, p, q, ck, _ in stacked_listing(bar_cross, qmax):
            put("stacked", 1, 26.0 ** -ck)
    return fam


# ------------------------------------------------------------------ search

_S = {}


def init(ct, cribs, bar_cross=BAR_CROSS, qmax=QMAX, parts=("battery", "hole", "stacked")):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]
    _S["a"] = (bar_cross, qmax, tuple(parts))
    if "stacked" in parts:
        stacked_fn(bar_cross, qmax)


def work(chunk):
    hits = []
    bc, qm, parts = _S["a"]
    for name, m in chunk:
        hits += test_alphabet(name, m, _S["p"], _S["c"], bc, qm, parts)
    return hits


def search(ct, cribs, alphas, bar_cross=BAR_CROSS, qmax=QMAX, parts=("battery", "hole", "stacked"), chunk=200):
    hits = []
    for h in pmap(work, alphas, init, (ct, cribs, bar_cross, qmax, tuple(parts)), chunk=chunk):
        hits += h
    return hits


# ------------------------------------------------------------------ reading a survivor

def read(hit, m, ct, cribs):
    """97 letters under the hit's setting with the two dropped clue letters re-read by the rule;
    '?' where the kept clue letters do not fix the key."""
    _, _, lay, form, _, D, _, info = hit
    plain, cipher = _faces(lay, m)
    ia = {c: i for i, c in enumerate(plain)}
    ib = {c: i for i, c in enumerate(cipher)}
    beau = form == "beau"
    keep = [POS[j] for j in range(N) if j not in D]

    def kval(i):
        x, y = ia[cribs[i]], ib[ct[i]]
        return (y + x) % 26 if beau else (y - x) % 26

    def plain_of(i, k):
        y = ib[ct[i]]
        return plain[(k - y) % 26 if beau else (y - k) % 26]

    key = {i: kval(i) for i in keep}
    kind_ = info[0]
    n = len(ct)
    if kind_ == "rep":
        p = info[1]
        cls = {i % p: v for i, v in key.items()}
        key = {i: cls[i % p] for i in range(n) if i % p in cls}
    elif kind_ == "prog":
        _, p, s, on, c = info
        if on is None:
            cls = {i % p: (v - s * (i // p)) % 26 for i, v in key.items()}
            key = {i: (cls[i % p] + s * (i // p)) % 26 for i in range(n) if i % p in cls}
        else:
            order = {"AZ": AZ, "KR": KR, "M": m}[on]
            io = {ch: t for t, ch in enumerate(order)}
            g2 = [io[ch] for ch in cipher]
            inv = {v: t for t, v in enumerate(g2)}
            cls = {i % p: (g2[(v + c) % 26] - s * (i // p)) % 26 for i, v in key.items()}
            key = {i: (inv[(cls[i % p] + s * (i // p)) % 26] - c) % 26 for i in range(n) if i % p in cls}
    elif kind_ == "slide":
        p = info[1]
        w = {}
        for i in keep:
            if i + 1 in key:
                w[i % p] = (key[i + 1] - key[i]) % 26
        if len(w) == p:
            start = keep[0]
            k0 = key[start]
            full = {start: k0}
            for i in range(start + 1, n):
                full[i] = (full[i - 1] + w[(i - 1) % p]) % 26
            for i in range(start - 1, -1, -1):
                full[i] = (full[i + 1] - w[i % p]) % 26
            key = full
    elif kind_ == "chain":
        _, t, mm = info
        changed = True
        while changed:
            changed = False
            for i in range(n):
                if i not in key and i - t in key and i - mm in key:
                    key[i] = (key[i - t] + key[i - mm]) % 26
                    changed = True
                elif i not in key and i + mm < n and i + mm in key and i + mm - t in key:
                    key[i] = (key[i + mm] - key[i + mm - t]) % 26
                    changed = True
    elif kind_ == "ak":
        _, feed, on, L, sg = info
        order = {"AZ": AZ, "KR": KR, "M": m}[on]
        num = {ch: t for t, ch in enumerate(order)}
        a, b = next((i, i + L) for i in keep if i + L in key)
        src = cribs if feed == "plain" else ct
        c0 = (key[b] - sg * num[src[a]]) % 26
        if feed == "cipher":
            key = {i: (sg * num[ct[i - L]] + c0) % 26 for i in range(L, n)}
        else:
            out = ["?"] * n
            for i in keep:
                out[i] = cribs[i]
            todo = list(keep)
            while todo:
                i = todo.pop()
                if i + L < n and out[i + L] == "?":
                    out[i + L] = plain_of(i + L, (sg * num[out[i]] + c0) % 26)
                    todo.append(i + L)
                if i - L >= 0 and out[i - L] == "?":
                    x, y = ia[out[i]], ib[ct[i]]
                    k = (y + x) % 26 if beau else (y - x) % 26
                    out[i - L] = order[(sg * (k - c0)) % 26]
                    todo.append(i - L)
            return "".join(out)
    elif kind_ == "st":
        _, p, q = info
        g = Graph(keep, p, q)
        at = g.key_at([key[i] for i in keep])
        key = {i: at(i) for i in range(n) if at(i) is not None}
    out = []
    for i in range(n):
        if i in key:
            out.append(plain_of(i, key[i]))
        else:
            out.append("?")
    for i in keep:
        assert out[i] == cribs[i], (hit, i)
    return "".join(out)


# ------------------------------------------------------------------ multiplier word + adder word (71A)

def pairs_search(ct, cribs, pmax=17, bar_cross=BAR_CROSS):
    """(systems tried, [(checks, view, rule, D)]) for C = A[i%p]*P + B[i%q], two clue letters dropped."""
    from .idea81_dropone import pair_fit, views
    hits, n = [], 0
    for vn, pv, cv in views(ct, cribs):
        for D in DROPS:
            pos, pj, cj = cut(POS, D), cut(pv, D), cut(cv, D)
            b = bar(D, bar_cross)
            for p in range(1, pmax + 1):
                for q in range(1, pmax + 1):
                    if len(pos) - p - q < b:          # cannot reach the bar
                        continue
                    n += 1
                    ck = pair_fit(p, q, pos, pj, cj)
                    if ck >= b:
                        hits.append((ck, vn, "multiplier word %d + adder word %d" % (p, q), D))
    return n, hits


def _pairs_work(chunk):
    from .idea81_dropone import pair_fit
    out = []
    for vn, pv, cv, D, b, pmax in chunk:
        pos, pj, cj = cut(POS, D), cut(pv, D), cut(cv, D)
        for p in range(1, pmax + 1):
            for q in range(1, pmax + 1):
                if len(pos) - p - q < b:
                    continue
                ck = pair_fit(p, q, pos, pj, cj)
                if ck >= b:
                    out.append((ck, vn, "multiplier word %d + adder word %d" % (p, q), D))
    return out


def _noop(*a):
    pass


def pairs_search_par(ct, cribs, pmax=17, bar_cross=BAR_CROSS):
    from .idea81_dropone import views
    jobs = [(vn, pv, cv, D, bar(D, bar_cross), pmax) for vn, pv, cv in views(ct, cribs) for D in DROPS]
    n = sum(1 for _, _, _, D, b, pm in jobs for p in range(1, pm + 1) for q in range(1, pm + 1) if 22 - p - q >= b)
    hits = []
    for h in pmap(_pairs_work, jobs, _noop, (), chunk=8):
        hits += h
    return n, hits


# ------------------------------------------------------------------ word-turned rotor (72), two wires dropped

ROTOR_MIN = 5


def _first_clash(pv, cv, s, sign, D):
    f, g = {}, {}
    for j, (x, y, t) in enumerate(zip(pv, cv, s)):
        if j in D:
            continue
        u, v = (x + t) % 26, (y + sign * t) % 26
        a, b = f.setdefault(u, (v, j)), g.setdefault(v, (u, j))
        if a[0] != v or b[0] != u:
            c = {j}
            if a[0] != v:
                c.add(a[1])
            if b[0] != u:
                c.add(b[1])
            return c, None
    return None, len(pv) - len(D) - len(f)


def wires_drop_two(pv, cv, s, sign, min_checks=ROTOR_MIN):
    """[(coincidences, D)] for every drop pair D (of DROPS) whose removal leaves a real wiring with
    at least min_checks forced coincidences, where the wiring needs exactly two letters dropped.
    (Fits with 0 or 1 letters dropped were idea 81's test and are reported as such, D of size < 2.)"""
    c0, ck = _first_clash(pv, cv, s, sign, ())
    if c0 is None:
        return [(ck, ())] if ck >= min_checks else []
    out = []
    for a in c0:
        c1, ck = _first_clash(pv, cv, s, sign, (a,))
        if c1 is None:
            if ck >= min_checks:
                out.append((ck, (a,)))
            continue
        for b in c1:
            D = (min(a, b), max(a, b))
            c2, ck = _first_clash(pv, cv, s, sign, D)
            if c2 is None and ck >= min_checks:
                out.append((ck, D))
    return sorted(set(out))


def rotor_word(w, vws, min_checks=ROTOR_MIN):
    from .idea81_dropone import ALPH, word_schemes
    hits = []
    for nn, num in ALPH.items():
        for sn, s in word_schemes(w, num):
            for vn, pv, cv in vws:
                for sign in (1, -1):
                    for ck, D in wires_drop_two(pv, cv, s, sign, min_checks):
                        hits.append((ck, vn, "%s %s (%s numbering), out %+d" % (sn, w, nn, sign), D))
    return hits


def _rotor_init(ct, cribs):
    from .idea81_dropone import views
    _S["v"] = views(ct, cribs)


def _rotor_work(chunk):
    hits = []
    for w in chunk:
        hits += rotor_word(w, _S["v"])
    return hits


def rotor_search(ct, cribs, words, chunk=3000):
    hits = []
    for h in pmap(_rotor_work, words, _rotor_init, (ct, cribs), chunk=chunk):
        hits += h
    return hits


def corrections(text, cribs, D):
    """The two clue words as the rule reads them, and the changed letters."""
    w1 = "".join(text[i] for i in B1)
    w2 = "".join(text[i] for i in B2)
    ch = ["%d:%s->%s" % (POS[j], cribs[POS[j]], text[POS[j]]) for j in D]
    return w1, w2, ch
