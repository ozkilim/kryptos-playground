"""Idea 104: close the two holes the idea-91 audit found in the key-rule battery.

Hole (a): two stacked repeating keys, K[i] = A[i mod p] + B[i mod q]. Attack 66 and
kryptos.round11.battery drop a length pair when two partial counts add up to less than 8, before
the exact solve is ever run. Here the exact test is run with no pre-filter.

The exact test, and why it is exact for any modulus. Make a graph with one node for each key
letter (p nodes for the first word, q for the second) and one edge for each clue letter, joining
the two key letters that are added at that position. The key values fit two stacked words exactly
when, around every closed loop of the graph, the key values taken with alternating signs add up
to zero. The loops left over by a spanning tree are independent, and their number is
(clue letters) - (nodes touched) + (connected pieces): that is the true number of checks. The
graph has two sides, so its matrix is totally unimodular and the loop test is the same as solving
the linear system mod 13 and mod 2 (attack 66's _stacked_exact; compared in tests/test_idea_104.py)
and also right mod 27..31, where round11.battery only had a necessary test.

Hole (b): autokey where the fed letter is numbered on A-Z or KRYPTOS instead of on the keyword
alphabet M, and a progressive key that is moved on in A-Z, KRYPTOS or M order while being looked
up on a different strip.

A hit is (checks, alphabet name, layout, form, rule, variant, info); info is what `read` needs to
decrypt it.
"""
import os

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET as KR
from .round11 import B1, B2, POS, _runs, pmap, streams
from . import idea88_slip as i88

SMOKE = os.environ.get("KRYPTOS_SMOKE")
MIN_CHECKS = 7
GAPS = (-3, -2, -1, 1, 2, 3)
MODS = (27, 28, 29, 30, 31)
MULTS = (3, 5, 7, 9, 11, 15, 17, 19, 21, 23)
QMAX_OLD = 13            # the stated scope of the old stacked test: p < q <= 13
QMAX_BASE = 50           # the plain 24-letter test also takes every longer second word with 7+ checks
PARTS = ("base", "gap", "mod", "mult", "drop", "breaks", "autokey", "progressive")
INBLOCK = set(POS)
MIN_NEW = 8              # a reading needs this many quadgrams that are not wholly inside the clues


# ------------------------------------------------------------------ the graph of one length pair

class Graph:
    """Two stacked keys of lengths p and q on clue letters at key positions `pos`.

    checks: the independent loop tests, [(plus, minus)] as indexes into pos, shortest first.
    n_checks = len(checks) is the true number of exact checks."""

    def __init__(self, pos, p, q):
        self.pos, self.p, self.q = list(pos), p, q
        adj = {}
        for j, i in enumerate(pos):
            u, v = (0, i % p), (1, i % q)
            adj.setdefault(u, []).append((j, v))
            adj.setdefault(v, []).append((j, u))
        # x[u] = A[u] for first-word nodes, x[v] = -B[v] for second-word nodes, so K[j] = x[u] - x[v].
        # coef[node] writes x[node] - x[root of its piece] as a signed sum of key values.
        coef, piece, used, checks = {}, {}, set(), []
        for root in sorted(adj):
            if root in coef:
                continue
            coef[root], piece[root] = {}, root
            queue = [root]
            for node in queue:
                for j, other in adj[node]:
                    if j in used:
                        continue
                    used.add(j)
                    u, v = (node, other) if node[0] == 0 else (other, node)
                    if other not in coef:
                        c = dict(coef[node])
                        c[j] = c.get(j, 0) + (-1 if node[0] == 0 else 1)
                        coef[other], piece[other] = c, root
                        queue.append(other)
                    else:                                  # a loop: K[j] - (x[u] - x[v]) = 0
                        vec = {j: 1}
                        for t, s in coef[u].items():
                            vec[t] = vec.get(t, 0) - s
                        for t, s in coef[v].items():
                            vec[t] = vec.get(t, 0) + s
                        vec = {t: s for t, s in vec.items() if s}
                        assert all(s in (1, -1) for s in vec.values())
                        checks.append((tuple(sorted(t for t, s in vec.items() if s == 1)),
                                       tuple(sorted(t for t, s in vec.items() if s == -1))))
        self.coef, self.piece = coef, piece
        self.checks = sorted(checks, key=lambda c: (len(c[0]) + len(c[1]), max(c[0] + c[1]), c))
        self.n_checks = len(checks)

    def fits(self, k, n=26):
        for plus, minus in self.checks:
            if (sum(k[j] for j in plus) - sum(k[j] for j in minus)) % n:
                return False
        return True

    def key_at(self, k, n=26):
        """t -> key value at key position t, or None where the clue letters do not fix it."""
        x = {node: sum(s * k[j] for j, s in c.items()) % n for node, c in self.coef.items()}
        p, q, piece = self.p, self.q, self.piece

        def at(t):
            u, v = (0, t % p), (1, t % q)
            if u in x and v in x and piece[u] == piece[v]:
                return (x[u] - x[v]) % n
            return None
        return at


def old_tested(pos, p, q, min_checks=MIN_CHECKS):
    """Did the pre-filter of attack 66 / round11.battery let this length pair through to its exact
    solve? It adds two partial counts that depend on the positions only."""
    if not (2 <= p <= 12 and p < q <= QMAX_OLD and q % p):
        return False
    runs = _runs(pos)

    def count(lag, m):
        pairs = [j for a, b in runs for j in range(a, b - lag)]
        return len(pairs) - len({pos[j] % m for j in pairs})
    return count(p, q) + count(q, p) >= min_checks + 1


_PAIRS = {}


def pairs(pos, qmax=QMAX_OLD, min_checks=MIN_CHECKS):
    """[(p, q, Graph, tested before)] for every length pair p < q <= qmax (q not a multiple of p)
    with at least min_checks exact checks on these positions."""
    key = (tuple(pos), qmax, min_checks)
    if key not in _PAIRS:
        out = []
        for p in range(2, qmax):
            for q in range(p + 1, qmax + 1):
                if q % p == 0:
                    continue
                g = Graph(pos, p, q)
                if g.n_checks >= min_checks:
                    out.append((p, q, g, old_tested(pos, p, q, min_checks)))
        _PAIRS[key] = out
    return _PAIRS[key]


# ------------------------------------------------------------------ position sets of the variants

SETS = {}        # label -> (indexes into the 24 clue letters, their key positions)


def _sets(part):
    """[(label, idx, pos)] for one family of position sets."""
    if part in ("base", "mod", "mult"):
        out = [("base", list(range(24)), list(POS))]
    elif part == "gap":
        out = [("clue 1 alone", list(range(13)), list(B1)), ("clue 2 alone", list(range(13, 24)), list(B2))]
        out += [("gap %+d" % g, list(range(24)), B1 + [i + g for i in B2]) for g in GAPS]
    elif part == "drop":
        out = [("drop %d" % POS[j], [t for t in range(24) if t != j], POS[:j] + POS[j + 1:]) for j in range(24)]
    else:   # word breaks counted: idea 88's position sets
        out = [("breaks %s x=%d" % (i88.label(p1, p2), x), list(range(24)), i88.positions(p1, p2, x))
               for p1 in range(3) for p2 in range(2) for x in i88.OFFSETS]
    for label, idx, pos in out:
        SETS[label] = (idx, pos)
    return out


def _finish(k, entries, n, out):
    for rest, ck, label, p, q in entries:
        for plus, minus in rest:
            if (sum(k[j] for j in plus) - sum(k[j] for j in minus)) % n:
                break
        else:
            out.append((ck, label, p, q))


_FN = {}


def stacked_fn(part, n=26, only_new=True):
    """(f, tests per key stream, chance passes per key stream, [(label, p, q, checks, tested before)]).

    f(k) -> [(checks, set label, p, q)]: every length pair of this family's position sets that the
    24 key values k fit exactly. Built as straight-line code: the shortest loop of each pair is
    tested inline, the others only if it holds."""
    key = (part, n, only_new)
    if key in _FN:
        return _FN[key]
    groups, listing, chance = {}, [], 0.0
    qmax = QMAX_BASE if part == "base" else QMAX_OLD
    for label, idx, pos in _sets(part):
        for p, q, g, old in pairs(pos, qmax):
            if old and only_new:
                continue
            listing.append((label, p, q, g.n_checks, old))
            chance += float(n) ** -g.n_checks
            chk = [(tuple(idx[j] for j in plus), tuple(idx[j] for j in minus)) for plus, minus in g.checks]
            plus, minus = chk[0]
            if min(minus) < min(plus):
                plus, minus = minus, plus
            groups.setdefault((plus, minus), []).append((chk[1:], g.n_checks, label, p, q))
    table = []
    src = ["def f(k):", "    out = []"]
    for (plus, minus), entries in sorted(groups.items()):
        expr = "+".join("k[%d]" % j for j in plus) + "".join("-k[%d]" % j for j in minus)
        src.append("    if not (%s) %% %d: fin(k, T[%d], %d, out)" % (expr, n, len(table), n))
        table.append(entries)
    src.append("    return out")
    env = {"fin": _finish, "T": table}
    exec("\n".join(src), env)
    _FN[key] = (env["f"], len(listing), chance, listing)
    return _FN[key]


# ------------------------------------------------------------------ hole (b): autokey and progressive

LAGS = {L: [(a, a + L) for a in range(13 - L)] + [(a, a + L) for a in range(13, 24 - L)] for L in range(1, 7)}
ORDERS = {"AZ": AZ, "KR": KR}
RES = {p: [i % p for i in POS] for p in range(1, 13)}
DIV = {p: [i // p for i in POS] for p in range(1, 13)}


def autokey_hits(k, feeds):
    """[(checks, feed, numbering, lag, sign)]: key = sign * (number of the letter `lag` places back)
    + constant, inside each clue. feeds: [(feed, numbering, the 24 letter numbers)]."""
    out = []
    for feed, num, x in feeds:
        for L in range(1, 7):
            pairs_ = LAGS[L]
            (a0, b0), (a1, b1) = pairs_[0], pairs_[1]
            d, e = k[b0] - k[b1], x[a0] - x[a1]
            for sg in (1, -1):
                if (d - sg * e) % 26:
                    continue
                c0 = (k[b0] - sg * x[a0]) % 26
                for a, b in pairs_:
                    if (k[b] - sg * x[a]) % 26 != c0:
                        break
                else:
                    out.append((len(pairs_) - 1, feed, num, L, sg))
    return out


def autokey_tests():
    """(tests per key stream, chance passes per key stream)."""
    n = sum(2 * 2 * 2 for L in LAGS)
    return n, sum(8 * 26.0 ** -(len(LAGS[L]) - 1) for L in LAGS)


def _progressive_ok(o, p):
    s = (o[p] - o[0]) % 26
    if not s:
        return 0
    seen = {}
    for v, r, d in zip(o, RES[p], DIV[p]):
        base = (v - s * d) % 26
        if seen.setdefault(r, base) != base:
            return 0
    return s


def progressive_hits(k, g2):
    """[(checks, index offset, p, step)]: the key letter is looked up on the cipher strip, but the
    key word is moved on `step` letters per cycle along ANOTHER alphabet. g2[v] = number in that
    other alphabet of the letter at place v of the cipher strip (table written out twice).
    The offset of the index letter is not known, so all 26 are tried: one check is spent on it."""
    out = []
    for c in range(26):
        o = [g2[v + c] for v in k]
        e = (o[0] - o[1]) % 26
        dd = [(o[j] - o[j + 1]) % 26 for j in range(1, 12)]
        if e in dd:
            for p in range(1, 12):
                if dd[p - 1] == e:
                    s = _progressive_ok(o, p)
                    if s:
                        out.append((22 - p, c, p, s))
        if not (o[19] - o[0] - 4 * (o[12] - o[0])) % 26:      # p = 12: letters 21, 33 and 69
            s = _progressive_ok(o, 12)
            if s:
                out.append((10, c, 12, s))
    return out


def progressive_tests():
    """(tests per key stream, chance passes per key stream): 2 orders x 26 offsets x p = 1..12."""
    return 2 * 26 * 12, sum(2 * 26 * 25 * 26.0 ** -(23 - p) for p in range(1, 13))


# ------------------------------------------------------------------ one alphabet, all parts

def _faces(lay, m):
    a, b = lay.split("/")
    pick = {"M": m, "AZ": AZ, "KR": KR}
    return pick[a], pick[b]


def test_alphabet(name, m, pl, cl, parts=PARTS, feeds=None):
    hits = []
    st = list(streams(m, pl, cl))
    for part in ("base", "gap", "drop", "breaks"):
        if part not in parts:
            continue
        f = stacked_fn(part, 26, part != "base")[0]
        for lay, form, k, _, _ in st:
            for ck, label, p, q in f(k):
                hits.append((ck, name, lay, form, "two stacked keys p=%d q=%d" % (p, q), label, ("st", 26, 1, label, p, q)))
    if "mod" in parts:
        for n in MODS:
            f = stacked_fn("mod", n)[0]
            for lay, form, k, _, _ in streams(m, pl, cl, n):
                for ck, label, p, q in f(k):
                    hits.append((ck, name, lay, form, "two stacked keys p=%d q=%d" % (p, q), "mod %d" % n,
                                 ("st", n, 1, label, p, q)))
    if "mult" in parts:
        f = stacked_fn("mult", 26)[0]
        iz = {c: i for i, c in enumerate(AZ)}
        ik = {c: i for i, c in enumerate(KR)}
        im = {c: i for i, c in enumerate(m)}
        for lay, ia, ib in (("M/M", im, im), ("M/AZ", im, iz), ("AZ/M", iz, im), ("M/KR", im, ik), ("KR/M", ik, im)):
            a, b = [ia[c] for c in pl], [ib[c] for c in cl]
            for mu in MULTS:
                k = [(y - mu * x) % 26 for x, y in zip(a, b)]
                for ck, label, p, q in f(k):
                    hits.append((ck, name, lay, "x%d" % mu, "two stacked keys p=%d q=%d" % (p, q), "multiplier %d" % mu,
                                 ("st", 26, mu, label, p, q)))
    if "autokey" in parts:
        feeds = feeds or make_feeds(pl, cl)
        for lay, form, k, _, _ in st:
            for ck, feed, num, L, sg in autokey_hits(k, feeds):
                hits.append((ck, name, lay, form, "autokey %s lag=%d sign=%+d" % (feed, L, sg),
                             "fed letter numbered on %s" % num, ("ak", feed, num, L, sg)))
    if "progressive" in parts:
        tabs = {}
        for lay, form, k, _, _ in st:
            cipher = _faces(lay, m)[1]
            for on, order in (("AZ", AZ), ("KR", KR), ("M", m)):
                if order == cipher or (on == "M" and m in (AZ, KR)):
                    continue
                g2 = tabs.get((on, cipher))
                if g2 is None:
                    io = {c: i for i, c in enumerate(order)}
                    g2 = tabs[on, cipher] = [io[c] for c in cipher] * 2
                for ck, c, p, s in progressive_hits(k, g2):
                    hits.append((ck, name, lay, form, "progressive p=%d step=%d" % (p, s),
                                 "key moved on in %s order" % on, ("pg", on, c, p, s)))
    return hits


def make_feeds(pl, cl):
    return [(feed, on, [order.index(c) for c in letters])
            for feed, letters in (("plain", pl), ("cipher", cl)) for on, order in ORDERS.items()]


_S = {}


def init(ct, cribs, parts=PARTS):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]
    _S["parts"] = tuple(parts)
    _S["feeds"] = make_feeds(_S["p"], _S["c"])


def work(chunk):
    hits = []
    for name, m in chunk:
        hits += test_alphabet(name, m, _S["p"], _S["c"], _S["parts"], _S["feeds"])
    return hits


def search(ct, cribs, alphas, parts=PARTS, chunk=600):
    hits = []
    for h in pmap(work, alphas, init, (ct, cribs, tuple(parts)), chunk=chunk):
        hits += h
    return hits


def sizes():
    """{part: (exact tests per alphabet, chance passes with 7+ checks per alphabet)}."""
    out = {}
    for part, streams_, kw in (("base", 10, {"only_new": False}), ("gap", 10, {}), ("drop", 10, {}), ("breaks", 10, {}),
                               ("mult", 50, {})):
        _, n, ch, _ = stacked_fn(part, 26, **kw)
        out[part] = (streams_ * n, streams_ * ch)
    n = ch = 0
    for md in MODS:
        _, a, b, _ = stacked_fn("mod", md)
        n, ch = n + 10 * a, ch + 10 * b
    out["mod"] = (n, ch)
    a, b = autokey_tests()
    out["autokey"] = (10 * a, 10 * b)
    a, b = progressive_tests()
    out["progressive"] = (10 * a, 10 * b)
    return out


# ------------------------------------------------------------------ reading a survivor

def read(hit, m, ct, cribs):
    """All 97 letters under the hit's setting, '?' where the clue letters do not fix the key (or the
    key position of the letter is not known: gap slack between the clues, word breaks outside them)."""
    lay, form, info = hit[2], hit[3], hit[6]
    plain, cipher = _faces(lay, m)
    ia = {c: i for i, c in enumerate(plain)}
    ib = {c: i for i, c in enumerate(cipher)}
    kind = info[0]
    n, mu = (info[1], info[2]) if kind == "st" else (26, 1)
    beau = form == "beau"

    def kval(i):                                   # key value the known letters force at clue position i
        x, y = ia[cribs[i]], ib[ct[i]]
        return (y + x) % n if beau else (y - mu * x) % n

    def plain_of(i, k):
        if ct[i] not in ib:
            return "?"
        y = ib[ct[i]]
        x = (k - y) % n if beau else ((y - k) * pow(mu, -1, n) if mu != 1 else (y - k)) % n
        return plain[x] if x < 26 else "?"

    out = ["?"] * len(ct)
    for i in cribs:
        out[i] = cribs[i]
    if kind == "st":
        label, p, q = info[3:]
        idx, pos = SETS.get(label) or [s for part in ("base", "gap", "drop", "breaks") for s in _sets(part)
                                       if s[0] == label][0][1:]
        g = Graph(pos, p, q)
        at = g.key_at([kval(POS[j]) for j in idx], n)
        if label.startswith("breaks"):
            return "".join(out)                    # key positions outside the clues are not known
        shift = int(label.split()[1]) if label.startswith("gap") else 0
        for i in range(len(ct)):
            if i in cribs or (shift and 33 < i < 63) or label.startswith("clue"):
                continue
            k = at(i + (shift if i >= 63 else 0))
            if k is not None:
                out[i] = plain_of(i, k)
    elif kind == "ak":
        _, feed, on, L, sg = info
        num = {c: i for i, c in enumerate(ORDERS[on])}
        b0 = POS[L]
        c0 = (kval(b0) - sg * num[(cribs if feed == "plain" else ct)[b0 - L]]) % 26
        if feed == "cipher":
            for i in range(L, len(ct)):
                out[i] = plain_of(i, (sg * num[ct[i - L]] + c0) % 26)
        else:
            todo = sorted(cribs)
            while todo:
                i = todo.pop()
                if i + L < len(ct) and out[i + L] == "?":          # forwards: this letter keys letter i + L
                    out[i + L] = plain_of(i + L, (sg * num[out[i]] + c0) % 26)
                    todo.append(i + L)
                if i - L >= 0 and out[i - L] == "?":               # backwards: letter i - L keyed this one
                    x, y = ia[out[i]], ib[ct[i]]
                    k = (y + x) % 26 if beau else (y - x) % 26
                    out[i - L] = ORDERS[on][(sg * (k - c0)) % 26]
                    todo.append(i - L)
    else:
        _, on, c, p, s = info
        order = {"AZ": AZ, "KR": KR, "M": m}[on]
        io = {ch: i for i, ch in enumerate(order)}
        base = {}
        for i in sorted(cribs):
            base[i % p] = (io[cipher[(kval(i) + c) % 26]] - s * (i // p)) % 26
        for i in range(len(ct)):
            if i not in cribs and i % p in base:
                letter = order[(base[i % p] + s * (i // p)) % 26]
                out[i] = plain_of(i, (ib[letter] - c) % 26)
    assert all(out[i] == cribs[i] for i in cribs)
    return "".join(out)


def read_score(pt, big):
    """(big-model score per quadgram, quadgrams) over the fully known quadgrams that are not wholly
    inside the clue words; -99 if fewer than MIN_NEW of them."""
    q = [pt[i:i + 4] for i in range(len(pt) - 3)
         if "?" not in pt[i:i + 4] and not all(j in INBLOCK for j in range(i, i + 4))]
    return (sum(big.logp.get(x, big.floor) for x in q) / len(q) if len(q) >= MIN_NEW else -99.0), len(q)


# ------------------------------------------------------------------ the idea-91 audit, pointed at this test

class Adapter:
    """Stands in for attack 66 inside kryptos.idea91_audit: the audit's textbook messages are given to
    this idea's tests (and, with_old, to attack 66's own battery as well, which covers what was never
    in doubt: repeating, sliding, and the rules numbered on M)."""

    def __init__(self, old=None, parts=("base", "autokey", "progressive")):
        self.old, self.parts = old, parts

    def init(self, ct, cribs):
        init(ct, cribs, self.parts)
        if self.old:
            self.old.init(ct, cribs)

    def work(self, chunk):
        hits = [h[:5] for h in work(chunk)]
        if self.old:
            hits += self.old.work(chunk)[1]
        return len(chunk), hits

    def _stacked_exact(self, k, p, q):
        g = Graph(POS, p, q)
        return g.n_checks if g.fits(k) else -1


def audit_stacked_map(seed=104):
    """idea 91's map of two stacked keys (every pair p < q <= 13, two textbook messages each), judged by
    this idea's test alone. Returns [(p, q, exact checks, found of 2, ...)]."""
    import random
    from . import idea91_audit as audit
    keep = audit._MODS.get("66")
    audit._MODS["66"] = Adapter(parts=("base",))
    try:
        return audit.Audit(random.Random(seed)).stacked_map()
    finally:
        if keep is None:
            del audit._MODS["66"]
        else:
            audit._MODS["66"] = keep


def audit_cells(n=6, seed=104, pick=None):
    """The idea-91 cells for attack 66 (73 models: 5 layouts x repeating, sliding, progressive, autokey,
    stacked, plus the key-letter-on-the-plain-strip and A-Z-label forms), `n` textbook messages each,
    judged by attack 66 together with this idea's tests. Returns the audit's records."""
    import random
    from . import idea91_audit as audit
    keep = audit._MODS.pop("66", None)
    real = audit.attack("66")
    audit._MODS["66"] = Adapter(old=real)
    try:
        cells = audit.cells()[8:81]
        records = []
        for index, call in enumerate(cells):
            if pick is not None and index not in pick:
                continue
            a = audit.Audit(random.Random(seed * 1000 + index))
            for _ in range(n):
                call(a)
            records += a.records
        assert all(r["attack"] == "66" for r in records)
        return records
    finally:
        audit._MODS["66"] = keep or real


# ------------------------------------------------------------------ planted answers

PLANTS = ("stacked", "stacked", "stacked pieces", "stacked long", "stacked 21", "autokey cipher strip", "autokey A-Z label", "autokey plain strip",
          "progressive A-Z order", "gap", "mod", "multiplier", "drop", "breaks")


def _new_pair(rng, part, label=None, n=26):
    from math import gcd
    rows = [r for r in stacked_fn(part, n, part != "base")[3] if not r[4] and (label is None or r[0] == label)
            and (part != "base" or r[2] <= QMAX_OLD)]
    return rng.choice([r for r in rows if gcd(r[1], r[2]) == 1] or rows)


def plant(kind, rng, alphas):
    """A planted message. Returns (ct, cribs, alphabet name, alphabet, (layout, form, rule, variant), plaintext).

    The plain cases (stacked, autokey, progressive) are enciphered by the textbook strip code of idea 91
    (kryptos/idea91_textbook.py, which shares no code with the tests); the variants by plain arithmetic."""
    from . import idea91_textbook as T
    from .data import CRIBS
    from .round11 import english97
    name, m = rng.choice([a for a in alphas if a[1] not in (AZ, KR)])
    beaufort = rng.random() < 0.5
    form = "beau" if beaufort else "vig"
    if kind in ("stacked", "stacked pieces", "stacked long", "stacked 21"):
        lay = rng.choice(("M/M", "M/AZ", "AZ/M", "M/KR", "KR/M"))
        plain, cipher = _faces(lay, m)
        if kind == "stacked":
            _, p, q, _, _ = _new_pair(rng, "base")
        elif kind == "stacked pieces":         # lengths with a common factor: the graph falls into pieces
            p, q = rng.choice(((6, 9), (6, 10), (8, 10), (8, 12), (9, 12)))
        elif kind == "stacked long":
            p, q = rng.choice(((2, 15), (2, 19), (3, 20), (9, 15)))
        else:                                  # second word of 14 or 21: the second clue meets the same key
            p, q = rng.choice(((2, 21), (3, 14), (6, 21)))      # letters as the first, so the graph is in pieces
        pt = T.k4_like(rng)
        key = T.stacked_key(T.random_word(rng, p), T.random_word(rng, q), cipher, 97)
        ct = T.tableau_encrypt(pt, plain, cipher, key, rng.choice(plain), beaufort)
        want = (lay, form, "two stacked keys p=%d q=%d" % (p, q), "base")
    elif kind.startswith("autokey"):
        feed, lag = rng.choice(("plain", "cipher")), rng.randrange(1, 7)
        how = kind.split(" ", 1)[1]
        lay = {"cipher strip": rng.choice(("M/AZ", "M/KR")), "A-Z label": "M/M", "plain strip": rng.choice(("AZ/M", "KR/M"))}[how]
        plain, cipher = _faces(lay, m)
        key_on = {"cipher strip": "cipher", "A-Z label": "label", "plain strip": "plain"}[how]
        if key_on != "cipher":
            beaufort, form = False, "vig"
        pt = T.k4_like(rng)
        ct = T.autokey_encrypt(pt, plain, cipher, T.random_word(rng, lag), feed, key_on, beaufort)
        on = {"cipher strip": lay.split("/")[1], "A-Z label": "AZ", "plain strip": lay.split("/")[0]}[how]
        want = (lay, form, "autokey %s lag=%d sign=%+d" % (feed, lag, -1 if key_on == "plain" else 1),
                "fed letter numbered on %s" % on)
    elif kind == "progressive A-Z order":
        lay = rng.choice(("M/M", "AZ/M", "KR/M"))
        plain, cipher = _faces(lay, m)
        p, step = rng.randrange(3, 11), rng.randrange(1, 26)
        pt = T.k4_like(rng)
        key = T.progressive_key(T.random_word(rng, p), step, AZ, 97)
        ct = T.tableau_encrypt(pt, plain, cipher, key, rng.choice(plain), beaufort)
        want = (lay, form, "progressive p=%d step=%d" % (p, step), "key moved on in AZ order")
    else:
        im = {c: i for i, c in enumerate(m)}
        lay, form, n, mu, wrong = "M/M", "vig", 26, 1, None
        pt = english97(rng, 98 if kind == "gap" else 97)
        tpos = list(range(len(pt)))                      # key position of each letter
        if kind == "gap":
            label, p, q, _, _ = _new_pair(rng, "gap", "gap +1")
        elif kind == "mod":
            n = rng.choice(MODS)
            label, p, q, _, _ = _new_pair(rng, "mod", n=n)
            label = "mod %d" % n
        elif kind == "multiplier":
            mu = rng.choice(MULTS)
            label, p, q, _, _ = _new_pair(rng, "mult")
            label, form = "multiplier %d" % mu, "x%d" % mu
        elif kind == "drop":
            wrong = rng.choice(POS)
            label, p, q, _, _ = _new_pair(rng, "drop", "drop %d" % wrong)
        else:
            p1, p2, x = rng.randrange(3), rng.randrange(2), rng.randrange(1, 9)
            label, p, q, _, _ = _new_pair(rng, "breaks", "breaks %s x=%d" % (i88.label(p1, p2), x))
            clue = i88.positions(p1, p2, x)
            between = sorted(rng.sample(range(34, 63), x - 1)) + [63]     # letters that start a new word
            tpos, t = [], 0
            for i in range(97):
                if i in between or (i > 73 and rng.random() < 0.2):
                    t += 1
                tpos.append(clue[POS.index(i)] if i in INBLOCK else i + t)
                if i in INBLOCK:
                    t = clue[POS.index(i)] - i
            assert all(b > a for a, b in zip(tpos, tpos[1:]))
        while True:
            a, b = [rng.randrange(n) for _ in range(p)], [rng.randrange(n) for _ in range(q)]
            nums = [(mu * im[ch] + a[t % p] + b[t % q]) % n for ch, t in zip(pt, tpos)]
            if all(nums[i] < 26 for i in (POS if kind != "gap" else range(98))):
                break
        ct = "".join((m + "?????")[v] for v in nums)
        if kind == "gap":
            cut = rng.randrange(36, 60)
            ct, pt = ct[:cut] + ct[cut + 1:], pt[:cut] + pt[cut + 1:]
        cribs = {i: pt[i] for i in CRIBS}
        if wrong is not None:
            cribs[wrong] = rng.choice([c for c in AZ if c != pt[wrong]])
        return ct, cribs, name, m, (lay, form, "two stacked keys p=%d q=%d" % (p, q), label), pt
    return ct, {i: pt[i] for i in T.clue_map()}, name, m, want, pt
