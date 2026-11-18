"""Idea 118: close the scope holes the idea-105 audit found in attacks 90, 59, 88, 60C, 61, 69B and 57.

The old attacks are not edited. Each hole gets a fixed copy of the attack's own test function here,
restricted (for the K4 run) to the settings the old code never really tested:

  90   _order() split the runs of clue pairs on the clue index, not the position, so at cipher lags
       30-33 the quick test compared letters 33 apart. Fixed: break runs on the position. New
       settings: cipher feed 30-33 back with a word of 2-4 on top (the word lengths whose old quick
       test was wrong there).
  59   `if len(use) < 12: continue` skipped cipher feed 34-60 back and plain feed 7-8 back. Fixed:
       the check count alone decides.
  88   the progressive key took its step only from two clue letters p apart in one unbroken run.
       Once word breaks cut the clues, lengths 6-12 (EAST|NORTH|EAST + BERLIN|CLOCK) and others had
       no such pair and were skipped. Fixed: the step is found from any two clue letters in the same
       class mod p (any pass), every step 1..25 that fits is kept.
       (88's two stacked keys were already closed by idea 104's part "breaks", which ran the exact
       loop solve on all 156 of 88's position sets; here that is only re-checked on the audit's plants.)
  60C  Slidefair: a pair whose two letters stand in the same column takes the letters to their right
       (ACA). Fixed: each clue pair may follow the normal rule or the same-column rule.
  61   the K3 quarter turn of the key was tested anticlockwise only. Fixed: clockwise (columns from
       the left, read upwards), and double turns in every mix of directions.
  69B  rows of 21 with a different tableau per row was joined on key NUMBERS. Fixed: join on the key
       LETTERS read off each row's own cipher strip at all 26 offsets.
  57   the key letter of an English running key was read as M[s] or KRYPTOS[s] only. Fixed: also
       M[s + c] and KRYPTOS[s + c] for every c (key set under any plain letter, e.g. under A, the ACA
       way), on M/M, M/KR and KR/M.
"""
import itertools
import heapq

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET as KR
from . import idea90_rowkey as R
from . import idea88_slip as S88
from .round11 import B1, B2, POS, _plan, pmap, streams

MIN_CHECKS = 7
IZ = {c: i for i, c in enumerate(AZ)}
IK = {c: i for i, c in enumerate(KR)}
_S = {}


# ================================================================== attack 90

def order_fixed(pairs):
    """Attack 90's _order with the bug fixed: a run continues only when the POSITION is consecutive."""
    runs, cur = [], [pairs[0]]
    for pr in pairs[1:]:
        if pr[1] == cur[-1][1] + 1:
            cur.append(pr)
        else:
            runs.append(cur)
            cur = [pr]
    runs.append(cur)
    runs.sort(key=len, reverse=True)
    assert len(runs[0]) >= 5
    return [pr for r in runs for pr in r]


def _old_valid(pairs, p):
    """Was the old quick test valid at word length p? It reads pairs 0 and 4 (p = 1, 2, 4) or 0 and 3 (p = 3)."""
    a, b = (pairs[0][1], pairs[3][1]) if p == 3 else (pairs[0][1], pairs[4][1])
    return (b - a) % p == 0


def build_tests90(only_hole=False):
    """Attack 90's tests with the fixed order. only_hole: keep only (test, word length) settings whose old
    quick test compared letters of different classes, i.e. settings the old run never really tested."""
    tests = []
    for s in R.SHIFTS:
        pos = R.positions(s)
        where = {i: j for j, i in enumerate(pos)}
        plain_lags = [L for L in range(34, 49)] + ([7, 8] if s == 0 else [])
        cipher_lags = range(1, 67) if s == 0 else range(34, 49)
        for src, lags in (("plain", plain_lags), ("cipher", cipher_lags)):
            for L in lags:
                if src == "plain":
                    pairs = [(j, i, where[i - L]) for j, i in enumerate(pos) if i - L in where]
                else:
                    pairs = [(j, i, R.NCLUE + i - L) for j, i in enumerate(pos) if i - L >= 0]
                if len(pairs) - 1 < MIN_CHECKS:
                    continue
                old = R._order(list(pairs))
                new = order_fixed(list(pairs))
                periods = [p for p in R.PERIODS if len(new) - len({i % p for _, i, _ in new}) >= MIN_CHECKS]
                if only_hole:
                    periods = [p for p in periods if not _old_valid(old, p)]
                if not periods:
                    continue
                tests.append({"src": src, "lag": L, "shift": s, "pairs": new, "periods": periods,
                              "quick": (new[0][0], new[3][0], new[4][0], new[0][2], new[3][2], new[4][2])})
    return tests


class Tests90:
    def __init__(self, tests):
        self.tests = tests
        self.qk = [t["quick"][:3] for t in tests]
        self.qx = [t["quick"][3:] for t in tests]
        self.sidx = [R.SHIFTS.index(t["shift"]) for t in tests]
        self.p124 = [[p for p in t["periods"] if p != 3] for t in tests]
        self.p3 = [[p for p in t["periods"] if p == 3] for t in tests]
        self.per_view = sum(len(t["periods"]) for t in tests)

    def settings(self, m):
        return (4 if m == AZ else 5) * 2 * (2 if m == AZ else 3) * 2 * self.per_view

    def chance(self, m):
        """Expected chance passes for one alphabet (uniform key values)."""
        views = (4 if m == AZ else 5) * 2 * (2 if m == AZ else 3) * 2
        tot = 0.0
        for t in self.tests:
            for p in t["periods"]:
                c = len(t["pairs"]) - len({i % p for _, i, _ in t["pairs"]})
                tot += 26.0 ** -c
        return views * tot

    def test_alphabet(self, name, m, ct, cribs):
        """Copy of idea90_rowkey.test_alphabet on these tests."""
        im, lays = R.layouts(m)
        pl = [cribs[i] for i in B1 + B2]
        feeds = (("M", im), ("AZ", IZ), ("KR", IK)) if m != AZ else (("AZ", IZ), ("KR", IK))
        xs = []
        for fn, ix in feeds:
            x = [ix[c] for c in pl] + [ix[c] for c in ct]
            q = (set(), set(), set(), set())
            for n, (a0, a3, a4) in enumerate(self.qx):
                q[0].add(n * 26 + (x[a4] - x[a0]) % 26)
                q[1].add(n * 26 + (x[a0] - x[a4]) % 26)
                q[2].add(n * 26 + (x[a3] - x[a0]) % 26)
                q[3].add(n * 26 + (x[a0] - x[a3]) % 26)
            xs.append((fn, x, q))
        cls = [[ct[i] for i in R.positions(s)] for s in R.SHIFTS]
        hits = []
        for lay, ia, ib in lays:
            a = [ia[c] for c in pl]
            bs = [[ib[c] for c in cl] for cl in cls]
            for form, ks in (("vig", [[(y - u) % 26 for u, y in zip(a, b)] for b in bs]),
                             ("beau", [[(y + u) % 26 for u, y in zip(a, b)] for b in bs])):
                c4 = [n * 26 + (ks[si][j4] - ks[si][j0]) % 26 for n, (si, (j0, j3, j4)) in enumerate(zip(self.sidx, self.qk))]
                c3 = [n * 26 + (ks[si][j3] - ks[si][j0]) % 26 for n, (si, (j0, j3, j4)) in enumerate(zip(self.sidx, self.qk))]
                for fn, x, q in xs:
                    for qs, cs, sg, per in ((q[0], c4, 1, self.p124), (q[1], c4, -1, self.p124),
                                            (q[2], c3, 1, self.p3), (q[3], c3, -1, self.p3)):
                        for c in qs.intersection(cs):
                            n = c // 26
                            if per[n]:
                                t = self.tests[n]
                                for checks, p, word in R._full(t, ks[self.sidx[n]], x, sg, per[n]):
                                    hits.append((checks, name, lay, form, fn, sg, t["src"], t["lag"], t["shift"], p, word))
        return hits


_T90 = {}


def tests90(only_hole):
    if only_hole not in _T90:
        _T90[only_hole] = Tests90(build_tests90(only_hole))
    return _T90[only_hole]


def init90(ct, cribs, only_hole):
    _S["ct"], _S["cribs"], _S["t90"] = ct, cribs, tests90(only_hole)


def work90(chunk):
    t = _S["t90"]
    out = []
    for name, m in chunk:
        out += t.test_alphabet(name, m, _S["ct"], _S["cribs"])
    return out


def search90(ct, cribs, alphas, only_hole=True, chunk=2000, procs=None):
    hits = []
    for h in pmap(work90, alphas, init90, (ct, cribs, only_hole), chunk=chunk, procs=procs):
        hits += h
    return hits


def fixed_test_alphabet90(name, m, ct, cribs):
    """Drop-in for idea90_rowkey.test_alphabet with every test's order fixed (for the audit plants)."""
    return tests90(False).test_alphabet(name, m, ct, cribs)


# ================================================================== attack 59

ALPH59 = {"AZ": AZ, "KR": KR}


def lags59(hole_only):
    if hole_only:
        return list(range(34, 61)), [7, 8]
    return list(range(1, 61)), list(range(1, 10))


def search59(ct, cribs, hole_only=True, min_checks=6):
    """Attack 59's search with `if len(use) < 12: continue` removed. Returns (tried, hits, chance)
    where chance is the expected number of passes (>= min_checks) for random text."""
    clags, plags = lags59(hole_only)
    tried, hits, chance = 0, [], 0.0
    for an, a_ in ALPH59.items():
        ia = {c: i for i, c in enumerate(a_)}
        for bn, b_ in ALPH59.items():
            ib = {c: i for i, c in enumerate(b_)}
            for un, iu in (("AZ", IZ), ("KR", IK)):
                for src, lags in (("C", clags), ("P", plags)):
                    for L in lags:
                        if src == "C":
                            use = [i for i in POS if i - L >= 0]
                            u = {i: iu[ct[i - L]] for i in use}
                        else:
                            use = [i for i in POS if i - L in cribs]
                            u = {i: iu[cribs[i - L]] for i in use}
                        if not use:
                            continue
                        ps = [p for p in range(1, 27) if len(use) - len({i % p for i in use}) >= min_checks]
                        if not ps:
                            continue
                        for a in (1, -1):
                            base = {i: ib[ct[i]] - a * ia[cribs[i]] for i in use}
                            for b in range(1, 26):
                                rem = {i: (base[i] - b * u[i]) % 26 for i in use}
                                for p in ps:
                                    tried += 1
                                    c = len(use) - len({i % p for i in use})
                                    chance += 26.0 ** -c
                                    seen, ok = {}, True
                                    for i in use:
                                        if seen.setdefault(i % p, rem[i]) != rem[i]:
                                            ok = False
                                            break
                                    if ok:
                                        hits.append((c, "pt%s/ct%s/u%s" % (an, bn, un), src, L, a, b, p))
    return tried, hits, chance


def fixed_search59(ct, cribs):
    """Drop-in for attack 59's search() (full claimed scope, no usable-letter filter)."""
    t, h, _ = search59(ct, cribs, hole_only=False)
    return t, h


def decrypt59(ct, cribs, hit):
    """Every plaintext letter the setting forces (cipher feed: all of them once the key is known)."""
    ck, name, src, L, a, b, p = hit
    an, bn, un = name[2:4], name[7:9], name[11:13]
    A, Bx, U = ALPH59[an], ALPH59[bn], ALPH59[un]
    ia, ib, iu = ({c: i for i, c in enumerate(x)} for x in (A, Bx, U))
    key = {}
    for i in POS:
        if (src == "C" and i - L >= 0) or (src == "P" and i - L in cribs):
            uu = iu[ct[i - L]] if src == "C" else iu[cribs[i - L]]
            key[i % p] = (ib[ct[i]] - a * ia[cribs[i]] - b * uu) % 26
    pt = ["."] * len(ct)
    for i in cribs:
        pt[i] = cribs[i]
    for _ in range(3):
        for i in range(len(ct)):
            if pt[i] != "." or i % p not in key or i < L:
                continue
            if src == "C":
                uu = iu[ct[i - L]]
            elif pt[i - L] != ".":
                uu = iu[pt[i - L]]
            else:
                continue
            pt[i] = A[(a * (ib[ct[i]] - b * uu - key[i % p])) % 26]
    return "".join(pt)


# ================================================================== attack 88, progressive key

def hole_cells88():
    """(p1, p2, p) where attack 88 never tested a progressive key: no two clue letters p apart in one run."""
    out = []
    for p1 in range(3):
        for p2 in range(2):
            pl0 = _plan(S88.positions(p1, p2, 0))
            for p in range(1, 13):
                if not pl0["lag"][p]:
                    out.append((p1, p2, p))
    return out


def _solutions():
    """SOL[d][v] = every step s in 1..25 with s * d = v (mod 26)."""
    sol = {}
    for d in range(-30, 31):
        sol[d] = {v: [s for s in range(1, 26) if (s * d - v) % 26 == 0] for v in range(26)}
    return sol


SOL = _solutions()
_P88 = {}


def prog_tables(min_checks=MIN_CHECKS, cells=None):
    """[(p1, p2, p, a, first block-1 equation, other block-1 equations, [(x, checks, block-2 equations)])]."""
    key = (min_checks, tuple(cells) if cells else None)
    if key in _P88:
        return _P88[key]
    out = []
    for p1, p2, p in (cells or hole_cells88()):
        for a in range(p):
            pre, by_x = None, []
            for x in S88.OFFSETS:
                pos = S88.positions(p1, p2, x, a)
                tr = S88._tree(zip((i % p for i in pos), range(24)))
                checks = len(tr) - 1
                eq = [(i, j, pos[j] // p - pos[i] // p) for i, j in tr]
                pre = [e for e in eq if e[1] < 13]
                if checks >= min_checks:
                    by_x.append((x, checks, [e for e in eq if e[1] >= 13]))
            if by_x and pre:
                out.append((p1, p2, p, a, pre[0], pre[1:], by_x))
    _P88[key] = out
    return out


def prog_hits88(k, min_checks=MIN_CHECKS, cells=None):
    """[(checks, p1, p2, x, rule)]: progressive key at the hole cells, exact, any step 1..25."""
    out = []
    for p1, p2, p, a, (i0, j0, d0), pre, by_x in prog_tables(min_checks, cells):
        for s in SOL[d0][(k[j0] - k[i0]) % 26]:
            for i, j, d in pre:
                if (k[j] - k[i] - s * d) % 26:
                    break
            else:
                for x, checks, eq in by_x:
                    for i, j, d in eq:
                        if (k[j] - k[i] - s * d) % 26:
                            break
                    else:
                        out.append((checks, p1, p2, x, "progressive p=%d step=%d start+%d" % (p, s, a)))
    return out


def prog_chance88(min_checks=MIN_CHECKS):
    """Expected chance passes per key stream (25 steps, uniform key values)."""
    return sum(25.0 / 26 * 26.0 ** -c for *_, by_x in prog_tables(min_checks) for _, c, _ in by_x)


def prog_tests88(min_checks=MIN_CHECKS):
    return sum(25 * len(by_x) for *_, by_x in prog_tables(min_checks))


def init88(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]
    prog_tables()


def test_alphabet88(name, m, pl, cl, min_checks=MIN_CHECKS):
    hits = []
    for lay, form, k, _, _ in streams(m, pl, cl):
        for ck, p1, p2, x, rule in prog_hits88(k, min_checks):
            hits.append((ck, name, lay, form, p1, p2, x, rule))
    return hits


def work88(chunk):
    out = []
    for name, m in chunk:
        out += test_alphabet88(name, m, _S["p"], _S["c"])
    return out


def search88(ct, cribs, alphas, chunk=1000, procs=None):
    hits = []
    for h in pmap(work88, alphas, init88, (ct, cribs), chunk=chunk, procs=procs):
        hits += h
    return hits


def stacked88_via104(name, m, pl, cl):
    """Idea 104's exact stacked test on 88's position sets, in attack 88's hit format."""
    from . import idea104_holes as H
    labels = {"breaks %s x=%d" % (S88.label(p1, p2), x): (p1, p2, x)
              for p1 in range(3) for p2 in range(2) for x in S88.OFFSETS}
    out = []
    for h in H.test_alphabet(name, m, pl, cl, parts=("breaks",)):
        p1, p2, x = labels[h[5]]
        out.append((h[0], name, h[2], h[3], p1, p2, x, h[4]))
    return out


# ================================================================== attack 60C, Slidefair

def slidefair_fixed(ct, cribs, same_column=True):
    """Settings (alphabet, start, kind) where every complete clue pair follows the Slidefair rule, or (with
    same_column) the ACA same-column rule. Vigenere kind: C1 + C2 = P1 + P2, or C1 = P1 + 1 and C2 = P2 + 1.
    Beaufort kind (strip written backwards): C1 + P1 - C2 - P2 = t for one t, or C1 = P1 + 1 and C2 = P2 - 1.
    Also attack 60's third identity (C1 + C2 + P1 + P2 constant) as it was. Returns (hits, settings, chance)."""
    hits, n, chance = [], 0, 0.0
    for an, a in ALPH59.items():
        x = {c: i for i, c in enumerate(a)}
        for start in (0, 1):
            pairs = [(i, i + 1) for i in range(start, 96, 2) if i in cribs and i + 1 in cribs]
            P = [(x[cribs[i]], x[cribs[j]], x[ct[i]], x[ct[j]]) for i, j in pairs]
            pr = 1 / 26.0 + (1 / 676.0 if same_column else 0)
            # Vigenere kind
            n += 1
            chance += pr ** len(P)
            if all((c1 + c2 - p1 - p2) % 26 == 0 or (same_column and (c1 - p1) % 26 == 1 and (c2 - p2) % 26 == 1)
                   for p1, p2, c1, c2 in P):
                hits.append((an, start, "vig", len(P)))
            # Beaufort kind, any constant t
            for t in range(26):
                n += 1
                chance += pr ** len(P)
                if all((c1 + p1 - c2 - p2) % 26 == t or (same_column and (c1 - p1) % 26 == 1 and (c2 - p2) % 26 == 25)
                       for p1, p2, c1, c2 in P):
                    hits.append((an, start, "beau t=%d" % t, len(P)))
            n += 1
            chance += 26.0 ** -(len(P) - 1)
            if len({(c1 + c2 + p1 + p2) % 26 for p1, p2, c1, c2 in P}) == 1:
                hits.append((an, start, "C1+C2+P1+P2 const", len(P)))
    return hits, n, chance


def fixed_slidefair(ct, cribs):
    """Drop-in for attack 60's slidefair(): [(alphabet, start, kind)]."""
    return [h[:3] for h in slidefair_fixed(ct, cribs)[0]]


# ================================================================== attack 61, quarter turns both ways

def rotate(seq, w, clockwise=False):
    """K3's quarter turn. Anticlockwise (attack 61): columns from the right, each read downwards.
    Clockwise: columns from the left, each read upwards."""
    n = len(seq)
    if clockwise:
        return [seq[i] for c in range(w) for i in reversed(range(c, n, w))]
    return [seq[i] for c in range(w - 1, -1, -1) for i in range(c, n, w)]


def new_perms61(n, first=None, singles=True):
    """Key scrambles attack 61 never tried: one clockwise turn at widths 2-48, and two turns where at least
    one is clockwise (every pair of widths 2-48). first: only double turns whose first width is this
    (0 = no double turns)."""
    ident = list(range(n))
    if singles:
        for w in range(2, 49):
            yield "rotation cw w%d" % w, rotate(ident, w, True)
    if first == 0:
        return
    for w1 in ([first] if first else range(2, 49)):
        for d1, d2 in ((True, False), (False, True), (True, True)):
            a = rotate(ident, w1, d1)
            for w2 in range(2, 49):
                yield "rotations w%d%s then w%d%s" % (w1, " cw" if d1 else "", w2, " cw" if d2 else ""), rotate(a, w2, d2)


def views61(ct, cribs):
    out = []
    for an, a in ALPH59.items():
        for bn, b in ALPH59.items():
            for m, mn in ((1, "vig"), (-1, "beau")):
                out.append(("%s/%s/%s" % (an, bn, mn), [(b.index(ct[i]) - m * a.index(cribs[i])) % 26 for i in POS]))
    return out


def check_slots61(src, views, name, hits, min_checks=6):
    """Attack 61's check_slots. Returns (settings, chance)."""
    n, chance = 0, 0.0
    for p in range(2, 27):
        slots = [s % p for s in src]
        c = 24 - len(set(slots))
        if c < min_checks:
            continue
        for vname, key in views:
            n += 1
            chance += 26.0 ** -c
            seen, ok = {}, True
            for s, k in zip(slots, key):
                if seen.setdefault(s, k) != k:
                    ok = False
                    break
            if ok:
                hits.append((c, name, p, vname))
    return n, chance


def search61(ct, cribs, offs=(0, 1), first=None, singles=True):
    """Every new scramble, as given and inverted; off = 1 counts the '?' as cell 0 (98 cells)."""
    views = views61(ct, cribs)
    hits, n, chance = [], 0, 0.0
    for off in offs:
        N = 97 + off
        tag = " [98 cells]" if off else ""
        for name, perm in new_perms61(N, first, singles):
            inv = [0] * N
            for j, s in enumerate(perm):
                inv[s] = j
            for nm, pp in ((name, perm), (name + " (inverse)", inv)):
                a, b = check_slots61([pp[i + off] for i in POS], views, nm + tag, hits)
                n, chance = n + a, chance + b
    return hits, n, chance


class Fixed61:
    """Drop-in for attack 61's module in the audit: its own jobs, plus the clockwise turns on its rotation jobs."""

    def __init__(self, orig):
        self.orig = orig

    def init(self, ct, cribs):
        self.orig.init(ct, cribs)
        self.ct, self.cribs = ct, cribs

    def work(self, job):
        n, hits = self.orig.work(job)
        if job[0] in ("rot1", "rot2"):
            if job[0] == "rot1":
                h, m, _ = search61(self.ct, self.cribs, offs=(0,), first=0)
            else:
                h, m, _ = search61(self.ct, self.cribs, offs=(0,), first=job[1], singles=False)
            n, hits = n + m, hits + h
        return n, hits


# ================================================================== attack 69B, join on key letters

def cipher_strip(lay, m):
    side = lay.split("/")[1]
    return {"M": m, "AZ": AZ, "KR": KR}[side]


def letter_sigs(m, pl, cl, xs):
    """For each stream (layout, form) of alphabet m: the rows-2 and row-4 signatures of the 11 shared
    columns' key LETTERS read off the stream's cipher strip, at the offsets that make column 0's letter
    one of xs (letter numbers). Yields (lay, form, x, sig2, sig4)."""
    for lay, form, k, _, _ in streams(m, pl, cl):
        strip = [IZ[c] for c in cipher_strip(lay, m)]
        where = {v: i for i, v in enumerate(strip)}
        for x in xs:
            o2 = (k[0] - where[x]) % 26
            o4 = (k[13] - where[x]) % 26
            s2 = s4 = 0
            for c in range(11):
                s2 = s2 * 26 + strip[(k[c] - o2) % 26]
                s4 = s4 * 26 + strip[(k[13 + c] - o4) % 26]
            yield lay, form, x, s2, s4


def init69(ct, cribs, xs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]
    _S["xs"] = xs


def work69(chunk):
    s2, s4 = [], []
    for name, m in chunk:
        for lay, form, x, a, b in letter_sigs(m, _S["p"], _S["c"], _S["xs"]):
            s2.append(a)
            s4.append(b)
    return s2, s4


def search69(ct, cribs, alphas, groups=6, procs=None):
    """Hash join of row-2 and row-4 letter signatures over every pair of streams. Column 0's letter is
    split into `groups` passes to keep memory small. Returns (joined signatures, n2, n4)."""
    joined, n2, n4 = set(), 0, 0
    letters = list(range(26))
    for g in range(groups):
        xs = letters[g::groups]
        a2, a4 = set(), []
        for s2, s4 in pmap(work69, alphas, init69, (ct, cribs, xs), chunk=2000, procs=procs):
            a2.update(s2)
            a4 += s4
        n2 += len(a2)
        n4 += len(a4)
        joined.update(s for s in a4 if s in a2)
    return joined, n2, n4


def name_join69(ct, cribs, alphas, joined):
    """[((name, layout, form), (name, layout, form), signature)] behind the joined signatures."""
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    left, right = {}, {}
    xs = sorted({s // 26 ** 10 for s in joined})
    for name, m in alphas:
        for lay, form, x, a, b in letter_sigs(m, pl, cl, xs):
            if a in joined:
                left.setdefault(a, []).append((name, lay, form))
            if b in joined:
                right.setdefault(b, []).append((name, lay, form))
    return [(u, v, s) for s in joined for u in left.get(s, []) for v in right.get(s, [])]


def sig_letters(s):
    out = []
    for _ in range(11):
        out.append(AZ[s % 26])
        s //= 26
    return "".join(reversed(out))


class Fixed69:
    """Drop-in for attack 69's module in the audit: old work/name_join plus the letter join."""

    def __init__(self, orig):
        self.orig = orig
        self.TAG = 26 ** 12

    def init(self, ct, cribs):
        self.orig.init(ct, cribs)
        self.ct, self.cribs = ct, cribs

    def work(self, chunk):
        hits, s2, s4 = self.orig.work(chunk)
        pl, cl = [self.cribs[i] for i in POS], [self.ct[i] for i in POS]
        for name, m in chunk:
            for lay, form, x, a, b in letter_sigs(m, pl, cl, range(26)):
                s2.append(self.TAG + a)
                s4.append(self.TAG + b)
        return hits, s2, s4

    def name_join(self, ct, cribs, chunk, joined):
        old = self.orig.name_join(ct, cribs, chunk, {s for s in joined if s < self.TAG})
        new = name_join69(ct, cribs, chunk, {s - self.TAG for s in joined if s >= self.TAG})
        return old + [(u, v) for u, v, _ in new]


def sig_letters(s):
    out = []
    for _ in range(11):
        out.append(AZ[s % 26])
        s //= 26
    return "".join(reversed(out))


class Fixed69:
    """Drop-in for attack 69's module in the audit: old work/name_join plus the letter join."""

    def __init__(self, orig):
        self.orig = orig
        self.TAG = 26 ** 12

    def init(self, ct, cribs):
        self.orig.init(ct, cribs)
        self.ct, self.cribs = ct, cribs

    def work(self, chunk):
        hits, s2, s4 = self.orig.work(chunk)
        pl, cl = [self.cribs[i] for i in POS], [self.ct[i] for i in POS]
        for name, m in chunk:
            for lay, form, x, a, b in letter_sigs(m, pl, cl, range(26)):
                s2.append(self.TAG + a)
                s4.append(self.TAG + b)
        return hits, s2, s4

    def name_join(self, ct, cribs, chunk, joined):
        old = self.orig.name_join(ct, cribs, chunk, {s for s in joined if s < self.TAG})
        new = name_join69(ct, cribs, chunk, {s - self.TAG for s in joined if s >= self.TAG})
        return old + [(u, v) for u, v, _ in new]


def chance69(n2, n4, same=False):
    """Expected chance joins: every pair of signatures with the same column-0 letter must agree on 10 more letters."""
    return n2 * n4 / 26.0 / 26.0 ** 10 if not same else 0.0


# ================================================================== attack 57, key letter under any plain letter

L57 = ("Q3", "Q4a", "Q4b")


def score57(wm, ct, cribs, tab, mod, keep=3):
    """Best key fragments for one alphabet over the NEW readings only: M[s + c] and KRYPTOS[s + c], c = 1..25
    (c = 0 is attack 57's own M and KR reading), on Q3 (M/M), Q4a (M/KR) and Q4b (KR/M), all four ciphers."""
    w, m = wm
    nm = [ord(c) - 65 for c in m]
    nk = [ord(c) - 65 for c in KR]
    best = []
    for label, s1, s2 in mod.views_for(m, ct, cribs):
        if label.split("/")[0] not in L57:
            continue
        for tag, al in (("M", nm), ("KR", nk)):
            for c in range(1, 26):
                v1 = [al[(x + c) % 26] for x in s1]
                v2 = [al[(x + c) % 26] for x in s2]
                sc = mod.frag_score(v1, v2, tab)
                item = (sc, w, label, "%s+%d" % (tag, c), "".join(AZ[x] for x in v1) + "|" + "".join(AZ[x] for x in v2))
                if len(best) < keep:
                    heapq.heappush(best, item)
                elif item > best[0]:
                    heapq.heapreplace(best, item)
    return best


def readings57(m, mod, ct, cribs, label):
    """Every key-letter reading the fixed test scores for one view: attack 57's 28 plus the 50 new."""
    nm = [ord(c) - 65 for c in m]
    nk = [ord(c) - 65 for c in KR]
    for lab, s1, s2 in mod.views_for(m, ct, cribs):
        if lab != label:
            continue
        reads = [([(x + c) % 26 for x in s1], [(x + c) % 26 for x in s2]) for c in range(26)]
        for al in (nm, nk):
            reads += [([al[(x + c) % 26] for x in s1], [al[(x + c) % 26] for x in s2]) for c in range(26)]
        return reads
    return []


def init57(ct, cribs, path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("attack57_for_118", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _S["mod"], _S["ct"], _S["cribs"], _S["tab"] = mod, ct, cribs, mod.quad_table()


def work57(chunk):
    out = []
    for wm in chunk:
        out.extend(score57(wm, _S["ct"], _S["cribs"], _S["tab"], _S["mod"], keep=1))
    return heapq.nlargest(20, out)


def search57(ct, cribs, alphas, path, chunk=500, procs=None):
    res = []
    for r in pmap(work57, alphas, init57, (ct, cribs, str(path)), chunk=chunk, procs=procs):
        res.extend(r)
    return heapq.nlargest(20, res)


# ================================================================== planted answers: idea 105's own plants

def english_filler():
    """The solved Kryptos plaintexts as extra filler, as idea 105 used them."""
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    return " ".join(json.load(open(root / "data" / "sculpture" / ("%s.json" % k)))["plaintext"] for k in ("k1", "k2", "k3"))


def install(late88=False):
    """Swap idea 105's handles on attacks 59, 60, 61, 69, 88 and 90 for the fixed tests (in this process).
    late88: attack 88's plants are built from spaced words and ignore the audit's offset, so for the
    'clue one letter late' control the test is handed the cipher letter one place early instead
    (the clue plain letter is then paired with the wrong cipher letter, exactly as when the clue sits late)."""
    from types import SimpleNamespace
    from . import idea105_audit as A
    A._MODS["59"] = SimpleNamespace(search=fixed_search59)
    A._MODS["60"] = SimpleNamespace(slidefair=fixed_slidefair)
    o61, o69, o88 = A.attack("61"), A.attack("69"), A.attack("88")
    A._MODS["61"] = Fixed61(getattr(o61, "orig", o61))
    A._MODS["69"] = Fixed69(getattr(o69, "orig", o69))
    o88 = getattr(o88, "orig", o88)

    held = {}

    def init(ct, cribs):
        o88.init(ct, cribs)
        held["cl"] = [ct[i - 1] for i in POS]

    def test_alphabet(name, m, pl, cl):
        if late88:
            cl = held["cl"]
        return (o88.test_alphabet(name, m, pl, cl) + test_alphabet88(name, m, pl, cl)
                + stacked88_via104(name, m, pl, cl))
    A._MODS["88"] = SimpleNamespace(init=init, test_alphabet=test_alphabet, orig=o88)
    R.test_alphabet = fixed_test_alphabet90
    return A


def plant57_fixed(a, index, layout):
    """idea105_audit.Audit.plant_57 with the fixed readings: is the planted key among them?"""
    from . import idea105_audit as A
    from . import idea91_textbook as T
    rng = a.rng
    name, m = a.alphabet(mixed=False)
    beaufort = rng.random() < 0.5
    plain, cipher = A.strips(layout, m)
    text = T.only_letters(T.FILLER + a.english)
    o = rng.randrange(len(text) - 97)
    key = text[o:o + 97]
    ct = T.tableau_encrypt(a.message(), plain, cipher, key, "A" if index == "A" else plain[0], beaufort)
    label = {"M/AZ": "Q1", "AZ/M": "Q2", "M/M": "Q3", "M/KR": "Q4a", "KR/M": "Q4b"}[layout] + ("/beau" if beaufort else "/vig")
    truth = ([AZ.index(key[i]) for i in A.B1], [AZ.index(key[i]) for i in A.B2])
    found = truth in readings57(m, A.attack("57"), ct, A.CRIBS, label)
    return a.record("57", "English running key [%s], key letter set under %s" % (
        layout, "the plain A (ACA)" if index == "A" else "the first letter of the plain strip"),
        "%s %s" % (name, label), found, 24, 0, None, [m])


def plant_cells(full=True):
    """(attack, cell name, call): the idea-105 cells of the seven holes (hole=True) and, with full, the cells
    of the same attacks that were already found (to show the fixed copies lose nothing)."""
    out = []

    def add(att, name, call, hole):
        if hole or full:
            out.append((att, name, call, hole))
    for f, lo, hi, hole in (("cipher", 30, 33, True), ("cipher", 1, 21, False), ("cipher", 22, 29, False),
                            ("cipher", 34, 63, False), ("plain", 7, 7, False), ("plain", 34, 48, False)):
        add("90", "%s %d-%d" % (f, lo, hi), lambda a, f=f, x=lo, y=hi: a.plant_90(f, x, y), hole)
    for f, lo, hi, hole in (("cipher", 34, 60, True), ("plain", 7, 9, True), ("cipher", 1, 21, False),
                            ("cipher", 22, 33, False), ("plain", 1, 6, False)):
        add("59", "%s %d-%d" % (f, lo, hi), lambda a, f=f, x=lo, y=hi: a.plant_59(f, x, y), hole)
    for p1, p2, lo, hi, hole in ((2, 1, 6, 12, True), (1, 1, 9, 12, True), (None, 0, 11, 12, True),
                                 (2, 1, 1, 5, False), (None, 0, 1, 12, False)):
        add("88", "progressive %s+%s %d-%d" % (p1, p2, lo, hi),
            lambda a, p1=p1, p2=p2, x=lo, y=hi: a.plant_88("progressive", p1=p1, p2=p2, pmin=x, pmax=y), hole)
    add("88", "stacked", lambda a: a.plant_88("stacked"), True)
    add("88", "repeating", lambda a: a.plant_88("repeating"), False)
    for kind, hole in (("same-column rule inside a clue", True), ("Vigenere", False), ("Beaufort", False)):
        add("60C", kind, lambda a, k=kind: a.plant_60_slidefair(k), hole)
    for kind, hole in (("quarter turn the other way", True), ("quarter turn", False), ("two quarter turns", False)):
        add("61", kind, lambda a, k=kind: a.plant_61(k), hole)
    for kind, hole in (("two tableaux, key letters found on each row's own strip", True),
                       ("two tableaux, same cipher strip", False), ("two tableaux, key given as numbers", False)):
        add("69B", kind, lambda a, k=kind: a.plant_69(k), hole)
    for layout in ("M/M", "M/KR", "KR/M", "M/AZ", "AZ/M"):
        for index in ("A", "first"):
            hole = index == "A" and layout in ("M/M", "M/KR", "KR/M")
            add("57", "%s key under %s" % (layout, index), lambda a, x=index, la=layout: plant57_fixed(a, x, la), hole)
    return out


def run_plant_cell(args):
    """Worker: one cell, n messages. Returns (index, records)."""
    import random
    from . import idea105_audit as A
    index, n, seed, english, full = args
    install()
    att, name, call, hole = plant_cells(full)[index]
    a = A.Audit(random.Random(seed * 1000 + index), english)
    for _ in range(n):
        call(a)
    return index, a.records


def stacked_map88(seed=118):
    """idea 105's map of two stacked keys through attack 88 (every pair p < q <= 13), now with idea 104's test."""
    import random
    from . import idea105_audit as A
    install()
    return A.Audit(random.Random(seed)).stacked_map("88", None)
