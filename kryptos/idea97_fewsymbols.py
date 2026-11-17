"""Idea 97 helpers: does the key use few symbols?

A key that is a list of numbers (digits in some base, clock hours, Roman numerals) uses few
different values, however irregular the list is. For one tableau setting the 24 clue letters
force 24 key values; `profile` measures how few symbols those values need:

  win     the smallest circular window of consecutive values that holds them all
          (digits 0-9 are a window of 10 starting at 0; clock hours 1-12 a window of 12 at 1)
  d       how many different values there are
  cov[w]  the most clue letters any window of w values covers (w = 5, 8, 10, 12, 16)
  top[n]  the most clue letters any n values cover (n = 2, 3, 4, 7), windows or not

Negating a key (P-C instead of C-P) mirrors the window, so all of these numbers are the same
for a view and its negative; only tests that name particular values (below 10, below a base,
the seven Roman numeral letters) differ, and those are computed for both signs.
"""
import random
from itertools import accumulate
from operator import sub

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round11 import B1, B2, POS, english97, pmap, streams

WIDTHS = (5, 8, 10, 12, 16)
TOPS = (2, 3, 4, 7)
ROMAN = "IVXLCDM"
SCOPES = ("all", "b1", "b2")
NB1 = len(B1)
KEEP = 100
# stats kept as histograms, per scope
STATS = ("win", "d") + tuple("cov%d" % w for w in WIDTHS) + tuple("top%d" % n for n in TOPS)
EXTRA = ("digits", "base", "roman")          # whole-clue stats that depend on the sign and naming


def profile(k):
    """(win, start, d, covs, tops, counts) for a list of key values mod 26."""
    c = [0] * 26
    for v in k:
        c[v] += 1
    vals = [v for v in range(26) if c[v]]
    gap, start = vals[0] + 26 - vals[-1], vals[0]
    for a, b in zip(vals, vals[1:]):
        if b - a > gap:
            gap, start = b - a, b
    acc = [0] + list(accumulate(c + c))
    covs = tuple(max(map(sub, acc[w:w + 26], acc)) for w in WIDTHS)
    s = sorted(c, reverse=True)
    t2 = s[0] + s[1]
    t3 = t2 + s[2]
    t4 = t3 + s[3]
    return 27 - gap, start, len(vals), covs, (t2, t3, t4, t4 + s[4] + s[5] + s[6]), c


def signed(c):
    """Sign-dependent numbers for one view and its negative, from the value counts c.

    Returns (digits, base): the most clue letters whose key value is a digit 0-9, and the
    smallest base b with every value below b, each taken as the better of the two signs."""
    lo = sum(c[:10])
    lo_neg = c[0] + sum(c[17:])
    hi = max(v for v in range(26) if c[v])
    nz = [v for v in range(1, 26) if c[v]]
    hi_neg = 26 - nz[0] if nz else 0
    return max(lo, lo_neg), min(hi, hi_neg) + 1


def roman_sets(m):
    """Value sets that spell only Roman numeral letters: the key letter read in A-Z, KRYPTOS or
    the tableau alphabet M, for a view and for its negative."""
    out = []
    for name, a in (("A-Z", AZ), ("KRYPTOS", KRYPTOS_ALPHABET), ("M", m)):
        r = [a.index(ch) for ch in ROMAN]
        out.append((name, "+", r))
        out.append((name, "-", [(-v) % 26 for v in r]))
    return out


class Tally:
    """Histograms of every stat and the best settings, for one ciphertext."""

    def __init__(self):
        self.h = {(sc, st): [0] * 27 for sc in SCOPES for st in STATS}
        for st in EXTRA:
            self.h["all", st] = [0] * 27
        self.best = {"win": [], "top7": [], "roman": [], "b1": [], "b2": []}
        self.cut = {}
        self.n = 0

    def keep(self, which, key, rec):
        cut = self.cut.get(which)
        if cut is not None and key >= cut:
            return
        lst = self.best[which]
        lst.append((key, rec))
        if len(lst) > 8 * KEEP:
            lst.sort()
            del lst[KEEP:]
            self.cut[which] = lst[-1][0]

    def merge(self, other):
        for key, v in other.h.items():
            mine = self.h[key]
            for i, x in enumerate(v):
                mine[i] += x
        for which, lst in other.best.items():
            self.best[which] = sorted(self.best[which] + lst)[:KEEP]
        self.n += other.n
        return self

    def top(self, which):
        return sorted(self.best[which])[:KEEP]

    def at_most(self, scope, stat, v):
        return sum(self.h[scope, stat][:v + 1])

    def at_least(self, scope, stat, v):
        return sum(self.h[scope, stat][v:])

    def lowest(self, scope, stat):
        h = self.h[scope, stat]
        v = next(i for i, x in enumerate(h) if x)
        return v, h[v]

    def highest(self, scope, stat):
        h = self.h[scope, stat]
        v = next(i for i in range(26, -1, -1) if h[i])
        return v, h[v]

    def summary(self):
        """The headline numbers: (value, how many settings reach it) per stat."""
        out = {}
        for sc in SCOPES:
            for st in STATS:
                out[sc + " " + st] = self.lowest(sc, st) if st in ("win", "d") else self.highest(sc, st)
        out["all digits"] = self.highest("all", "digits")
        out["all base"] = self.lowest("all", "base")
        out["all roman"] = self.highest("all", "roman")
        return out


def scan(alphas, pl, cl, tally=None):
    """Profile every key stream of every alphabet in `alphas` ([(name, alphabet)])."""
    t = tally or Tally()
    h = t.h
    hs = {sc: [h[sc, st] for st in STATS] for sc in SCOPES}
    hd, hb, hr = h["all", "digits"], h["all", "base"], h["all", "roman"]
    for name, m in alphas:
        rs = roman_sets(m)
        for lay, form, k, _, _ in streams(m, pl, cl):
            t.n += 1
            for sc, kk in (("all", k), ("b1", k[:NB1]), ("b2", k[NB1:])):
                win, start, d, covs, tops, c = profile(kk)
                hh = hs[sc]
                hh[0][win] += 1
                hh[1][d] += 1
                for j, v in enumerate(covs):
                    hh[2 + j][v] += 1
                for j, v in enumerate(tops):
                    hh[7 + j][v] += 1
                if sc == "all":
                    dg, base = signed(c)
                    hd[dg] += 1
                    hb[base] += 1
                    rbest = (-1, None, None)
                    for rn, sg, r in rs:
                        n = 0
                        for v in r:
                            n += c[v]
                        if n > rbest[0]:
                            rbest = (n, rn, sg)
                    hr[rbest[0]] += 1
                    rec = (name, lay, form, tuple(k), win, start, d, covs, tops)
                    t.keep("win", (win, d, -covs[2], name, lay, form), rec)
                    t.keep("top7", (-tops[3], d, win, name, lay, form), rec)
                    t.keep("roman", (-rbest[0], name, lay, form), rec + (rbest[1], rbest[2]))
                else:
                    t.keep(sc, (win, d, name, lay, form), (name, lay, form, tuple(k), win, start, d, covs, tops))
    return t


# ---------------------------------------------------------------- parallel search

_G = {}


def init(pl, cl):
    _G["pl"], _G["cl"] = pl, cl


def work(chunk):
    t = scan(chunk, _G["pl"], _G["cl"])
    for which in t.best:
        t.best[which] = t.top(which)
    return t


def search(ct, cribs, alphas, chunk=4000, procs=None):
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    total = Tally()
    for t in pmap(work, alphas, init, (pl, cl), chunk=chunk, procs=procs):
        total.merge(t)
    return total


# ---------------------------------------------------------------- planted messages

def encrypt(pt, key, m, lay="M/M", form="vig"):
    """Encrypt with key VALUES on a tableau: vig C = B[a(P) + k], beau C = B[k - a(P)]."""
    names = {"M": m, "AZ": AZ, "KR": KRYPTOS_ALPHABET}
    a, b = (names[x] for x in lay.split("/"))
    ia = {c: i for i, c in enumerate(a)}
    sg = 1 if form == "vig" else -1
    return "".join(b[(k + sg * ia[p]) % 26] for p, k in zip(pt, key))


def plant(rng, m, values, lay="M/M", form="vig"):
    """A random, non-periodic key drawn from `values` over an English 97-letter text."""
    pt = english97(rng)
    key = [rng.choice(values) for _ in pt]
    return encrypt(pt, key, m, lay, form), pt, key


def roman_values(alpha=AZ):
    return [alpha.index(ch) for ch in ROMAN]


def fmt_key(k):
    k = list(k)
    return " ".join("%2d" % v for v in k[:NB1]) + "  |  " + " ".join("%2d" % v for v in k[NB1:])


def line(rec):
    name, lay, form, k, win, start, d, covs, tops = rec[:9]
    return "%-22s %-5s %-4s window %2d (from %2d) distinct %2d cover5/8/10/12/16 %s any2/3/4/7 %s\n        %s" % (
        name[:22], lay, form, win, start, d, "/".join(map(str, covs)), "/".join(map(str, tops)), fmt_key(k))


# ---------------------------------------------------------------- side check: one clue block alone, many shuffles

def work_block(chunk):
    """Smallest window of the first clue block alone, for many ciphertexts at once: [min window per text]."""
    pl, cls = _G["pl"], _G["cl"]
    best = [26] * len(cls)
    for name, m in chunk:
        for j, cl in enumerate(cls):
            for lay, form, k, _, _ in streams(m, pl, cl):
                vals = sorted(set(k))
                gap = vals[0] + 26 - vals[-1]
                for a, b in zip(vals, vals[1:]):
                    if b - a > gap:
                        gap = b - a
                if 27 - gap < best[j]:
                    best[j] = 27 - gap
    return best


def block_windows(cts, cribs, alphas, block=B1, chunk=4000):
    pl = [cribs[i] for i in block]
    cls = [[ct[i] for i in block] for ct in cts]
    best = [26] * len(cts)
    for r in pmap(work_block, alphas, init, (pl, cls), chunk=chunk):
        best = [min(a, b) for a, b in zip(best, r)]
    return best
