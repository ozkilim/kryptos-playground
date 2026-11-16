"""Idea 54: mine the clues for ANY short formula for the key.

Earlier rounds tested named key rules one at a time (repeating, progressive, autokey, Gromark,
clock dials, row/column wheels). This turns the question round: take a library of ~190
ingredients a hand rule could use, and test EVERY combination of up to three of them (four on
a smaller library) for an exact fit to all the clue letters:

    idx(C_i) = a*idx(P_i) + sum_j  b_j * feature_j(i) + c      (mod 26)

The plaintext coefficient a is free, so Vigenere (a=1), Beaufort (a=-1) and every affine
tableau are covered at once. Alphabets: A-Z or KRYPTOS on each side (4 combinations).

Ingredients:
  position       i, i^2, i^3, triangular numbers, primes, Fibonacci, powers of 2 and 3, digits of pi and e
  grids          for every width 2-40: column, row, row*column; the carved 4/31/31/31 layout
  neighbours     P[i-L], C[i-L], P[i+L], C[i+L] for L = 1..5 (letter positions in A-Z and KRYPTOS)
  products       P*i, P^2, P*P[i-1], P*C[i-1], C[i-1]*C[i-2], P[i-1]*P[i-2]

24 equations against at most 6 unknowns: a wrong formula survives mod 13 with chance 13^-18
or less, so a single exact fit would be meaningful. "checks" = equations minus unknowns used.

  python attacks/54_formula_mining.py
"""
import itertools
import os
import random
import sys
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import POS, shuffled_control  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
ALPH = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
MIN_CHECKS = 8
# KRYPTOS_QMARK=1: count the "?" carved before K4 as symbol 0 (98 = 7 x 14 cells), shifting every grid
OFF = 1 if os.environ.get("KRYPTOS_QMARK") else 0
_S = {}


def carved(i):
    """(row, column) of K4 letter i on the copper: 4 letters end the K3 row, then rows of 31."""
    if i < 4:
        return 0, 27 + i
    return 1 + (i - 4) // 31, (i - 4) % 31


def library(ct, cribs, small=False):
    """{name: {pos: value}}; a feature is missing at positions where it needs unknown plaintext."""
    lib = {}
    pos = sorted(cribs)
    lib["i"] = {i: i for i in pos}
    lib["i^2"] = {i: i * i for i in pos}
    lib["i^3"] = {i: i ** 3 for i in pos}
    lib["tri(i)"] = {i: i * (i + 1) // 2 for i in pos}
    # number sequences a puzzle-maker might reach for (counted from 0 and from 1)
    pi = "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821"
    e = "27182818284590452353602874713526624977572470936999595749669676277240766303535475945713821785251664274274"
    primes = [n for n in range(2, 700) if all(n % d for d in range(2, int(n ** 0.5) + 1))]
    fib = [0, 1]
    while len(fib) < 110:
        fib.append(fib[-1] + fib[-2])
    for off in (0, 1):
        lib["pi_digit+%d" % off] = {i: int(pi[i + off]) for i in pos}
        lib["e_digit+%d" % off] = {i: int(e[i + off]) for i in pos}
        lib["prime+%d" % off] = {i: primes[i + off] for i in pos}
        lib["fib+%d" % off] = {i: fib[i + off] for i in pos}
    lib["2^i"] = {i: pow(2, i, 26 * 13) for i in pos}
    lib["3^i"] = {i: pow(3, i, 26 * 13) for i in pos}
    widths = (7, 31) if small else range(2, 41)
    for w in widths:
        lib["col%d" % w] = {i: (i + OFF) % w for i in pos}
        lib["row%d" % w] = {i: (i + OFF) // w for i in pos}
        lib["row*col%d" % w] = {i: ((i + OFF) % w) * ((i + OFF) // w) for i in pos}
    lib["carved_row"] = {i: carved(i)[0] for i in pos}
    lib["carved_col"] = {i: carved(i)[1] for i in pos}
    lib["carved_row*col"] = {i: carved(i)[0] * carved(i)[1] for i in pos}
    for an, a in ALPH.items():
        ia = {c: k for k, c in enumerate(a)}
        for lag in range(1, 6):
            lib["P[i-%d]%s" % (lag, an)] = {i: ia[cribs[i - lag]] for i in pos if i - lag in cribs}
            lib["P[i+%d]%s" % (lag, an)] = {i: ia[cribs[i + lag]] for i in pos if i + lag in cribs}
            lib["C[i-%d]%s" % (lag, an)] = {i: ia[ct[i - lag]] for i in pos if i - lag >= 0}
            lib["C[i+%d]%s" % (lag, an)] = {i: ia[ct[i + lag]] for i in pos if i + lag < len(ct)}
        lib["P*i %s" % an] = {i: ia[cribs[i]] * i for i in pos}
        lib["P^2 %s" % an] = {i: ia[cribs[i]] ** 2 for i in pos}
        lib["P*P[i-1] %s" % an] = {i: ia[cribs[i]] * ia[cribs[i - 1]] for i in pos if i - 1 in cribs}
        lib["P*C[i-1] %s" % an] = {i: ia[cribs[i]] * ia[ct[i - 1]] for i in pos}
        lib["C[i-1]*C[i-2] %s" % an] = {i: ia[ct[i - 1]] * ia[ct[i - 2]] for i in pos}
        lib["P[i-1]*P[i-2] %s" % an] = {i: ia[cribs[i - 1]] * ia[cribs[i - 2]]
                                        for i in pos if i - 1 in cribs and i - 2 in cribs}
    return lib


def fits(cols, target, p):
    """Is target in the span of cols (+ nothing else) over GF(p)? Rows = equations. Returns rank or -1."""
    m = [list(r) + [t] for r, t in zip(zip(*cols), target)]
    n = len(cols)
    r = 0
    for c in range(n):
        s = -1
        for i in range(r, len(m)):
            if m[i][c] % p:
                s = i
                break
        if s < 0:
            continue
        m[r], m[s] = m[s], m[r]
        inv = pow(m[r][c], p - 2, p) if p > 2 else 1
        pr = [(v * inv) % p for v in m[r]]
        m[r] = pr
        for i in range(r + 1, len(m)):
            f = m[i][c] % p
            if f:
                mi = m[i]
                m[i] = [(a - f * b) % p for a, b in zip(mi, pr)]
        r += 1
    for i in range(r, len(m)):
        if m[i][n] % p:
            return -1
    return r


def test_combo(names, lib, tgt_all, plain_all):
    """Returns (checks, ok mod 2) if the formula fits every usable clue letter mod 13, else None."""
    rows = [i for i in POS if all(i in lib[n] for n in names)]
    if len(rows) - len(names) - 2 < MIN_CHECKS:
        return None
    cols = [[1] * len(rows), [plain_all[i] for i in rows]] + [[lib[n][i] for i in rows] for n in names]
    tgt = [tgt_all[i] for i in rows]
    r = fits(cols, tgt, 13)
    if r < 0:
        return None
    checks = len(rows) - r
    if checks < MIN_CHECKS:
        return None
    return checks, fits(cols, tgt, 2) >= 0


def init(ct, cribs, small):
    _S["lib"] = library(ct, cribs, small)
    _S["ct"], _S["cribs"] = ct, cribs


def work(job):
    first, names, size = job
    lib, ct, cribs = _S["lib"], _S["ct"], _S["cribs"]
    hits, n = [], 0
    rest = names[names.index(first) + 1:]
    for an, a in ALPH.items():
        ia = {c: k for k, c in enumerate(a)}
        plain = {i: ia[cribs[i]] for i in POS}
        for bn, b in ALPH.items():
            ib = {c: k for k, c in enumerate(b)}
            tgt = {i: ib[ct[i]] for i in POS}
            for extra in itertools.combinations(rest, size - 1):
                combo = (first,) + extra
                n += 1
                res = test_combo(combo, lib, tgt, plain)
                if res:
                    hits.append(("pt%s/ct%s" % (an, bn), combo, res[0], res[1]))
    return n, hits


def mine(ct, cribs, procs=None, small=False):
    """Search sizes 0-3 on the full library and size 4 on the grid-free library."""
    init(ct, cribs, small)
    lib = _S["lib"]
    names = sorted(lib)
    core = [n for n in names if not (n.startswith("col") or n.startswith("row"))] + \
           [n for n in names if n in ("col7", "row7", "col31", "row31", "col21", "row21")]
    core = sorted(set(core))
    jobs = [(None, names, 0)]
    for size in (1, 2, 3):
        jobs += [(f, names, size) for f in names]
    if not small:
        jobs += [(f, core, 4) for f in core]
    tried, hits = 0, []
    # size 0: constant + plaintext coefficient only
    for an, a in ALPH.items():
        for bn, b in ALPH.items():
            tried += 1
            res = test_combo((), lib, {i: b.index(ct[i]) for i in POS}, {i: a.index(cribs[i]) for i in POS})
            if res:
                hits.append(("pt%s/ct%s" % (an, bn), (), res[0], res[1]))
    with Pool(procs, initializer=init, initargs=(ct, cribs, small)) as pool:
        for n, h in pool.imap_unordered(work, jobs[1:], chunksize=4):
            tried += n
            hits += h
    return tried, hits, len(names)


def plant(rng):
    """A message whose key follows a hidden 3-ingredient formula (grid row + column + previous plaintext)."""
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    w = rng.choice([7, 31])   # widths present in the small library, so the planted run is quick
    b1, b2, b3, c = rng.randrange(1, 26), rng.randrange(1, 26), rng.randrange(1, 26), rng.randrange(26)
    ct = []
    for i, p in enumerate(pt):
        prev = AZ.index(pt[i - 1]) if i else 0
        ct.append(AZ[(AZ.index(p) + b1 * ((i + OFF) % w) + b2 * ((i + OFF) // w) + b3 * prev + c) % 26])
    truth = ("col%d" % w, "row%d" % w, "P[i-1]AZ")
    return "".join(ct), {i: pt[i] for i in CRIBS}, truth


if __name__ == "__main__":
    small = bool(SMOKE)
    with Experiment("formula mining: every 0-4 ingredient linear key formula" + (" [? counted: 98 cells]" if OFF else ""), puzzle="k4",
                    notes="C = a*P + sum b_j*feature_j + c mod 26; position, grids 2-40, carved layout, "
                          "neighbour letters, products; exact fit to all usable clue letters", cribs_forced=True) as ex:
        tried, hits, nlib = mine(K4, CRIBS, small=small)
        ex.count(tried)
        print("library: %d ingredients; formulas tested: %d" % (nlib, tried))
        print("K4 formulas fitting mod 13 with >= %d checks: %d" % (MIN_CHECKS, len(hits)))
        for h in sorted(hits, key=lambda x: -x[2])[:20]:
            print("   %s  %s  checks=%d  also fits mod 2: %s" % h)
        ctrl = []
        for seed in (1, 2):
            t, h, _ = mine(shuffled_control(seed), CRIBS, small=small)
            ctrl.append(len(h))
        print("shuffled K4s: fits per control:", ctrl)
        rng = random.Random(11)
        ok = 0
        for _ in range(3):
            ct, cribs, truth = plant(rng)
            _, h, _ = mine(ct, cribs, small=True)
            found = any(set(x[1]) == set(truth) and x[3] for x in h)
            ok += found
            print("planted %s -> found exactly: %s (fits: %d)" % (truth, found, len(h)))
        print("planted recovered: %d/3" % ok)
        print("VERDICT:", "FIT FOUND - inspect" if hits else "no formula fits (K4 0; shuffled %s)" % ctrl)
