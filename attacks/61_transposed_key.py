"""Idea 61: K2's system keyed by K3's system. Scramble the KEY, leave the text in place.

Sanborn: the lower half uses "two separate systems". K3 is a grid transposition; K1/K2 are a
key word on a tableau. Every earlier test that combined them scrambled the TEXT, which breaks
Sanborn's statement that BERLINCLOCK sits where its cipher letters sit. There is another way
to use both systems that keeps every letter in place: write the repeating key word out 97
letters long, scramble THAT with a grid route, and encipher with the scrambled key.

    C_i = P_i + key[ perm(i) mod p ]

The result has no period (the scramble hides it), flat statistics, and is "plain letter in,
cipher letter out". It is also an easy hand job: one extra worksheet for the key.

Scrambles tried (each also inverted):
  columnar      every column order for widths 2-8; keyword orders (dictionary) for widths 9-14
  K3 rotations  one quarter-turn at every width 2-48, and every pair of widths (double rotation)
  routes        columns, back-and-forth rows/columns, spirals, diagonals at every width 2-48
  skips         every a-th position (a*i + b mod 97)
  grid-linear   slot = alpha*column + beta*row mod p for every width 2-48

Then: do equal key slots get equal key letters at the 24 clue positions? p = 2..26,
Vigenere/Beaufort, A-Z/KRYPTOS each side. "checks" = 24 - distinct slots; survivors need 6.

  python attacks/61_transposed_key.py
"""
import itertools
import os
import random
import sys
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import POS, shuffled_control  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
# KRYPTOS_QMARK=1: count the "?" carved before K4 as symbol 0, so the key grid has 98 = 7 x 14 cells
OFF = 1 if os.environ.get("KRYPTOS_QMARK") else 0
N = 97 + OFF
MIN_CHECKS = 6
ALPH = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
_S = {}


def columnar(order):
    """Text written in rows of len(order), columns read in `order`: perm[j] = source index."""
    w = len(order)
    return [i for c in order for i in range(c, N, w)]


def rotate(seq, w):
    """K3-style quarter turn: write seq in rows of w, read columns from the right, top to bottom."""
    return [seq[i] for c in range(w - 1, -1, -1) for i in range(c, len(seq), w)]


def routes(w):
    h = -(-N // w)
    cell = lambda r, c: r * w + c
    ok = lambda r, c: 0 <= r < h and 0 <= c < w and cell(r, c) < N
    yield "columns w%d" % w, [cell(r, c) for c in range(w) for r in range(h) if ok(r, c)]
    yield "snake rows w%d" % w, [cell(r, c if r % 2 == 0 else w - 1 - c) for r in range(h) for c in range(w)
                                 if ok(r, c if r % 2 == 0 else w - 1 - c)]
    yield "snake columns w%d" % w, [cell(r if c % 2 == 0 else h - 1 - r, c) for c in range(w) for r in range(h)
                                    if ok(r if c % 2 == 0 else h - 1 - r, c)]
    yield "diagonals w%d" % w, [cell(r, d - r) for d in range(h + w - 1) for r in range(h) if ok(r, d - r)]
    yield "anti-diagonals w%d" % w, [cell(r, w - 1 - (d - r)) for d in range(h + w - 1) for r in range(h)
                                     if ok(r, w - 1 - (d - r))]
    # spiral inwards, clockwise from the top-left
    seen, out, r, c, dr, dc = set(), [], 0, 0, 0, 1
    for _ in range(h * w):
        if ok(r, c):
            out.append(cell(r, c))
        seen.add((r, c))
        nr, nc = r + dr, c + dc
        if not (0 <= nr < h and 0 <= nc < w) or (nr, nc) in seen:
            dr, dc = dc, -dr
            nr, nc = r + dr, c + dc
        r, c = nr, nc
    if len(out) == N:
        yield "spiral w%d" % w, out


def keyword_orders(minw=9, maxw=14, limit=None):
    seen, out = set(), []
    for w in wordkeys.theme_words() + wordkeys.common_words() + wordkeys.big_dictionary():
        if not (minw <= len(w) <= maxw):
            continue
        order = tuple(sorted(range(len(w)), key=lambda i: (w[i], i)))
        if order not in seen:
            seen.add(order)
            out.append(order)
            if limit and len(out) >= limit:
                break
    return out


def perm_jobs():
    """Chunks of (name, perm) generators, described compactly so workers can rebuild them."""
    jobs = [("routes", w) for w in range(2, 49)]
    jobs += [("rot1", 0)]
    jobs += [("rot2", w1) for w1 in range(2, 12 if SMOKE else 49)]
    jobs += [("skip", a) for a in range(2, 12 if SMOKE else 97)]
    for w in range(2, 7 if SMOKE else 9):
        allp = list(itertools.permutations(range(w)))
        for i in range(0, len(allp), 2000):
            jobs.append(("col", allp[i:i + 2000]))
    kw = keyword_orders(limit=2000 if SMOKE else None)
    for i in range(0, len(kw), 2000):
        jobs.append(("col", kw[i:i + 2000]))
    return jobs


def perms(job):
    kind, arg = job
    ident = list(range(N))
    if kind == "routes":
        yield from routes(arg)
    elif kind == "rot1":
        for w in range(2, 49):
            yield "rotation w%d" % w, rotate(ident, w)
    elif kind == "rot2":
        first = rotate(ident, arg)
        for w2 in range(2, 49):
            yield "rotations w%d then w%d" % (arg, w2), rotate(first, w2)
    elif kind == "skip":
        from math import gcd
        if gcd(arg, N) == 1:
            for b in range(N):
                yield "skip %d*i+%d" % (arg, b), [(arg * i + b) % N for i in range(N)]
    else:
        for order in arg:
            yield "columnar %s" % (order,), columnar(order)


def key_views(ct, cribs):
    out = []
    for an, a in ALPH.items():
        for bn, b in ALPH.items():
            for m, mn in ((1, "vig"), (-1, "beau")):
                out.append(("%s/%s/%s" % (an, bn, mn), [(b.index(ct[i]) - m * a.index(cribs[i])) % 26 for i in POS]))
    return out


def check_slots(src, views, name, hits):
    """src[k] = key-table index used at the k-th clue position."""
    n = 0
    for p in range(2, 27):
        slots = [s % p for s in src]
        distinct = len(set(slots))
        if 24 - distinct < MIN_CHECKS:
            continue
        for vname, key in views:
            n += 1
            seen, ok = {}, True
            for s, k in zip(slots, key):
                if seen.setdefault(s, k) != k:
                    ok = False
                    break
            if ok:
                hits.append((24 - distinct, name, p, vname))
    return n


def init(ct, cribs):
    _S["views"] = key_views(ct, cribs)


def work(job):
    views, hits, n = _S["views"], [], 0
    if job[0] == "linear":
        w = job[1]
        for p in range(2, 27):
            for al in range(p):
                for be in range(p):
                    if al == 0 and be == 0:
                        continue
                    slots = [(al * ((i + OFF) % w) + be * ((i + OFF) // w)) % p for i in POS]
                    distinct = len(set(slots))
                    if 24 - distinct < MIN_CHECKS:
                        continue
                    for vname, key in views:
                        n += 1
                        seen, ok = {}, True
                        for s, k in zip(slots, key):
                            if seen.setdefault(s, k) != k:
                                ok = False
                                break
                        if ok:
                            hits.append((24 - distinct, "grid w%d slot=%d*col+%d*row" % (w, al, be), p, vname))
        return n, hits
    for name, perm in perms(job):
        if len(perm) != N:
            continue
        n += check_slots([perm[i + OFF] for i in POS], views, name, hits)
        inv = [0] * N
        for j, s in enumerate(perm):
            inv[s] = j
        n += check_slots([inv[i + OFF] for i in POS], views, name + " (inverse)", hits)
    return n, hits


def search(ct, cribs, procs=None):
    jobs = perm_jobs() + [("linear", w) for w in range(2, 12 if SMOKE else 49)]
    tried, hits = 0, []
    with Pool(procs, initializer=init, initargs=(ct, cribs)) as pool:
        for n, h in pool.imap_unordered(work, jobs):
            tried += n
            hits += h
    return tried, hits


def plant(rng, kind):
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    p = rng.randrange(5, 10)
    key = [rng.randrange(26) for _ in range(p)]
    if kind == "rot2":
        w1, w2 = rng.randrange(2, 11), rng.randrange(2, 30)
        name, perm = "rotations w%d then w%d" % (w1, w2), rotate(rotate(list(range(N)), w1), w2)
    else:
        order = tuple(rng.sample(range(6), 6))
        name, perm = "columnar %s" % (order,), columnar(order)
    k = KRYPTOS_ALPHABET
    ct = "".join(k[(k.index(ch) + key[perm[i + OFF] % p]) % 26] for i, ch in enumerate(pt))
    return ct, {i: pt[i] for i in CRIBS}, (name, p)


if __name__ == "__main__":
    with Experiment("scrambled key: K3-style transposition applied to the repeating key" + (" [? counted: 98 cells]" if OFF else ""), puzzle="k4",
                    notes="C_i = P_i + key[perm(i) mod p]; columnar 2-8 all orders + keyword orders 9-14, single/double "
                          "rotations, routes, skips, grid-linear slots; p 2-26; exact", cribs_forced=True) as ex:
        tried, hits = search(K4, CRIBS)
        ex.count(tried)
        best = max((h[0] for h in hits), default=0)
        print("K4: %d settings, %d survive with >= %d checks (best %d)" % (tried, len(hits), MIN_CHECKS, best))
        for h in sorted(hits, reverse=True)[:10]:
            print("   checks=%d %s p=%d %s" % h)
        ctrl = []
        for seed in range(1, 3 if SMOKE else 6):
            _, h = search(shuffled_control(seed), CRIBS)
            ctrl.append((len(h), max((x[0] for x in h), default=0)))
        print("shuffled K4s (survivors, best checks):", ctrl)
        rng = random.Random(12)
        ok = 0
        for kind in ("rot2", "col", "rot2", "col"):
            ct, cribs, truth = plant(rng, kind)
            _, h = search(ct, cribs)
            found = any(x[1] == truth[0] and x[2] == truth[1] for x in h)
            ok += found
            print("planted %s -> found=%s (survivors %d, best checks %d)" % (truth, found, len(h), max((x[0] for x in h), default=0)))
        print("planted recovered: %d/4" % ok)
        cbest = max(c[1] for c in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if best > cbest else
              "no signal (K4 best checks %d, %d survivors; shuffled best %d, survivors %s)" % (
                  best, len(hits), cbest, [c[0] for c in ctrl]))
