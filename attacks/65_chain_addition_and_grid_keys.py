"""Idea 65: keys an agent can rebuild from memory: chain addition, and a row word + column word.

Scheidt (2011): K4's cipher is like those "provided agents or pilots in case of capture",
"simple, can be remembered". Two classic ways to stretch a short remembered word into a long
key with no period:

  A  CHAIN ADDITION in letters (the VIC / Gromark idea on a 26-letter wheel): start from the key
     word and make each new key letter from two earlier ones,
         K_i = a*K_{i-n} + b*K_{i-m} + c      (any two taps n < m <= 10; a, b, c free)
     Gromark with digits was tested in rounds 2, 6 and 7, and round 9's formula search reached
     taps up to 5. This covers every tap pair up to 10 and any multipliers.

  B  ROW WORD + COLUMN WORD on a worksheet grid: the key for a cell is (column letter + row
     letter), with both words free:      K(row, col) = col_key[col] + row_key[row]
     Widths 2-48. Suggested by the layout: the two clue blocks start exactly 42 letters apart,
     and 42 is the width of Sanborn's K3 worksheet; both starts are multiples of 7 and 21.
     Also run with the "?" before K4 counted as a cell (98 = 7 x 14).

Both are exact linear systems on the clue letters. Vigenere/Beaufort, A-Z/KRYPTOS each side.

  python attacks/65_chain_addition_and_grid_keys.py
"""
import os
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import BLOCKS, POS, shuffled_control, solve_mod_p  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
ALPH = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
MIN_CHECKS = 4


def views(ct, cribs):
    for an, a in ALPH.items():
        for bn, b in ALPH.items():
            for m, mn in ((1, "vig"), (-1, "beau")):
                yield "%s/%s/%s" % (an, bn, mn), {i: (b.index(ct[i]) - m * a.index(cribs[i])) % 26 for i in POS}


def fit(rows, rhs):
    """Checks passed (equations - rank mod 13) if consistent mod 13 and mod 2, else -1."""
    s13, s2 = solve_mod_p(rows, rhs, 13), solve_mod_p(rows, rhs, 2)
    if s13 is None or s2 is None:
        return -1
    return len(rows) - (len(rows[0]) - len(s13[1]))


def chain(ct, cribs):
    tried, hits = 0, []
    for name, key in views(ct, cribs):
        for m in range(2, 11):
            for n in range(1, m):
                rows, rhs = [], []
                for blk in BLOCKS:
                    for i in blk:
                        if i - m in blk:
                            rows.append([key[i - n], key[i - m], 1])
                            rhs.append(key[i])
                tried += 1
                if len(rows) < 3 + MIN_CHECKS:
                    continue
                ck = fit(rows, rhs)
                if ck >= MIN_CHECKS:
                    hits.append((ck, name, "taps %d,%d" % (n, m)))
    return tried, hits


def grid(ct, cribs, off):
    tried, hits = 0, []
    for name, key in views(ct, cribs):
        for w in range(2, 49):
            cols = sorted({(i + off) % w for i in POS})
            rws = sorted({(i + off) // w for i in POS})
            ci = {c: k for k, c in enumerate(cols)}
            ri = {r: len(cols) + k for k, r in enumerate(rws)}
            rows, rhs = [], []
            for i in POS:
                v = [0] * (len(cols) + len(rws))
                v[ci[(i + off) % w]] = 1
                v[ri[(i + off) // w]] = 1
                rows.append(v)
                rhs.append(key[i])
            tried += 1
            ck = fit(rows, rhs)
            if ck >= MIN_CHECKS:
                hits.append((ck, name, "width %d%s" % (w, " (? counted)" if off else "")))
    return tried, hits


def search(ct, cribs):
    t1, h1 = chain(ct, cribs)
    t2, h2 = grid(ct, cribs, 0)
    t3, h3 = grid(ct, cribs, 1)
    return t1 + t2 + t3, h1 + h2 + h3


def _pt(rng):
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    return text[o:o + 97]


def plant_chain(rng):
    pt, k = _pt(rng), KRYPTOS_ALPHABET
    m = rng.randrange(3, 8)
    n = rng.randrange(1, m)
    key = [rng.randrange(26) for _ in range(m)]
    while len(key) < 97:
        key.append((key[-n] + key[-m]) % 26)
    ct = "".join(k[(k.index(ch) + key[i]) % 26] for i, ch in enumerate(pt))
    return ct, {i: pt[i] for i in CRIBS}, ("KR/KR/vig", "taps %d,%d" % (n, m))


def plant_grid(rng):
    pt, k = _pt(rng), KRYPTOS_ALPHABET
    w = rng.choice([7, 14, 21])
    ck = [rng.randrange(26) for _ in range(w)]
    rk = [rng.randrange(26) for _ in range(97 // w + 1)]
    ct = "".join(k[(k.index(ch) + ck[i % w] + rk[i // w]) % 26] for i, ch in enumerate(pt))
    return ct, {i: pt[i] for i in CRIBS}, ("KR/KR/vig", "width %d" % w)


if __name__ == "__main__":
    with Experiment("chain-addition key in letters (any two taps <= 10) and row word + column word grids", puzzle="k4",
                    notes="K_i=a*K[i-n]+b*K[i-m]+c; K(r,c)=col[c]+row[r] widths 2-48, with and without the ? as a cell; "
                          "Vigenere/Beaufort, A-Z/KRYPTOS; exact", cribs_forced=True) as ex:
        tried, hits = search(K4, CRIBS)
        ex.count(tried)
        best = max((h[0] for h in hits), default=0)
        print("K4: %d settings, %d fit with >= %d checks" % (tried, len(hits), MIN_CHECKS))
        for h in sorted(hits, reverse=True)[:10]:
            print("   checks=%d %s %s" % h)
        ctrl = []
        for seed in range(1, 6 if SMOKE else 101):
            _, h = search(shuffled_control(seed), CRIBS)
            ctrl.append(max((x[0] for x in h), default=0))
        print("shuffled K4s: best checks max %d; controls with any fit: %d of %d" % (max(ctrl), sum(1 for c in ctrl if c), len(ctrl)))
        rng = random.Random(14)
        ok = 0
        for f in (plant_chain, plant_grid, plant_chain, plant_grid, plant_chain, plant_grid):
            ct, cribs, truth = f(rng)
            _, h = search(ct, cribs)
            found = any(x[1:] == truth for x in h)
            ok += found
            print("planted %s -> found=%s (best checks %d)" % (truth, found, max((x[0] for x in h), default=0)))
        print("planted recovered: %d/6" % ok)
        print("VERDICT:", "FIT - inspect" if best > max(ctrl) else
              "no signal (K4 best checks %d; shuffled best %d)" % (best, max(ctrl)))
