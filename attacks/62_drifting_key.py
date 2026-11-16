"""Idea 62: a key word that DRIFTS. Each key letter moves on by its own step every cycle.

A new observation from the clues. EAST appears twice, 9 letters apart (inside EASTNORTHEAST),
and its two encryptions are nearly the same: FLRV and GKSS. Letter by letter the cipher moves
by +1, -1, +1, -3. In BERLINCLOCK the one pair 9 apart (B and C) also moves by +1. So over 9
letters the key barely changes, five times out of six, yet it is not a period-9 key (the two
clue blocks disagree completely).

Part A measures how unusual that is: for every cipher view and lag 1-12, count the within-block
pairs whose key letters differ by at most 1, score the most surprising lag, and compare with
shuffled K4s put through the same search (so the choice of lag and view is paid for).

Part B tests the model it suggests: a key of w letters where letter c steps on by its own
amount b_c each time round,

    key(row, column) = a_c + row * b_c        (rows of w letters; w = 2..40)

For each column with three or more clue letters the two unknowns are fixed by two of them and
the rest are checks. Widths up to 9 give at least 4 checks; wider keys cannot be decided.

  python attacks/62_drifting_key.py
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
OFF = 1 if os.environ.get("KRYPTOS_QMARK") else 0   # count the "?" before K4 as symbol 0 (98 cells)


def views(ct, cribs):
    for an, a in ALPH.items():
        for bn, b in ALPH.items():
            for m, mn in ((1, "vig"), (-1, "beau")):
                yield "%s/%s/%s" % (an, bn, mn), {i: (b.index(ct[i]) - m * a.index(cribs[i])) % 26 for i in POS}


def _tail(n, tot, q):
    """P(X >= n) for X ~ Binomial(tot, q)."""
    from math import comb
    return sum(comb(tot, k) * q ** k * (1 - q) ** (tot - k) for k in range(n, tot + 1))


def near_repeat(ct, cribs, tol=1):
    """Most surprising lag: over views and lags 1-12, the smallest binomial tail probability of
    (pairs inside a block whose key letters differ by <= tol). Returns (-log10 p, detail)."""
    from math import log10
    q = (2 * tol + 1) / 26
    best = (0.0, None)
    for name, key in views(ct, cribs):
        for lag in range(1, 13):
            n = tot = 0
            for blk in BLOCKS:
                for i in blk:
                    if i + lag in blk:
                        tot += 1
                        d = (key[i + lag] - key[i]) % 26
                        n += min(d, 26 - d) <= tol
            if tot >= 4:
                sc = -log10(_tail(n, tot, q))
                if sc > best[0]:
                    best = (sc, (name, "lag %d" % lag, "%d of %d pairs" % (n, tot)))
    return best


def drift_fit(key, w):
    """Checks passed by key(r,c) = a_c + r*b_c, or -1 if some column contradicts it."""
    checks = 0
    for c in range(w):
        pts = [((i + OFF) // w, key[i]) for i in POS if (i + OFF) % w == c]
        if len(pts) < 3:
            continue
        rows = [[1, r] for r, _ in pts]
        rhs = [k for _, k in pts]
        s13, s2 = solve_mod_p(rows, rhs, 13), solve_mod_p(rows, rhs, 2)
        if s13 is None or s2 is None:
            return -1
        checks += len(pts) - (2 - len(s13[1]))
    return checks


def search(ct, cribs):
    tried, hits = 0, []
    for name, key in views(ct, cribs):
        for w in range(2, 41):
            tried += 1
            ck = drift_fit(key, w)
            if ck >= MIN_CHECKS:
                hits.append((ck, name, w))
    return tried, hits


def plant(rng):
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    w = rng.randrange(5, 10)   # widths 10+ leave fewer than 4 checks: undecidable
    a = [rng.randrange(26) for _ in range(w)]
    b = [rng.randrange(26) for _ in range(w)]
    k = KRYPTOS_ALPHABET
    ct = "".join(k[(k.index(ch) + a[(i + OFF) % w] + ((i + OFF) // w) * b[(i + OFF) % w]) % 26] for i, ch in enumerate(pt))
    return ct, {i: pt[i] for i in CRIBS}, ("KR/KR/vig", w)


if __name__ == "__main__":
    with Experiment("drifting key word (each key letter steps at its own rate) + lag-9 near-repeat measured" + (" [? counted]" if OFF else ""),
                    puzzle="k4", notes="key(r,c)=a_c+r*b_c, widths 2-40, 8 cipher views, exact; plus near-repeat "
                    "statistic vs shuffles", cribs_forced=True) as ex:
        nr = near_repeat(K4, CRIBS)
        n = 300 if SMOKE else 5000
        ctrl = [near_repeat(shuffled_control(s), CRIBS)[0] for s in range(1, n + 1)]
        ge = sum(1 for c in ctrl if c >= nr[0])
        print("A. near-repeating key inside the clue blocks (key letters within 1 at some lag 1-12)")
        print("   K4: surprise %.2f %s | shuffled K4s: mean %.2f, max %.2f, %d of %d as high (p = %.4f)" % (
            nr[0], nr[1], sum(ctrl) / n, max(ctrl), ge, n, ge / n))
        print("B. drifting key word")
        tried, hits = search(K4, CRIBS)
        ex.count(tried)
        best = max((h[0] for h in hits), default=0)
        print("   K4: %d settings, %d fit with >= %d checks" % (tried, len(hits), MIN_CHECKS))
        for h in sorted(hits, reverse=True)[:8]:
            print("      checks=%d %s width=%d" % h)
        cb = []
        for seed in range(1, 6 if SMOKE else 201):
            _, h = search(shuffled_control(seed), CRIBS)
            cb.append(max((x[0] for x in h), default=0))
        print("   shuffled K4s: best checks max %d; controls with any fit: %d of %d" % (max(cb), sum(1 for c in cb if c), len(cb)))
        rng = random.Random(3)
        ok = 0
        for _ in range(5):
            ct, cribs, truth = plant(rng)
            _, h = search(ct, cribs)
            found = any(x[1:] == truth for x in h)
            ok += found
        print("   planted drifting keys recovered: %d/5" % ok)
        print("VERDICT:", "drift model FITS - inspect" if best > max(cb) else
              "drift model dead (K4 best checks %d; shuffled best %d). Near-repeat p = %.4f" % (best, max(cb), ge / n))
