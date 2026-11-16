"""Idea 69: "ID BY ROWS" on a 21-wide grid.

EASTNORTHEAST starts at letter 21 and BERLINCLOCK at letter 63. Write K4 in rows of 21 and both
clues start a row (rows 2 and 4); the last row is 13 letters long, the length of EASTNORTHEAST;
and K3's worksheet was 42 = 2 x 21 wide. So the clue letters sit in the SAME 11 columns of two
different rows. If the column decides the key letter and the row decides something else (an
offset, a different tableau keyword, a different cipher form), then

    key(row 2, column c) - key(row 4, column c)   is the same for all 11 columns.

That is 10 exact checks, and it needs no guess about the key word.

  A  one dictionary tableau for both rows; row 4's key = row 2's key moved s columns (s = -5..5)
     plus a constant. s = 0 is "column word + row offset" (tested before on A-Z/KRYPTOS only).
  B  a DIFFERENT dictionary tableau per row (and a different layout or cipher form per row):
     every pair of alphabets, found with a hash join on the 10 column differences.

  python attacks/69_rows_of_21.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap, streams  # noqa: E402

MIN_CHECKS = 7
_S = {}


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]


def sig(v):
    """10 column differences packed into one integer."""
    s = 0
    for c in range(1, 11):
        s = s * 26 + (v[c] - v[0]) % 26
    return s


def work(chunk):
    """Per alphabet: A-hits, plus the row-2 and row-4 signatures of every layout and form."""
    hits, s2, s4 = [], [], []
    for name, m in chunk:
        for lay, form, k, _, _ in streams(m, _S["p"], _S["c"]):
            r2, r4 = k[:13], k[13:]
            s2.append(sig(r2))
            s4.append(sig(r4))
            for s in range(-5, 6):
                cs = [c for c in range(11) if 0 <= c + s < 13]
                d = set((r4[c] - r2[c + s]) % 26 for c in cs)
                if len(d) == 1 and len(cs) - 1 >= MIN_CHECKS:
                    hits.append((len(cs) - 1, name, lay, form, "row key moved %+d columns" % s))
    return hits, s2, s4


def search(ct, cribs, alphas):
    hits, a2, a4 = [], set(), []
    for h, s2, s4 in pmap(work, alphas, init, (ct, cribs)):
        hits += h
        a2.update(s2)
        a4 += s4
    joined = set(s for s in a4 if s in a2)
    return hits, joined, len(a2), len(a4)


def name_join(ct, cribs, alphas, joined):
    """Recover which (alphabet, layout, form) pairs produced the joined signatures."""
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    left, right = {}, {}
    for name, m in alphas:
        for lay, form, k, _, _ in streams(m, pl, cl):
            a, b = sig(k[:13]), sig(k[13:])
            if a in joined:
                left.setdefault(a, []).append((name, lay, form))
            if b in joined:
                right.setdefault(b, []).append((name, lay, form))
    return [(x, y) for s in joined for x in left.get(s, []) for y in right.get(s, [])]


def plant(rng, alphas, two_tableaux):
    pt = english97(rng)
    (n1, m1), (n2, m2) = rng.choice(alphas), rng.choice(alphas)
    if not two_tableaux:
        n2, m2 = n1, m1
    col = [rng.randrange(26) for _ in range(21)]
    off = [rng.randrange(26) for _ in range(5)]
    ct = []
    for i, ch in enumerate(pt):
        m = m2 if i // 21 == 3 else m1           # the BERLINCLOCK row has its own tableau
        ct.append(m[(m.index(ch) + col[i % 21] + off[i // 21]) % 26])
    return "".join(ct), {i: pt[i] for i in CRIBS}, n1, n2


if __name__ == "__main__":
    alphas = dictionary_alphabets(mixed=False)
    with Experiment("rows of 21: column key shared by the two clue rows, row decides offset or tableau", puzzle="k4",
                    notes="%d keyword alphabets x 5 layouts x 2 forms; A: row key moved -5..5 columns; "
                          "B: hash join over every pair of (alphabet, layout, form)" % len(alphas),
                    cribs_forced=True) as ex:
        hits, joined, n2, n4 = search(K4, CRIBS, alphas)
        ex.count(len(alphas) * 10 * 11 + n2 * n4)
        print("alphabets: %d; A tests %d; B pairs joined %d x %d = %.2e" % (len(alphas), len(alphas) * 110, n2, n4, n2 * n4))
        print("K4  A (one tableau, >= %d checks): %d hits" % (MIN_CHECKS, len(hits)))
        for h in sorted(hits, reverse=True)[:10]:
            print("   checks=%d %s %s %s %s" % h)
        print("K4  B (two tableaux, all 10 checks): %d hits" % len(joined))
        for x, y in name_join(K4, CRIBS, alphas, joined)[:10]:
            print("   row 2: %s   row 4: %s" % (x, y))
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3, 4, 5):
            h, j, _, _ = search(shuffled_control(seed), CRIBS, alphas)
            ctrl.append((len(h), len(j)))
        print("shuffled K4s (A hits, B hits):", ctrl)
        rng = random.Random(69)
        ok = 0
        for two in (False, True, True):
            ct, cribs, w1, w2 = plant(rng, alphas, two)
            h, j, _, _ = search(ct, cribs, alphas)
            pairs = name_join(ct, cribs, alphas, j)
            if two:
                found = any(x == (w1, "M/M", "vig") and y == (w2, "M/M", "vig") for x, y in pairs)
            else:
                found = any(x[1:] == (w1, "M/M", "vig", "row key moved +0 columns") for x in h)
            ok += found
            print("planted rows of 21, tableaux %s / %s -> found=%s (A %d, B %d)" % (w1, w2, found, len(h), len(j)))
        print("planted recovered: %d/3" % ok)
        print("VERDICT:", "HIT - inspect" if (hits or joined) and (len(hits), len(joined)) > max(ctrl) else
              "no signal (K4 A %d, B %d; shuffled %s)" % (len(hits), len(joined), ctrl))
