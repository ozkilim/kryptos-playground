"""Idea 92: short key formulas when the tableau alphabet is hidden.

Idea 54 tested every short formula for the key (position, grids, number sequences), but only with
A-Z or KRYPTOS as the tableau alphabet. Sanborn's coding chart need not be either. Here the formula
is the same kind, and the alphabet X is any order of the 26 letters at all:

  V      X[C] = X[P] + k        one hidden alphabet on both sides, Vigenere form
  B      X[C] = k - X[P]        one hidden alphabet on both sides, Beaufort form
  hpAZ / hpKR   A[C] = X[P] + k     hidden plain side, cipher side A-Z or KRYPTOS
  hcAZ / hcKR   X[C] = A[P] + k     hidden cipher side, plain side A-Z or KRYPTOS

  k_i = b1*f1(i) + b2*f2(i) + b3*f3(i) + c  (mod 26),   b = 1..25, c = 0..25

Ingredients f: idea 54's position and grid library without the neighbour-letter terms (idea 55 has
those): i, i^2, i^3, triangular numbers, primes, Fibonacci, powers of 2 and 3, digits of pi and e,
column / row / row*column for every width 2-40, the carved 4/31/31/31 layout.

Why a hidden alphabet can still be tested: the key is KNOWN once the formula is picked. Each clue
letter then says "cipher letter sits k places after plain letter" in X. K4's 24 clue letters tie 21
letters into one piece and close 4 loops, so 4 sums of key values must come out exactly (in layout V:
k = 0 where S encrypts to S and K to K, and two longer loops). After that the 21 letters must all land
on different positions. Chance for a random key: 26^-4 for the loops times 6.5e-6 for the positions,
about 1e-11. The half-hidden layouts give 10 or 11 exact tests.

This is the weighted union-find of kryptos/solvers/freealpha.py worked out once per ciphertext as
integer vectors (kryptos/idea92_hidden.py), so a formula costs a few dot products; because the tests
are linear in the formula, a hash join over single ingredients finds every fitting formula. That made
THREE ingredients affordable too (the idea asked for two).

Survivors are completed: the letters the clues do not place are tried on the free positions (all
orders when 6 or fewer are free, hill climbing otherwise) and the best reading is scored on the big
English model.

Not testable, and not tested: two DIFFERENT hidden alphabets (plain and cipher side). Then the clue
graph has almost no loops and nearly every formula fits.

  python attacks/92_formula_keys_hidden_alphabet.py
"""
import os
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.data import DATA_DIR, load, letters  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402
from kryptos import idea92_hidden as h  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
ENGLISH = -5.1          # big-model score a real reading reaches (planted texts: about -4.2 to -4.9)
SEEDS = (1, 2, 3) if SMOKE else tuple(range(1, 21))
SIZES = (0, 1, 2, 3)
RIGHT = 90              # letters of 97 a planted reading must get right (rare letters outside the clues are guessed)
# the same keys on the first text drawn, whatever its loops (a gauge of what fewer loop tests cost; not required)
LOOSE = [("V", [(3, "i")]), ("V", [(5, "i^2"), (10, "i")]), ("V", [(7, "row7"), (4, "col7")]),
         ("B", [(3, "i")]), ("B", [(5, "i^2"), (10, "i")]), ("B", [(7, "row7"), (4, "col7")])]

# (layout, formula): the three the idea names, in both forms, two half-hidden ones, one with 3 ingredients
PLANTS = [
    ("V", [(3, "i")]), ("V", [(5, "i^2"), (10, "i")]), ("V", [(7, "row7"), (4, "col7")]),
    ("B", [(3, "i")]), ("B", [(5, "i^2"), (10, "i")]), ("B", [(7, "row7"), (4, "col7")]),
    ("hpKR", [(5, "i^2"), (10, "i")]), ("hcAZ", [(7, "row7"), (4, "col7")]),
    ("V", [(7, "row7"), (4, "col7"), (9, "prime+0")]), ("B", [(2, "row31"), (21, "col31"), (5, "fib+1")]),
]


def run(ct, cribs, small, score, big, seed=0, layouts=h.LAYOUTS, sizes=SIZES):
    """All layouts on one ciphertext. Returns {layout: result} with the readings added."""
    out = {}
    for lay in layouts:
        r = h.search(lay, ct, cribs, small=small, sizes=sizes)
        rng = random.Random(9200 + seed)
        rows, total, laid = h.read_hits(r, ct, score, rng)
        r["rows"] = [(big.score(pt), sc, pt, name, x, k) for sc, pt, name, x, k in rows]
        r["rows"].sort(key=lambda x: (-x[0], x[3]))
        r["streams_hit"], r["laid"] = total, laid
        out[lay] = r
    return out


def line(lay, r):
    c26, c2, nl, pieces = r["loops"]
    best = r["rows"][0] if r["rows"] else None
    near = "closest miss %d/%d letters apart" % (r["near"], r["letters"]) if r["passes"] > len(r["hits"]) else "no near miss"
    return ("  %-4s tests %2d%s  letters %2d in %d piece%s | settings %13d | loop tests passed %8d, not flat %8d "
            "(uniform guess %10.1f) | fits %d%s (uniform guess %.3f) | %s%s%s" % (
                lay, c26, "+%d parity" % c2 if c2 else "", nl, pieces, "" if pieces == 1 else "s", r["tested"],
                r["passes"], r["passes"] - r["flat"], r["pred_passes"], r["laid"],
                " key streams (%d formulas fit piece by piece, %d key streams)" % (len(r["hits"]), r["streams_hit"])
                if r["hits"] else "", r["pred_hits"], near,
                " | best reading %.2f" % best[0] if best else "",
                " | NOT RUN: sizes %s (too few loop tests to decide)" % ",".join(r["skipped"]) if r["skipped"] else ""))


def show(r, n=3):
    for bsc, sc, pt, name, x, k in r["rows"][:n]:
        print("       %.2f on the big model, words %.2f  key = %s  alphabet %s\n       %s" % (
            bsc, word_coverage(pt), name, x, pt))


def totals(res):
    return (sum(r["tested"] for r in res.values()), sum(r["laid"] for r in res.values()),
            max([r["rows"][0][0] for r in res.values() if r["rows"]] or [None], key=lambda v: -99 if v is None else v))


if __name__ == "__main__":
    small = bool(SMOKE)
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    score = h.Scorer(big)
    text = letters(load("k2")["plaintext"] + load("k3")["plaintext"] + load("k1")["plaintext"])
    with Experiment("key formulas (0-3 ingredients) with a hidden tableau alphabet", puzzle="k4",
                    notes="k = b1*f1 + b2*f2 + b3*f3 + c mod 26 over position, sequence and grid (widths 2-40, carved) "
                          "ingredients; one hidden alphabet on both sides (Vig, Beau) or on one side against A-Z / KRYPTOS; "
                          "exact loop tests, then all placed letters on different positions; survivors completed on English",
                    cribs_forced=True) as ex:
        t0 = time.time()
        t = h.Tables("V", K4, CRIBS, small)
        print("library: %d ingredients, %d different on the clue positions" % (len(t.lib), t.ncls))
        nf, ns = h.distinct_streams(t)
        print("formulas with 0-2 ingredients (constant aside): %d; different key streams on the clue positions: %d "
              "(in layouts V and B a stream and its 11 other unit multiples are one test)" % (nf, ns))
        k4 = run(K4, CRIBS, small, score, big)
        n4, hits4, best4 = totals(k4)
        ex.count(n4)
        print("K4 (%.0f s):" % (time.time() - t0))
        for lay in h.LAYOUTS:
            print(line(lay, k4[lay]))
            show(k4[lay])
            for bsc, sc, pt, name, x, k in k4[lay]["rows"][:20]:
                ex.add(pt, layout=lay, key=name, alphabet=x)
        print("K4 total: %d (formula, constant) settings; fits (key streams laid out on one alphabet): %d; "
              "best reading: %s" % (n4, hits4, best4))

        ctrl = []
        for seed in SEEDS:
            c = shuffled_control(seed)
            res = run(c, CRIBS, small, score, big, seed)
            ctrl.append(totals(res) + (sum(len(r["skipped"]) > 0 for r in res.values()),))
            print("shuffled K4 seed %d: settings %d; fits %d; best reading %s (%.0f s)" % (
                (seed,) + ctrl[-1][:3] + (time.time() - t0,)))
            for lay in h.LAYOUTS:
                print(line(lay, res[lay]))
                show(res[lay], 1)
        ok = 0
        for j, (lay, terms) in enumerate(PLANTS):
            rng = random.Random(9200 + j)
            ct, cribs, pt, x, k, draws = h.plant(lay, terms, rng, text, t.lib)
            r = run(ct, cribs, small, score, big, j, layouts=(lay,))[lay]
            top = r["rows"][0] if r["rows"] else None
            in_hits = h.canon(lay, k) in {h.canon(lay, row[5]) for row in r["rows"]}
            good = bool(top) and in_hits and h.same_reading(top[2], pt) >= RIGHT and top[0] > ENGLISH
            ok += good
            print("planted %-4s key %s (text draw %d, %d loop tests): formulas fitting %d = %d key streams; true key among those read: %s; "
                  "best reading %s, %d/97 letters right -> found=%s" % (
                      lay, " + ".join("%d*%s" % bt for bt in terms), draws, r["loops"][0] + r["loops"][1],
                      len(r["hits"]), r["streams_hit"], in_hits, "%.2f" % top[0] if top else "-",
                      h.same_reading(top[2], pt) if top else 0, good))
        print("planted recovered: %d/%d" % (ok, len(PLANTS)))
        loose = 0
        for j, (lay, terms) in enumerate(LOOSE):
            rng = random.Random(9300 + j)
            ct, cribs, pt, x, k, draws = h.plant(lay, terms, rng, text, t.lib, min_tests=None)
            r = run(ct, cribs, small, score, big, j, layouts=(lay,), sizes=(0, 1, 2))[lay]
            top = r["rows"][0] if r["rows"] else None
            good = bool(top) and h.same_reading(top[2], pt) >= RIGHT and top[0] > ENGLISH
            loose += good
            print("first-text plant %-2s key %s (%d loop tests, %d letters in %d pieces): formulas fitting %d = %d key streams, %d laid out; "
                  "best reading %s, %d/97 letters right -> found=%s%s" % (
                      lay, " + ".join("%d*%s" % bt for bt in terms), r["loops"][0] + r["loops"][1], r["loops"][2],
                      r["loops"][3], len(r["hits"]), r["streams_hit"], r["laid"],
                      "%.2f" % top[0] if top else "-", h.same_reading(top[2], pt) if top else 0, good,
                      " (search left out: too few loop tests)" if r["skipped"] else ""))
        print("first-text plants found: %d/%d (not required: with few loop tests many keys fit and the reading decides)"
              % (loose, len(LOOSE)))
        cbest = [c[2] for c in ctrl if c[2] is not None]
        english = best4 is not None and best4 > ENGLISH
        beats = english and all(best4 > b + 0.3 for b in cbest)
        print("controls: fits per shuffled K4 %s; best readings %s; controls with a search left out: %d" % (
            [c[1] for c in ctrl], ["%.2f" % b for b in cbest], sum(c[3] > 0 for c in ctrl)))
        print("VERDICT:", "K4 has a fit that reads as English and beats the controls - inspect" if beats else
              "no signal (K4: %d fits, best reading %s; %d shuffled K4s: %d fits in all, best reading %s)" % (
                  hits4, best4, len(ctrl), sum(c[1] for c in ctrl), max(cbest) if cbest else None))
        if ok != len(PLANTS):
            print("WARNING: a planted answer was missed - the negative does not stand")
        print("total time %.0f s" % (time.time() - t0))
