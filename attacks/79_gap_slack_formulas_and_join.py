"""Idea 79: the gap between the clues off by 1-3 letters, for formula mining and the three-keyword join.

EASTNORTHEAST sits at 21-33 and BERLINCLOCK at 63-73. Sanborn dropped a letter when he cut K2, so
one letter missing or extra between the two clues is a real possibility. Idea 68 re-ran the battery
of key rules with the second clue moved by -3..+3 and found nothing. Two other exact tests also tie
the clues together through their absolute positions and were only ever run with the carved gap:

  formula mining (54)   C = a*P + up to 3 of ~186 ingredients + c (mod 26). Position, grid row and
                        column, and number-sequence ingredients all depend on where a letter sits.
  three keywords (63)   Quagmire IV: two dictionary keyword alphabets and a repeating key. The key
                        slot of each clue letter is its position mod the key length.

Here both are re-run for gap shifts g = -3, -2, -1, +1, +2, +3. g > 0 means g letters were lost
between the clues (the encipherer's second clue sat at 63+g); g < 0 means -g letters were added.
The original attacks are used unchanged: we hand them the text with the gap put right
(kryptos/idea79_gap.py). Neither test reads a ciphertext letter further than 5 places from a clue,
so the answer does not depend on where between observed positions 39 and 57 the slip happened.

  formula part   sizes 0-3 on the full library (no size 4), 8 or more checks, as in 54
  join part      key lengths 1-20, Vigenere and Beaufort, every dictionary alphabet on each side;
                 every match decrypted, scored, and its key tested as a dictionary word, as in 63

Controls: 2 shuffled K4s per shift, in both parts. Planted: three formula-key messages and three
Quagmire IV messages with letters lost or added between the clues (+1, +2, -1), which must be found
at the right shift and must NOT be found with the carved gap.

  python attacks/79_gap_slack_formulas_and_join.py
"""
import os
import random
import sys
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea79_gap as G  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import english97  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
GAPS = (-1, 1) if SMOKE else G.GAPS
MAX_P = 20
PLANT_GAPS = (1, 2, -1)
CONTROL_SEEDS = (1, 2)


def carved(pt, enc, g, rng):
    """Encrypt pt, then damage the gap by g. Returns carved ciphertext and the clue letters as observed."""
    ct, seen = G.damage(enc, pt, g, rng)
    return ct, {i: seen[i] for i in CRIBS}


def formula_part(ex):
    small = bool(SMOKE)
    texts = [("K4", K4)] + [("shuffled %d" % s, shuffled_control(s)) for s in CONTROL_SEEDS]
    runs = {(name, g): G.regap(ct, CRIBS, g) for name, ct in texts for g in GAPS}
    with Pool(None, initializer=G.formula_init, initargs=(runs, small)) as pool:
        res = G.formula_mine(runs, small, pool=pool)
    k4_tried = sum(res["K4", g][0] for g in GAPS)
    ex.count(k4_tried)
    print("FORMULA MINING, sizes 0-3, %s library, >= %d checks" % ("small" if small else "full", G.m54().MIN_CHECKS))
    k4_hits = []
    for g in GAPS:
        h = res["K4", g][1]
        k4_hits += [(g,) + x for x in h]
        print("   gap %+d: K4 %d fits of %d formulas; shuffled %s" % (
            g, len(h), res["K4", g][0], [len(res["shuffled %d" % s, g][1]) for s in CONTROL_SEEDS]))
    for h in sorted(k4_hits, key=lambda x: -x[3])[:20]:
        print("      gap %+d %s %s checks=%d also fits mod 2: %s" % h)
    ctrl = [sum(len(res["shuffled %d" % s, g][1]) for g in GAPS) for s in CONTROL_SEEDS]

    # planted: formula key, gap damaged; search every shift and the carved gap on the small library
    rng = random.Random(79)
    plants, pruns = [], {}
    for k, g in enumerate(PLANT_GAPS):
        pt = english97(rng, 97 + g)
        enc, truth = G.formula_plant(pt, rng)
        ct, cribs = carved(pt, enc, g, rng)
        plants.append((g, truth))
        for t in (0,) + G.GAPS:
            pruns[k, t] = G.regap(ct, cribs, t)
    with Pool(None, initializer=G.formula_init, initargs=(pruns, True)) as pool:
        pres = G.formula_mine(pruns, True, pool=pool)
    ok = 0
    for k, (g, truth) in enumerate(plants):
        at = [t for t in (0,) + G.GAPS if any(set(x[1]) == set(truth) and x[3] for x in pres[k, t][1])]
        good = at == [g]
        ok += good
        print("   planted %s with gap %+d -> found at shifts %s (carved gap finds it: %s) %s" % (
            truth, g, at, 0 in at, "OK" if good else "MISSED"))
    print("   planted recovered: %d/%d" % (ok, len(plants)))
    return k4_tried, k4_hits, ctrl, ok


def join_job(args):
    label, ct, cribs, g, want = args
    return label, g, G.join_analyse(ct, cribs, g, max_p=MAX_P, want=want)


def join_part(ex):
    m = G.m63()
    alphas = m.alphabets()
    n_alpha = len(alphas)
    rng = random.Random(7963)
    jobs = [("K4", K4, CRIBS, g, None) for g in GAPS]
    jobs += [("shuffled %d" % s, shuffled_control(s), CRIBS, g, None) for s in CONTROL_SEEDS for g in GAPS]
    plants = []
    for k, g in enumerate(PLANT_GAPS):
        pt = english97(rng, 97 + g)
        (w1, a1), (w2, a2) = rng.choice(alphas[2:]), rng.choice(alphas[2:])
        key = rng.choice([w for L in range(7, 15) for w in sorted(m.words_by_length().get(L, []))[:400]])
        ct, cribs = carved(pt, G.join_plant(pt, a1, a2, key), g, rng)
        want = ("vig", w1, w2, len(key))
        plants.append((g, w1, w2, key))
        jobs += [("planted %d" % k, ct, cribs, g, want), ("planted %d" % k, ct, cribs, 0, want)]
    with Pool(min(6, os.cpu_count() or 2)) as pool:
        res = {(label, g): r for label, g, r in pool.imap_unordered(join_job, jobs)}
    tested = n_alpha * n_alpha * 2 * MAX_P * len(GAPS)
    ex.count(tested)
    print("THREE-KEYWORD JOIN, %d alphabets per side (%.1f billion pairs per key length and form), key lengths 1-%d" % (
        n_alpha, n_alpha ** 2 / 1e9, MAX_P))

    def summary(label):
        rs = [res[label, g] for g in GAPS]
        best = max((r["top"][0][0] for r in rs if r["top"]), default=-9.0)
        wbest = max((r["worded"][0][0] for r in rs if r["worded"]), default=None)
        return sum(r["n"] for r in rs), best, sum(r["n_worded"] for r in rs), wbest

    for label in ["K4"] + ["shuffled %d" % s for s in CONTROL_SEEDS]:
        n, best, nw, wbest = summary(label)
        print("   %s: %d consistent settings over all shifts; best partial decrypt %.2f; word keys %d (best %s)" % (
            label, n, best, nw, wbest))
        for g in GAPS:
            r = res[label, g]
            print("      gap %+d: %d settings, by key length %s, best %s, word keys %d" % (
                g, r["n"], dict(sorted(r["by_p"].items())), r["top"][0][0] if r["top"] else None, r["n_worded"]))
    print("   K4 best matches:")
    rows = sorted(((g,) + t for g in GAPS for t in res["K4", g]["top"]), key=lambda x: -x[1])
    for row in rows[:12]:
        print("      gap %+d score %.2f p=%d %s %s / %s  %s" % row)
    print("   K4 matches whose key can be a dictionary word:")
    for row in sorted(((g,) + t for g in GAPS for t in res["K4", g]["worded"]), key=lambda x: -x[1])[:12]:
        print("      gap %+d score %.2f p=%d %s %s / %s  %s  key %s" % row)
    ok = 0
    for k, (g, w1, w2, key) in enumerate(plants):
        hit, carved_hit = res["planted %d" % k, g], res["planted %d" % k, 0]
        good = hit["found"] and not carved_hit["found"]
        ok += good
        print("   planted %s / %s key %s (length %d) with gap %+d -> found at %+d: %s; with the carved gap: %s %s" % (
            w1, w2, key, len(key), g, g, hit["found"], carved_hit["found"], "OK" if good else "MISSED"))
    print("   planted recovered: %d/%d" % (ok, len(plants)))
    return tested, summary("K4"), [summary("shuffled %d" % s) for s in CONTROL_SEEDS], ok


if __name__ == "__main__":
    with Experiment("gap off by 1-3 letters: formula mining and the three-keyword join", puzzle="k4",
                    notes="second clue moved by %s; attack 54 sizes 0-3 (>=8 checks) and attack 63 hash join, key "
                          "lengths 1-%d; 2 shuffled K4s per shift" % (list(GAPS), MAX_P), cribs_forced=True) as ex:
        f_tried, f_hits, f_ctrl, f_ok = formula_part(ex)
        j_tested, j_k4, j_ctrl, j_ok = join_part(ex)
        print("planted recovered in all: %d/%d" % (f_ok + j_ok, 2 * len(PLANT_GAPS)))
        exact = [h for h in f_hits if h[4]]
        j_signal = j_k4[1] > max(c[1] for c in j_ctrl) + 0.4 or (j_k4[3] is not None and j_k4[3] > -4.6)
        if exact or j_signal:
            print("VERDICT: INSPECT (formula fits mod 26: %d; join best %.2f vs shuffled %s)" % (
                len(exact), j_k4[1], ["%.2f" % c[1] for c in j_ctrl]))
        else:
            print("VERDICT: no signal. Formulas: K4 %d fits of %d (shuffled %s). Join: K4 %d settings, best "
                  "decrypt %.2f, word keys %d (shuffled: %s)" % (
                      len(f_hits), f_tried, f_ctrl, j_k4[0], j_k4[1], j_k4[2],
                      ["%d settings, best %.2f, word keys %d" % (c[0], c[1], c[2]) for c in j_ctrl]))
