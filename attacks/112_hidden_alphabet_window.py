"""Idea 112: a small-number key under a hidden alphabet - the narrowest window any alphabet allows.

Bean noticed that K4's clue plaintext and ciphertext letters sit unusually close in the alphabet,
and the fingerprint ranking names "small-shift keys under an unknown mixed alphabet" as a top open
target. If the key is a list of small numbers (digits 0-9, values 0-4, clock hours 1-12), then on
the RIGHT alphabet all 24 key values forced by the clue letters lie inside a narrow window of
consecutive values. Idea 97 measured the narrowest window on 667,000 listed keyword tableaux
(K4: 12, inside the controls). Here the alphabet is free: for each layout we decide EXACTLY
whether any arrangement of the 26 letters puts all 24 key values inside a circular window of w
values, for w = 1, 2, 3 ... until it can be done, and report the smallest such w.

Layouts (kryptos/idea112_window.py has the algebra):
  same/vig   one hidden alphabet on both sides, k = x(C) - x(P)  (variant Beaufort is the mirror)
  same/beau  one hidden alphabet on both sides, k = x(C) + x(P)
  ptX/AZ, ptX/KR   hidden plain alphabet against A-Z / KRYPTOS on the cipher side
  ctX/AZ, ctX/KR   hidden cipher alphabet against A-Z / KRYPTOS on the plain side
  two        two independent hidden alphabets (extra; not in the idea's list)
With one hidden side Vigenere, Beaufort and variant are the same problem (mirror the alphabet).

The solver is backtracking with forward checking and an all-different matching test at every
node, so a "no" is a proof. Each clue block (EASTNORTHEAST, BERLINCLOCK) is also done alone.
Counts of arrangements are "up to shifting the alphabet" and capped at 10,000 (K4 only; the
controls need only the smallest w); letters outside the clues are free and not counted.

Statistic, fixed before the run: the primary layout is same/vig on all 24 clue letters. K4
counts as low only if its smallest w is at or below the value reached by at most 5% of the 200
shuffled K4s (one-sided p = share of shuffles with w <= K4's w, p < 0.05). Every layout and block
is reported; to pay for looking at all of them, K4's smallest p over the 7 full-clue layouts is
compared with the same "smallest p" of each shuffle (computed against the other shuffles).

Planted: three English 97-letter texts under random hidden alphabets with keys of digits 0-9,
values 0-4 and values 1-12, each enciphered in every layout. The solver must give w at or below
the planted window and the planted alphabet must be a solution the search reaches at that window.

Scope: a statistic, not a decryption. Windows wider than about 8 are feasible for most texts in
the one-alphabet layouts and say nothing there; see the power line printed after the plants.

  python attacks/112_hidden_alphabet_window.py
"""
import random
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round11 import POS, SMOKE, english97  # noqa: E402
from kryptos import idea112_window as W  # noqa: E402

SEEDS = tuple(range(1, 6)) if SMOKE else tuple(range(1, 201))
PARTS = ("all", "b1", "b2")
PRIMARY = ("same/vig", "all")
PLANTS = [("digits 0-9", list(range(10))), ("values 0-4", list(range(5))), ("values 1-12", list(range(1, 13)))]
BLOCKS = [list(range(13)), list(range(13, 24))]


def pval(v, vals):
    return sum(x <= v for x in vals) / float(len(vals))


def dist(vals):
    return " ".join("%d:%d" % (v, vals.count(v)) for v in sorted(set(vals)))


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("hidden alphabet: narrowest window of the 24 clue key values (exact)", puzzle="k4",
                    notes="7 layouts (one hidden alphabet both sides vig/beau; hidden plain or cipher side vs A-Z/KRYPTOS; "
                          "two hidden alphabets), smallest circular window w any arrangement allows, exact backtracking; "
                          "all clues and each block; %d shuffled controls; 3 planted texts x 3 small-number keys" % len(SEEDS),
                    cribs_forced=True) as ex:
        pl, cl = [CRIBS[i] for i in POS], [K4[i] for i in POS]
        k4 = W.profile(pl, cl, BLOCKS, count_cap=10000)
        decisions = sum(r[0] * len(W.Model(lay, pl, cl).starts) for (lay, _), r in k4.items())
        print("K4: smallest window w per layout (arrangements at w, capped at 10,000; window starts that work)")
        for lay in W.LAYOUTS:
            print("   %-10s " % lay + "   ".join("%s w=%2d (n=%s%s)" % (
                part, k4[(lay, part)][0], k4[(lay, part)][1], "+" if k4[(lay, part)][1] >= 10000 else "")
                for part in PARTS))
        for lay in ("same/vig", "same/beau", "ptX/AZ", "ctX/AZ"):
            w = k4[(lay, "all")][0]
            s, sol = W.one_solution(lay, pl, cl, w)
            places = {}
            for (g, letter), v in sol.items():
                places.setdefault(g, {})[v] = letter
            alph = " ".join("%s:" % g + "".join(places[g].get(v, ".") for v in range(26)) for g in sorted(places))
            print("   witness %-9s w=%d start %d  places %s" % (lay, w, s, alph))
        print("   (%.0f s)" % (time.time() - t0))

        # ---- shuffled controls
        ctrl = {}
        jobs = [(seed, K4, CRIBS, POS, 1) for seed in SEEDS]
        with Pool() as pool:
            for seed, res in pool.imap_unordered(W.control_job, jobs):
                ctrl[seed] = res
                decisions += sum(r[0] * (26 if lay.startswith("same") else 1) for (lay, _), r in res.items())
        ex.count(decisions)
        print("\n%d shuffled K4s done (%.0f s). K4 against the controls (p = share of shuffles with w <= K4's):" % (
            len(ctrl), time.time() - t0))
        pk = {}
        for lay in W.LAYOUTS:
            for part in PARTS:
                vals = [ctrl[s][(lay, part)][0] for s in SEEDS]
                v = k4[(lay, part)][0]
                pk[(lay, part)] = pval(v, vals)
                print("   %-10s %-3s K4 w=%2d   controls %-34s p=%.3f   5th pct %d" % (
                    lay, part, v, dist(vals), pk[(lay, part)], sorted(vals)[max(0, int(0.05 * len(vals)) - 1)]))
        prim = pk[PRIMARY]
        # pay for the choice: smallest p over the 7 full-clue layouts, compared with each shuffle's own
        k4min = min(pk[(lay, "all")] for lay in W.LAYOUTS)
        cmins = []
        for s in SEEDS:
            others = [t for t in SEEDS if t != s]
            cmins.append(min(pval(ctrl[s][(lay, "all")][0], [ctrl[t][(lay, "all")][0] for t in others])
                             for lay in W.LAYOUTS))
        adj = sum(c <= k4min for c in cmins) / float(len(cmins))
        print("\nprimary (same/vig, all 24): K4 w=%d, p=%.3f" % (k4[PRIMARY][0], prim))
        print("smallest p over the 7 full-clue layouts: K4 %.3f; shuffles with a smallest p this low or lower: %.3f"
              % (k4min, adj))

        # ---- planted answers
        rng = random.Random(11200)
        ok = tot = 0
        power = []
        for label, values in PLANTS:
            text = english97(rng)
            key = [rng.choice(values) for _ in range(97)]
            wp = max(values) - min(values) + 1
            for lay in W.LAYOUTS:
                X, Y = list(AZ), list(AZ)
                rng.shuffle(X)
                rng.shuffle(Y)
                alph = {"X": "".join(X), "Y": "".join(Y)}
                ct = W.encrypt(lay, text, key, alph)
                p, c = [text[i] for i in POS], [ct[i] for i in POS]
                assert W.key_values(lay, p, c, alph) == [key[i] for i in POS]
                wmin = W.min_window(lay, p, c, 1)[0]
                found = wmin <= wp and W.planted_found(lay, p, c, alph, wp)
                tot += 1
                ok += found
                vals = [ctrl[s][(lay, "all")][0] for s in SEEDS]
                power.append((label, lay, wmin, pval(wmin, vals)))
                print("planted %-11s %-10s planted window %2d -> smallest w %2d, truth among solutions at %d: %s;"
                      " shuffles with w <= %d: %.3f" % (label, lay, wp, wmin, wp, found, wmin, pval(wmin, vals)))
            ex.add(text, plant=label)
        print("\nplanted recovered: %d/%d" % (ok, tot))
        det = [x for x in power if x[3] < 0.05]
        print("power: planted texts that would have been called low (p < 0.05 in their own layout): %d/%d (%s)" % (
            len(det), len(power), ", ".join("%s %s" % (a, b) for a, b, _, _ in det) or "none"))

        low = prim < 0.05
        print("\nVERDICT:", "K4 LOW in the primary layout: complete the alphabet on the big model next" if low else
              "no signal: K4's smallest window sits inside the shuffled K4s (primary p=%.3f, choice-adjusted %.3f)"
              % (prim, adj))
        if ok != tot:
            print("WARNING: a planted answer was missed - the negative does not stand")
        print("decisions (text x layout x part x w x window start): %d; total %.0f s" % (decisions, time.time() - t0))
