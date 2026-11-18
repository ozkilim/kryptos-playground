"""Idea 133: a small-shift key on the first part of K4 only (hidden plain alphabet against A-Z).

The one measured anomaly left from idea 112: with a hidden plain alphabet and cipher letters on
A-Z, EASTNORTHEAST alone fits a key window of 5 (only 0.3% of shuffled K4s do), while BERLINCLOCK
and all 24 clue letters do not. Sanborn spoke of "two separate systems". So suppose the first part
of K4 (letters 1..E, E before BERLINCLOCK) was enciphered with a key of small numbers (digits
0-4, or 0-5) on a mixed plain alphabet, and the rest by something else.

The model: C_i = AZ[x(P_i) + k_i], k_i in 0..w-1, for letters 1..E. Each plain letter then has a
set of allowed places in the hidden alphabet (the cipher letters it stands under, minus 0..w-1);
a reading is possible exactly when all letters can take distinct places (a matching). The clue
block fixes E A S T N O R H to 4,288 arrangements at w = 5 and 36,960 at w = 6 (idea 112).

Part A, free key (any digit at each letter). Beam search, width 2000, on the big quadgram model:
letters 21..1 grown leftwards from EASTNORTHEAST, then 35..63 rightwards, the alphabet kept as
letter domains plus a matching (exact model; the 4,288 arrangements are covered implicitly).
Score = best mean quadgram of letters 1..E for E = 49..63 (15+ letters on the right).

Part B, key repeating with period p inside the window. The 13 clue key values then fix the whole
key (p <= 13), each letter's place is known, and the reading is a simple substitution on the
places EASTNORTHEAST leaves empty; solved by hill climbing for E = 49 and E = 63.
  w = 5: p = 2..13 (p = 13: the clue block's key repeated); w = 6: p = 2..11.

Controls: shuffled K4s (kryptos.round9.shuffled_control) whose first block ALSO fits w = 5
(about 0.3% of them), drawn until there are 10. K4 must beat all 10.
Planted: English 97-letter texts with the clues in place, letters 1..E under a 0-4 (or 0-5) key
on a random plain alphabet, the rest (BERLINCLOCK included) under a Vigenere word.

Scope: the first part only; it says nothing about the second part's system. One hidden plain
alphabet against straight A-Z cipher letters (ptX/AZ); no transposition.
"""
import random
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, english97  # noqa: E402
from kryptos.score import word_coverage  # noqa: E402
from kryptos import idea133_beam as B  # noqa: E402

BLK = "EASTNORTHEAST"
NCTRL = 2 if SMOKE else 10
WIDTH = 300 if SMOKE else 2000
PERIODS = {5: list(range(2, 9)) if SMOKE else list(range(2, 14)),
           6: list(range(2, 9)) if SMOKE else list(range(2, 12))}
ES = (49, 63)


def with_clues(text):
    t = list(text)
    for i, ch in CRIBS.items():
        t[i] = ch
    return "".join(t)


def periodic_plant(text, E, w, p, rng):
    X = list(B.AZ)
    rng.shuffle(X)
    key = [rng.randrange(w) for _ in range(p)]
    ct = "".join(B.AZ[(X.index(ch) + key[i % p]) % 26] if i < E else B.AZ[(ord(ch) - 65 + 11) % 26]
                 for i, ch in enumerate(text))
    return ct, key


def find_controls(n):
    out, seed = [], 0
    while len(out) < n:
        seed += 1
        sh = shuffled_control(seed, K4)
        if B.min_window_b1(sh, BLK) is not None and B.min_window_b1(sh, BLK) <= 5:
            out.append((seed, sh))
    return out, seed


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("first part only: small-shift key (0-4/0-5) on a hidden plain alphabet vs A-Z", puzzle="k4",
                    notes="idea 133: letters 1..E (E 49-63) C=AZ[x(P)+k], k in window 5 or 6; A: free key, beam 2000 "
                          "on big model; B: period 2-13 keys exact + hill climb; controls = shuffled K4s with "
                          "first block at w<=5", cribs_forced=True) as ex:
        print("K4 first block smallest window (ptX/AZ):", B.min_window_b1(K4, BLK))
        for w in (5, 6):
            print("  w=%d arrangements %d; period-p keys possible:" % (w, len(B.arrangements(K4, BLK, w))),
                  " ".join("p%d:%d" % (p, len(B.periodic_keys(K4, BLK, w, p))) for p in range(2, 14)))
        ctrls, scanned = find_controls(NCTRL)
        print("controls: %d shuffled K4s with first block at w<=5, found among seeds 1..%d (%.2f%%): seeds %s" % (
            len(ctrls), scanned, 100.0 * len(ctrls) / scanned, [s for s, _ in ctrls]))

        rng = random.Random(13300)
        texts = [("K4", K4)] + [("ctrl%d" % s, sh) for s, sh in ctrls]
        # planted free-key texts (Part A) and periodic texts (Part B)
        plantsA, plantsB, plant_keys = [], [], {}
        for E, w in ((50, 5), (58, 5), (63, 6)):
            pt = with_clues(english97(rng))
            ct, _ = B.plant(pt, E, w, rng)
            plantsA.append(("plantA_E%d_w%d" % (E, w), ct, pt, E, w))
        for E, w, p in ((58, 5, 8), (50, 5, 11), (63, 6, 7)):
            pt = with_clues(english97(rng))
            ct, key = periodic_plant(pt, E, w, p, rng)
            plant_keys["plantB_E%d_w%d_p%d" % (E, w, p)] = key
            plantsB.append(("plantB_E%d_w%d_p%d" % (E, w, p), ct, pt, E, w, p))

        jobsA = [(lab, ct, w, WIDTH) for lab, ct in texts for w in (5, 6)]
        jobsA += [(lab, ct, w, WIDTH) for lab, ct, _, _, w in plantsA]
        jobsB = [(lab, ct, w, p, ES, 7, 3) for lab, ct in texts for w in (5, 6) for p in PERIODS[w]]
        jobsB += [(lab, ct, w, p, ES, 7, 3) for lab, ct, _, _, w, _ in plantsB for p in PERIODS[w]]
        A, Bres = {}, {}
        tested = 0
        with Pool(13) as pool:
            for lab, w, res, n in pool.imap_unordered(B.beam_job, jobsA):
                A[(lab, w)] = res
                tested += n
            print("Part A done (%.0f s)" % (time.time() - t0))
            for lab, w, p, n, top in pool.imap_unordered(B.periodic_job, jobsB, chunksize=1):
                Bres[(lab, w, p)] = (n, top)
                tested += n * len(ES)
        ex.count(tested)
        print("Part B done (%.0f s)" % (time.time() - t0))

        # ---- Part A report
        def bestA(lab, w):
            r = A[(lab, w)]
            E = max(r, key=lambda e: r[e][0])
            return r[E][0], E, r[E][1]

        print("\nPART A: free key in the window, beam %d. Best mean quadgram (big model) over E=49..63" % WIDTH)
        okA = True
        for w in (5, 6):
            k = bestA("K4", w)
            cs = sorted(bestA(lab, w)[0] for lab, _ in texts[1:])
            beat = sum(k[0] > c for c in cs)
            print("  w=%d K4 %.3f (E=%d) %s  wc=%.2f" % (w, k[0], k[1], k[2], word_coverage(k[2])))
            print("       controls %s ; K4 beats %d/%d" % (" ".join("%.3f" % c for c in cs), beat, len(cs)))
            ex.add(k[2], part="A", w=w, E=k[1], score=round(k[0], 3))
        for lab, ct, pt, E, w in plantsA:
            s, Eb, txt = bestA(lab, w)
            reg = [i for i in range(min(E, Eb)) if not 21 <= i <= 33]
            agree = B.agreement(txt, pt, reg)
            cs = [bestA(l2, w)[0] for l2, _ in texts[1:]]
            print("  planted %s: best %.3f (E=%d) agree %d/%d; truth scores %.3f; beats %d/%d controls; %s" % (
                lab, s, Eb, agree, len(reg), B.mean_score(pt[:E]), sum(s > c for c in cs), len(cs), txt))
            okA = okA and agree >= 0.8 * len(reg)
        print("  Part A planted recovered (80%% of letters):", okA)

        # ---- Part B report
        print("\nPART B: key with period p inside the window (exact key from the clues + hill climb)")
        def bestB(lab, w):
            tops = [(t[0], p, t) for (l2, w2, p), (n, top) in Bres.items() if l2 == lab and w2 == w for t in top[:1]]
            return max(tops) if tops else (-99.0, None, None)
        for w in (5, 6):
            print("  w=%d  counts of period keys per p (K4): %s" % (w, " ".join(
                "p%d:%d" % (p, Bres[("K4", w, p)][0]) for p in PERIODS[w])))
            k = bestB("K4", w)
            cs = sorted(bestB(lab, w)[0] for lab, _ in texts[1:])
            if k[2]:
                print("  w=%d K4 best %.3f p=%d E=%d key %s %s  wc=%.2f" % (w, k[0], k[1], k[2][1], k[2][3], k[2][2],
                                                                        word_coverage(k[2][2])))
                ex.add(k[2][2], part="B", w=w, p=k[1], E=k[2][1], key=k[2][3], score=round(k[0], 3))
            have = [c for c in cs if c > -98]
            print("       controls %s ; K4 beats %d of the %d controls that have any period key (%d have none)" % (
                " ".join("%.3f" % c if c > -98 else "none" for c in cs), sum(k[0] > c for c in have), len(have),
                len(cs) - len(have)))
            for lab, _ in texts[1:]:
                print("       %s counts %s" % (lab, " ".join("p%d:%d" % (p, Bres[(lab, w, p)][0]) for p in PERIODS[w])))
        okB = True
        for lab, ct, pt, E, w, p in plantsB:
            s, pb, t = bestB(lab, w)
            if t is None or p not in PERIODS[w]:
                print("  planted %s: period not searched in this mode" % lab)
                continue
            allt = sorted(((x[0], p2, x) for (l2, w2, p2), (n, top) in Bres.items() if l2 == lab and w2 == w
                           for x in top), reverse=True)[:3]
            rank = None
            for r, (sc, p2, x) in enumerate(allt):
                reg = [q for q in range(min(E, x[1])) if not 21 <= q <= 33]
                if p2 == p and list(x[3]) == list(plant_keys[lab]) and B.agreement(x[2], pt, reg) >= 0.75 * len(reg):
                    rank = r + 1
                    break
            reg = [q for q in range(min(E, t[1])) if not 21 <= q <= 33]
            agree = B.agreement(t[2], pt, reg)
            cs = [bestB(l2, w)[0] for l2, _ in texts[1:]]
            good = rank is not None and all(s > c for c in cs)
            okB = okB and good
            print("  planted %s: best p=%d %.3f E=%d agree %d/%d; true key at rank %s of the top 3; beats %d/%d "
                  "controls; %s %s" % (lab, pb, s, t[1], agree, len(reg), rank, sum(s > c for c in cs), len(cs), t[2],
                                       "OK" if good else "MISSED"))
        print("  Part B planted recovered:", okB)
        print("\ntested (beam candidates + arrangement x E solves): %d; total %.0f s" % (tested, time.time() - t0))
