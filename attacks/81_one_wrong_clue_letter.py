"""Idea 81: one deliberately wrong clue letter, for the round 9-11 exact tests.

Sanborn's texts carry deliberate misspellings (IQLUSION, UNDERGRUUND, DESPARATLY). If one of
the 24 clue letters of K4 is "misspelled" in the same way (the plaintext letter we assume, or
the cipher letter on the sculpture), every exact test of rounds 9-11 fails on the true method,
because those tests demand that all 24 letters fit. Round 7 (attack 45) allowed one wrong
letter only for periodic, two-key and Gromark models.

Here each of the 24 clue positions is left out in turn and three exact tests are re-run on the
23 letters that remain:

  battery   every keyword alphabet x 5 layouts x Vigenere/Beaufort, against the battery of key
            rules (repeating, sliding, progressive, autokey, two stacked keys, chain addition);
            7 or more independent checks
  pairs     attack 71 part A: C = A[i mod p] * P + B[i mod q], a multiplier word and an adder
            word, exact solve for every p, q = 1..17 on A-Z/KRYPTOS; 7 or more checks
  rotor     attack 72: a rotor with hidden wiring turned by a dictionary word (word, sliding
            word, word + 1 per letter; two numberings; four face pairs; both directions);
            hits are kept from 5 forced coincidences as in attack 72, 7+ is the headline

Leaving a letter out also loses the links through it (the key difference to its neighbours),
so the tests are a little weaker than on 24 letters; the planted answers show they still find
a message with one wrong clue letter.

To keep the run near half an hour, the battery runs on every alphabet for K4 and on a
different third of the alphabets for each of the three shuffled K4s (every third alphabet, so
each third has theme, common and big-dictionary words). The pairs and rotor tests run in full
on K4 and on every control. The planted sliding-key message is searched on a sample of
alphabets that includes the one it was built on.

  python attacks/81_one_wrong_clue_letter.py
"""
import random
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets, vocabulary  # noqa: E402
from kryptos.idea81_dropone import (MIN_CHECKS, ROTOR_MIN, battery_search, pairs_search, plant_pair,  # noqa: E402
                                    plant_rotor, plant_sliding, rotor_search)

PMAX = 6 if SMOKE else 17
SAMPLE = 400 if SMOKE else 9000


def best(hits):
    return max((h[0] for h in hits), default=0)


def strong(hits):
    return [h for h in hits if h[0] >= MIN_CHECKS]


def show(tag, hits):
    for h in sorted(hits, reverse=True)[:15]:
        print("   %s checks=%d %s  [dropped position %d]" % (tag, h[0], " ".join(str(x) for x in h[1:-1]), h[-1]))
    if hits:
        print("   %s hits by dropped position: %s" % (tag, dict(sorted(Counter(h[-1] for h in hits).items()))))


if __name__ == "__main__":
    alphas = dictionary_alphabets(mixed=False)
    words = sorted(set(w for w in vocabulary() if 2 <= len(w) <= 22))
    if SMOKE:
        alphas, words = alphas[:1500], words[:6000]
    n_bat = len(alphas) * 10 * 24
    n_rot = len(words) * 2 * 3 * 8 * 24
    with Experiment("one wrong clue letter: battery, multiplier+adder words and rotor on every 23 of the 24 clue letters",
                    puzzle="k4",
                    notes="each of 24 clue positions dropped in turn; battery on %d keyword alphabets x 5 layouts x "
                          "Vig/Beau (>=%d checks); 71A p,q=1..%d on A-Z/KRYPTOS (>=%d checks); rotor wire test with %d "
                          "words x 3 schemes x 2 numberings (>=%d coincidences kept, 7+ headline); battery controls "
                          "on a third of the alphabets each" % (len(alphas), MIN_CHECKS, PMAX, MIN_CHECKS, len(words),
                                                                ROTOR_MIN),
                    cribs_forced=True) as ex:
        t0 = time.time()
        bh = battery_search(K4, CRIBS, alphas)
        print("battery: %d alphabets, %d (stream, dropped letter) settings; K4 passes with >= %d checks: %d, best %d "
              "(%.0f s)" % (len(alphas), n_bat, MIN_CHECKS, len(bh), best(bh), time.time() - t0))
        show("battery", bh)
        n_pair, ph = pairs_search(K4, CRIBS, PMAX)
        print("pairs: %d (view, dropped letter, p, q) systems; K4 fits with >= %d checks: %d, best %d" % (
            n_pair, MIN_CHECKS, len(ph), best(ph)))
        show("pairs", ph)
        t1 = time.time()
        rh = rotor_search(K4, CRIBS, words)
        print("rotor: %d words, %d (setting, dropped letter) tests; K4 real wirings with >= %d coincidences: %d "
              "(with >= 7: %d), best %d (%.0f s)" % (len(words), n_rot, ROTOR_MIN, len(rh), len(strong(rh)), best(rh),
                                                     time.time() - t1))
        show("rotor", rh)
        ex.count(n_bat + n_pair + n_rot)

        ctrl = []
        for seed in (1, 2, 3):
            c = shuffled_control(seed)
            part = alphas[seed - 1::3]
            cb = battery_search(c, CRIBS, part)
            cp = pairs_search(c, CRIBS, PMAX)[1]
            cr = rotor_search(c, CRIBS, words)
            ctrl.append({"battery": (len(cb), best(cb)), "pairs": (len(cp), best(cp)),
                         "rotor5": (len(cr), best(cr)), "rotor7": len(strong(cr))})
            print("shuffled K4 seed %d: battery on %d alphabets (%d settings) passes %d, best %d; pairs %d, best %d; "
                  "rotor >=%d: %d, >=7: %d, best %d" % (seed, len(part), len(part) * 240, len(cb), best(cb), len(cp),
                                                        best(cp), ROTOR_MIN, len(cr), len(strong(cr)), best(cr)))
            show("  control battery", cb)
            show("  control pairs", cp)
            show("  control rotor", cr)

        ok = 0
        for j in range(3):                      # sliding key with one wrong clue letter
            rng = random.Random(8100 + j)
            ct, cribs, want = plant_sliding(rng, alphas)
            sample = rng.sample(alphas, min(SAMPLE, len(alphas)))
            if want[0] not in {n for n, _ in sample}:
                sample.append(next(a for a in alphas if a[0] == want[0]))
            h = battery_search(ct, cribs, sample, chunk=200)
            found = any(x[1:] == want for x in h)
            ok += found
            print("planted battery %s -> found=%s (settings passing %d, on %d alphabets)" % (want, found, len(h), len(sample)))
        for j in range(2):
            ct, cribs, want = plant_pair(random.Random(8110 + j))
            h = pairs_search(ct, cribs, PMAX)[1]
            found = any(x[1:] == want for x in h)
            ok += found
            print("planted pairs %s -> found=%s (fits %d)" % (want, found, len(h)))
        for j in range(2):
            ct, cribs, want = plant_rotor(random.Random(8120 + j), words)
            h = rotor_search(ct, cribs, words)
            found = any(x[1:] == want for x in h)
            ok += found
            print("planted rotor %s -> found=%s (settings passing %d)" % (want, found, len(h)))
        print("planted recovered: %d/7" % ok)

        # compare as rates: the battery controls saw a third of the alphabets each
        k4_rate = len(bh) / float(n_bat)
        c_rate = max(c["battery"][0] / float(len(alphas[s::3]) * 240) for s, c in enumerate(ctrl))
        beats = ((bh and k4_rate > 3 * c_rate and best(bh) > max(c["battery"][1] for c in ctrl) + 1)
                 or (ph and best(ph) > max(c["pairs"][1] for c in ctrl) + 1)
                 or (rh and best(rh) > max(c["rotor5"][1] for c in ctrl) + 1))
        print("VERDICT:", "K4 beats every control - inspect" if beats else
              "no signal (K4 battery %d best %d, pairs %d best %d, rotor %d (>=7: %d) best %d; shuffled %s)" % (
                  len(bh), best(bh), len(ph), best(ph), len(rh), len(strong(rh)), best(rh), ctrl))
