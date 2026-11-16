"""Idea 78: the round 11 battery on transposition-mixed keyword alphabets.

Ideas 68, 70, 71 (part B) and 74 tried every plain keyword alphabet (KRYPTOSABCDEFGH...).
A keyword alphabet is often mixed one step further by hand: write it in rows under the
keyword and read it off by columns, either left to right ("~cols") or in the alphabetical
order of the keyword's letters ("~keyed"). Round 10 used these two forms; the four round 11
tests did not. This script re-runs those four tests, with their own functions, on every
~cols / ~keyed alphabet that is not also a plain keyword alphabet:

  68   each clue alone, and both clues with the gap off by -3..+3 (battery of key rules)
  70   key arithmetic mod 27..31 (battery; multiplying key mod 29 and 31)
  71B  a fixed multiplier 3..23 on the plaintext letter, then the battery
  74   autokey where a repeating pattern says how far back to look (M/M tableau)

Every test is exact on the 24 clue letters and needs 7 or more independent checks.

To keep the run near half an hour, K4 is tested on every new alphabet, each of the three
shuffled K4s on a different third of them (every third alphabet, so theme, common and big
dictionary words are all in each), and each planted message on a sample of alphabets that
includes the one it was built on.

  python attacks/78_mixed_alphabet_battery.py
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE  # noqa: E402
from kryptos.idea78_mixed import PER_ALPHABET, TESTS, new_alphabets, plant, search  # noqa: E402

PLANTS = (("68", 0), ("68", 1), ("70", 0), ("70", 1), ("71", 0), ("74", 0), ("74", 1))
SAMPLE = 600 if SMOKE else 9000


def summary(hits):
    return {t: (len(h), max((x[0] for x in h), default=0)) for t, h in hits.items()}


if __name__ == "__main__":
    alphas = new_alphabets()
    if SMOKE:
        alphas = alphas[:3000]
    n_tests = len(alphas) * sum(PER_ALPHABET.values())
    with Experiment("round 11 battery (68, 70, 71B, 74) on transposition-mixed keyword alphabets", puzzle="k4",
                    notes="%d new ~cols/~keyed alphabets (plain keyword alphabets skipped); tests of attacks 68, 70, "
                          "71B, 74 unchanged; >=7 checks; controls on a third of the alphabets each" % len(alphas),
                    cribs_forced=True) as ex:
        t0 = time.time()
        hits = search(K4, CRIBS, alphas)
        ex.count(n_tests)
        k4 = summary(hits)
        print("new mixed alphabets: %d (%d ~cols, %d ~keyed); settings tested: %d; %.0f s" % (
            len(alphas), sum(n.endswith("~cols") for n, _ in alphas), sum(n.endswith("~keyed") for n, _ in alphas),
            n_tests, time.time() - t0))
        for t in TESTS:
            print("K4 test %s: %d settings pass with >= 7 checks; best %d (%d settings tried)" % (
                t, k4[t][0], k4[t][1], len(alphas) * PER_ALPHABET[t]))
            for h in sorted(hits[t], reverse=True)[:12]:
                print("   ", h)
        ctrl = []
        for seed in (1, 2, 3):
            part = alphas[seed - 1::3]
            c = summary(search(shuffled_control(seed), CRIBS, part))
            ctrl.append(c)
            print("shuffled K4 seed %d on %d alphabets (settings passing, best checks) per test: %s" % (seed, len(part), c))
        mixed_only = [a for a in alphas if "~" in a[0]]
        ok = 0
        for j, (t, variant) in enumerate(PLANTS):
            rng = random.Random(7800 + j)
            ct, cribs, want, found = plant(t, rng, mixed_only, variant)
            sample = rng.sample(alphas, min(SAMPLE, len(alphas)))
            if want[0] not in {n for n, _ in sample}:
                sample.append(next(a for a in alphas if a[0] == want[0]))
            h = search(ct, cribs, sample, tests=(t,), chunk=300)[t]
            f = found(h)
            ok += f
            print("planted test %s %s -> found=%s (settings passing %d of %d alphabets)" % (t, want, f, len(h), len(sample)))
        print("planted recovered: %d/%d" % (ok, len(PLANTS)))
        # controls saw a third of the alphabets each, so compare K4's count with three times a control's
        beats = [t for t in TESTS if k4[t][0] and all(k4[t][1] > c[t][1] + 1 for c in ctrl)]
        many = [t for t in TESTS if k4[t][0] > 3 * max(c[t][0] for c in ctrl) + 3]
        print("VERDICT:", "K4 beats every control in test(s) %s - inspect" % sorted(set(beats + many)) if beats or many else
              "no signal (K4 %s; shuffled %s)" % (k4, ctrl))
        if ok != len(PLANTS):
            print("WARNING: a planted answer was missed - the negative does not stand")
