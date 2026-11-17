"""Idea 88: word spaces use up key letters.

Scheidt (2015) said special characters "don't work" and must be accounted for. Suppose Sanborn
enciphered from a sheet that still had the word spaces, and the key simply ran on over each
space. Then the key position of letter i is i plus the number of word breaks before it. Earlier
tests restarted the key at words (idea 56) or moved the second clue by up to 3 places (idea 68),
but never let the key slip one place per word *inside* the clues.

Inside the clues the breaks are known, up to how the words were written:

  clue 1   EASTNORTHEAST  /  EAST|NORTHEAST  /  EAST|NORTH|EAST
  clue 2   BERLINCLOCK    /  BERLIN|CLOCK

The number of breaks between the clues is unknown, so the second clue gets every extra offset
0..25 (this also covers a break just before BERLIN, and a sentence break that eats two key
letters). The number of breaks before EAST only matters for the progressive rule; starts 0..11
cover every count for periods up to 12.

On each of these 156 position sets the round-11 battery of key rules runs on the clue letters:
repeating key (period 1-17), sliding key (1-15), progressive key (1-12), two stacked repeating
keys, chain addition. Autokey is skipped: a key made from the text does not care about spaces.
Tableaux: A-Z, KRYPTOS and every dictionary keyword alphabet in the five layouts, Vigenere and
Beaufort. Every test is exact. 7 or more independent coincidences count as a hit; near misses
with 5 or 6 are also counted, only to compare K4 with the controls where chance gives something.

  python attacks/88_spaces_use_key_letters.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea88_slip as S  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, pmap, streams  # noqa: E402

MIN_CHECKS = 7
LOW = 5                      # near misses, for the K4-versus-controls comparison only
_S = {}


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]
    S._tables(LOW)


def test_alphabet(name, m, pl, cl, min_checks=LOW):
    hits = []
    for lay, form, k, _, _ in streams(m, pl, cl):
        for ck, p1, p2, x, rule in S.fast_hits(k, min_checks):
            hits.append((ck, name, lay, form, p1, p2, x, rule))
    return hits


def work(chunk):
    hits = []
    for name, m in chunk:
        hits += test_alphabet(name, m, _S["p"], _S["c"])
    return hits


def search(ct, cribs, alphas):
    hits = []
    for h in pmap(work, alphas, init, (ct, cribs), chunk=400):
        hits += h
    return sorted(hits, reverse=True)


def show(h):
    ck, name, lay, form, p1, p2, x, rule = h
    return "checks=%d %s %s %s [%s, offset %s] %s" % (ck, name, lay, form, S.label(p1, p2),
                                                      "any" if x < 0 else "+%d" % x, rule)


def tally(hits):
    """(hits with >= MIN_CHECKS, near misses with LOW..MIN_CHECKS-1 checks, best checks)."""
    return (sum(1 for h in hits if h[0] >= MIN_CHECKS), sum(1 for h in hits if h[0] < MIN_CHECKS),
            max((h[0] for h in hits), default=0))


if __name__ == "__main__":
    alphas = dictionary_alphabets(mixed=False)
    n_streams = len(alphas) * 10 - 2
    n_sets = 3 * 2 * len(S.OFFSETS)
    n_tests = n_streams * n_sets
    with Experiment("spaces use up key letters: key-rule battery with word breaks counted in the key", puzzle="k4",
                    notes="%d alphabets x 5 layouts x Vigenere/Beaufort; 3 parsings of clue 1 x 2 of clue 2 x "
                          "extra offset 0..25 for clue 2 (progressive: starts 0..11 as well); repeating, sliding, "
                          "progressive, stacked, chain; >=%d checks" % (len(alphas), MIN_CHECKS),
                    cribs_forced=True) as ex:
        print("alphabets: %d; key streams: %d; position sets per stream: %d; settings: %d"
              % (len(alphas), n_streams, n_sets, n_tests))
        for mc in (MIN_CHECKS, LOW):
            e1, e0 = S.expected_chance(mc), S.expected_chance(mc, slipped=False)
            t1, t0 = sum(e1.values()), sum(e0.values())
            print("chance, uniformly random key values, >= %d checks: %.3g hits expected per ciphertext "
                  "(carved positions alone: %.3g; the breaks and offsets multiply chance by %.0f)"
                  % (mc, t1 * n_streams, t0 * n_streams, t1 / t0))
            print("   per family:", ", ".join("%s %.2g" % (f, v * n_streams) for f, v in e1.items()))
        hits = search(K4, CRIBS, alphas)
        ex.count(n_tests)
        k4 = tally(hits)
        print("K4: %d settings with >= %d checks, %d with %d-%d; best %d"
              % (k4[0], MIN_CHECKS, k4[1], LOW, MIN_CHECKS - 1, k4[2]))
        for h in hits[:20]:
            print("   " + show(h))
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            h = search(shuffled_control(seed), CRIBS, alphas)
            ctrl.append(tally(h))
            for x in h[:5]:
                print("   shuffled %d: %s" % (seed, show(x)))
        print("shuffled K4s (>= %d checks, %d-%d checks, best):" % (MIN_CHECKS, LOW, MIN_CHECKS - 1), ctrl)
        rng = random.Random(88)
        ok = 0
        for rule in ("repeating", "sliding", "progressive"):
            ct, cribs, want = S.plant(rng, alphas, rule)
            h = search(ct, cribs, alphas)
            found = any(x[1:] == want and x[0] >= MIN_CHECKS for x in h)
            carved = any(x[4:7] == (0, 0, 0) and x[1:4] == want[:3] for x in h)
            ok += found
            print("planted %s [%s, offset +%d] %s -> found=%s (settings passing %d; passes with the carved "
                  "positions: %s)" % (" ".join(want[:3]), S.label(want[3], want[4]), want[5], want[6], found,
                                      len(h), carved))
        print("planted recovered: %d/3" % ok)
        cb = max(c[2] for c in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if k4[2] >= MIN_CHECKS and k4[2] > cb + 1 else
              "no signal (K4 %d hits, %d near misses, best %d checks; shuffled %s)" % (k4[0], k4[1], k4[2], ctrl))
