"""Idea 68: stop trusting the 42-letter gap between the two clues.

Almost every exact test so far joins EASTNORTHEAST (21-33) and BERLINCLOCK (63-73) through the
gap between them: the key must be in step across 42 letters. Sanborn dropped a letter when he
carved K2. If one letter is missing or extra between the clues, or the system simply restarts
somewhere in between, every one of those joint tests fails on the true answer.

Two robust re-tests on every dictionary keyword tableau (plain keyword alphabets, five
layouts, Vigenere and Beaufort):

  each clue alone   the battery of key rules on block 1 only and on block 2 only
                    (repeating, sliding, progressive, autokey, stacked, chain addition)
  gap slack         both blocks together, but with the second block's key position moved by
                    -3..+3 (1 to 3 letters dropped or added between the clues)

Every test is exact and needs 7 or more independent coincidences to count.

  python attacks/68_blocks_alone_and_gap_slack.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import B1, B2, POS, SMOKE, battery, dictionary_alphabets, english97, pmap, streams  # noqa: E402

GAPS = (-3, -2, -1, 1, 2, 3)
MIN_CHECKS = 7
_S = {}


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]


def test_alphabet(name, m, pl, cl):
    hits = []
    for lay, form, k, xp, xc in streams(m, pl, cl):
        for bn, a, b in (("clue 1 alone", 0, 13), ("clue 2 alone", 13, 24)):
            for ck, rule in battery(k[a:b], POS[a:b], xp=xp[a:b], xc=xc[a:b], min_checks=MIN_CHECKS):
                hits.append((ck, name, lay, form, bn, rule))
        for g in GAPS:
            pos = B1 + [i + g for i in B2]
            for ck, rule in battery(k, pos, min_checks=MIN_CHECKS, skip=("autokey", "chain")):
                hits.append((ck, name, lay, form, "gap %+d" % g, rule))
    return hits


def work(chunk):
    hits = []
    for name, m in chunk:
        hits += test_alphabet(name, m, _S["p"], _S["c"])
    return hits


def search(ct, cribs, alphas):
    hits = []
    for h in pmap(work, alphas, init, (ct, cribs)):
        hits += h
    return hits


def plant_dropped_letter(rng, alphas):
    """A sliding-key message with one ciphertext letter lost between the clues."""
    pt = english97(rng, 98)
    name, m = rng.choice(alphas)
    p = rng.randrange(5, 9)
    word = [rng.randrange(26) for _ in range(p)]
    ct, k = [], 0
    for i, ch in enumerate(pt):
        k = (k + word[i % p]) % 26
        ct.append(m[(m.index(ch) + k) % 26])
    cut = rng.randrange(36, 60)
    del ct[cut]
    kept = pt[:cut] + pt[cut + 1:]
    return "".join(ct), {i: kept[i] for i in CRIBS}, (name, "M/M", "vig", "gap +1", "sliding p=%d" % p)


def plant_two_halves(rng, alphas):
    """A repeating key that changes word (and length) half way through."""
    pt = english97(rng)
    name, m = rng.choice(alphas)
    w1 = [rng.randrange(26) for _ in range(5)]
    w2 = [rng.randrange(26) for _ in range(4)]
    ct = [m[(m.index(ch) + (w1[i % 5] if i < 48 else w2[i % 4])) % 26] for i, ch in enumerate(pt)]
    return "".join(ct), {i: pt[i] for i in CRIBS}, (name, "M/M", "vig", "clue 1 alone", "repeating p=5")


if __name__ == "__main__":
    alphas = dictionary_alphabets(mixed=False)
    n_tests = len(alphas) * 10 * (2 + len(GAPS))
    with Experiment("each clue alone, and both clues with the gap off by 1-3 letters", puzzle="k4",
                    notes="%d alphabets x 5 layouts x Vigenere/Beaufort; battery of key rules on each block "
                          "alone and with gap slack -3..+3; >=%d checks" % (len(alphas), MIN_CHECKS),
                    cribs_forced=True) as ex:
        hits = search(K4, CRIBS, alphas)
        ex.count(n_tests)
        print("alphabets: %d; key-stream settings tested: %d" % (len(alphas), n_tests))
        print("K4: %d settings pass with >= %d checks; best %d" % (len(hits), MIN_CHECKS, max((h[0] for h in hits), default=0)))
        for h in sorted(hits, reverse=True)[:15]:
            print("   checks=%d %s %s %s [%s] %s" % h)
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            h = search(shuffled_control(seed), CRIBS, alphas)
            ctrl.append((len(h), max((x[0] for x in h), default=0)))
        print("shuffled K4s (settings passing, best checks):", ctrl)
        rng = random.Random(68)
        ok = 0
        for f in (plant_dropped_letter, plant_two_halves, plant_dropped_letter):
            ct, cribs, want = f(rng, alphas)
            h = search(ct, cribs, alphas)
            found = any(x[1:] == want for x in h)
            ok += found
            print("planted %s -> found=%s (settings passing %d)" % (want, found, len(h)))
        print("planted recovered: %d/3" % ok)
        best, cb = max((h[0] for h in hits), default=0), max(c[1] for c in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if best > cb + 1 else
              "no signal (K4 %d settings, best %d checks; shuffled %s)" % (len(hits), best, ctrl))
