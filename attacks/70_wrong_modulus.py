"""Idea 70: the arithmetic is not mod 26.

Every exact test so far adds letters mod 26. Two clues say the wheel may have more cells:
Scheidt's "special characters must be accounted for" (the "?" makes a 27-symbol alphabet), and
the carved tableau itself, whose rows are 30-31 letters wide because the header runs on with
ABCD. If the strip or disk has 27-31 cells, a correct key looks like noise mod 26.

For N = 27, 28, 29, 30, 31 and every dictionary keyword alphabet (five layouts, Vigenere and
Beaufort), the clue letters force key values mod N. The same battery of exact key rules is run
on them (repeating, sliding, progressive, autokey, stacked, chain addition), and, for the prime
sizes 29 and 31, a multiplying key (C = K * P, letters numbered from 1).

Where the extra symbols sit does not matter: these tests only use differences between
letters, which are the same wherever the extra cells are placed after the alphabet.

  python attacks/70_wrong_modulus.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, battery, dictionary_alphabets, english97, pmap, streams  # noqa: E402

MODS = (27, 28, 29, 30, 31)
MIN_CHECKS = 7
_S = {}


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]


def test_alphabet(name, m, pl, cl):
    hits = []
    for n in MODS:
        for lay, form, k, xp, xc in streams(m, pl, cl, n):
            for ck, rule in battery(k, POS, n, xp, xc, MIN_CHECKS):
                hits.append((ck, name, n, lay, form, rule))
    # multiplying key on a prime wheel, letters numbered 1..26 in M
    im = {c: i + 1 for i, c in enumerate(m)}
    for n in (29, 31):
        k = [(im[c] * pow(im[p], n - 2, n)) % n for p, c in zip(pl, cl)]
        for ck, rule in battery(k, POS, n, min_checks=MIN_CHECKS, skip=("sliding", "progressive", "stacked", "chain")):
            hits.append((ck, name, n, "M/M", "multiply", rule))
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


def plant(rng, alphas, n=27):
    """A sliding key on a wheel of n cells (the alphabet plus extra symbols). Keys are redrawn
    until the clue positions hold letters; extra symbols elsewhere are written "?"."""
    name, m = rng.choice(alphas)
    while True:
        pt = english97(rng)
        p = rng.randrange(5, 9)
        word = [rng.randrange(n) for _ in range(p)]
        ct, k = [], 0
        for i, ch in enumerate(pt):
            k = (k + word[i % p]) % n
            ct.append((m.index(ch) + k) % n)
        if all(ct[i] < 26 for i in POS):       # the clue letters must be letters; others may be "?"
            sym = m + "?????"
            return "".join(sym[x] for x in ct), {i: pt[i] for i in CRIBS}, (name, n, "M/M", "vig", "sliding p=%d" % p)


if __name__ == "__main__":
    alphas = dictionary_alphabets(mixed=False)
    n_tests = len(alphas) * (10 * len(MODS) + 2)
    with Experiment("wrong modulus: key arithmetic on a wheel of 27-31 cells", puzzle="k4",
                    notes="%d keyword alphabets x 5 layouts x Vigenere/Beaufort x N=27..31; battery of key rules; "
                          "multiplying key mod 29 and 31; >=%d checks" % (len(alphas), MIN_CHECKS),
                    cribs_forced=True) as ex:
        hits = search(K4, CRIBS, alphas)
        ex.count(n_tests)
        best = max((h[0] for h in hits), default=0)
        print("alphabets: %d; key streams tested: %d" % (len(alphas), n_tests))
        print("K4: %d settings pass with >= %d checks; best %d" % (len(hits), MIN_CHECKS, best))
        for h in sorted(hits, reverse=True)[:15]:
            print("   checks=%d %s N=%d %s %s %s" % h)
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            h = search(shuffled_control(seed), CRIBS, alphas)
            ctrl.append((len(h), max((x[0] for x in h), default=0)))
        print("shuffled K4s (settings passing, best checks):", ctrl)
        rng = random.Random(70)
        ok = 0
        for n in (27, 31, 27):
            ct, cribs, want = plant(rng, alphas, n)
            h = search(ct, cribs, alphas)
            found = any(x[1:] == want for x in h)
            ok += found
            print("planted %s -> found=%s (settings passing %d)" % (want, found, len(h)))
        print("planted recovered: %d/3" % ok)
        cb = max(c[1] for c in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if best > cb + 1 else
              "no signal (K4 %d settings, best %d checks; shuffled %s)" % (len(hits), best, ctrl))
