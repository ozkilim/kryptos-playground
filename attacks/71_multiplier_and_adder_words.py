"""Idea 71: a multiplier word and an adder word.

Every key rule tested so far ADDS a key to the plaintext letter. A decimated alphabet
multiplies instead (C = a * P), and it is as easy by hand as a shifted one: lay the alphabet
out taking every a-th letter. Earlier formula mining allowed one fixed multiplier for the whole
message. Here the multiplier itself is a repeating key:

    C[i] = A[i mod p] * P[i] + B[i mod q]        (mod 26)

with a multiplier word A of length p and an adder word B of length q. The unknowns A and B
enter linearly, so each (p, q) is one small linear system on the 24 clue letters, solved mod 13
and mod 2. Multipliers must be usable (odd, and not a multiple of 13).

  A  A-Z / KRYPTOS on each side: every p, q = 1..17 with 7 or more checks
  B  every dictionary keyword tableau: each of the 10 fixed multipliers other than +-1,
     against the full battery of key rules (repeating, sliding, progressive, autokey, stacked,
     chain addition). +-1 was round 10.

  python attacks/71_multiplier_and_adder_words.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control, solve_mod_p  # noqa: E402
from kryptos.round11 import POS, SMOKE, battery, dictionary_alphabets, english97, pmap  # noqa: E402

ALPH = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
MULTS = (3, 5, 7, 9, 11, 15, 17, 19, 21, 23)
MIN_CHECKS = 7
PMAX = 6 if SMOKE else 17
_S = {}


def pair_fit(p, q, pv, cv):
    """Checks if C = A[i%p]*P + B[i%q] fits the clue letters, else -1."""
    # mod 2: A must be odd, so B = C - P must repeat with period q
    seen = {}
    for i, x, y in zip(POS, pv, cv):
        if seen.setdefault(i % q, (y - x) % 2) != (y - x) % 2:
            return -1
    rows = []
    for i, x in zip(POS, pv):
        v = [0] * (p + q)
        v[i % p] = x % 13
        v[p + i % q] = 1
        rows.append(v)
    s = solve_mod_p(rows, cv, 13)
    if s is None:
        return -1
    part, basis = s
    for j in range(p):                       # a multiplier forced to 0 mod 13 is not usable
        if part[j] == 0 and all(b[j] == 0 for b in basis):
            return -1
    return len(POS) - (p + q - len(basis))


def pairs_search(ct, cribs):
    hits, n = [], 0
    for an, a in ALPH.items():
        pv = [a.index(cribs[i]) for i in POS]
        for bn, b in ALPH.items():
            cv = [b.index(ct[i]) for i in POS]
            for p in range(1, PMAX + 1):
                for q in range(1, PMAX + 1):
                    n += 1
                    ck = pair_fit(p, q, pv, cv)
                    if ck >= MIN_CHECKS:
                        hits.append((ck, "pt%s/ct%s" % (an, bn), "multiplier word %d + adder word %d" % (p, q)))
    return n, hits


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]


def work(chunk):
    pl, cl = _S["p"], _S["c"]
    iz = {c: i for i, c in enumerate(AZ)}
    ik = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    hits = []
    for name, m in chunk:
        im = {c: i for i, c in enumerate(m)}
        xp, xc = [im[c] for c in pl], [im[c] for c in cl]
        for lay, ia, ib in (("M/M", im, im), ("M/AZ", im, iz), ("AZ/M", iz, im), ("M/KR", im, ik), ("KR/M", ik, im)):
            a, b = [ia[c] for c in pl], [ib[c] for c in cl]
            for mu in MULTS:
                k = [(y - mu * x) % 26 for x, y in zip(a, b)]
                for ck, rule in battery(k, POS, 26, xp, xc, MIN_CHECKS):
                    hits.append((ck, name, lay, "x%d" % mu, rule))
    return hits


def dict_search(ct, cribs, alphas):
    hits = []
    for h in pmap(work, alphas, init, (ct, cribs)):
        hits += h
    return hits


def plant_pair(rng):
    pt = english97(rng)
    p, q = rng.randrange(3, 7), rng.randrange(3, 7)
    units = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    a, b = [rng.choice(units) for _ in range(p)], [rng.randrange(26) for _ in range(q)]
    ct = "".join(AZ[(a[i % p] * AZ.index(ch) + b[i % q]) % 26] for i, ch in enumerate(pt))
    return ct, {i: pt[i] for i in CRIBS}, "multiplier word %d + adder word %d" % (p, q)


def plant_dict(rng, alphas):
    pt = english97(rng)
    name, m = rng.choice(alphas)
    mu, p = rng.choice(MULTS), rng.randrange(5, 9)
    word = [rng.randrange(26) for _ in range(p)]
    ct, k = [], 0
    for i, ch in enumerate(pt):
        k = (k + word[i % p]) % 26
        ct.append(m[(mu * m.index(ch) + k) % 26])
    return "".join(ct), {i: pt[i] for i in CRIBS}, (name, "M/M", "x%d" % mu, "sliding p=%d" % p)


if __name__ == "__main__":
    alphas = dictionary_alphabets(mixed=False)
    with Experiment("multiplier word + adder word (C = A*P + B, both repeating)", puzzle="k4",
                    notes="A: A-Z/KRYPTOS, p,q=1..%d exact linear solve; B: %d keyword alphabets x 5 layouts x 10 "
                          "fixed multipliers x battery of key rules; >=%d checks" % (PMAX, len(alphas), MIN_CHECKS),
                    cribs_forced=True) as ex:
        n, hits = pairs_search(K4, CRIBS)
        dh = dict_search(K4, CRIBS, alphas)
        ex.count(n + len(alphas) * 50)
        print("A: %d (alphabets, p, q) systems; K4 fits with >= %d checks: %d" % (n, MIN_CHECKS, len(hits)))
        for h in sorted(hits, reverse=True)[:10]:
            print("   checks=%d %s %s" % h)
        print("B: %d key streams; K4 settings passing: %d" % (len(alphas) * 50, len(dh)))
        for h in sorted(dh, reverse=True)[:10]:
            print("   checks=%d %s %s %s %s" % h)
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            c = shuffled_control(seed)
            ctrl.append((len(pairs_search(c, CRIBS)[1]), len(dict_search(c, CRIBS, alphas))))
        print("shuffled K4s (A fits, B settings):", ctrl)
        rng = random.Random(71)
        ok = 0
        for _ in range(3):
            ct, cribs, want = plant_pair(rng)
            h = pairs_search(ct, cribs)[1]
            found = any(x[1] == "ptAZ/ctAZ" and x[2] == want for x in h)
            ok += found
            print("planted %s -> found=%s (fits %d)" % (want, found, len(h)))
        for _ in range(2):
            ct, cribs, want = plant_dict(rng, alphas)
            h = dict_search(ct, cribs, alphas)
            found = any(x[1:] == want for x in h)
            ok += found
            print("planted %s -> found=%s (settings %d)" % (want, found, len(h)))
        print("planted recovered: %d/5" % ok)
        print("VERDICT:", "FIT - inspect" if (len(hits), len(dh)) > max(ctrl) and (hits or dh) else
              "no signal (K4 A %d, B %d; shuffled %s)" % (len(hits), len(dh), ctrl))
