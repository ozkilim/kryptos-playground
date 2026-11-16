"""Idea 74: autokey where a key word says how far back to look.

In an autokey the key letter is an earlier letter of the message. Every autokey test so far
looked a FIXED distance back (1, 2, ... letters). A small twist keeps it a one-line hand rule
but breaks all those tests: a key word of numbers says how far back to look at each step,

    key[i] = letter at position i - L[i mod p]  (+ a constant),

where the letter is taken from the plaintext or from the ciphertext, and L is a repeating
pattern of distances (for example the letters of a key word as numbers).

The test is exact. For a constant c and a period p, every position class i mod p must have one
distance L that explains all its clue letters. With the ciphertext as the feed all 24 clue
letters can be checked; with the plaintext as the feed only those whose source also lies
inside a clue.

  alphabets   A-Z / KRYPTOS on each side, and every dictionary keyword tableau (M/M)
  ciphers     Vigenere, Beaufort; feed added or subtracted
  feed        ciphertext, distances 1..20; plaintext, distances 1..8
  periods     1..13

  python attacks/74_keyed_lag_autokey.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402

LMAX = {"cipher": 20, "plain": 8}
PMAX = 13
MIN_SCORE = 7
CLASSES = {p: [[j for j, i in enumerate(POS) if i % p == r] for r in range(p)] for p in range(1, PMAX + 1)}
CLASSES = {p: [c for c in cl if c] for p, cl in CLASSES.items()}
_S = {}


def fits(k, feed, sign):
    """k: 24 key values. feed[j][L] = number of the letter L places before clue letter j, or None.
    Returns [(score, period, constant, lag pattern)] with score = checked letters - period - 1 >= MIN_SCORE."""
    out = []
    lmax = len(feed[0]) - 1
    for c in range(26):
        ok, ver = [], []
        for j in range(24):
            a = b = 0
            f = feed[j]
            for L in range(1, lmax + 1):
                if f[L] is None:
                    a |= 1 << L
                elif (k[j] - sign * f[L] - c) % 26 == 0:
                    a |= 1 << L
                    b |= 1 << L
            if not a:
                break
            ok.append(a)
            ver.append(b)
        else:
            if sum(1 for b in ver if b) < MIN_SCORE + 2:
                continue
            for p in range(1, PMAX + 1):
                total, lags = 0, []
                for cl in CLASSES[p]:
                    a = ~0
                    for j in cl:
                        a &= ok[j]
                    if not a:
                        break
                    bl, bv = 0, -1
                    for L in range(1, lmax + 1):
                        if a >> L & 1:
                            v = sum(1 for j in cl if ver[j] >> L & 1)
                            if v > bv:
                                bl, bv = L, v
                    total += bv
                    lags.append(bl)
                else:
                    if total - p - 1 >= MIN_SCORE:
                        out.append((total - p - 1, p, c, tuple(lags)))
    return out


def feeds(ct, cribs, num):
    """{source: feed table} with letter numbers taken in alphabet `num`."""
    out = {}
    lm = LMAX["cipher"]
    out["cipher"] = [[None] + [num[ct[i - L]] if i - L >= 0 else None for L in range(1, lm + 1)] for i in POS]
    lm = LMAX["plain"]
    out["plain"] = [[None] + [num[cribs[i - L]] if i - L in cribs else None for L in range(1, lm + 1)] for i in POS]
    return out


def test_view(name, ia, ib, inum, ct, cribs):
    hits = []
    a, b = [ia[cribs[i]] for i in POS], [ib[ct[i]] for i in POS]
    fd = feeds(ct, cribs, inum)
    for form, k in (("vig", [(y - x) % 26 for x, y in zip(a, b)]), ("beau", [(y + x) % 26 for x, y in zip(a, b)])):
        for src in ("cipher", "plain"):
            for sign in (1, -1):
                for sc, p, c, lags in fits(k, fd[src], sign):
                    hits.append((sc, name, form, "%s feed %+d" % (src, sign), "period %d lags %s const %d" % (p, lags, c)))
    return hits


def init(ct, cribs):
    _S["ct"], _S["cribs"] = ct, cribs


def work(chunk):
    hits = []
    for name, m in chunk:
        im = {c: i for i, c in enumerate(m)}
        hits += test_view(name, im, im, im, _S["ct"], _S["cribs"])
    return hits


def search(ct, cribs, alphas):
    hits = []
    ix = {"AZ": {c: i for i, c in enumerate(AZ)}, "KR": {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}}
    for an in ix:
        for bn in ix:
            for nn in ix:
                hits += test_view("pt%s/ct%s feed on %s" % (an, bn, nn), ix[an], ix[bn], ix[nn], ct, cribs)
    for h in pmap(work, alphas, init, (ct, cribs)):
        hits += h
    return hits


def plant(rng, alphas, src):
    pt = english97(rng)
    name, m = rng.choice(alphas)
    im = {c: i for i, c in enumerate(m)}
    p = rng.randrange(3, 7)
    lags = [rng.randrange(1, 6 if src == "plain" else 13) for _ in range(p)]
    c0 = rng.randrange(26)
    ct = []
    for i, ch in enumerate(pt):
        L = lags[i % p]
        if i - L < 0:
            u = rng.randrange(26)
        else:
            u = im[pt[i - L]] if src == "plain" else im[ct[i - L]]
        ct.append(m[(im[ch] + u + c0) % 26])
    return "".join(ct), {i: pt[i] for i in CRIBS}, name, src, p


if __name__ == "__main__":
    alphas = dictionary_alphabets(mixed=False)
    n = (8 + len(alphas)) * 2 * 2 * 2 * 26 * PMAX
    with Experiment("autokey with a keyed distance (a repeating pattern says how far back to look)", puzzle="k4",
                    notes="%d keyword alphabets (M/M) + A-Z/KRYPTOS views; Vigenere/Beaufort; cipher feed lags 1-20, "
                          "plain feed lags 1-8; periods 1-%d; exact" % (len(alphas), PMAX), cribs_forced=True) as ex:
        hits = search(K4, CRIBS, alphas)
        ex.count(n)
        print("settings tested: %d" % n)
        print("K4: %d fits with score >= %d (score = clue letters checked - period - 1)" % (len(hits), MIN_SCORE))
        for h in sorted(hits, reverse=True)[:12]:
            print("   score=%d %s %s %s %s" % h)
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            h = search(shuffled_control(seed), CRIBS, alphas)
            ctrl.append((len(h), max((x[0] for x in h), default=0)))
        print("shuffled K4s (fits, best score):", ctrl)
        rng = random.Random(74)
        ok = 0
        for src in ("cipher", "plain", "cipher", "plain"):
            ct, cribs, name, s, p = plant(rng, alphas, src)
            h = search(ct, cribs, alphas)
            found = any(x[1] == name and x[2] == "vig" and x[3] == "%s feed +1" % s and x[4].startswith("period %d " % p) for x in h)
            ok += found
            print("planted %s, %s feed, period %d -> found=%s (fits %d, best score %d)" % (
                name, s, p, found, len(h), max((x[0] for x in h), default=0)))
        print("planted recovered: %d/4" % ok)
        best, cb = max((h[0] for h in hits), default=0), max(c[1] for c in ctrl)
        print("VERDICT:", "FIT - inspect" if hits and best > cb + 1 else
              "no signal (K4 %d fits, best score %d; shuffled %s)" % (len(hits), best, ctrl))
