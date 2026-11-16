"""Idea 59: two systems stacked: a repeating key word AND an autokey ("LAYER TWO").

Sanborn: the lower half uses "two separate systems". K2 ends "X LAYER TWO". The two simplest
hand systems that both keep "plain letter in, cipher letter out" are a repeating key word
(K1/K2's own system) and an autokey (each letter also shifted by an earlier letter). Each alone
is dead. Together they were only tested behind a transposition. Stacked directly:

    idx(C_i) = a*idx(P_i) + b*idx(U_i) + key[i mod p]      U_i = C[i-L] or P[i-L]

The autokey part hides the period (no period signature, flat counts), and the key word stops
the usual autokey test from working. But strip the autokey part off with the right (b, L) and
what remains must repeat with period p. With a ciphertext source U is known everywhere, so all
24 clue letters are usable for every lag.

  a        +1 or -1 (Vigenere / Beaufort)       b   any of 1..25
  L        1..60 (ciphertext source), 1..9 (plaintext source)
  p        1..26                                 alphabets   A-Z / KRYPTOS on each side

"checks" = usable clue letters minus distinct key slots. Survivors need >= 6 checks.

  python attacks/59_autokey_plus_repeating_key.py
"""
import os
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import POS, shuffled_control  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
ALPH = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
MIN_CHECKS = 6


def search(ct, cribs):
    tried, hits = 0, []
    for an, a_ in ALPH.items():
        ia = {c: i for i, c in enumerate(a_)}
        for bn, b_ in ALPH.items():
            ib = {c: i for i, c in enumerate(b_)}
            for un, iu in (("AZ", {c: i for i, c in enumerate(AZ)}), ("KR", {c: i for i, c in enumerate(KRYPTOS_ALPHABET)})):
                for src in "CP":
                    lags = range(1, (4 if SMOKE else 61) if src == "C" else (3 if SMOKE else 10))
                    for L in lags:
                        if src == "C":
                            use = [i for i in POS if i - L >= 0]
                            u = {i: iu[ct[i - L]] for i in use}
                        else:
                            use = [i for i in POS if i - L in cribs]
                            u = {i: iu[cribs[i - L]] for i in use}
                        if len(use) < 12:
                            continue
                        for a in (1, -1):
                            base = {i: ib[ct[i]] - a * ia[cribs[i]] for i in use}
                            for b in range(1, 26):
                                rem = {i: (base[i] - b * u[i]) % 26 for i in use}
                                for p in range(1, 27):
                                    tried += 1
                                    seen, ok = {}, True
                                    for i in use:
                                        if seen.setdefault(i % p, rem[i]) != rem[i]:
                                            ok = False
                                            break
                                    if ok and len(use) - len(seen) >= MIN_CHECKS:
                                        hits.append((len(use) - len(seen), "pt%s/ct%s/u%s" % (an, bn, un), src, L, a, b, p))
    return tried, hits


def plant(rng):
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    k = KRYPTOS_ALPHABET
    p = rng.randrange(5, 11)
    key = [rng.randrange(26) for _ in range(p)]
    L, b = rng.randrange(1, 6), rng.choice([1, 25])
    ct = []
    for i, ch in enumerate(pt):
        u = k.index(ct[i - L]) if i >= L else 0
        ct.append(k[(k.index(ch) + b * u + key[i % p]) % 26])
    return "".join(ct), {i: pt[i] for i in CRIBS}, ("ptKR/ctKR/uKR", "C", L, 1, b, p)


if __name__ == "__main__":
    with Experiment("autokey stacked with a repeating key (two systems)", puzzle="k4",
                    notes="C = a*P + b*U[i-L] + key[i mod p]; C-source lags 1-60, P-source 1-9, b 1-25, p 1-26, "
                          "A-Z/KRYPTOS; exact", cribs_forced=True) as ex:
        tried, hits = search(K4, CRIBS)
        ex.count(tried)
        print("K4: %d settings, %d survive with >= %d checks" % (tried, len(hits), MIN_CHECKS))
        for h in sorted(hits, reverse=True)[:10]:
            print("   checks=%d %s src=%s lag=%d a=%+d b=%d period=%d" % h)
        ctrl = []
        for seed in range(1, 3 if SMOKE else 11):
            _, h = search(shuffled_control(seed), CRIBS)
            ctrl.append((len(h), max((x[0] for x in h), default=0)))
        print("shuffled K4s (survivors, best checks):", ctrl)
        rng = random.Random(8)
        ok = 0
        for _ in range(4):
            ct, cribs, truth = plant(rng)
            _, h = search(ct, cribs)
            found = any(x[1:] == truth for x in h)
            ok += found
            print("planted %s -> found=%s (survivors %d, best checks %d)" % (truth, found, len(h), max((x[0] for x in h), default=0)))
        print("planted recovered: %d/4" % ok)
        best, cbest = max((x[0] for x in hits), default=0), max(c[1] for c in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if best > cbest else
              "no signal (K4 best checks %d, %d survivors; shuffled best %d, survivors %s)" % (
                  best, len(hits), cbest, [c[0] for c in ctrl]))
