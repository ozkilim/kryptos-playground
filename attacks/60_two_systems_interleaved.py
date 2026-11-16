"""Idea 60: "two separate systems" used turn and turn about.

Sanborn (1990): the lower half uses two separate systems, "a major clue in itself". Round 7
tested a different system for each *part* of K4. Three other literal readings were open:

  A  SWITCHING. A handful of fixed alphabets (tableau rows), and something outside the text
     (Morse dots and dashes, a clock, a coin) says which one each letter uses. Then the clue
     letters must be covered by 2, 3 or 4 fixed rows. We find the best cover over every row of
     every A-Z/KRYPTOS Vigenere and Beaufort tableau (208 rows) and compare with shuffled K4s.
     The switching sequence itself is left completely free, so this is the most generous test.

  B  INTERLEAVING. Letters 1, 3, 5... go through one system and 2, 4, 6... through another (or
     three or four systems in turn). Each stream has its own cipher type, alphabets and
     repeating key. Combined this looks like one long key (up to 4 x 13 letters), beyond what
     the repeating-key tests reached.

  C  SLIDEFAIR-type pairs: letters enciphered two at a time on the tableau, each taking the
     other's column. The key cancels out of every complete pair, so the test is exact.

  python attacks/60_two_systems_interleaved.py
"""
import itertools
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


def views(ct, cribs):
    for an, a in ALPH.items():
        for bn, b in ALPH.items():
            for m, mn in ((1, "vig"), (-1, "beau")):
                yield "%s/%s/%s" % (an, bn, mn), {i: (b.index(ct[i]) - m * a.index(cribs[i])) % 26 for i in POS}


# ---- A: switching between a few fixed rows
def best_cover(ct, cribs, k, top=70):
    rows = {}
    for name, key in views(ct, cribs):
        for i, s in key.items():
            rows.setdefault((name, s), set()).add(i)
    items = sorted(rows.items(), key=lambda x: -len(x[1]))[:top]
    best = (0, None)
    for combo in itertools.combinations(items, k):
        n = len(set().union(*[c[1] for c in combo]))
        if n > best[0]:
            best = (n, [c[0] for c in combo])
    return best


# ---- B: interleaved streams
def interleaved(ct, cribs, k, max_p=13, min_stream_checks=2):
    """For streams i mod k: every (view, period) each stream could be. Returns the best total
    checks if every stream has an option, else -1, plus the number of full combinations."""
    vs = list(views(ct, cribs))
    per_stream = []
    for r in range(k):
        use = [i for i in POS if i % k == r]
        opts = []
        for name, key in vs:
            for p in range(1, max_p + 1):
                seen, ok = {}, True
                for i in use:
                    if seen.setdefault((i // k) % p, key[i]) != key[i]:
                        ok = False
                        break
                if ok and len(use) - len(seen) >= min_stream_checks:
                    opts.append((len(use) - len(seen), name, p))
        per_stream.append(opts)
    if not all(per_stream):
        return -1, 0, None
    total = sum(max(o)[0] for o in per_stream)
    count = 1
    for o in per_stream:
        count *= len(o)
    return total, count, [max(o) for o in per_stream]


# ---- C: Slidefair pairs
def slidefair(ct, cribs):
    """Pairs (P1,P2)->(C1,C2) with C1 = P2 -/+ k and C2 = P1 +/- k: then C1 + C2 = P1 + P2 (or the
    Beaufort forms) in every complete pair. Returns the settings where every clue pair agrees."""
    ok = []
    for an, a in ALPH.items():
        for start in (0, 1):
            pairs = [(i, i + 1) for i in range(start, 96, 2) if i in cribs and i + 1 in cribs]
            x = lambda ch: a.index(ch)
            tests = {
                "C1+C2=P1+P2": all((x(ct[i]) + x(ct[j]) - x(cribs[i]) - x(cribs[j])) % 26 == 0 for i, j in pairs),
                "C1-C2=P2-P1 const": len({(x(ct[i]) - x(ct[j]) - x(cribs[j]) + x(cribs[i])) % 26 for i, j in pairs}) == 1,
                "C1+C2+P1+P2 const": len({(x(ct[i]) + x(ct[j]) + x(cribs[i]) + x(cribs[j])) % 26 for i, j in pairs}) == 1,
            }
            ok += [(an, start, t) for t, v in tests.items() if v]
    return ok


def plant_switch(rng, k=2):
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    rows = [(rng.choice([AZ, KRYPTOS_ALPHABET]), rng.randrange(26)) for _ in range(k)]
    ct = "".join((lambda a, s: a[(a.index(p) + s) % 26])(*rng.choice(rows)) for p in pt)
    return ct, {i: pt[i] for i in CRIBS}


def plant_interleaved(rng, k=2):
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    sys_ = [(rng.choice([AZ, KRYPTOS_ALPHABET]), [rng.randrange(26) for _ in range(rng.randrange(2, {2: 7, 3: 5, 4: 4}[k]))]) for _ in range(k)]
    ct = "".join(sys_[i % k][0][(sys_[i % k][0].index(p) + sys_[i % k][1][(i // k) % len(sys_[i % k][1])]) % 26]
                 for i, p in enumerate(pt))
    return ct, {i: pt[i] for i in CRIBS}


if __name__ == "__main__":
    nctrl = 3 if SMOKE else 20
    with Experiment("two systems in turn: switching rows, interleaved streams, Slidefair pairs", puzzle="k4",
                    notes="A: best cover of clues by 2-4 fixed tableau rows; B: i mod k streams (k 2-4) each with own "
                          "cipher/alphabet/period<=13; C: Slidefair pair identities", cribs_forced=True) as ex:
        rng = random.Random(6)
        print("A. switching between k fixed rows (24 = every clue letter covered)")
        signal = False
        for k in (2, 3, 4):
            b = best_cover(K4, CRIBS, k)
            ctrl = [best_cover(shuffled_control(s), CRIBS, k)[0] for s in range(1, nctrl + 1)]
            pl = [best_cover(*plant_switch(rng, k), k)[0] for _ in range(3)]
            ex.count(208 ** k)
            signal |= b[0] > max(ctrl) + 2
            print("   k=%d  K4 %d/24 %s | shuffled max %d mean %.1f | planted %s" % (
                k, b[0], b[1], max(ctrl), sum(ctrl) / len(ctrl), pl))
        print("B. interleaved streams")
        for k in (2, 3, 4):
            t, n, opts = interleaved(K4, CRIBS, k)
            ctrl = [interleaved(shuffled_control(s), CRIBS, k)[0] for s in range(1, nctrl + 1)]
            pl = [interleaved(*plant_interleaved(rng, k), k)[0] for _ in range(3)]
            ex.count((8 * 13) ** k)
            signal |= t > max(ctrl)
            print("   k=%d  K4 best total checks %d (%d combinations) %s | shuffled best %s | planted %s" % (
                k, t, n, opts, sorted(ctrl, reverse=True)[:5], pl))
        print("C. Slidefair pair identities")
        s = slidefair(K4, CRIBS)
        ctrl = [len(slidefair(shuffled_control(x), CRIBS)) for x in range(1, nctrl + 1)]
        ex.count(12)
        signal |= bool(s)
        print("   K4 settings where every clue pair agrees: %s | shuffled: %s" % (s, ctrl))
        print("VERDICT:", "K4 beats controls somewhere - inspect" if signal else "no signal in A, B or C")
