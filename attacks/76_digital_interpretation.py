"""Idea 76: "DIGETAL INTERPRETATU" taken literally: letters as bits.

The Morse text at the entrance says DIGETAL INTERPRETATU. Round 5 tested teleprinter (Baudot)
codes. This tests the plain ways of writing a letter as five bits, and the Morse dots and
dashes themselves as a switch.

  A  bit keys. Number the letters (A-Z or KRYPTOS order, from 0 or from 1), write the number in
     binary or Gray code (Bacon's cipher is the A-Z, from-0, binary case), and give each of the
     five bits its own repeating key (XOR), with any wiring of plain bits to cipher bits. For
     each cipher bit we find the longest list of coincidences any period 1-60 explains, and add
     up the best one-to-one wiring. K4 is compared with shuffled K4s.

     A caution that is itself evidence: XOR on five bits makes 32 symbols, and a random key
     would put one of the 6 non-letters into a 97-letter text all but (26/32)^97 = 2e-9 of the time.

  B  Morse as a switch. The dots and dashes of the entrance text (forwards, backwards, swapped,
     from every starting point) choose, letter by letter, between two systems: two alphabets or
     cipher forms sharing one repeating key (periods 1-10), or two separate key words
     (periods 1-5 each).

  python attacks/76_digital_interpretation.py
"""
import itertools
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, english97  # noqa: E402

MORSE_TEXT = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUSHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ"
MORSE = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..",
         "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
         "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--.."}
PERMS = list(itertools.permutations(range(5)))
LMAX = 60
MIN_CHECKS = 8


def numberings():
    out = {}
    for an, a in (("AZ", AZ), ("KR", KRYPTOS_ALPHABET)):
        for off in (0, 1):
            for cn, f in (("binary", lambda x: x), ("gray", lambda x: x ^ (x >> 1))):
                out["%s from %d, %s" % (an, off, cn)] = {c: f(i + off) for i, c in enumerate(a)}
    return out


NUMS = numberings()


def bit_score(pnum, cnum):
    """pnum, cnum: 24 five-bit numbers. Returns (score, per-cipher-bit detail): the best wiring's total
    of coincidences explained by a repeating XOR key on each bit."""
    best = [[0] * 5 for _ in range(5)]            # best[cipher bit][plain bit] = (checks)
    for cb in range(5):
        for pb in range(5):
            x = [(c >> cb ^ p >> pb) & 1 for p, c in zip(pnum, cnum)]
            for L in range(1, LMAX + 1):
                seen = {}
                for v, i in zip(x, POS):
                    if seen.setdefault(i % L, v) != v:
                        break
                else:
                    best[cb][pb] = max(best[cb][pb], 24 - len(seen))
    top = 0
    for perm in PERMS:
        vals = [best[cb][perm[cb]] for cb in range(5)]
        if min(vals) >= 4:
            top = max(top, sum(vals))
    return top


def bits_search(pl, cnums):
    """pl: clue plaintext letters; cnums: {numbering: [cipher numbers at the clue positions]}."""
    best = (0, None)
    for pn, pm in NUMS.items():
        pv = [pm[c] for c in pl]
        for cn, cv in cnums.items():
            s = bit_score(pv, cv)
            if s > best[0]:
                best = (s, "plain %s / cipher %s" % (pn, cn))
    return best


def selectors():
    s = "".join(MORSE[c] for c in MORSE_TEXT)
    base = [1 if ch == "-" else 0 for ch in s]
    out = []
    for name, b in (("forwards", base), ("backwards", base[::-1])):
        for flip in (0, 1):
            for start in range(len(b) - 74):
                out.append(("%s%s from %d" % (name, " swapped" if flip else "", start),
                            [b[start + i] ^ flip for i in POS]))
    return out


def systems(ct, cribs):
    out = []
    for an, a in (("AZ", AZ), ("KR", KRYPTOS_ALPHABET)):
        for bn, b in (("AZ", AZ), ("KR", KRYPTOS_ALPHABET)):
            x, y = [a.index(cribs[i]) for i in POS], [b.index(ct[i]) for i in POS]
            out.append(("pt%s/ct%s vig" % (an, bn), [(v - u) % 26 for u, v in zip(x, y)]))
            out.append(("pt%s/ct%s beau" % (an, bn), [(v + u) % 26 for u, v in zip(x, y)]))
    return out


def switch_search(ct, cribs, sels):
    sy = systems(ct, cribs)
    hits, n = [], 0
    for sn, sel in sels:
        if sum(sel) in (0, 24):
            continue
        for (n0, k0), (n1, k1) in itertools.product(sy, repeat=2):
            k = [b if s else a for a, b, s in zip(k0, k1, sel)]
            if n0 != n1:                      # two systems, one shared key
                for p in range(1, 11):
                    n += 1
                    seen = {}
                    for v, i in zip(k, POS):
                        if seen.setdefault(i % p, v) != v:
                            break
                    else:
                        if 24 - len(seen) >= MIN_CHECKS:
                            hits.append((24 - len(seen), sn, "%s | %s" % (n0, n1), "shared key p=%d" % p))
            if n0 <= n1:                      # two separate key words (same or different systems)
                for p in range(1, 6):
                    n += 1
                    seen = {}
                    for v, i, s in zip(k, POS, sel):
                        if seen.setdefault((s, i % p), v) != v:
                            break
                    else:
                        if 24 - len(seen) >= MIN_CHECKS:
                            hits.append((24 - len(seen), sn, "%s | %s" % (n0, n1), "two key words p=%d" % p))
    return n, hits


def cnums_of(ct):
    return {name: [m[ct[i]] for i in POS] for name, m in NUMS.items()}


def plant_bits(rng):
    """Five bit-keys with their own periods and a scrambled wiring; ciphertext is 5-bit numbers (0-31)."""
    pt = english97(rng)
    perm = list(range(5))
    rng.shuffle(perm)
    keys = [[rng.randrange(2) for _ in range(rng.randrange(4, 10))] for _ in range(5)]
    cn = []
    for i in POS:
        p = AZ.index(pt[i])
        cn.append(sum(((p >> perm[cb] & 1) ^ keys[cb][i % len(keys[cb])]) << cb for cb in range(5)))
    return [pt[i] for i in POS], {"raw 5-bit": cn}


def plant_switch(rng, sels):
    pt = english97(rng)
    sn, sel = rng.choice(sels)
    full = dict(zip(POS, sel))
    p = rng.randrange(3, 6)
    w0, w1 = [rng.randrange(26) for _ in range(p)], [rng.randrange(26) for _ in range(p)]
    ct = list(english97(rng))                  # filler away from the clues
    for i in POS:
        k = (w1 if full[i] else w0)[i % p]
        ct[i] = AZ[(AZ.index(pt[i]) + k) % 26]
    return "".join(ct), {i: pt[i] for i in CRIBS}, (sn, "ptAZ/ctAZ vig | ptAZ/ctAZ vig", "two key words p=%d" % p)


if __name__ == "__main__":
    sels = selectors()
    if SMOKE:
        sels = sels[::12]
    with Experiment("digital interpretation: letters as 5 bits (binary, Gray, Bacon) and Morse as a switch", puzzle="k4",
                    notes="A: 8 x 8 numberings, per-bit XOR keys periods 1-%d, any bit wiring. B: %d Morse dot/dash "
                          "selectors x 64 system pairs x shared key p<=10 / two keys p<=5" % (LMAX, len(sels)),
                    cribs_forced=True) as ex:
        pl = [CRIBS[i] for i in POS]
        a = bits_search(pl, cnums_of(K4))
        n, hits = switch_search(K4, CRIBS, sels)
        ex.count(64 * 25 * LMAX + n)
        print("A  K4 best bit-key score: %d  (%s)   [a real bit-key system scores 60+]" % a)
        ca = [bits_search(pl, cnums_of(shuffled_control(s)))[0] for s in range(1, 6 if SMOKE else 21)]
        print("A  shuffled K4s:", sorted(ca))
        rng = random.Random(76)
        oka = 0
        for _ in range(3):
            ppl, cn = plant_bits(rng)
            s = bits_search(ppl, cn)
            oka += s[0] >= 60
            print("A  planted bit keys -> score %d (%s)" % s)
        print("B  switch settings tested: %d; K4 fits with >= %d checks: %d" % (n, MIN_CHECKS, len(hits)))
        for h in sorted(hits, reverse=True)[:10]:
            print("   checks=%d Morse %s; %s; %s" % h)
        cb = [len(switch_search(shuffled_control(s), CRIBS, sels)[1]) for s in ((1, 2) if SMOKE else (1, 2, 3))]
        print("B  shuffled K4s fits:", cb)
        okb = 0
        for _ in range(3):
            ct, cribs, want = plant_switch(rng, sels)
            h = switch_search(ct, cribs, sels)[1]
            found = any(x[1:] == want for x in h)
            okb += found
            print("B  planted switch %s -> found=%s (fits %d)" % (want, found, len(h)))
        print("planted recovered: A %d/3, B %d/3" % (oka, okb))
        print("VERDICT:", "SIGNAL - inspect" if a[0] > max(ca) + 8 or len(hits) > max(cb) else
              "no signal (A: K4 %d vs shuffled max %d; B: K4 %d fits vs shuffled %s)" % (a[0], max(ca), len(hits), cb))
