"""Idea 73: an alphabet that changes after every letter.

Every key rule tested so far slides fixed alphabets against each other. A different hand habit
is to change the alphabet itself after each letter: move the letter just used to the front,
swap it with its neighbour, turn the strip to it. The statistics come out flat and there is no
period, yet the rule is one sentence long ("simple, can be remembered").

Nothing here needs unknown plaintext. If the starting alphabet is known (a keyword alphabet),
the whole message decrypts step by step from letter 0, because each change depends only on
letters already decrypted. So for every start alphabet and rule we just decrypt and count how
many of the 24 clue letters come out right.

  start alphabets   A-Z, KRYPTOS, reversed, every dictionary keyword alphabet
  lookup            S is the cipher alphabet against A-Z or KRYPTOS, or the plain alphabet
                    against A-Z or KRYPTOS; for theme alphabets also S against itself, shifted 1-25
  change after      move to front / to end, swap with previous / next, swap with first / last,
  each letter       turn the strip to the letter (and one further), reverse up to the letter,
                    Chaocipher's left-wheel step
  driven by         the cipher letter or the plain letter just handled
  plus              the real two-wheel Chaocipher, six start pairs per keyword alphabet

  python attacks/73_evolving_alphabet.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402

FIXED = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
N_SHIFT = 300 if SMOKE else 3000      # how many leading (theme / common word) alphabets get the shifted lookup
_S = {}


def mtf(s, j):
    s.insert(0, s.pop(j))


def mte(s, j):
    s.append(s.pop(j))


def swap_prev(s, j):
    s[j], s[j - 1] = s[j - 1], s[j]


def swap_next(s, j):
    k = (j + 1) % 26
    s[j], s[k] = s[k], s[j]


def swap_first(s, j):
    s[j], s[0] = s[0], s[j]


def swap_last(s, j):
    s[j], s[25] = s[25], s[j]


def turn_to(s, j):
    s[:] = s[j:] + s[:j]


def turn_past(s, j):
    j = (j + 1) % 26
    s[:] = s[j:] + s[:j]


def rev_prefix(s, j):
    s[:j + 1] = s[j::-1]


def chao_left(s, j):
    s[:] = s[j:] + s[:j]
    s.insert(13, s.pop(1))


RULES = {"move to front": mtf, "move to end": mte, "swap with previous": swap_prev, "swap with next": swap_next,
         "swap with first": swap_first, "swap with last": swap_last, "turn strip to letter": turn_to,
         "turn strip one past letter": turn_past, "reverse up to letter": rev_prefix, "Chaocipher left step": chao_left}
MODES = [(side, an) for side in ("cipher", "plain") for an in FIXED] + [("self", k) for k in range(1, 26)]


def decrypt_step(s, c, mode):
    """(plain letter, index of c in s, index of the plain letter in s)."""
    side, arg = mode
    j = s.index(c)
    if side == "cipher":          # s is the cipher alphabet, read against a fixed alphabet
        p = FIXED[arg][j]
        return p, j, s.index(p)
    if side == "plain":           # s is the plain alphabet, read against a fixed alphabet
        jp = FIXED[arg].index(c)
        return s[jp], j, jp
    jp = (j - arg) % 26           # s against itself, shifted
    return s[jp], j, jp


def encrypt_step(s, p, mode):
    side, arg = mode
    if side == "cipher":
        c = s[FIXED[arg].index(p)]
    elif side == "plain":
        c = FIXED[arg][s.index(p)]
    else:
        c = s[(s.index(p) + arg) % 26]
    return c


def run(ct, cribs, start, rule, driver, mode, stop=74):
    """Clue letters right. Stops after the first clue if fewer than 5 of its 13 letters match."""
    s, f, m = list(start), RULES[rule], 0
    for i in range(stop):
        p, j, jp = decrypt_step(s, ct[i], mode)
        if i in cribs and p == cribs[i]:
            m += 1
        if i == 33 and m < 5:
            return m
        f(s, j if driver == "cipher" else jp)
    return m


def chaocipher(ct, cribs, left, right, stop=74):
    le, ri, m = list(left), list(right), 0
    for i in range(stop):
        j = le.index(ct[i])
        p = ri[j]
        if i in cribs and p == cribs[i]:
            m += 1
        if i == 33 and m < 5:
            return m
        le = le[j:] + le[:j]
        le.insert(13, le.pop(1))
        ri = ri[j + 1:] + ri[:j + 1]
        ri.insert(13, ri.pop(2))
    return m


def encrypt(pt, start, rule, driver, mode):
    s, f, out = list(start), RULES[rule], []
    for p in pt:
        c = encrypt_step(s, p, mode)
        out.append(c)
        f(s, s.index(c) if driver == "cipher" else decrypt_step(s, c, mode)[2])
    return "".join(out)


def init(ct, cribs):
    _S["ct"], _S["cribs"] = ct, cribs


def work(chunk):
    ct, cribs = _S["ct"], _S["cribs"]
    best, n = (0, None), 0
    for idx, name, m in chunk:
        modes = MODES if idx < N_SHIFT else MODES[:4]
        for rule in RULES:
            for driver in ("cipher", "plain"):
                for mode in modes:
                    n += 1
                    r = run(ct, cribs, m, rule, driver, mode)
                    if r > best[0]:
                        best = (r, (name, rule, "driven by " + driver, "%s %s" % mode))
        for ln, le, rn, ri in (("M", m, "AZ", AZ), ("AZ", AZ, "M", m), ("M", m, "KR", KRYPTOS_ALPHABET),
                               ("KR", KRYPTOS_ALPHABET, "M", m), ("M", m, "M", m), ("M", m, "M reversed", m[::-1])):
            n += 1
            r = chaocipher(ct, cribs, le, ri)
            if r > best[0]:
                best = (r, (name, "Chaocipher", "left " + ln, "right " + rn))
    return n, best


def search(ct, cribs, alphas):
    items = [(i, n, m) for i, (n, m) in enumerate(alphas)]
    best, n = (0, None), 0
    for c, b in pmap(work, items, init, (ct, cribs), chunk=400):
        n += c
        best = max(best, b, key=lambda x: x[0])
    return n, best


def starts():
    out = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET), ("(Z-A)", AZ[::-1]), ("KRYPTOS reversed", KRYPTOS_ALPHABET[::-1])]
    seen = set(m for _, m in out)
    for n, m in dictionary_alphabets(mixed=False):
        if m not in seen:
            seen.add(m)
            out.append((n, m))
    return out


if __name__ == "__main__":
    alphas = starts()
    with Experiment("evolving alphabet: the alphabet changes after every letter (decrypt from letter 0)", puzzle="k4",
                    notes="%d start alphabets x 10 change rules x cipher/plain driven x 4 lookups (29 for the first %d); "
                          "two-wheel Chaocipher x 6 start pairs; count of 24 clue letters" % (len(alphas), N_SHIFT),
                    cribs_forced=True) as ex:
        n, best = search(K4, CRIBS, alphas)
        ex.count(n)
        print("settings decrypted: %d" % n)
        print("K4 best: %d/24 clue letters  %s" % best)
        ctrl = [search(shuffled_control(seed), CRIBS, alphas)[1][0] for seed in ((1, 2) if SMOKE else (1, 2, 3))]
        print("shuffled K4s best:", ctrl)
        rng = random.Random(73)
        ok = 0
        for rule, driver, mode in (("move to front", "cipher", ("cipher", "AZ")), ("swap with previous", "plain", ("plain", "KR")),
                                   ("Chaocipher left step", "cipher", ("cipher", "AZ"))):
            name, m = rng.choice(alphas[4:])
            pt = english97(rng)
            ct = encrypt(pt, m, rule, driver, mode)
            b = search(ct, {i: pt[i] for i in CRIBS}, alphas)[1]
            ok += b[0] == 24
            print("planted %s, %s, driven by %s, %s %s -> %d/24  %s" % (name, rule, driver, mode[0], mode[1], b[0], b[1]))
        print("planted recovered: %d/3" % ok)
        print("VERDICT:", "FULL HIT" if best[0] == 24 else
              ("K4 beats controls - inspect" if best[0] > max(ctrl) + 3 else
               "no signal (K4 %d/24; shuffled %s; 24 needed)" % (best[0], ctrl)))
