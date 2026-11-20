"""Planted tests for idea 144: a key word on one tableau, a second tableau turned by a step list."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.idea144_steps import Scanner, decrypt, encrypt, key_values, periods, slow_scan, turn
from kryptos.idea98_turning import encrypt as encrypt98
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, english97
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
SMALL = Quadgrams()                      # the small table is enough to rank the readings here


def attack():
    spec = importlib.util.spec_from_file_location("__main__x144", ROOT / "attacks" /
                                                  "144_step_pattern_second_tableau.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_turn_and_constant_step_is_idea_98():
    assert [turn((3, 11), 7, i) for i in range(6)] == [7, 10, 21, 24, 9, 12]
    assert [turn((5, 0, 19), 1, i) for i in range(7)] == [1, 6, 6, 25, 4, 4, 23]
    rng = random.Random(1)
    pt, m = english97(rng), keyword_alphabet("LODESTONE")
    key = [rng.randrange(26) for _ in range(9)]
    for order in (1, 2):
        assert encrypt(pt, KRYPTOS_ALPHABET, m, key, (4, 4), 9, -1, 1, order) == \
            encrypt98(pt, KRYPTOS_ALPHABET, m, key, 4, 9, -1, 1, order, 0)


def test_fast_scan_agrees_with_slow_scan():
    """k = 1: every setting of a pair agrees with the slow scan. k = 2 (140,608 settings, 15 s
    for the slow scan, checked in full once by hand): the planted lane is found and every hit is
    confirmed by the slow key values."""
    rng = random.Random(5)
    m = keyword_alphabet("PALIMPSEST")
    a, b = KRYPTOS_ALPHABET, m
    pt = english97(rng)
    ct = encrypt(pt, a, b, [rng.randrange(26) for _ in range(12)], (9,), 4, -1, 1, 2)
    ptl, ctl = [pt[i] for i in POS], [ct[i] for i in POS]
    fast = Scanner(POS, 1).scan(a, b, ptl, ctl)
    assert fast == slow_scan(a, b, ptl, ctl, POS, 1) and (2, -1, 1, (9,), 4) in fast
    ct = encrypt(pt, a, b, [rng.randrange(26) for _ in range(12)], (9, 4), 7, -1, 1, 2)
    ctl = [ct[i] for i in POS]
    fast = Scanner(POS, 2).scan(a, b, ptl, ctl)
    assert (2, -1, 1, (9, 4), 7) in fast
    for order, ek, eg, steps, t in fast:                     # no false positives
        assert periods(key_values(ptl, ctl, POS, a, b, steps, t, ek, eg, order), POS)


def test_planted_step_pattern_found():
    m = attack()
    rng = random.Random(144)
    words = {8: {"ABSCISSA", "ILLUSION"}, 7: {"LANTERN"}}
    dic = keyword_alphabet("LODESTONE")
    small = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)]
    pairs = m.part1_pairs(small) + m.part2_pairs(
        [(w, keyword_alphabet(w)) for w in ("LODESTONE", "SHADOW", "MEDUSA")], small)
    cases = [(KRYPTOS_ALPHABET, dic, "ABSCISSA", (3, 11), 7, 1, 1, 1),       # key word first
             (dic, AZ, "LANTERN", (25, 4), 20, -1, -1, 2),                   # turn first, both Beaufort
             (AZ, dic, "ILLUSION", (5, 0, 19), 11, 1, 1, 1)]                 # k = 3
    for a, b, word, steps, t, ek, eg, order in cases:
        k = len(steps)
        pt, ct, cribs = m.plant(rng, a, b, word, steps, t, ek, eg, order)
        m.init(ct, cribs, k)
        hits = m.headline(m.work(pairs if k == 2 else [("A", a, "B", b)])[1])
        true = [h for h in hits if (h[2], h[4], h[5], h[6], h[7], h[8], h[9]) == (a, b, order, ek, eg, steps, t)]
        assert len(true) == 1 and true[0][10] == len(word) and true[0][0] == 24 - len(word)
        done = m.complete_all(hits, ct, cribs, SMALL, words)
        assert done[0][1] == pt and done[0][2] == word and done[0][5] == [word]   # message and key word back
        kv = key_values([pt[i] for i in POS], [ct[i] for i in POS], POS, a, b, steps, t, ek, eg, order)
        assert decrypt(ct, a, b, periods(kv, POS)[len(word)], steps, t, ek, eg, order) == pt


if __name__ == "__main__":
    _runner.run(globals())
