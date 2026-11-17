"""Planted tests for idea 98: a key word on one tableau, a steadily turning second tableau."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.idea98_turning import (Scanner, checks, decrypt, encrypt, g_of, key_values, periods, slow_scan,
                                    twin)
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, english97
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
SMALL = Quadgrams()                      # the small table is enough to rank the readings here


def attack():
    spec = importlib.util.spec_from_file_location("__main__x98", ROOT / "attacks" / "98_turning_second_tableau.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_checks_and_row_layouts():
    assert checks(8, POS) == 16 and checks(17, POS) == 7 and checks(24, POS) == 5
    assert all(checks(p, POS) >= 7 for p in range(1, 24))
    # carved rows restart at K4 letters 1, 5, 36, 67 (0-based 0, 4, 35, 66)
    assert [g_of(1, i) for i in (0, 3, 4, 34, 35, 65, 66, 96)] == [0, 3, 0, 30, 0, 30, 0, 30]
    # rows of 42 look like rows of 21 on the clue letters once t is moved
    v, s, t = twin(2, 7, 4)
    assert all((s * g_of(v, i) + t) % 26 == (7 * g_of(2, i) + 4) % 26 for i in POS)
    assert any((s * g_of(v, i) + t) % 26 != (7 * g_of(2, i) + 4) % 26 for i in range(97))


def test_fast_scan_agrees_with_slow_scan():
    rng = random.Random(5)
    sc = Scanner(POS)
    m = keyword_alphabet("PALIMPSEST")
    a, b = KRYPTOS_ALPHABET, m
    pt = english97(rng)
    ct = encrypt(pt, a, b, [rng.randrange(26) for _ in range(12)], 9, 4, -1, 1, 2, 1)
    ptl, ctl = [pt[i] for i in POS], [ct[i] for i in POS]
    fast = sc.scan(a, b, ptl, ctl)
    assert fast == slow_scan(a, b, ptl, ctl, POS)           # every one of the 15,600 settings agrees
    assert (2, -1, 1, 1, 9, 4) in fast


def test_planted_turning_tableau_found_and_k4_clean():
    m = attack()
    rng = random.Random(98)
    dic = keyword_alphabet("LODESTONE")
    small = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)]
    pairs = m.part1_pairs(small) + m.part2_pairs(
        [(w, keyword_alphabet(w)) for w in ("LODESTONE", "SHADOW", "MEDUSA", "BERLIN", "CLOCK")], small)
    cases = [(KRYPTOS_ALPHABET, dic, "ABSCISSA", 3, 11, 1, 1, 1, 0),      # key word first, +3 turn second
             (KRYPTOS_ALPHABET, dic, "ILLUSION", 3, 20, 1, 1, 2, 0),      # the reverse order
             (dic, AZ, "LANTERN", 11, 5, -1, 1, 1, 1),                    # Beaufort key word, carved rows
             (AZ, KRYPTOS_ALPHABET, "PALIMPSESTS", 25, 7, 1, -1, 2, 3)]   # rows of 42, read as the twin
    for a, b, word, s, t, ek, eg, order, v in cases:
        pt, ct, cribs = m.plant(rng, a, b, word, s, t, ek, eg, order, v)
        m.init(ct, cribs)
        hits = m.headline(m.work(pairs)[1])
        assert len(hits) == 1                                    # the single survivor
        h = hits[0]
        assert (h[2], h[4], h[5], h[6], h[7]) == (a, b, order, ek, eg)
        assert h[8:11] == m.on_clues(v, s, t) and h[11] == len(word) and h[0] == 24 - len(word)
        done = m.complete_all(hits, ct, cribs, SMALL)
        assert done[0][1] == pt and done[0][2] == word           # message and key word read back
        # the slow pieces agree with each other
        kv = key_values([pt[i] for i in POS], [ct[i] for i in POS], POS, a, b, s, t, ek, eg, order, v)
        assert decrypt(ct, a, b, periods(kv, POS)[len(word)], s, t, ek, eg, order, v) == pt
    m.init(K4, CRIBS)
    assert not m.headline(m.work(pairs)[1])                      # K4: nothing with 7+ checks on these pairs


if __name__ == "__main__":
    _runner.run(globals())
