"""Planted tests for idea 90: a worksheet row keys the next (autokey 7, 8 or about 42 letters back)."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import mixes
from kryptos.idea90_rowkey import TESTS, decrypt, plant, test_alphabet as run_alphabet

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w + tag, m) for w in WORDS for tag, m in mixes(w)]


def test_scope_of_tests():
    have = {(t["src"], t["lag"], t["shift"]): len(t["pairs"]) for t in TESTS}
    assert have["plain", 42, 0] == 11 and have["plain", 7, 0] == 10 and have["plain", 8, 0] == 8
    assert have["plain", 45, 0] == 8 and ("plain", 46, 0) not in have and have["plain", 46, 1] == 8
    assert have["cipher", 7, 0] == 24 and have["cipher", 42, 0] == 11 and have["cipher", 66, 0] == 8
    assert ("plain", 9, 0) not in have and ("cipher", 67, 0) not in have


def test_planted_rows_are_found_and_read_back():
    rng = random.Random(90)
    cases = (("plain", 42, 0, 1, 10), ("cipher", 7, 0, 1, 23), ("plain", 41, 2, 2, 8), ("cipher", 50, 0, 3, 8),
             ("plain", 7, 0, 3, 7), ("cipher", 44, -2, 4, 7), ("plain", 8, 0, 1, 7))
    for src, lag, shift, p, checks in cases:
        ct, cribs, want, pt, m = plant(rng, ALPHAS, src, lag, shift, p)
        mine = [h for h in run_alphabet(want[0], m, ct, cribs) if h[1:10] == want]
        assert mine and mine[0][0] == checks, (want, mine)
        got = decrypt(ct, cribs, m, mine[0])
        assert all(a == "." or a == b for a, b in zip(got, pt))
        if src == "cipher":
            assert "." not in got[lag:]                # cipher feed: everything after the primer is forced
        elif lag == 7:
            assert got == pt                           # plain feed, short lag: the clue rows unlock every row


def test_k4_is_clean_on_theme_alphabets():
    for name, m in ALPHAS + [("(A-Z)", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"), ("KRYPTOS", keyword_alphabet("KRYPTOS"))]:
        assert not run_alphabet(name, m, K4, CRIBS)


if __name__ == "__main__":
    _runner.run(globals())
