"""Planted tests for idea 96: the message enciphered back to front (autokey that looks ahead)."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import mixes
from kryptos.idea96_ahead import (TESTS, decrypt, hidden_plant, hidden_survivors, plant, small_decrypt,
                                  small_plant, small_search, test_alphabet as run_alphabet)

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w + tag, m) for w in WORDS for tag, m in mixes(w)]


def test_scope_of_tests():
    have = {(t["src"], t["d"], t["shift"]): len(t["pairs"]) for t in TESTS}
    assert have["plain", 1, 0] == 22 and have["plain", 3, 0] == 18 and have["plain", 8, 0] == 8
    assert have["plain", 42, 0] == 11 and have["plain", 45, 0] == 8 and have["plain", 46, 1] == 8
    assert have["cipher", 11, 0] == 24 and have["cipher", 42, 0] == 13 and have["cipher", 68, 0] == 8
    assert ("plain", 9, 0) not in have and ("plain", 46, 0) not in have and ("cipher", 69, 0) not in have


def test_planted_back_to_front_messages_are_found_and_read_back():
    rng = random.Random(96)
    cases = (("plain", 3, 0, 1, 17), ("cipher", 11, 0, 1, 23), ("plain", 42, 0, 1, 10), ("plain", 40, -2, 2, 9),
             ("cipher", 50, 0, 3, 10), ("plain", 8, 0, 1, 7), ("cipher", 68, 0, 1, 7), ("plain", 5, 0, 4, 10))
    for src, d, shift, p, checks in cases:
        ct, cribs, want, pt, m = plant(rng, ALPHAS, src, d, shift, p)
        mine = [h for h in run_alphabet(want[0], m, ct, cribs) if h[1:10] == want]
        assert mine and mine[0][0] == checks, (want, mine)
        got = decrypt(ct, cribs, m, mine[0])
        assert all(a == "." or a == b for a, b in zip(got, pt))
        if src == "cipher":
            assert "." not in got[:len(pt) - d]        # cipher feed: everything before the primer is forced
        elif d <= 8:
            assert got == pt                           # plain feed, short distance: the clues unlock everything


def test_small_and_hidden_plants():
    rng = random.Random(960)
    ct, cribs, want, pt = small_plant(rng, "cipher", 11, 5)
    _, hits, _ = small_search(ct, cribs)
    mine = [h for h in hits if h[1:9] == want]
    assert mine and small_decrypt(ct, cribs, mine[0])[:86] == pt[:86]
    for mode, src, d in ((("?", "AZ"), "P", 3), (("KR", "?"), "C", 5)):
        ct, cribs, want, _ = hidden_plant(rng, mode, src, d)
        assert any(s[0] == want and s[3] >= 3 for s in hidden_survivors(ct, cribs)[1])


def test_k4_is_clean_on_theme_alphabets():
    for name, m in ALPHAS + [("(A-Z)", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"), ("KRYPTOS", keyword_alphabet("KRYPTOS"))]:
        assert not run_alphabet(name, m, K4, CRIBS)
    assert not small_search(K4, CRIBS)[1]
    assert not [s for s in hidden_survivors(K4, CRIBS)[1] if s[3] >= 3]


if __name__ == "__main__":
    _runner.run(globals())
