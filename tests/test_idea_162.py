"""Planted tests for idea 162: the coordinate slip (row digit from one letter, column digit from another)."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea162_slip as S
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import english97


def _message(rng):
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


def _plant(rng, words, g, mode, u, w, a, b, fill):
    for _ in range(5000):
        word = rng.choice(words)
        cells = S.keyword_grid(keyword_alphabet(word), g, fill)
        pt = _message(rng)
        ct = S.encrypt(pt, cells, g, mode, u, w, a, b)
        if ct and "." not in ct:
            return word, cells, pt, ct
    raise AssertionError("no message without an empty cell")


WORDS = ["PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN", "CLOCK", "LANGLEY", "MATRIX", "SANBORN", "SCHEIDT",
         "QUARTZ", "LODESTONE", "COMPASS", "ILLUSION", "IQLUSION", "DIGETAL", "NORTHWEST", "EGYPT", "CARTER"]


def test_planted_keyword_grids_survive_and_read_back():
    rng = random.Random(1620)
    alphabets = [(w, keyword_alphabet(w)) for w in WORDS]
    for g, mode, u, w, a, b, fill in (((5, 6), "RC", 0, 3, 0, 0, "rows"), ((3, 9), "RC", 0, 21, 0, 0, "rows"),
                                      ((6, 5), "RC", -7, 0, 0, 0, "cols"), ((4, 7), "RC", 0, 5, 0, 3, "rows"),
                                      ((5, 6), "RC", 2, -4, 0, 0, "rows"), ((5, 6), "CR", 0, 3, 0, 0, "cols")):
        word, cells, pt, ct = _plant(rng, WORDS, g, mode, u, w, a, b, fill)
        for wrap in (False, True):
            v, place = S.decide(ct, CRIBS, g, mode, u, w, a, b, wrap=wrap)
            assert v is True, (g, mode, u, w, wrap)
            assert S.check_grid(ct, CRIBS, S.build_grid(place, g), g, mode, u, w, a, b, wrap)
        hits = S.dictionary_hits(ct, CRIBS, alphabets, g, mode, u, w, a, b, wrap=True)
        assert any(c == cells for _, _, c in hits)
        assert any(S.decrypt(ct, c, g, mode, u, w, a, b) == pt for _, _, c in hits)


def test_k4_home_line_is_impossible():
    # the idea as stated: one digit line at home. No grid of any of the eight shapes fits the clue letters.
    for g in S.GRIDS:
        for s in (1, -1, 3, 7, 21, -21, 45):
            for u, w in ((0, s), (s, 0)):
                assert S.decide(K4, CRIBS, g, "RC", u, w)[0] is False
                assert S.decide(K4, CRIBS, g, "CR", u, w)[0] is False
    # with a constant on the home line, K = K at letter 74 forces it back to 0
    assert S.decide(K4, CRIBS, (2, 13), "RC", 0, 3, 1, 0)[0] is False
    # both lines slid, wrapped ends: a sample
    for u, w in ((1, 2), (-3, 4), (20, -20), (36, 35)):
        assert S.decide(K4, CRIBS, (5, 6), "RC", u, w, wrap=True)[0] is False


if __name__ == "__main__":
    _runner.run(globals())
