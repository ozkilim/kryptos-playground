"""Planted tests for idea 139: four-square and two-square on 26/27-cell rectangles with all squares free."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea139_freesquares as F
from kryptos.round11 import english97


def _message(rng):
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


def test_planted_random_squares_are_feasible():
    rng = random.Random(1390)
    n = 0
    for g in F.GRIDS:
        for c in ("four", "two"):
            for w in (1, 7, 21, 40):
                o = rng.randrange(2 * w)
                order = rng.choice("AB")
                f = F.four_square if c == "four" else F.two_square
                for _ in range(20):
                    sq = F.random_squares(g, c, rng)
                    pt = _message(rng)
                    ct = f(pt, w, o, g, sq, order)
                    if "?" not in ct:
                        break
                assert f(ct, w, o, g, sq, order, decrypt=True) == pt
                v, a = F.decide(ct, CRIBS, w, o, g, c, order)
                assert v is True, (c, g, w, o, order)
                assert F.check_assignment(ct, CRIBS, w, o, g, c, order, a)
                n += 1
    assert n == 32


def test_k4_ordinary_pairs():
    # four-square with ANY squares: impossible on 2x13 and 13x2 at w = 1, possible on 3x9 at start 0
    for g in ((2, 13), (13, 2)):
        for o in (0, 1):
            for order in "AB":
                assert F.decide(K4, CRIBS, 1, o, g, "four", order)[0] is False
    assert F.decide(K4, CRIBS, 1, 0, (3, 9), "four", "A")[0] is True
    # two-square with any squares: impossible on all four grids (agrees with idea 103's quick test)
    for g in F.GRIDS:
        for o in (0, 1):
            for order in "AB":
                assert F.decide(K4, CRIBS, 1, o, g, "two", order)[0] is False


if __name__ == "__main__":
    _runner.run(globals())
