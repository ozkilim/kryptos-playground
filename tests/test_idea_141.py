"""Idea 141: king moves on any hidden grid. Texts moved by random king moves on random hidden grids must
come out feasible, with the true grid accepted and listed; K4 must be feasible on a 7-wide flat grid with 4
different moves (its lower bound) and impossible on two flat rows of 13."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea141_anygrid as A
from kryptos.round11 import POS, english97


def test_planted_grids_feasible():
    rng = random.Random(141)
    for n, w, conv, steps in ((26, 7, "flat", None), (27, 9, "twrap", None), (26, 5, "cwrap", None),
                              (26, 6, "flat", [(0, 0), (0, 1), (1, 0), (1, 1)])):
        grid = A.random_grid(n, rng)
        text = english97(rng)
        ct = A.encrypt(text, grid, w, conv, rng, steps)
        pairs = [(text[i], ct[i]) for i in POS]
        truth = A.grid_place(grid, pairs)
        td = A.check(truth, pairs, n, w, conv)
        assert td is not None and (steps is None or td <= len(steps))
        v, sols, _ = A.solve(pairs, n, w, conv, limit=300000)
        assert v == "SAT" and A.check(sols[0], pairs, n, w, conv) is not None
        v, sols, _ = A.solve(pairs, n, w, conv, maxdirs=td, limit=300000)
        assert v == "SAT" and A.check(sols[0], pairs, n, w, conv) <= td
        # with all but 6 letters pinned to the truth, the complete list of grids must hold the truth
        letters = A.graph(pairs)[0]
        free = set(rng.sample(letters, 6))
        pinned = {ch: truth[ch] for ch in letters if ch not in free}
        v, sols, _ = A.solve(pairs, n, w, conv, limit=300000, want=10 ** 9, pinned=pinned)
        assert v == "SAT" and truth in sols
        assert all(A.check(s, pairs, n, w, conv) is not None for s in sols)


def test_wrong_grid_rejected():
    pairs = A.clue_pairs(K4, CRIBS)
    place = {ch: i for i, ch in enumerate(A.graph(pairs)[0])}        # letters in a row: not king moves
    assert A.check(place, pairs, 26, 7, "flat") is None


def test_k4():
    pairs = A.clue_pairs(K4, CRIBS)
    assert A.lower_bound(pairs) == 4 and A.rings(pairs) == 1
    lo, hi, place = A.min_dirs(pairs, 26, 7, "flat", limit=200000)
    assert (lo, hi) == (4, 4) and A.check(place, pairs, 26, 7, "flat") == 4
    grid = A.complete(place, 26)
    assert sorted(grid) == sorted(A.AZ)
    assert A.solve(pairs, 26, 13, "flat", limit=200000)[0] == "UNSAT"


if __name__ == "__main__":
    _runner.run(globals())
