"""Idea 137: Quagmire III Beaufort at key lengths 23 and 26, any alphabet, clue equations hard.

Fast planted checks of the machinery: the repair move keeps every clue equation exact, the planted
truth is a local optimum the annealer climbs back to from a nearby start, and the Vigenere form is
closed at 23 and 26 by a forced-equal certificate."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.data import DATA_DIR
from kryptos.idea130_exact import certificate, equations
from kryptos.idea137_anneal import AZ, Problem, anneal, encrypt, load_table, near_truth, truth_score
from kryptos.round11 import english97

_T = []


def table():
    if not _T:
        _T.append(load_table(DATA_DIR / "english" / "quadgrams_big.txt"))
    return _T[0]


def plant(rng, L):
    alpha = "".join(rng.sample(AZ, 26))
    key = [rng.randrange(26) for _ in range(L)]
    pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(english97(rng)))
    return pt, alpha, key, encrypt(pt, alpha, key, "beau")


def test_vigenere_form_closed_at_23_and_26():
    assert ("R", "P") in certificate(equations(K4, CRIBS, 23, "vig"))
    assert ("E", "F") in certificate(equations(K4, CRIBS, 26, "vig"))
    assert not certificate(equations(K4, CRIBS, 23, "beau"))


def test_every_visited_state_keeps_the_clues():
    rng = random.Random(5)
    for L in (23, 26):
        prob = Problem(K4, CRIBS, L, "beau")
        q, al, kf = anneal(prob, table(), rng, 3000)
        txt, br = prob.text(al, kf)
        assert br == 0 and all(txt[i] == c for i, c in CRIBS.items())


def test_planted_truth_is_recovered_from_nearby():
    rng = random.Random(137)
    for L in (23, 26):
        pt, alpha, key, ct = plant(rng, L)
        prob = Problem(ct, CRIBS, L, "beau")
        ts, ttxt, br = truth_score(prob, table(), alpha, key)
        assert br == 0 and ttxt == pt
        q, txt = near_truth(prob, table(), rng, alpha, key, swaps=1, iters=15000)
        assert q >= ts - 0.005, (L, q, ts)
        assert sum(a == b for a, b in zip(txt, pt)) >= 80


if __name__ == "__main__":
    _runner.run(globals())
