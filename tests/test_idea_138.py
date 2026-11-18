"""Idea 138: exact Quagmire I/II/IV decision at the community's open key lengths. Planted alphabets must come
out SAT with no false certificate; K4 must be closed for Quagmire I at 20 (x[A] = x[L]) and Quagmire II at
13 (y[K] = y[R]) and satisfiable at the other open lengths."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.idea138_quag import (alphabets, certificate, clue_key, decide, encrypt, equations, random_pair,
                                  read)
from kryptos.round11 import english97


def pairs(rows):
    return [{c[1][1], c[2][1]} for c in certificate(rows)]


def test_k4_open_lengths():
    assert pairs(equations(K4, CRIBS, 20, "QI")) == [{"A", "L"}]
    assert pairs(equations(K4, CRIBS, 13, "QII")) == [{"K", "R"}]
    assert decide(equations(K4, CRIBS, 20, "QI"))[0] == "UNSAT"
    for model, L in (("QI", 13), ("QII", 20), ("QIV", 8), ("QIV", 19)):
        rows = equations(K4, CRIBS, L, model)
        v, wit, _ = decide(rows)
        assert v == "SAT" and not certificate(rows)
        pa, ca = alphabets(model, wit)
        assert clue_key(pa, ca, K4, CRIBS, L)[1]
    # regression against idea 130: Quagmire III Beaufort closed at 18 by B = H
    assert pairs(equations(K4, CRIBS, 18, "QIII", "beau")) == [{"B", "H"}]


def test_planted_satisfiable():
    rng = random.Random(5)
    for model, L, form in (("QI", 20, "vig"), ("QII", 13, "beau"), ("QIV", 8, "vig"), ("QIV", 19, "beau")):
        pa, ca = random_pair(model, rng)
        key = [rng.randrange(26) for _ in range(L)]
        pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(english97(rng)))
        ct = encrypt(pt, pa, ca, key, form)
        rows = equations(ct, CRIBS, L, model, form)
        assert not certificate(rows)
        assert decide(rows)[0] == "SAT"
        back, ok = read(pa, ca, ct, CRIBS, L, form)
        assert ok and all(a == b or a == "?" for a, b in zip(back, pt))


if __name__ == "__main__":
    _runner.run(globals())
