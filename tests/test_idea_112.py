"""Planted tests for idea 112: the narrowest window of clue key values any hidden alphabet allows."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ
from kryptos.round11 import POS, english97
from kryptos import idea112_window as W


def _alphabets(rng):
    X, Y = list(AZ), list(AZ)
    rng.shuffle(X)
    rng.shuffle(Y)
    return {"X": "".join(X), "Y": "".join(Y)}


def test_planted_small_keys_recovered_in_every_layout():
    rng = random.Random(112)
    for values in (list(range(5)), list(range(10))):
        text = english97(rng)
        key = [rng.choice(values) for _ in range(97)]
        wp = max(values) - min(values) + 1
        for lay in W.LAYOUTS:
            alph = _alphabets(rng)
            ct = W.encrypt(lay, text, key, alph)
            p, c = [text[i] for i in POS], [ct[i] for i in POS]
            assert W.key_values(lay, p, c, alph) == [key[i] for i in POS]
            assert W.min_window(lay, p, c, 1)[0] <= wp
            assert W.planted_found(lay, p, c, alph, wp), lay


def test_witness_is_a_real_arrangement_and_w_minus_1_fails():
    pl, cl = [CRIBS[i] for i in POS], [K4[i] for i in POS]
    for lay in ("same/vig", "ptX/AZ", "ctX/KR"):
        w = W.min_window(lay, pl, cl, 1)[0]
        s, sol = W.one_solution(lay, pl, cl, w)
        win = {(s + j) % 26 for j in range(w)}
        m = W.Model(lay, pl, cl)
        place = [sol[k] for k in m.names]
        assert len(set(place)) == len(place)
        for pe, ce in m.ends:
            a = place[pe[1]] if pe[0] == "v" else pe[1]
            b = place[ce[1]] if ce[0] == "v" else ce[1]
            assert (b + m.sp * a) % 26 in win
        assert W.feasible(m, w - 1)[0] == 0


def test_k4_known_values():
    pl, cl = [CRIBS[i] for i in POS], [K4[i] for i in POS]
    assert W.min_window("same/vig", pl, cl, 1)[0] == 6
    assert W.min_window("ptX/AZ", pl, cl, 1)[0] == 12
    assert W.min_window("ctX/AZ", pl[:13], cl[:13], 1)[0] == 3


if __name__ == "__main__":
    _runner.run(globals())
