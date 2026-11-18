"""Planted test for idea 133: small-shift key on the first part only, hidden plain alphabet vs A-Z."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.round11 import english97
from kryptos import idea133_beam as B

BLK = "EASTNORTHEAST"


def _with_clues(text):
    t = list(text)
    for i, ch in CRIBS.items():
        t[i] = ch
    return "".join(t)


def test_k4_block_counts():
    assert B.min_window_b1(K4, BLK) == 5
    assert len(B.arrangements(K4, BLK, 5)) == 4288          # idea 112's count
    assert [len(B.periodic_keys(K4, BLK, 5, p)) for p in range(2, 9)] == [0, 0, 0, 0, 0, 0, 7]


def test_planted_period_key_recovered():
    rng = random.Random(4)
    pt = _with_clues(english97(rng))
    X = list(B.AZ)
    rng.shuffle(X)
    key = [rng.randrange(5) for _ in range(8)]
    E = 58
    ct = "".join(B.AZ[(X.index(ch) + key[i % 8]) % 26] if i < E else B.AZ[(ord(ch) - 54) % 26]
                 for i, ch in enumerate(pt))
    _, w, p, n, top = B.periodic_job(("t", ct, 5, 8, (49,), 7, 3))
    assert n >= 1
    s, E1, txt, k, _ = top[0]
    assert list(k) == key
    reg = [i for i in range(E1) if not 21 <= i <= 33]
    assert B.agreement(txt, pt, reg) >= 0.75 * len(reg)


def test_free_key_beam_reading_is_valid():
    rng = random.Random(9)
    pt = _with_clues(english97(rng))
    ct, _ = B.plant(pt, 55, 5, rng)
    assert B.check_reading(ct, pt[:55], 5)
    res, n = B.beam(ct, BLK, 5, width=60)
    for E, (s, txt, _) in res.items():
        assert txt[21:34] == BLK and B.check_reading(ct, txt, 5)


if __name__ == "__main__":
    _runner.run(globals())
