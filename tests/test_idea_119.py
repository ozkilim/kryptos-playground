"""Planted test for idea 119: the key added to the message as a long number, with carries."""
import random
import _runner  # noqa: F401

from kryptos import idea119_carry as Q
from kryptos.ciphers.substitution import KRYPTOS_ALPHABET
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, english97


def _plant(rng, m, lay, L, n, form, d, model):
    _, r, restart = model
    o = 1 if n == 27 else 0
    ia, ib = Q.layout_maps(m, lay)
    while True:
        pt = english97(rng)
        w = [rng.randrange(26) + o for _ in range(L)]
        kp = [i - Q.row_start(i, Q.ROWS[r]) if restart else i for i in range(97)]
        ct = Q.encrypt(pt, ia, ib, n, o, form, d, [w[t % L] for t in kp], r)
        if ct is not None:
            return pt, ct, kp, ia, ib, o


def test_planted_carry_keys_are_found_and_read_back():
    rng = random.Random(1190)
    full = Q.models(True)
    cases = [(KRYPTOS_ALPHABET, "KRYPTOS", "M/M", 5, 26, "add", "RL", full[0]),
             (KRYPTOS_ALPHABET, "KRYPTOS", "M/M", 8, 26, "beau", "LR", full[1]),
             (KRYPTOS_ALPHABET, "KRYPTOS", "M/M", 11, 26, "sub", "RL", full[4]),
             (keyword_alphabet("SHADOW"), "SHADOW", "M/AZ", 8, 27, "add", "LR", full[0])]
    for m, name, lay, L, n, form, d, model in cases:
        pt, ct, kp, ia, ib, o = _plant(rng, m, lay, L, n, form, d, model)
        hits, tested, exp = Q.test_alphabet(name, m, [pt[i] for i in POS], [ct[i] for i in POS], full)
        good = [h for h in hits if h[2:7] == (lay, n, form, d, "repeating p=%d" % L) and model[0] in h[7]]
        assert good, (name, L, form, d, model)
        h = good[0]
        keys = Q.key_stream(list(h[9]), kp, h[6], n, Q.key_index(model))
        assert Q.decrypt(ct, ia, ib, n, o, form, d, keys, model[1]) == pt
        assert exp < 1e-6


def test_no_carry_k4_style_random_vectors_rarely_pass():
    rng = random.Random(7)
    passes = 0
    for _ in range(3000):
        k = [rng.randrange(26) for _ in POS]
        passes += len(Q.fast_rules(k, POS, 26))
    assert passes == 0


if __name__ == "__main__":
    _runner.run(globals())
