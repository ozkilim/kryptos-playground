"""Planted tests for idea 123: compass steps on a letter grid."""
import random
import _runner  # noqa: F401

from kryptos.ciphers.substitution import KRYPTOS_ALPHABET
from kryptos.data import DATA_DIR
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, english97
from kryptos import idea123_compass as C


def test_planted_compass_steps_give_R1_at_the_planted_grid():
    rng = random.Random(123)
    for alpha, n, w, conv in ((KRYPTOS_ALPHABET, 26, 7, "flat"), (keyword_alphabet("UNDERGROUND"), 26, 5, "flat"),
                              (keyword_alphabet("PALIMPSEST"), 27, 9, "twrap"), (KRYPTOS_ALPHABET, 27, 4, "cwrap")):
        text = english97(rng)
        ct = C.encrypt(text, alpha, n, w, conv, rng)
        st = C.stats(C.keys(alpha, n, [text[i] for i in POS], [ct[i] for i in POS]), C.tables(n, w, conv))
        assert st[0][0] == 1 and st[1][0] == 1 and st[2][0] == 1
        cand = C.candidates(alpha, n, w, conv)
        assert all(text[i] in cand[c] for i, c in enumerate(ct))


def test_planted_reading_beats_random_choice():
    rng = random.Random(1230)
    model = C.Model(DATA_DIR / "english" / "quadgrams_big.txt")
    alpha = keyword_alphabet("UNDERGROUND")
    text = english97(rng)
    ct = C.encrypt(text, alpha, 26, 5, "flat", rng)
    cand = C.candidates(alpha, 26, 5, "flat")
    t = C.beam_decode(ct, {i: text[i] for i in POS}, cand, model)
    right = sum(a == b for a, b in zip(t, text))
    assert right >= 24 + 73 // 9 + 15, right


def test_moves_are_shortest_and_wrap():
    # width 5, cells 0..25: from A (0) to E (4) is 4 columns flat, 1 column left with wrap
    t_flat = C.tables(26, 5, "flat")[0]
    t_wrap = C.tables(26, 5, "cwrap")[0]
    assert t_flat[0 * 27 + 4] == 4 and t_wrap[0 * 27 + 4] == 1
    assert C.move(0, 25, 26, 5, "twrap") == (-1, 0)


if __name__ == "__main__":
    _runner.run(globals())
