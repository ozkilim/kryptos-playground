"""Planted tests for idea 136: plain autokey lags 5-12 on a half-hidden tableau (one dictionary alphabet, one free)."""
import random
import _runner  # noqa: F401

from kryptos.ciphers.substitution import AZ
from kryptos.data import DATA_DIR
from kryptos.round9 import keyword_alphabet
from kryptos import idea136_half as H

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS", "QUARTZ",
         "HOROLOGE", "LANGLEY", "SCULPTURE"]


def _plant(rng, cell, word):
    pt = H.plant_text(rng)
    M = keyword_alphabet(word)
    free = H.random_alphabet(rng)
    mp, mc = (M, free) if cell[0] == "P" else (free, M)
    c = rng.randrange(26) if cell[0] == "C" else 0
    primer = "".join(rng.choice(AZ) for _ in range(cell[3]))
    return pt, H.encrypt(pt, cell, mp, mc, c, primer), M, mp, mc, c


def test_every_cell_passes_its_own_planted_message_and_decrypts_it():
    rng = random.Random(136)
    for cell in H.cells():
        pt, ct, M, mp, mc, c = _plant(rng, cell, rng.choice(WORDS))
        st, _ = H.Cell(cell, ct).test([M.index(ch) for ch in AZ])
        assert st != "none", H.name(cell)
        dec, bad = H.Decryptor(cell, ct).run(mp, mc, c)
        assert bad == 0 and dec == pt, H.name(cell)


def test_exact_test_singles_out_the_true_alphabet():
    rng = random.Random(5)
    for cell in (("C", "M", "back", 5, 1), ("C", "M", "ahead", 7, -1)):
        pt, ct, M, *_ = _plant(rng, cell, "PALIMPSEST")
        C = H.Cell(cell, ct)
        others = [keyword_alphabet(w) for w in WORDS if w != "PALIMPSEST"] + [H.random_alphabet(rng) for _ in range(300)]
        assert C.test([M.index(ch) for ch in AZ])[0] != "none"
        assert sum(C.test([a.index(ch) for ch in AZ])[0] != "none" for a in others) <= 1


def test_planted_messages_read_back():
    big = H.Big(DATA_DIR / "english" / "quadgrams.txt")
    for seed, cell in ((0, ("P", "M", "back", 7, 1)), (1, ("C", "M", "ahead", 9, -1)), (2, ("C", "AZ", "back", 5, 1))):
        rng = random.Random(seed)
        pt, ct, M, *_ = _plant(rng, cell, "SHADOW")
        st, sols = H.Cell(cell, ct).solve([M.index(ch) for ch in AZ], max_points=2000, max_sols=64)
        assert st != "none"
        r = H.read(cell, ct, M, H.starts_from(cell, sols, M, ct), big, rng, width=300, iters=1200)
        assert sum(a == b for a, b in zip(r[1], pt)) >= 85, H.name(cell)


if __name__ == "__main__":
    _runner.run(globals())
