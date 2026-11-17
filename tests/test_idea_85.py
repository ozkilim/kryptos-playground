"""Planted tests for idea 85: cipher letters as skip counts through the sculpture's own text."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4

ROOT = Path(__file__).resolve().parent.parent


def attack(name):
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = attack("85_skip_counts_through_the_text.py")
KEEP = ("tableau panel by rows", "tableau body (26 rows, no labels)", "K1-K3 plaintext corrected")
TL = [(n, t) for n, t in M.texts(extra=False) if n in KEEP]


def test_planted_window_and_walk_are_found_and_read_back():
    rng = random.Random(85)
    for spec in (M.PLANTS[0], M.PLANTS[3], M.PLANTS[5]):      # rule A on the tableau, rule B twice
        ct, cribs, pt, s, _ = M.plant(rng, spec, TL)
        m, n24, good = M.check_plant(spec, ct, cribs, pt, s, TL, serial=True)
        assert m == 24 and good, (spec, m)
        assert M.encode(pt, dict(TL)[spec[1]], spec[0], M.ALPHAS[spec[3]], spec[4], s, rng, spec[5], spec[6]) is not None


def test_reading_inverts_encoding():
    rng = random.Random(1)
    text = dict(TL)["K1-K3 plaintext corrected"]
    pt = text[100:197]
    ct = M.encode(pt, text, "B", M.AZ, 1, 99, rng, "random")
    assert ct and M.read(ct, text, "B", "AZ", 1, 1, 99) == pt
    assert M.encode("JAZZ", text, "B", M.AZ, 1, 0, rng) is None      # K1-K3 has no J and no Z


def test_k4_is_at_chance_on_these_texts():
    r = M.search(K4, CRIBS, TL, serial=True)
    assert r["top"] < 13 and r["n"] > 500000


if __name__ == "__main__":
    _runner.run(globals())
