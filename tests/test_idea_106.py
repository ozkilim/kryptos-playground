"""Planted tests for idea 106: K4 letters count words through the solved K1-K3 text."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea106_words as W

ROOT = Path(__file__).resolve().parent.parent


def attack(name):
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = attack("106_word_counts_through_k1_k3.py")
KEEP = (M.MAIN, "K1-K3 (corrected, X dropped, LAYER TWO)", "Morse (as carved, X kept, ID BY ROWS)")
TL = [(n, t) for n, t in W.word_texts(full=False) if n in KEEP]
T = dict(TL)


def test_word_lists_spell_the_carved_plaintexts():
    assert W.check_transcription()
    assert len(T[M.MAIN]) == 163 and T[M.MAIN][0] == "BETWEEN" and T[M.MAIN][-1] == "Q"
    assert W.line(T[M.MAIN], "1")[:13] == "BSSATAOLLTNOI" and W.line(["I", "AM"], "2") == "?M"


def test_planted_walk_and_window_are_found_and_read_back():
    rng = random.Random(106)
    words = M.vocab()
    for spec in M.PLANTS[:3]:                 # walk on first letters, walk on last letters, window
        ct, cribs, pt, s = M.plant(rng, spec, T, words)
        m, n24, good = M.check_plant(spec, ct, cribs, pt, s, TL, serial=True)
        assert m == 24 and good, (spec, m)


def test_planted_pairs_are_found_and_read_back():
    rng = random.Random(7)
    ct, cribs, pt, s, _ = M.plant_c(rng, T, M.vocab())
    m, n24, good = M.check_plant_c(ct, cribs, pt, s, TL[:1], serial=True)
    assert m == 24 and good


def test_reading_inverts_encoding_and_english_cannot_be_walked():
    rng = random.Random(1)
    text = W.line(T[M.MAIN], "1")
    pt = "MEETATTHEWALL"
    ct = W.encode(pt, text, "W", W.AZ, 1, 40, rng)
    assert ct and W.read(ct, text, "W", "AZ", 1, 1, 40) == pt
    assert W.encode("THISISATEST", text, "W", W.AZ, 1, 40, rng) is None    # even this cannot be walked
    assert W.encode("VIVA", text, "W", W.AZ, 1, 0, rng) is None       # no word of K1-K3 starts with V
    assert W.encode("VIVA", text, "B", W.AZ, 0, 0, rng) is None


def test_k4_is_at_chance_on_these_texts():
    r = W.search(K4, CRIBS, TL, serial=True)
    assert r["top"] < 13 and r["n"] > 500000


if __name__ == "__main__":
    _runner.run(globals())
