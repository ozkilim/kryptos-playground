"""Idea 140: cipher-letter counters into a key word. Planted recovery, the K4 proof, and the
writer getting stuck on English."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ
from kryptos.idea140_cipher import counts, decrypt, encrypt, k13, settings
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS

ROOT = Path(__file__).resolve().parent.parent


def attack():
    spec = importlib.util.spec_from_file_location("a140", ROOT / "attacks" / "140_cipher_letter_counters.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_encrypt_decrypt_round_trip_with_one_letter_key():
    m = keyword_alphabet("SHADOW")
    pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    for form in ("vig", "beau", "var"):
        ct = encrypt(pt, m, m, form, [5])
        assert ct and decrypt(ct, m, m, form, [5]) == pt
    ct = encrypt("ABC", AZ, AZ, "vig", [0, 1, 2])
    assert decrypt(ct, AZ, AZ, "vig", [0, 1, 2]) == "ABC"
    assert encrypt("AA", AZ, AZ, "vig", [0, 1]) is None          # a doubled plain letter blocks at once


def test_k4_start_is_impossible():
    n = counts(K4)
    assert n[21] == n[30] == 1 and CRIBS[21] == CRIBS[30] == "E" and K4[21] != K4[30]
    _, dead, plans = settings(K4, CRIBS, [768, 0])
    assert dead == 52 and not plans


def test_planted_word_key_found():
    m = attack()
    pre = k13()
    rng = random.Random(4)
    alphas = [("(A-Z)", AZ)] + [(w, keyword_alphabet(w)) for w in ("SHADOW", "MEDUSA", "LODESTONE", "COMPASS")]
    wlen = m.by_length(["PALIMPSEST", "ABSCISSA", "BERLIN", "ILLUSION", "SHADOWS", "CLOCKWISE"])
    big = m.Quadgrams()
    a = keyword_alphabet("LODESTONE")
    wv = [a.index(c) for c in "PALIMPSEST"]
    ct = "".join(rng.choice(AZ) for _ in range(97))
    pt = decrypt(ct, a, a, "vig", wv, pre[300:])
    cribs = {i: pt[i] for i in POS}
    m.STARTS = [298, 299, 300, 301]
    s = m.run_all("planted", ct, cribs, alphas, wlen, big, pool=False, quiet=True)
    assert any(r[2] == pt and "PALIMPSEST (rotation 0) on LODESTONE M/M, Vigenere" in r[3] for r in s["readings"])


if __name__ == "__main__":
    _runner.run(globals())
