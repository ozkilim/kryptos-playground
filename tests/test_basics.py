"""Run with: python -m pytest   (or just: python tests/test_basics.py)"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, load_k1, crib_hits, passes_cribs, normalize
from kryptos.ciphers import (
    vigenere_decrypt, keyed_alphabet, columnar_decrypt, caesar_decrypt,
)


def test_k4_length():
    assert len(K4) == 97


def test_crib_positions_line_up_with_ciphertext():
    # Sanborn: ciphertext FLRVQQPRNGKSS (22-34) -> EASTNORTHEAST
    #          ciphertext NYPVTTMZFPK  (64-74) -> BERLINCLOCK
    assert K4[21:34] == "FLRVQQPRNGKSS"
    assert K4[63:74] == "NYPVTTMZFPK"
    assert "".join(CRIBS[i] for i in range(21, 34)) == "EASTNORTHEAST"
    assert "".join(CRIBS[i] for i in range(63, 74)) == "BERLINCLOCK"


def test_kryptos_alphabet():
    assert keyed_alphabet("KRYPTOS") == "KRYPTOSABCDEFGHIJLMNQUVWXZ"


def test_vigenere_solves_k1():
    k1 = load_k1()
    alpha = keyed_alphabet(k1["alphabet_keyword"])
    assert vigenere_decrypt(k1["ciphertext"], k1["key"], alpha) == k1["plaintext"]


def test_caesar():
    assert caesar_decrypt("KHOOR", 3) == "HELLO"


def test_columnar_roundtrip():
    pt, key = "WEAREDISCOVEREDFLEEATONCE", "ZEBRAS"
    # encrypt by hand: read columns in key order
    order = sorted(range(len(key)), key=lambda i: (key[i], i))
    ct = "".join(pt[i::len(key)] for i in order)
    assert columnar_decrypt(ct, key) == pt


def test_internal_check():
    fake = ["A"] * 97
    for i, ch in CRIBS.items():
        fake[i] = ch
    fake = "".join(fake)
    assert crib_hits(fake) == 24 and passes_cribs(fake)
    assert crib_hits(K4) < 24 and not passes_cribs(K4)
    assert not passes_cribs(fake[:-1])  # wrong length
    assert normalize("Berlin clock!") == "BERLINCLOCK"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
    print("all passed")
