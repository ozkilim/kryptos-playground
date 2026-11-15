"""Every cipher reproduces the real Kryptos solutions and round-trips."""
import _runner  # noqa: F401
from kryptos import load
from kryptos.ciphers import (
    AZ, KRYPTOS_ALPHABET, keyed_alphabet, caesar_decrypt, vigenere_encrypt, vigenere_decrypt,
    beaufort_decrypt, variant_beaufort_decrypt, columnar_encrypt, columnar_decrypt,
    rotation_encrypt, rotation_decrypt, railfence_decrypt,
)


def test_kryptos_alphabet():
    assert keyed_alphabet("KRYPTOS") == KRYPTOS_ALPHABET == "KRYPTOSABCDEFGHIJLMNQUVWXZ"


def test_k1():
    d = load("k1")
    assert vigenere_decrypt(d["ciphertext"], "PALIMPSEST", KRYPTOS_ALPHABET) == d["plaintext"]


def test_k2_as_carved_and_corrected():
    d = load("k2")
    assert vigenere_decrypt(d["ciphertext"], "ABSCISSA", KRYPTOS_ALPHABET) == d["plaintext"]
    assert vigenere_decrypt(d["ciphertext_corrected"], "ABSCISSA", KRYPTOS_ALPHABET) == d["plaintext_corrected"]
    assert d["plaintext_corrected"].endswith("WESTXLAYERTWO")


def test_k3_both_directions():
    d = load("k3")
    assert rotation_decrypt(d["ciphertext"], 24, 8) == d["plaintext"]
    assert rotation_encrypt(d["plaintext"], 24, 8) == d["ciphertext"]


def test_vigenere_family_roundtrips():
    pt, key = "ATTACKATDAWN", "LEMON"
    for alpha in (AZ, KRYPTOS_ALPHABET):
        ct = vigenere_encrypt(pt, key, alpha)
        assert vigenere_decrypt(ct, key, alpha) == pt
        assert variant_beaufort_decrypt(vigenere_decrypt(pt, key, alpha), key, alpha) == pt
        assert beaufort_decrypt(beaufort_decrypt(pt, key, alpha), key, alpha) == pt  # self-inverse
    assert vigenere_encrypt("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"  # textbook example
    assert caesar_decrypt("KHOOR", 3) == "HELLO"


def test_columnar_roundtrip_and_position_map():
    pt = "WEAREDISCOVEREDFLEEATONCE"
    for key in ("ZEBRAS", [2, 0, 1, 3], "KRYPTOS"):
        ct = columnar_encrypt(pt, key)
        assert columnar_decrypt(ct, key) == pt
        m = columnar_decrypt(list(range(len(pt))), key)
        assert all(ct[m[i]] == pt[i] for i in range(len(pt)))


def test_railfence():
    assert railfence_decrypt("WECRLTEERDSOEEFEAOCAIVDEN", 3) == "WEAREDISCOVEREDFLEEATONCE"


if __name__ == "__main__":
    _runner.run(globals())
