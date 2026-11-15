"""The automatic solvers crack K1-K3 blind (no key given). If these pass,
the toolkit is trustworthy enough to point at K4."""
import _runner  # noqa: F401
from kryptos import load, quadgram_score, letters
from kryptos.analysis import triage
from kryptos.ciphers import KRYPTOS_ALPHABET
from kryptos.solvers import crack_periodic, crack_rotation, crack_columnar
from kryptos.solvers.periodic import crack_wordlist, VARIANTS


def test_quadgrams_separate_english_from_noise():
    for k in ("k1", "k2", "k3"):
        d = load(k)
        assert quadgram_score(d["plaintext"]) > -5.2
        assert quadgram_score(d["ciphertext"]) < -6.5


def test_triage_tells_the_cipher_types_apart():
    assert "period ~8" in triage(load("k2")["ciphertext"])["guess"]
    assert "transposition" in triage(load("k3")["ciphertext"])["guess"]
    assert "flat" in triage(load("k4")["ciphertext"])["guess"]


def test_blind_k1_via_dictionary():
    best = crack_wordlist(load("k1")["ciphertext"], variants={"vigenere": VARIANTS["vigenere"]},
                          alphabets={"KRYPTOS": KRYPTOS_ALPHABET})[0]
    assert best.params["key"] == "PALIMPSEST"


def test_blind_k2_finds_abscissa():
    best = crack_periodic(load("k2")["ciphertext"])[0]
    assert best.params == {"key": "ABSCISSA", "alphabet": "KRYPTOS", "period": 8}


def test_blind_k3_rotation():
    assert crack_rotation(load("k3")["ciphertext"])[0].plaintext == load("k3")["plaintext"]


def test_blind_pk2_columnar():
    d = load("pk2")
    assert crack_columnar(d["ciphertext"])[0].plaintext == letters(d["plaintext"])


if __name__ == "__main__":
    _runner.run(globals())
