"""K1: Vigenere on the KRYPTOS tableau, key PALIMPSEST.

  python solved/k1.py
Shows (1) the decrypt with the known key and (2) the same answer found
blind by trying every dictionary word as the key.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import load  # noqa: E402
from kryptos.ciphers import vigenere_decrypt, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.solvers.periodic import crack_wordlist, VARIANTS  # noqa: E402

k1 = load("k1")
pt = vigenere_decrypt(k1["ciphertext"], "PALIMPSEST", KRYPTOS_ALPHABET)
print("known key :", pt)
assert pt == k1["plaintext"]

# 63 letters is too short for statistics, but a dictionary attack finds it.
best = crack_wordlist(k1["ciphertext"], variants={"vigenere": VARIANTS["vigenere"]},
                      alphabets={"KRYPTOS": KRYPTOS_ALPHABET})[0]
print("blind     :", best.plaintext, best.params)
assert best.plaintext == k1["plaintext"]
print("K1 ok")
