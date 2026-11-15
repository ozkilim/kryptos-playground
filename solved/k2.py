"""K2: Vigenere on the KRYPTOS tableau, key ABSCISSA.

  python solved/k2.py
Shows the known-key decrypt, Sanborn's 2006 correction (X LAYER TWO),
and the key recovered blind by the periodic solver (no key given).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import load  # noqa: E402
from kryptos.ciphers import vigenere_decrypt, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.solvers import crack_periodic  # noqa: E402

k2 = load("k2")
pt = vigenere_decrypt(k2["ciphertext"], "ABSCISSA", KRYPTOS_ALPHABET)
assert pt == k2["plaintext"]
print("as carved :", pt[-40:])
fixed = vigenere_decrypt(k2["ciphertext_corrected"], "ABSCISSA", KRYPTOS_ALPHABET)
assert fixed == k2["plaintext_corrected"]
print("corrected :", fixed[-40:])

best = crack_periodic(k2["ciphertext"])[0]
print("blind     :", best.params, best.plaintext[:50], "...")
assert best.params["key"] == "ABSCISSA"
print("K2 ok")
