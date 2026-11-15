"""K3: double rotation transposition (grids 24 wide, then 8 wide).

  python solved/k3.py
Shows the known-method decrypt and the same answer found blind by trying
every grid shape that fits 336 letters.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import load  # noqa: E402
from kryptos.ciphers import rotation_decrypt  # noqa: E402
from kryptos.solvers import crack_rotation  # noqa: E402

k3 = load("k3")
pt = rotation_decrypt(k3["ciphertext"], 24, 8)
assert pt == k3["plaintext"]
print("known     :", pt[:60], "...")

best = crack_rotation(k3["ciphertext"])[0]
print("blind     :", best.plaintext[:60], "...", best.params)
assert best.plaintext == k3["plaintext"]
print("K3 ok")
