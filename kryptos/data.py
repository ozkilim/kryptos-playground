"""Load the ciphertext and known clues (cribs) from data/."""

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load(name):
    with open(DATA_DIR / name) as f:
        return json.load(f)


_k4 = _load("k4.json")

K4 = _k4["ciphertext"]
assert len(K4) == _k4["length"] == 97, "K4 ciphertext must be 97 letters"

# Turn the cribs into {0-indexed position: plaintext letter}
CRIBS = {}
for c in _k4["cribs"]:
    word, start = c["plaintext"], c["start"]
    assert c["end"] - start + 1 == len(word), f"bad crib length for {word}"
    for i, ch in enumerate(word):
        CRIBS[start - 1 + i] = ch

assert len(CRIBS) == 24


def load_k1():
    return _load("k1.json")
