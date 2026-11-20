"""Load puzzles from data/.

Every puzzle is one JSON file:
  data/sculpture/k1.json .. k4.json   the four Kryptos sections
  data/ctf/pk1.json .. pk10.json      Paradigm's Kryptos CTF practice puzzles

    from kryptos.data import load, K4, CRIBS
    k2 = load("k2")
    k2["ciphertext"], k2["key"]
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
# The big English word list: Webster's Second (1934, public domain), the macOS /usr/share/dict/words.
# Kept in the repo so every machine searches the same 235,976 words (Linux ships a different list).
WORDS = str(DATA_DIR / "web2.txt")


def _path(pid):
    pid = pid.lower()
    folder = "ctf" if pid.startswith("pk") else "sculpture"
    return DATA_DIR / folder / f"{pid}.json"


def load(pid):
    """Load one puzzle by id: 'k1'..'k4' or 'pk1'..'pk10'."""
    p = _path(pid)
    if not p.exists():
        raise KeyError(f"no puzzle called {pid!r} (try: {', '.join(all_ids())})")
    with open(p) as f:
        return json.load(f)


def all_ids():
    ids = [p.stem for p in sorted((DATA_DIR / "sculpture").glob("k*.json"))]
    ids += sorted((p.stem for p in (DATA_DIR / "ctf").glob("pk*.json")), key=lambda s: int(s[2:]))
    return ids


def letters(text):
    """Uppercase and keep only A-Z."""
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


_k4 = load("k4")
K4 = _k4["ciphertext"]
assert len(K4) == _k4["length"] == 97, "K4 ciphertext must be 97 letters"

# The cribs as {0-indexed position: plaintext letter}
CRIBS = {}
for _c in _k4["cribs"]:
    _word, _start = _c["plaintext"], _c["start"]
    assert _c["end"] - _start + 1 == len(_word), f"bad crib length for {_word}"
    for _i, _ch in enumerate(_word):
        CRIBS[_start - 1 + _i] = _ch
assert len(CRIBS) == 24


def load_k1():  # kept for backwards compatibility
    return load("k1")
