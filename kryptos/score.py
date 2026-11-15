"""How English does a candidate look? (Lower-level than the crib check.)

  quadgram_score(text)   best general-purpose fitness. Average log10
                         probability per 4-letter window. English ~ -4.0
                         to -4.6, random letters ~ -6.
  chi_squared(text)      single-letter frequency distance. English 20-60
                         at ~100 letters, random 250+.
  ioc(text)              index of coincidence. English ~0.066, random 0.038.

The quadgram table lives in data/english/quadgrams.txt. Rebuild it from a
bigger corpus with:  python tools/build_ngrams.py some_books/*.txt
"""

import math
from collections import Counter

from .data import DATA_DIR, letters

ENGLISH_FREQ = {
    "A": 8.17, "B": 1.49, "C": 2.78, "D": 4.25, "E": 12.70, "F": 2.23,
    "G": 2.02, "H": 6.09, "I": 6.97, "J": 0.15, "K": 0.77, "L": 4.03,
    "M": 2.41, "N": 6.75, "O": 7.51, "P": 1.93, "Q": 0.10, "R": 5.99,
    "S": 6.33, "T": 9.06, "U": 2.76, "V": 0.98, "W": 2.36, "X": 0.15,
    "Y": 1.97, "Z": 0.07,
}
ENGLISH_IOC = 0.066
RANDOM_IOC = 1 / 26


def chi_squared(text):
    p = letters(text)
    if not p:
        return float("inf")
    counts, n = Counter(p), len(p)
    return sum((counts.get(L, 0) - n * f / 100) ** 2 / (n * f / 100) for L, f in ENGLISH_FREQ.items())


def ioc(text):
    p = letters(text)
    n = len(p)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in Counter(p).values()) / (n * (n - 1))


class Quadgrams:
    """Log-probability scorer. Loaded once, lazily."""

    def __init__(self, path=DATA_DIR / "english" / "quadgrams.txt"):
        counts = {}
        with open(path) as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                q, c = line.split()
                counts[q] = int(c)
        total = sum(counts.values())
        self.logp = {q: math.log10(c / total) for q, c in counts.items()}
        self.floor = math.log10(0.01 / total)

    def score(self, text):
        """Mean log10 probability per quadgram (length-independent)."""
        p = letters(text)
        if len(p) < 4:
            return self.floor
        get, fl = self.logp.get, self.floor
        return sum(get(p[i:i + 4], fl) for i in range(len(p) - 3)) / (len(p) - 3)


_QG = None


def quadgram_score(text):
    global _QG
    if _QG is None:
        _QG = Quadgrams()
    return _QG.score(text)


def english_score(text):
    """Back-compat alias: chi-squared, lower is better."""
    return chi_squared(text)


_WORDS = None


def word_coverage(text, min_len=4, max_len=15):
    """Fraction of letters covered by dictionary words (/usr/share/dict/words +
    data/keys.txt) of at least min_len letters, best non-overlapping cover.
    A second English check that doesn't share the quadgram model's quirks."""
    global _WORDS
    if _WORDS is None:
        _WORDS = set()
        for path in ("/usr/share/dict/words", str(DATA_DIR / "keys.txt")):
            try:
                with open(path) as f:
                    _WORDS |= {w.strip().upper() for w in f
                               if w.strip().isalpha() and min_len <= len(w.strip()) <= max_len}
            except OSError:
                pass
    p = letters(text)
    n = len(p)
    best = [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        b = best[i + 1]
        for L in range(min_len, min(max_len, n - i) + 1):
            if p[i:i + L] in _WORDS:
                b = max(b, L + best[i + L])
        best[i] = b
    return best[0] / n if n else 0.0
