"""The internal check. Free, instant, run it millions of times.

A candidate plaintext must put the 24 known letters in the right places.
If it does, we also score how English-like the rest looks, so you can
rank survivors before paying for an official check.
"""

import math
from collections import Counter

from .data import CRIBS

# Standard English letter frequencies (percent)
ENGLISH_FREQ = {
    "A": 8.17, "B": 1.49, "C": 2.78, "D": 4.25, "E": 12.70, "F": 2.23,
    "G": 2.02, "H": 6.09, "I": 6.97, "J": 0.15, "K": 0.77, "L": 4.03,
    "M": 2.41, "N": 6.75, "O": 7.51, "P": 1.93, "Q": 0.10, "R": 5.99,
    "S": 6.33, "T": 9.06, "U": 2.76, "V": 0.98, "W": 2.36, "X": 0.15,
    "Y": 1.97, "Z": 0.07,
}


def normalize(text):
    """Uppercase and keep only A-Z. 'Berlin clock' -> 'BERLINCLOCK'."""
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def crib_hits(plaintext):
    """How many of the 24 known letters this candidate gets right."""
    p = normalize(plaintext)
    return sum(1 for i, ch in CRIBS.items() if i < len(p) and p[i] == ch)


def passes_cribs(plaintext):
    """True only if all 24 known letters are in place and length is 97."""
    p = normalize(plaintext)
    return len(p) == 97 and crib_hits(p) == len(CRIBS)


def english_score(plaintext):
    """Chi-squared distance from English letter frequencies.
    Lower is more English. At 97 letters, real English scores around
    30-60; random letters score roughly 250-1000.
    """
    p = normalize(plaintext)
    if not p:
        return float("inf")
    counts = Counter(p)
    n = len(p)
    chi = 0.0
    for letter, pct in ENGLISH_FREQ.items():
        expected = n * pct / 100
        chi += (counts.get(letter, 0) - expected) ** 2 / expected
    return chi


def index_of_coincidence(text):
    """About 0.066 for English, about 0.038 for random letters."""
    p = normalize(text)
    n = len(p)
    if n < 2:
        return 0.0
    counts = Counter(p)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def crib_report(plaintext):
    """Human-readable check. Shows each known position and whether it matched."""
    p = normalize(plaintext)
    lines = [
        f"length:        {len(p)} (need 97)",
        f"crib hits:     {crib_hits(p)}/{len(CRIBS)}",
        f"english score: {english_score(p):.1f} (lower is better)",
        f"IoC:           {index_of_coincidence(p):.4f} (English ~0.066)",
        f"PASSES:        {passes_cribs(p)}",
    ]
    marks = "".join(
        ("." if i not in CRIBS else ("+" if i < len(p) and p[i] == CRIBS[i] else "x"))
        for i in range(97)
    )
    lines += ["", p, marks, "(+ match, x wrong, . unknown)"]
    return "\n".join(lines)
