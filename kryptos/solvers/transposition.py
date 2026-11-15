"""Crack transpositions by trying every shape and ranking by English score.

  crack_rotation  K3-style double grid rotation, all width pairs that fit
  crack_columnar  keyed columnar, every column order up to max_cols
  crack_railfence rail fence, 2..max_rails
"""

from itertools import permutations

from ..ciphers.transposition import rotation_decrypt, columnar_decrypt, railfence_decrypt, reverse
from ..data import letters
from ..score import quadgram_score
from . import Candidate


def _divisors(n):
    return [d for d in range(2, n) if n % d == 0]


def crack_rotation(ct, top=5):
    raw = letters(ct)
    out = []
    for w1 in _divisors(len(raw)):
        for w2 in _divisors(len(raw)):
            pt = rotation_decrypt(raw, w1, w2)
            out.append(Candidate(quadgram_score(pt), pt, "rotation", {"width1": w1, "width2": w2}))
    out.sort(key=lambda c: -c.score)
    return out[:top]


def crack_columnar(ct, max_cols=7, top=5):
    raw = letters(ct)
    out = []
    for n in range(2, max_cols + 1):
        for order in permutations(range(n)):
            pt = columnar_decrypt(raw, list(order))
            out.append(Candidate(quadgram_score(pt), pt, "columnar", {"order": list(order)}))
    out.sort(key=lambda c: -c.score)
    return out[:top]


def crack_railfence(ct, max_rails=12, top=3):
    raw = letters(ct)
    out = []
    for text, rev in ((raw, False), (reverse(raw), True)):
        for r in range(2, max_rails + 1):
            pt = railfence_decrypt(text, r)
            out.append(Candidate(quadgram_score(pt), pt, "railfence", {"rails": r, "reversed": rev}))
    out.sort(key=lambda c: -c.score)
    return out[:top]
