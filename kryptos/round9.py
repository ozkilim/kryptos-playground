"""Shared tools for round 9: key views of the clues and exact linear algebra mod 26.

Everything in round 9 leans on one trick. Inside the two clue blocks we know plaintext and
ciphertext, so any model that is *linear* in its unknowns (key slots, formula coefficients,
even the 26 positions of a hidden alphabet) becomes a small linear system mod 26. Z_26 is not
a field, so we solve mod 13 and mod 2 separately (Chinese remainder theorem) and join them.
"""
import itertools
import random

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import CRIBS, K4

POS = sorted(CRIBS)                      # the 24 clue positions, 0-indexed
BLOCKS = [list(range(21, 34)), list(range(63, 74))]
WORDS = [list(range(21, 25)), list(range(25, 34)), list(range(63, 69)), list(range(69, 74))]
ALPHAS = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
UNITS = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


def keyword_alphabet(word, base=AZ):
    seen, out = set(), []
    for ch in word + base:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


def crib_cipher(ct=K4):
    return {i: ct[i] for i in POS}


def shuffled_control(seed, ct=K4):
    """A control ciphertext: K4's letters in random order (clue plaintext stays put)."""
    s = list(ct)
    random.Random(seed).shuffle(s)
    return "".join(s)


def key_views(ct=K4, cribs=CRIBS, multipliers=(1, 25)):
    """Every 'key value' reading of the clues: k = idx_B(C) - m * idx_A(P) mod 26.

    m = 1 is Vigenere (variant Beaufort is its negative), m = 25 is Beaufort (k = C + P).
    Other units m give affine tableaux. Yields (name, {pos: k}).
    """
    for an, a in ALPHAS.items():
        ia = {c: i for i, c in enumerate(a)}
        for bn, b in ALPHAS.items():
            ib = {c: i for i, c in enumerate(b)}
            for m in multipliers:
                yield (f"pt{an}/ct{bn}/m{m}",
                       {i: (ib[ct[i]] - m * ia[cribs[i]]) % 26 for i in sorted(cribs)})


# ---------------------------------------------------------------- linear algebra mod p

def solve_mod_p(rows, rhs, p):
    """Solve rows * x = rhs over GF(p). Returns (particular, nullspace basis) or None."""
    n = len(rows[0]) if rows else 0
    m = [[v % p for v in r] + [b % p] for r, b in zip(rows, rhs)]
    piv, r = [], 0
    for c in range(n):
        s = next((i for i in range(r, len(m)) if m[i][c]), None)
        if s is None:
            continue
        m[r], m[s] = m[s], m[r]
        inv = pow(m[r][c], p - 2, p) if p > 2 else 1
        m[r] = [(v * inv) % p for v in m[r]]
        for i in range(len(m)):
            if i != r and m[i][c]:
                f = m[i][c]
                m[i] = [(a - f * b) % p for a, b in zip(m[i], m[r])]
        piv.append(c)
        r += 1
        if r == len(m):
            break
    for i in range(r, len(m)):
        if m[i][n]:
            return None
    part = [0] * n
    for i, c in enumerate(piv):
        part[c] = m[i][n]
    free = [c for c in range(n) if c not in piv]
    basis = []
    for f in free:
        v = [0] * n
        v[f] = 1
        for i, c in enumerate(piv):
            v[c] = (-m[i][f]) % p
        basis.append(v)
    return part, basis


def consistent_mod26(rows, rhs):
    """(ok mod 13, ok mod 2, free dimensions mod 13, free dimensions mod 2)."""
    s13, s2 = solve_mod_p(rows, rhs, 13), solve_mod_p(rows, rhs, 2)
    return (s13 is not None, s2 is not None,
            len(s13[1]) if s13 else -1, len(s2[1]) if s2 else -1)


def solutions_mod26(rows, rhs, limit=200000):
    """Every solution mod 26 (None if inconsistent, 'many' if more than `limit`)."""
    s13, s2 = solve_mod_p(rows, rhs, 13), solve_mod_p(rows, rhs, 2)
    if s13 is None or s2 is None:
        return None
    if 13 ** len(s13[1]) * 2 ** len(s2[1]) > limit:
        return "many"

    def span(sol, p):
        part, basis = sol
        for coef in itertools.product(range(p), repeat=len(basis)):
            v = list(part)
            for c, b in zip(coef, basis):
                if c:
                    v = [(x + c * y) % p for x, y in zip(v, b)]
            yield v

    all2 = list(span(s2, 2))
    out = []
    for v13 in span(s13, 13):
        for v2 in all2:
            # CRT: x = v13 mod 13, x = v2 mod 2
            out.append([(a + 13 * ((a + b) % 2)) % 26 for a, b in zip(v13, v2)])
    return out
