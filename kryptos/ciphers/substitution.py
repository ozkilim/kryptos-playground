"""Periodic substitution ciphers, with an optional keyed alphabet.

Kryptos K1 and K2 are Vigenere on the KRYPTOS-keyed alphabet
(KRYPTOSABCDEFGHIJLMNQUVWXZ), which is the tableau carved on the sculpture.

Non-letters (like the '?' in K2) pass through untouched and do NOT advance
the key, matching how Sanborn enciphered K2.
"""

from string import ascii_uppercase as AZ


def keyed_alphabet(keyword):
    """KRYPTOS -> KRYPTOSABCDEFGHIJLMNQUVWXZ (keyword first, no repeats)."""
    seen = []
    for ch in keyword.upper() + AZ:
        if ch in AZ and ch not in seen:
            seen.append(ch)
    return "".join(seen)


KRYPTOS_ALPHABET = keyed_alphabet("KRYPTOS")


def _periodic(text, key, alphabet, fn):
    key = key.upper()
    idx = {c: i for i, c in enumerate(alphabet)}
    out, j = [], 0
    for c in text:
        if c not in idx:
            out.append(c)
            continue
        out.append(alphabet[fn(idx[c], idx[key[j % len(key)]]) % 26])
        j += 1
    return "".join(out)


def caesar_decrypt(ct, shift, alphabet=AZ):
    return _periodic(ct, alphabet[shift % 26], alphabet, lambda c, k: c - k)


def vigenere_encrypt(pt, key, alphabet=AZ):
    return _periodic(pt, key, alphabet, lambda p, k: p + k)


def vigenere_decrypt(ct, key, alphabet=AZ):
    """P = C - K. K1 = vigenere_decrypt(ct, "PALIMPSEST", KRYPTOS_ALPHABET)."""
    return _periodic(ct, key, alphabet, lambda c, k: c - k)


def beaufort_decrypt(ct, key, alphabet=AZ):
    """P = K - C (Beaufort is its own inverse)."""
    return _periodic(ct, key, alphabet, lambda c, k: k - c)


def variant_beaufort_decrypt(ct, key, alphabet=AZ):
    """P = C + K (the inverse of Vigenere)."""
    return _periodic(ct, key, alphabet, lambda c, k: c + k)
