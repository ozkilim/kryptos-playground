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


# ---------- index-level helpers (used by crib-consistency attacks) ----------
# For one letter: c, p, k are positions (0-25) in the alphabet.
#   vigenere:          c = p + k   ->  k = c - p
#   beaufort:          c = k - p   ->  k = c + p
#   variant_beaufort:  c = p - k   ->  k = p - c
KEY_FROM = {
    "vigenere": lambda c, p: (c - p) % 26,
    "beaufort": lambda c, p: (c + p) % 26,
    "variant_beaufort": lambda c, p: (p - c) % 26,
}
PLAIN_FROM = {
    "vigenere": lambda c, k: (c - k) % 26,
    "beaufort": lambda c, k: (k - c) % 26,
    "variant_beaufort": lambda c, k: (c + k) % 26,
}


def autokey_decrypt(ct, primer, mode="ciphertext", variant="vigenere", alphabet=AZ):
    """Autokey: after a short primer, the key is the text itself.

    mode="ciphertext": key[i] = ct[i - len(primer)]   (no primer needed past the start)
    mode="plaintext":  key[i] = pt[i - len(primer)]   (classic Vigenere autokey)
    """
    idx = {c: i for i, c in enumerate(alphabet)}
    dec = PLAIN_FROM[variant]
    L = len(primer)
    out = []
    for i, c in enumerate(ct):
        if i < L:
            k = idx[primer[i]]
        elif mode == "ciphertext":
            k = idx[ct[i - L]]
        else:
            k = idx[out[i - L]]
        out.append(alphabet[dec(idx[c], k)])
    return "".join(out)
