"""Basic ciphers to experiment with. K1-K3 used these ideas.

Add your own here. Every decrypt function takes ciphertext and returns a
candidate plaintext, so it plugs straight into the internal check.
"""

from string import ascii_uppercase as AZ


def keyed_alphabet(keyword):
    """KRYPTOS -> KRYPTOSABCDEFGHIJLMNQUVWXZ (keyword first, no repeats)."""
    seen = []
    for ch in keyword.upper() + AZ:
        if ch in AZ and ch not in seen:
            seen.append(ch)
    return "".join(seen)


def caesar_decrypt(ct, shift):
    return "".join(AZ[(AZ.index(c) - shift) % 26] for c in ct)


def vigenere_decrypt(ct, key, alphabet=AZ):
    """Vigenere with an optional scrambled alphabet (the Kryptos tableau).
    K1 and K2 = vigenere_decrypt(ct, key, keyed_alphabet("KRYPTOS")).
    """
    key = key.upper()
    out = []
    for i, c in enumerate(ct):
        shift = alphabet.index(key[i % len(key)])
        out.append(alphabet[(alphabet.index(c) - shift) % 26])
    return "".join(out)


def beaufort_decrypt(ct, key, alphabet=AZ):
    key = key.upper()
    out = []
    for i, c in enumerate(ct):
        k = alphabet.index(key[i % len(key)])
        out.append(alphabet[(k - alphabet.index(c)) % 26])
    return "".join(out)


def columnar_decrypt(ct, key):
    """Undo a keyed columnar transposition (columns read in key order)."""
    key = key.upper()
    ncols = len(key)
    nrows, extra = divmod(len(ct), ncols)
    order = sorted(range(ncols), key=lambda i: (key[i], i))
    col_lens = [nrows + (1 if i < extra else 0) for i in range(ncols)]
    cols, pos = [None] * ncols, 0
    for i in order:
        cols[i] = ct[pos:pos + col_lens[i]]
        pos += col_lens[i]
    out = []
    for r in range(nrows + 1):
        for c in range(ncols):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)
