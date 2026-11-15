"""Teleprinter (Baudot / ITA2) codes and Vernam XOR.

K2 says the information was "transmitted underground"; the CIA's Berlin
Tunnel (1955) tapped Soviet teleprinter lines, where text travelled as 5-bit
ITA2 codes and was enciphered by XOR (Vernam, later the Lorenz machine).

ITA2 letter codes, bit 1 written first (A = 11000 means bits 1 and 2 set).
Letters cover 26 of the 32 codes; the other 6 are control codes (null,
space, CR, LF, FIGS, LTRS). A Vernam ciphertext that is all letters is
itself a constraint: every key must keep every character inside the letters.
"""

ITA2_BITS = {
    "A": "11000", "B": "10011", "C": "01110", "D": "10010", "E": "10000", "F": "10110", "G": "01011",
    "H": "00101", "I": "01100", "J": "11010", "K": "11110", "L": "01001", "M": "00111", "N": "00110",
    "O": "00011", "P": "01101", "Q": "11101", "R": "01010", "S": "10100", "T": "00001", "U": "11100",
    "V": "01111", "W": "11001", "X": "10111", "Y": "10101", "Z": "10001",
}
CODE = {k: int(v, 2) for k, v in ITA2_BITS.items()}
LETTER = {v: k for k, v in CODE.items()}
assert len(LETTER) == 26


def xor_text(text, key_codes):
    """Vernam: XOR each letter's code with the key code; None where the result isn't a letter."""
    out = []
    for c, k in zip(text, key_codes):
        out.append(LETTER.get(CODE[c] ^ k))
    return out


def required_keys(ct, cribs):
    """Key code each clue letter forces (XOR is its own inverse)."""
    return {i: CODE[ct[i]] ^ CODE[p] for i, p in cribs.items()}


class XorUF:
    """Union-find over unknowns with XOR offsets: value(a) ^ value(b) = d."""

    def __init__(self):
        self.parent, self.off = {}, {}

    def find(self, a):
        if a not in self.parent:
            self.parent[a], self.off[a] = a, 0
            return a, 0
        o, n = 0, a
        while self.parent[n] != n:
            o ^= self.off[n]
            n = self.parent[n]
        return n, o

    def union(self, a, b, d):
        ra, oa = self.find(a)
        rb, ob = self.find(b)
        if ra == rb:
            return (oa ^ ob) == d
        self.parent[rb] = ra
        self.off[rb] = oa ^ ob ^ d
        return True
