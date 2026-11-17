"""Idea 98: a key-word layer on one tableau and a steadily turning layer on ANOTHER tableau.

    key layer    X -> A[ ek * A^-1(X) + a_(i mod p) ]        repeating key a (length p) on alphabet A
    turn layer   X -> B[ eg * B^-1(X) + s * g(i) + t ]       shift grows by s per letter, starts at t

    order 1: key layer first, turn layer second.     order 2: turn layer first, key layer second.

ek, eg = +1 is Vigenere (variant Beaufort is covered: key letters, s and t are free), -1 is
Beaufort. g(i) is the letter count the turn runs on: the whole text (g = i), or restarting at
each row (ROWS).

For a given B, eg, s, t and g the turn layer is completely known, so on the clue letters the
key layer shows its key value directly, and a repeating key of length p must give the same
value wherever i mod p is the same. Checks = clue letters minus key slots the clues touch.

The fast scan tests all 2 x 3 x 25 x 26 = 3,900 (eg, g, s, t) at once. With D = A^-1 o B and
u_i = the turn layer's known B-position at clue letter i,

    order 1:  u_i = eg * (B^-1(C_i) - s g(i) - t)      key a_i = D(u_i) - ek * A^-1(P_i)
    order 2:  u_i = eg * B^-1(P_i) + s g(i) + t        key a_i = -ek * (D(u_i) - ek * A^-1(C_i))

so in both orders "same key value" is "same D(u_i) - ek * z_i". The u_i for all 3,900 settings
are one precomputed byte string per (order, clue letter, letter value); one bytes.translate
turns it into the key values; as big integers, XOR of two of them is zero in exactly the lanes
where the two key values agree. No numpy needed.
"""
from .ciphers.substitution import AZ

ROWS = ("whole text", "carved rows (starts 1, 5, 36, 67)", "rows of 21", "rows of 42")
# On the clue letters rows of 42 are rows of 21 with t moved by 21 s (letters 21-33 and 63-73 sit
# in the second half of a 42-row), so the scan runs layouts 0-2 only and every rows-of-21 survivor
# is also read as rows of 42 (twin()).
S_VALUES = tuple(range(1, 26))
NV, NS, NT = 3, len(S_VALUES), 26
HALF = NV * NS * NT                    # lanes per value of eg
LANES = 2 * HALF                       # eg = +1 lanes, then eg = -1 lanes
EG = (1, -1)
MAXP = 24                              # periods 1..24 have 5+ checks on the 24 clue letters

_C7F = int.from_bytes(b"\x7f" * LANES, "little")
_C80 = int.from_bytes(b"\x80" * LANES, "little")
_SUB = [bytes((v - k) % 26 for v in range(26)) + bytes(230) for k in range(26)]


def g_of(v, i):
    """Letter count of the turn at text position i (0-based) for row layout v."""
    if v == 0:
        return i
    if v == 1:
        return i if i < 4 else (i - 4) % 31
    return i % (21 if v == 2 else 42)


def twin(v, s, t):
    """The rows-of-42 setting that looks the same on the clue letters as rows of 21 (v = 2)."""
    return (3, s, (t - 21 * s) % 26) if v == 2 else None


def touched(p, pos):
    return len(set(i % p for i in pos))


def checks(p, pos):
    return len(pos) - touched(p, pos)


# ---- the slow, plain version (encrypt, decrypt, key values): the fast scan is checked against it

def turn(v, s, t, i):
    return (s * g_of(v, i) + t) % 26


def encrypt(pt, a, b, key, s, t, ek=1, eg=1, order=1, v=0):
    """key = list of numbers (positions on A). Returns the ciphertext."""
    ia, ib = {c: k for k, c in enumerate(a)}, {c: k for k, c in enumerate(b)}
    out = []
    for i, ch in enumerate(pt):
        k, a_i = turn(v, s, t, i), key[i % len(key)]
        if order == 1:
            y = a[(ek * ia[ch] + a_i) % 26]
            out.append(b[(eg * ib[y] + k) % 26])
        else:
            y = b[(eg * ib[ch] + k) % 26]
            out.append(a[(ek * ia[y] + a_i) % 26])
    return "".join(out)


def key_values(ptl, ctl, pos, a, b, s, t, ek, eg, order, v):
    """The key value each clue letter forces (list parallel to pos)."""
    ia, ib = {c: k for k, c in enumerate(a)}, {c: k for k, c in enumerate(b)}
    out = []
    for p_, c_, i in zip(ptl, ctl, pos):
        k = turn(v, s, t, i)
        if order == 1:
            y = b[(eg * (ib[c_] - k)) % 26]
            out.append((ia[y] - ek * ia[p_]) % 26)
        else:
            y = b[(eg * ib[p_] + k) % 26]
            out.append((ia[c_] - ek * ia[y]) % 26)
    return out


def periods(kv, pos, maxp=MAXP):
    """{p: key slots (None where the clues do not reach)} for every p the key values fit."""
    out = {}
    for p in range(1, maxp + 1):
        slot = [None] * p
        for k, i in zip(kv, pos):
            if slot[i % p] is None:
                slot[i % p] = k
            elif slot[i % p] != k:
                break
        else:
            out[p] = slot
    return out


def decrypt(ct, a, b, slots, s, t, ek, eg, order, v):
    """All letters; '?' where the key slot is unknown."""
    ia, ib = {c: k for k, c in enumerate(a)}, {c: k for k, c in enumerate(b)}
    out = []
    for i, ch in enumerate(ct):
        k, a_i = turn(v, s, t, i), slots[i % len(slots)]
        if a_i is None:
            out.append("?")
        elif order == 1:
            y = b[(eg * (ib[ch] - k)) % 26]
            out.append(a[(ek * (ia[y] - a_i)) % 26])
        else:
            y = a[(ek * (ia[ch] - a_i)) % 26]
            out.append(b[(eg * (ib[y] - k)) % 26])
    return "".join(out)


def key_text(slots, a):
    return "".join("?" if k is None else a[k] for k in slots)


# ---- the fast scan ----------------------------------------------------------------------------

def lane(h, v, s, t):
    return ((h * NV + v) * NS + (s - 1)) * NT + t


def unlane(n):
    n, t = divmod(n, NT)
    n, s = divmod(n, NS)
    h, v = divmod(n, NV)
    return h, v, s + 1, t


def build_u(pos):
    """U[order][j][w]: bytes over the lanes, the turn layer's B-position at clue letter j when
    the letter that meets the turn layer (cipher letter in order 1, plain letter in order 2) sits
    at B-position w."""
    out = {}
    for order in (1, 2):
        per = []
        for i in pos:
            halves = []
            for eg in EG:
                base = bytearray()
                for v in range(NV):
                    g = g_of(v, i)
                    for s in S_VALUES:
                        for t in range(NT):
                            k = s * g + t
                            base.append((-eg * k) % 26 if order == 1 else k % 26)
                halves.append(bytes(base))
            # adding eg * w to every lane of a half = translate by "v -> v + eg*w"
            per.append([halves[0].translate(_SUB[(-w) % 26]) + halves[1].translate(_SUB[w]) for w in range(26)])
        out[order] = per
    return out


def edge_plan(pos, maxp=MAXP):
    """Periods to scan. Every p < 12 has a multiple in 12..24 and a key that repeats every p also
    repeats every multiple of p, so scanning 12..24 misses nothing. [(p, [(j1, j2), ...])] with
    j indexing pos; the edges tie clue letters in the same key slot."""
    out = []
    for p in range(maxp // 2, maxp + 1):
        last, edges = {}, []
        for j, i in enumerate(pos):
            if i % p in last:
                edges.append((last[i % p], j))
            last[i % p] = j
        out.append((p, edges))
    return out


class Scanner:
    """scan(a, b, ptl, ctl) -> [(order, ek, eg, v, s, t)] : every setting whose key values fit some
    period up to MAXP. Exact (no false positives or misses) - the caller reads the period off the
    slow key_values()."""

    def __init__(self, pos):
        self.pos = list(pos)
        self.u = build_u(self.pos)
        self.plan = edge_plan(self.pos)

    def scan(self, a, b, ptl, ctl):
        ia = {c: k for k, c in enumerate(a)}
        ib = {c: k for k, c in enumerate(b)}
        d = bytes(ia[c] for c in b)                          # D = A^-1 o B
        tabs = {}
        hits = []
        frm = int.from_bytes
        for order in (1, 2):
            w = [ib[c] for c in (ctl if order == 1 else ptl)]      # letter that meets the turn layer
            z = [ia[c] for c in (ptl if order == 1 else ctl)]      # letter that meets the key layer
            uo = self.u[order]
            us = [uo[j][w[j]] for j in range(len(w))]
            for ek in (1, -1):
                K = []
                for j, u in enumerate(us):
                    k = (ek * z[j]) % 26
                    tab = tabs.get(k)
                    if tab is None:
                        tab = tabs[k] = d.translate(_SUB[k]) + bytes(230)
                    K.append(frm(u.translate(tab), "little"))
                for p, edges in self.plan:
                    acc = 0
                    n = 0
                    for j1, j2 in edges:
                        acc |= K[j1] ^ K[j2]
                        n += 1
                        if n >= 3 and ((acc + _C7F) & _C80) == _C80:
                            break
                    else:
                        left = ((acc + _C7F) & _C80) ^ _C80
                        while left:
                            low = left & -left
                            h, v, s, t = unlane((low.bit_length() - 1) // 8)
                            hits.append((order, ek, EG[h], v, s, t))
                            left ^= low
        return sorted(set(hits))


def slow_scan(a, b, ptl, ctl, pos, maxp=MAXP):
    """The same answer as Scanner.scan, one setting at a time (for tests)."""
    out = []
    for order in (1, 2):
        for ek in (1, -1):
            for eg in EG:
                for v in range(NV):
                    for s in S_VALUES:
                        for t in range(NT):
                            if periods(key_values(ptl, ctl, pos, a, b, s, t, ek, eg, order, v), pos, maxp):
                                out.append((order, ek, eg, v, s, t))
    return sorted(out)


assert len(AZ) == 26
