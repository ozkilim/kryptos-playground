"""Idea 144: a key-word layer on one tableau and a second tableau turned by a short repeating
list of steps.

    key layer    X -> A[ ek * A^-1(X) + a_(i mod p) ]        repeating key a (length p) on alphabet A
    turn layer   X -> B[ eg * B^-1(X) + T(i) ]               T(0) = t, T(i+1) = T(i) + s[i mod k]

    order 1: key layer first, turn layer second.     order 2: turn layer first, key layer second.

So the strip B is moved by s[0], then s[1], ..., then s[k-1], then s[0] again. k = 1 is idea 98
(one constant step). ek, eg = +1 is Vigenere (variant Beaufort is covered: key letters, steps
and t are free), -1 is Beaufort.

For given B, eg, step list and t the turn layer is fully known, so each clue letter shows the
key layer's key value outright, and a key word of length p must give the same value wherever
i mod p is the same. Checks = clue letters minus the key slots the clues touch.

The fast scan keeps one bit per (step list, t) "lane". For a clue letter and each B-position x
there is a precomputed big integer of the lanes where the turn layer sits at x. Two clue
letters in the same key slot agree in exactly the lanes OR_x M1[x] & M2[pi(x)], where pi is
read off the two alphabets; ANDing the ties of a key length leaves the lanes that fit it. No
key is guessed and nothing is approximated. Lanes: 26^k step lists x 26 starts, 17,576 for
k = 2 and 456,976 for k = 3, per layer order and Vigenere/Beaufort choice.
"""
from functools import reduce
from operator import and_, itemgetter, or_

from .idea98_turning import MAXP, checks, edge_plan, key_text, periods, touched  # noqa: F401


def turn(steps, t, i):
    """Shift of the turning tableau at text position i (0-based)."""
    q, r = divmod(i, len(steps))
    return (t + q * sum(steps) + sum(steps[:r])) % 26


def encrypt(pt, a, b, key, steps, t, ek=1, eg=1, order=1):
    """key = list of numbers (positions on A). Returns the ciphertext."""
    ia, ib = {c: n for n, c in enumerate(a)}, {c: n for n, c in enumerate(b)}
    out = []
    for i, ch in enumerate(pt):
        k, a_i = turn(steps, t, i), key[i % len(key)]
        if order == 1:
            y = a[(ek * ia[ch] + a_i) % 26]
            out.append(b[(eg * ib[y] + k) % 26])
        else:
            y = b[(eg * ib[ch] + k) % 26]
            out.append(a[(ek * ia[y] + a_i) % 26])
    return "".join(out)


def key_values(ptl, ctl, pos, a, b, steps, t, ek, eg, order):
    """The key value each clue letter forces (list parallel to pos)."""
    ia, ib = {c: n for n, c in enumerate(a)}, {c: n for n, c in enumerate(b)}
    out = []
    for p_, c_, i in zip(ptl, ctl, pos):
        k = turn(steps, t, i)
        if order == 1:
            y = b[(eg * (ib[c_] - k)) % 26]
            out.append((ia[y] - ek * ia[p_]) % 26)
        else:
            y = b[(eg * ib[p_] + k) % 26]
            out.append((ia[c_] - ek * ia[y]) % 26)
    return out


def decrypt(ct, a, b, slots, steps, t, ek, eg, order):
    """All letters; '?' where the key slot is unknown."""
    ia, ib = {c: n for n, c in enumerate(a)}, {c: n for n, c in enumerate(b)}
    out = []
    for i, ch in enumerate(ct):
        k, a_i = turn(steps, t, i), slots[i % len(slots)]
        if a_i is None:
            out.append("?")
        elif order == 1:
            y = b[(eg * (ib[ch] - k)) % 26]
            out.append(a[(ek * (ia[y] - a_i)) % 26])
        else:
            y = a[(ek * (ia[ch] - a_i)) % 26]
            out.append(b[(eg * (ib[y] - k)) % 26])
    return "".join(out)


def step_lists(k):
    """All 26^k step lists in lane order."""
    out = [()]
    for _ in range(k):
        out = [s + (x,) for s in out for x in range(26)]
    return out


class Scanner:
    """scan(a, b, ptl, ctl) -> [(order, ek, eg, steps, t)]: every setting whose key values fit some
    period up to MAXP. Exact: no false positives and no misses (checked against slow_scan); the
    caller reads the period off the slow key_values().

    Lanes are cut into blocks of 676 step lists x 26 starts = 17,576 bits (k = 3: one block per
    first step), so the big integers stay small and a block is dropped as soon as it is empty."""

    def __init__(self, pos, k):
        self.pos, self.k = list(pos), k
        self.plan = edge_plan(self.pos)
        lists = step_lists(k)
        size = 676 if k >= 2 else 26
        row = ["0" * (25 - t) + "1" + "0" * t for t in range(26)]        # one-hot start t, bit t
        self.blocks = []
        for o in range(0, len(lists), size):
            part = lists[o:o + size]
            mt = []                     # mt[j][x] = lanes of this block where T(i_j) = x
            for i in self.pos:
                vals = [turn(s, 0, i) for s in reversed(part)]
                mt.append([int("".join([row[(x - v) % 26] for v in vals]), 2) for x in range(26)])
            self.blocks.append((part, mt, {}))

    @staticmethod
    def _views(mt, cache, order, eg, j, w):
        """26 integers: lanes where the turn layer's B-position at clue letter j is x = 0..25.
        order 1: u = eg * (w - T); order 2: u = eg * w + T."""
        key = (order, eg, j, w)
        v = cache.get(key)
        if v is None:
            m = mt[j]
            if order == 1:
                v = tuple(m[(w - eg * x) % 26] for x in range(26))
            else:
                v = tuple(m[(x - eg * w) % 26] for x in range(26))
            cache[key] = v
        return v

    def scan(self, a, b, ptl, ctl):
        ia = {c: n for n, c in enumerate(a)}
        ib = {c: n for n, c in enumerate(b)}
        d = [ia[c] for c in b]                               # D = A^-1 o B
        dinv = [0] * 26
        for x, y in enumerate(d):
            dinv[y] = x
        # same key value at two clue letters: D(u1) - ek z1 = D(u2) - ek z2, so u2 = pi_delta(u1)
        pis = [itemgetter(*[dinv[(d[x] - dl) % 26] for x in range(26)]) for dl in range(26)]
        hits, views, plan, nj = [], self._views, self.plan, len(self.pos)
        for order in (1, 2):
            w = [ib[c] for c in (ctl if order == 1 else ptl)]      # letter that meets the turn layer
            z = [ia[c] for c in (ptl if order == 1 else ctl)]      # letter that meets the key layer
            for eg in (1, -1):
                for part, mt, cache in self.blocks:
                    ms = [views(mt, cache, order, eg, j, w[j]) for j in range(nj)]
                    for ek in (1, -1):
                        for p, edges in plan:
                            acc = -1
                            for j1, j2 in edges:
                                acc &= reduce(or_, map(and_, ms[j1], pis[(ek * (z[j1] - z[j2])) % 26](ms[j2])))
                                if not acc:
                                    break
                            else:
                                while acc:
                                    low = acc & -acc
                                    n, t = divmod(low.bit_length() - 1, 26)
                                    hits.append((order, ek, eg, part[n], t))
                                    acc ^= low
        return sorted(set(hits))


def slow_scan(a, b, ptl, ctl, pos, k, maxp=MAXP):
    """The same answer as Scanner.scan, one setting at a time (for tests)."""
    out = []
    for order in (1, 2):
        for ek in (1, -1):
            for eg in (1, -1):
                for s in step_lists(k):
                    for t in range(26):
                        if periods(key_values(ptl, ctl, pos, a, b, s, t, ek, eg, order), pos, maxp):
                            out.append((order, ek, eg, s, t))
    return sorted(out)
