"""Tools for idea 128: two-word keys (word A then word B) on ONE hidden alphabet.

Idea 93 settled single known words on a hidden alphabet. A key made of two words written one after the
other cannot be listed pair by pair (265k x 265k words), but every condition the clue letters put on the
key splits by word:

  located models (true Quagmire III, C = P + K, P - K, K - P; true Quagmire II)
      two clue places whose equations differ only in the key letter must carry the SAME key letter
      (S->S at 32 with K->K at 73; R->P at 27 and 65; 0-based), and about 20-60 pairs of clue places must
      carry DIFFERENT key letters. Each condition names two key slots; a slot belongs to word A or word B.
  numeric models (one hidden alphabet, key valued on A-Z or KRYPTOS, C = P + k or C = k - P)
      the left null space gives a few fixed dot products  sum c_j k_j = t (mod 13 or mod 2)  on the key
      values; each splits as (A part) + (B part), so the join is exact on the vector of residues.

A word is reduced to the letters (or the partial sums) it puts on the slots the conditions touch; the two
sides are joined (by hash for equalities, by bit masks for "must differ"), and only joined pairs are
solved exactly with kryptos/idea93_hidden.py (24 equations mod 26, letters in distinct places).

Key forms (a "template" lists, for each key slot, which word and which letter of it):
  pair      A + B                     (length a + b, repeated)
  sandwich  A + B + A                 (length 2a + b, repeated)
Numeric models also take the sliding form (key = running sum of the repeated A + B), which stays linear
in the letter values, so it splits the same way.
"""
from collections import defaultdict

from . import idea93_hidden as H
from .ciphers.substitution import AZ

POS = H.POS


def template(form, a, b):
    if form == "pair":
        return [(0, i) for i in range(a)] + [(1, i) for i in range(b)]
    if form == "sandwich":
        return [(0, i) for i in range(a)] + [(1, i) for i in range(b)] + [(0, i) for i in range(a)]
    raise ValueError(form)


def key_string(form, A, B):
    return A + B if form == "pair" else A + B + A


def clue_slots(tmpl, phi):
    """(side, letter index) of the key at each of the 24 clue places, repeating key, phase phi."""
    L = len(tmpl)
    return [tmpl[(i + phi) % L] for i in POS]


# ---------------------------------------------------------------- located models: letter conditions

def located_conditions(t, cs):
    """Split the forced-equal / forced-different clue pairs into conditions on word letters.

    Returns None if the cell is impossible (a forced-different pair falls on the same key letter), else
    dict with eqA, neA, eqB, neB (index pairs inside one word) and eqX, neX ((iA, iB) across)."""
    out = {k: set() for k in ("eqA", "neA", "eqB", "neB", "eqX", "neX")}
    for kind, pairs in (("eq", t["eq"]), ("ne", t["ne"])):
        for p, q in pairs:
            (s1, i1), (s2, i2) = cs[p], cs[q]
            if (s1, i1) == (s2, i2):
                if kind == "ne":
                    return None
                continue
            if s1 == s2:
                out[kind + "AB"[s1]].add((min(i1, i2), max(i1, i2)))
            else:
                out[kind + "X"].add((i1, i2) if s1 == 0 else (i2, i1))
    return out


def side_filter(words, eq, ne):
    if not eq and not ne:
        return words
    out = []
    for w in words:
        ok = True
        for i, j in eq:
            if w[i] != w[j]:
                ok = False
                break
        if ok:
            for i, j in ne:
                if w[i] == w[j]:
                    ok = False
                    break
        if ok:
            out.append(w)
    return out


def group(words, idx):
    g = defaultdict(list)
    for w in words:
        g["".join(w[i] for i in idx)].append(w)
    return g


def located_join(cond, wa, wb, limit=None):
    """Join words of length a (side A) and b (side B) under the conditions. Yields (count, pairs-generator)
    in two stages: first returns the exact joined count (so a cell can be skipped), then the pairs."""
    A = side_filter(wa, cond["eqA"], cond["neA"])
    B = side_filter(wb, cond["eqB"], cond["neB"])
    if not A or not B:
        return 0, []
    ia = sorted({i for i, _ in cond["eqX"] | cond["neX"]})
    ib = sorted({j for _, j in cond["eqX"] | cond["neX"]})
    pa = {i: k for k, i in enumerate(ia)}
    pb = {j: k for k, j in enumerate(ib)}
    ga, gb = group(A, ia), group(B, ib)
    if not ia:
        return len(A) * len(B), [(list(ga.values())[0], list(gb.values())[0])]
    bkeys = list(gb)
    full = (1 << len(bkeys)) - 1
    mask = {}
    for n, k in enumerate(bkeys):
        bit = 1 << n
        for j, ch in zip(ib, k):
            mask[j, ch] = mask.get((j, ch), 0) | bit
    eqx = [(pa[i], j) for i, j in cond["eqX"]]
    nex = [(pa[i], j) for i, j in cond["neX"]]
    sizes = [len(gb[k]) for k in bkeys]
    total, groups = 0, []
    for ka, la in ga.items():
        m = full
        for p, j in eqx:
            m &= mask.get((j, ka[p]), 0)
            if not m:
                break
        if not m:
            continue
        for p, j in nex:
            m &= ~mask.get((j, ka[p]), 0)
            if not m:
                break
        if not m:
            continue
        nb = 0
        hits = []
        while m:
            low = m & -m
            n = low.bit_length() - 1
            nb += sizes[n]
            hits.append(gb[bkeys[n]])
            m ^= low
        total += len(la) * nb
        groups.append((la, hits))
        if limit is not None and total > limit:
            return total, []
    return total, [(la, [w for h in hits for w in h]) for la, hits in groups]


def located_shifts(t, kl):
    sh = [H.SH[H.LI[c]] for c in set(kl) if c not in t["fixedset"]]
    return sh + ([] if t["q3"] else [H.SH[H.EX]]) + t["fixed"]


def solve_located(T, li, key, phi):
    """Exact test of one full key (repeating) on located model li: None or (solutions, status)."""
    t = T.loc[li]
    rows = T.located_rows(li, "R", key, phi)
    L = len(key)
    kl = [key[(i + phi) % L] for i in POS]
    return H.decide_located(rows, located_shifts(t, kl), not t["q3"])


# ---------------------------------------------------------------- numeric models: dot products

def numeric_forms(T, mi):
    """All fixed dot products of numeric model mi: [(idx, coefs, target, prime)]."""
    _, first, rest, _, _, _ = T.num[mi]
    a, c, ca, cc, tgt, prime = first
    fs = list(rest)
    if ca or cc:
        fs = [((a, c), (ca, cc), tgt, prime)] + fs
    return fs


def numeric_weights(fs, tmpl, phi, kind):
    """Per dot product, the weight each (side, letter index) carries: k_j = sum over slots of count * value.

    kind R: k at clue j is the value of its own key letter; S: the running sum of the repeated key up to and
    including that place (sliding key). The start of a sliding key is a constant added to every k, which
    the numeric models already absorb in their free constant (the dot products are blind to it)."""
    L = len(tmpl)
    if kind == "R":
        cnt = [{tmpl[(i + phi) % L]: 1} for i in POS]
    else:
        cnt = []
        for i in POS:
            n = i + phi + 1
            q, r = divmod(n, L)
            c = defaultdict(int)
            for s in tmpl:
                c[s] += q
            for s in tmpl[:r]:
                c[s] += 1
            cnt.append(c)
    out = []
    for idx, cf, tgt, prime in fs:
        w = defaultdict(int)
        for j, c in zip(idx, cf):
            for s, n in cnt[j].items():
                w[s] += c * n
        wa = [(i, v % prime) for (side, i), v in w.items() if side == 0 and v % prime]
        wb = [(i, v % prime) for (side, i), v in w.items() if side == 1 and v % prime]
        out.append((wa, wb, tgt, prime))
    return out


def numeric_join(weights, vals, wa, wb):
    """Exact hash join: A's partial sums must equal target minus B's partial sums for every dot product."""
    va = [[vals[c] for c in w] for w in wa]
    idx = defaultdict(list)
    for w, v in zip(wb, ([vals[c] for c in w] for w in wb)):
        idx[tuple((tgt - sum(x * v[i] for i, x in lb)) % p for _, lb, tgt, p in weights)].append(w)
    out = []
    for w, v in zip(wa, va):
        k = tuple(sum(x * v[i] for i, x in la) % p for la, _, _, p in weights)
        m = idx.get(k)
        if m:
            out.append((w, m))
    return out


def numeric_key_values(form, A, B, phi, kind, vals):
    key = key_string(form, A, B)
    L = len(key)
    if kind == "R":
        return [vals[key[(i + phi) % L]] for i in POS]
    v = [vals[c] for c in key]
    tot = sum(v)
    pre = [0]
    for x in v:
        pre.append(pre[-1] + x)
    return [(((i + phi + 1) // L) * tot + pre[(i + phi + 1) % L]) % 26 for i in POS]


def encrypt_located(T_model, key, phi, alpha, pt, E=0):
    return H.encrypt(T_model, "R", key, phi, None, alpha, E, pt)


def all_letters():
    return AZ


# ---------------------------------------------------------------- fast exact solve for the numeric models

class NumericSolver:
    """solve_injective of idea 93 for a FIXED matrix (numeric models): the mod 13 row reduction is done once,
    and each right-hand side then costs one matrix-vector product before the same enumeration of solutions
    with distinct places."""

    def __init__(self, T, mi):
        m, _, _, mat, b, _ = T.num[mi]
        self.m, self.b = m, b
        self.cols = [j for j in range(H.NC) if any(r[j] % 26 for r in mat)]
        self.sub = [[r[j] % 26 for j in self.cols] for r in mat]
        n, R = len(self.cols), len(self.sub)
        p = 13
        aug = [[v % p for v in r] + [1 if k == i else 0 for k in range(R)] for i, r in enumerate(self.sub)]
        piv, r = [], 0
        for c in range(n):
            s = next((i for i in range(r, R) if aug[i][c]), None)
            if s is None:
                continue
            aug[r], aug[s] = aug[s], aug[r]
            inv = pow(aug[r][c], p - 2, p)
            aug[r] = [(v * inv) % p for v in aug[r]]
            for i in range(R):
                if i != r and aug[i][c]:
                    f = aug[i][c]
                    aug[i] = [(x - f * y) % p for x, y in zip(aug[i], aug[r])]
            piv.append(c)
            r += 1
            if r == R:
                break
        self.piv = piv
        self.tp = [aug[i][n:] for i in range(len(piv))]
        self.tz = [aug[i][n:] for i in range(len(piv), R)]
        free = [c for c in range(n) if c not in piv]
        self.basis = []
        for f in free:
            v = [0] * n
            v[f] = 1
            for i, c in enumerate(piv):
                v[c] = (-aug[i][f]) % p
            self.basis.append(v)
        self.n = n

    def solve13(self, rhs):
        for t in self.tz:
            if sum(a * x for a, x in zip(t, rhs)) % 13:
                return None
        part = [0] * self.n
        for t, c in zip(self.tp, self.piv):
            part[c] = sum(a * x for a, x in zip(t, rhs)) % 13
        return part, self.basis

    def solutions(self, k, max_points=40000, max_sols=512):
        m, b = self.m, self.b
        rhs = [(-(b[a] + m.kn * k[a])) % 26 for a in range(24)]
        if not any(rhs):
            return H.solve_injective(self._full(), rhs)
        s13 = self.solve13(rhs)
        if s13 is None:
            return [], "none"
        return _enumerate(self.sub, rhs, self.cols, s13, max_points, max_sols)

    def _full(self):
        out = []
        for r in self.sub:
            row = [0] * H.NC
            for j, v in zip(self.cols, r):
                row[j] = v
            out.append(row)
        return out


def _enumerate(sub, rhs, cols, s13, max_points, max_sols):
    """The inhomogeneous half of idea 93's solve_injective, from a given mod 13 solution space."""
    import itertools
    from .round9 import solve_mod_p
    part, basis = s13
    d = len(basis)
    if 13 ** d > max_points:
        return [], "many"

    def walk(v, k):
        if k == d:
            yield v
            return
        yield from walk(v, k + 1)
        bb = basis[k]
        for _ in range(12):
            v = [(x + y) % 13 for x, y in zip(v, bb)]
            yield from walk(v, k + 1)

    li = [k for k, j in enumerate(cols) if j < 26]
    sub2 = [[x % 2 for x in r] for r in sub]
    rhs2 = [x % 2 for x in rhs]
    n = len(cols)
    sols = []
    for v in walk(part, 0):
        bins, ok = {}, True
        for k in li:
            bn = bins.setdefault(v[k], [])
            if len(bn) == 2:
                ok = False
                break
            bn.append(k)
        if not ok:
            continue
        more = []
        for bn in bins.values():
            if len(bn) == 2:
                row = [0] * n
                row[bn[0]] = row[bn[1]] = 1
                more.append(row)
        s2 = solve_mod_p(sub2 + more, rhs2 + [1] * len(more), 2)
        if s2 is None:
            continue
        p2, b2 = s2
        for c2 in itertools.islice(itertools.product(range(2), repeat=len(b2)), 256):
            w = list(p2)
            for c, bb in zip(c2, b2):
                if c:
                    w = [x ^ y for x, y in zip(w, bb)]
            x = [a if a % 2 == bq else a + 13 for a, bq in zip(v, w)]
            assert all(sum(a * y for a, y in zip(r, x)) % 26 == t % 26 for r, t in zip(sub, rhs))
            assert len({x[k] for k in li}) == len(li)
            sols.append(({AZ[cols[k]]: x[k] for k in li}, x[cols.index(H.EX)] if H.EX in cols else 0))
            if len(sols) >= max_sols:
                return sols, "capped"
    return sols, ("ok" if sols else "none")
