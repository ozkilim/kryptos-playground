"""Tools for idea 93: KNOWN key streams (words, phrases, readings of the sculpture) on a HIDDEN alphabet.

When the key letters are known, a hidden alphabet is just 26 unknown positions X[letter] mod 26, and every
clue letter gives one linear equation in them. Every model below is one equation per letter:

    cx*X[C] + cv*v(C) + px*X[P] + pv*v(P) + kx*KEY + kn*k + ex*em*E = 0   (mod 26)

  X[.]   position of a letter in the hidden alphabet          v(.)  position in A-Z or KRYPTOS
  k      the key as a number (key letter valued on A-Z or KRYPTOS; `numeric` models)
  KEY    the key located on the hidden alphabet itself: X[key letter], or a running sum of them (`located`)
  E      one extra unknown: a constant offset, the start of a sliding key, or the step of a progressive key

Two ways of deciding a system:
  numeric models   the matrix depends only on the clue letters, so "is it consistent" is a handful of fixed
                   dot products on the key values (the left null space, computed once per ciphertext);
  located models   the matrix changes with the key, so each system is eliminated mod 13 with the 24 rows
                   packed into Python integers (about 50 microseconds).
Anything that passes goes to `solve_injective`: every solution mod 26 (mod 13 and mod 2 joined) in which the
letters sit in DIFFERENT places. X = 0 solves every homogeneous system, so consistency alone means nothing.
"""
import itertools
from collections import Counter, namedtuple

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round9 import UNITS, solve_mod_p  # noqa: F401

POS = list(range(21, 34)) + list(range(63, 74))
VAL = {"AZ": {c: i for i, c in enumerate(AZ)}, "KR": {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}}
ALPH = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
LI = {c: i for i, c in enumerate(AZ)}       # column of a letter
EX, RH, NC = 26, 27, 27                      # extra column, right-hand side, number of unknown columns

Model = namedtuple("Model", "name cx cv px pv kx kn vc vp")


def numeric_models():
    out = [Model("one hidden alphabet, C = P + k", 1, 0, -1, 0, 0, -1, None, None),
           Model("one hidden alphabet, C = k - P", 1, 0, 1, 0, 0, -1, None, None)]
    for a in ("AZ", "KR"):
        out.append(Model("hidden plain alphabet, cipher on %s, P = C - k" % a, 0, 1, -1, 0, 0, -1, a, None))
        out.append(Model("hidden plain alphabet, cipher on %s, P = C + k" % a, 0, 1, -1, 0, 0, 1, a, None))
        out.append(Model("hidden cipher alphabet, plain on %s, C = P + k" % a, 1, 0, 0, -1, 0, -1, None, a))
        out.append(Model("hidden cipher alphabet, plain on %s, C = P - k" % a, 1, 0, 0, -1, 0, 1, None, a))
    return out


def located_models():
    return [Model("Quagmire III, C = P + K", 1, 0, -1, 0, -1, 0, None, None),
            Model("Quagmire III, C = P - K", 1, 0, -1, 0, 1, 0, None, None),
            Model("Quagmire III, C = K - P", 1, 0, 1, 0, -1, 0, None, None),
            Model("Quagmire II, plain on AZ", 1, 0, 0, -1, -1, 0, None, "AZ"),
            Model("Quagmire II, plain on KR", 1, 0, 0, -1, -1, 0, None, "KR")]


NUMERIC, LOCATED = numeric_models(), located_models()
NUM_KINDS = ("R", "S", "G+", "G-")           # repeating, sliding (running sum), word +1 / -1 per pass


def is_q3(m):
    return bool(m.kx) and not m.pv


def extra(m, kind):
    """(coefficient of E, how E is multiplied: 'none', 'const' or 'pass')."""
    if m.kn or not is_q3(m):
        return -1, "const"
    if kind == "S":
        return m.kx, "const"
    if kind == "G":
        return m.kx, "pass"
    return 0, "none"


def key_at(kind, word, phi, i, vals=None):
    """Key at text position i: (number k, {letter: count} for located keys, pass index).

    kind R/G: letter word[(i+phi) % L]; S: running sum of the word's letters up to there; G+/G-: the letter's
    value plus / minus the pass number; 'run': the stream is not repeated (None outside it)."""
    j = i + phi
    L = len(word)
    if kind == "run":
        if not 0 <= j < L:
            return None
        return (vals[word[j]] if vals else 0), {word[j]: 1}, 0
    q, r = divmod(j, L)
    if kind == "S":
        form = Counter()
        for ch in word:
            form[ch] += q
        for ch in word[:r + 1]:
            form[ch] += 1
        k = sum(vals[ch] * n for ch, n in form.items()) % 26 if vals else 0
        return k, form, q
    k = vals[word[r]] if vals else 0
    if kind == "G+":
        k = (k + q) % 26
    elif kind == "G-":
        k = (k - q) % 26
    return k, {word[r]: 1}, q


def _known(m, kind, word, phi, vals, X, E, i, c=None, p=None):
    """Sum of the equation's terms that do not involve the wanted letter; None if something is unknown."""
    ka = key_at(kind, word, phi, i, vals)
    if ka is None:
        return None
    k, form, q = ka
    ex, em = extra(m, kind)
    t = m.kn * k + ex * E * (q if em == "pass" else (1 if em == "const" else 0))
    if m.kx:
        for ch, n in form.items():
            if ch not in X:
                return None
            t += m.kx * n * X[ch]
    if c is not None:
        if m.cx:
            if c not in X:
                return None
            t += m.cx * X[c]
        if m.cv:
            t += m.cv * VAL[m.vc][c]
    if p is not None:
        if m.px:
            if p not in X:
                return None
            t += m.px * X[p]
        if m.pv:
            t += m.pv * VAL[m.vp][p]
    return t % 26


def read(m, kind, word, phi, vals, X, E, ct):
    """Decrypt every letter the solution forces; '?' where it does not. X: {letter: position}."""
    X = dict(X)
    if len(X) == 25:                       # one letter left, one place left
        X[next(c for c in AZ if c not in X)] = next(v for v in range(26) if v not in X.values())
    inv = {v: c for c, v in X.items()}
    out = []
    for i, c in enumerate(ct):
        t = _known(m, kind, word, phi, vals, X, E, i, c=c)
        if t is None:
            out.append("?")
        elif m.px:
            out.append(inv.get((-t * m.px) % 26, "?"))
        else:
            out.append(ALPH[m.vp][(-t * m.pv) % 26])
    return "".join(out)


def encrypt(m, kind, word, phi, vals, alpha, E, pt):
    """Encrypt pt with a full hidden alphabet `alpha` (a 26-letter string); for planted answers."""
    X = {c: i for i, c in enumerate(alpha)}
    out = []
    for i, p in enumerate(pt):
        t = _known(m, kind, word, phi, vals, X, E, i, p=p)
        out.append(alpha[(-t * m.cx) % 26] if m.cx else ALPH[m.vc][(-t * m.cv) % 26])
    return "".join(out)


# ---------------------------------------------------------------- exact solutions with distinct positions

def solve_injective(rows, rhs, max_points=40000, max_sols=512):
    """Solutions mod 26 of rows * x = rhs (columns 0-25 letters, 26 the extra unknown) in which all letters
    that occur take different values. Returns (solutions, status): each solution is ({letter: value}, E);
    status 'none', 'ok', 'capped' (more solutions than max_sols) or 'many' (too many candidates to list).
    A homogeneous system is listed up to scaling (scaling the alphabet does not change the cipher)."""
    cols = [j for j in range(NC) if any(r[j] % 26 for r in rows)]
    sub = [[r[j] % 26 for j in cols] for r in rows]
    s13 = solve_mod_p(sub, rhs, 13)
    if s13 is None:
        return [], "none"
    part, basis = s13
    d = len(basis)
    hom = not any(x % 26 for x in rhs)
    if hom and d == 0:
        return [], "none"
    if (13 ** d - 1) // 12 > max_points if hom else 13 ** d > max_points:
        return [], "many"

    def walk(v, k):
        if k == d:
            yield v
            return
        yield from walk(v, k + 1)
        b = basis[k]
        for _ in range(12):
            v = [(x + y) % 13 for x, y in zip(v, b)]
            yield from walk(v, k + 1)

    points = (v for lead in range(d) for v in walk(basis[lead], lead + 1)) if hom else walk(part, 0)
    li = [k for k, j in enumerate(cols) if j < 26]
    sub2 = [[x % 2 for x in r] for r in sub]
    rhs2 = [x % 2 for x in rhs]
    n = len(cols)
    sols = []
    for v in points:
        bins, ok = {}, True
        for k in li:
            b = bins.setdefault(v[k], [])
            if len(b) == 2:
                ok = False
                break
            b.append(k)
        if not ok:
            continue
        more = []
        for b in bins.values():
            if len(b) == 2:                 # same place mod 13: must differ mod 2
                row = [0] * n
                row[b[0]] = row[b[1]] = 1
                more.append(row)
        s2 = solve_mod_p(sub2 + more, rhs2 + [1] * len(more), 2)
        if s2 is None:
            continue
        p2, b2 = s2
        for c2 in itertools.islice(itertools.product(range(2), repeat=len(b2)), 256):
            w = list(p2)
            for c, b in zip(c2, b2):
                if c:
                    w = [x ^ y for x, y in zip(w, b)]
            x = [a if a % 2 == b else a + 13 for a, b in zip(v, w)]
            assert all(sum(a * b for a, b in zip(r, x)) % 26 == t % 26 for r, t in zip(sub, rhs))
            assert len({x[k] for k in li}) == len(li)
            sols.append(({AZ[cols[k]]: x[k] for k in li}, x[cols.index(EX)] if EX in cols else 0))
            if len(sols) >= max_sols:
                return sols, "capped"
    return sols, ("ok" if sols else "none")


# ---------------------------------------------------------------- packed elimination mod 13

W = 32                                       # bits per field; digits stay below 2**16
M16 = 0xFFFF
SH = [W * j for j in range(NC + 1)]
LOW = sum(M16 << s for s in SH)
_INV = [0] + [pow(a, 11, 13) for a in range(1, 13)]
FAC = [[(-d * _INV[p]) % 13 for d in range(13)] for p in range(13)]     # FAC[pivot digit][digit]
RHS = SH[RH]
LETTER_LIMIT = SH[EX]


def pack(coefs, rhs=0):
    """coefs: {column: value}; values are stored mod 26 so the row can be unpacked for the mod 2 half."""
    r = (rhs % 26) << RHS
    for j, v in coefs.items():
        r += (v % 26) << SH[j]
    return r


def unpack(r):
    return [((r >> SH[j]) & M16) % 26 for j in range(NC)], ((r >> RHS) & M16) % 26


def elim13(rows, shifts, inhom=False):
    """Forward elimination mod 13 over the columns in `shifts` (rows is changed in place).

    Homogeneous: True if some column has no pivot (a nonzero solution exists). With a right-hand side:
    True if the system is consistent."""
    m, rank = len(rows), 0
    for sh in shifts:
        p = rank
        while p < m and not ((rows[p] >> sh) & M16) % 13:
            p += 1
        if p == m:
            if not inhom:
                return True
            continue
        pr = rows[p]
        pr -= 13 * (((pr * 5041) >> 16) & LOW)          # every digit back below 16
        rows[p] = rows[rank]
        rows[rank] = pr
        f = FAC[((pr >> sh) & M16) % 13]
        for r in range(p + 1, m):
            x = rows[r]
            d = ((x >> sh) & M16) % 13
            if d:
                rows[r] = x + f[d] * pr
        rank += 1
        if rank == m:
            break
    if not inhom:
        return rank < len(shifts)
    for r in range(rank, m):
        if ((rows[r] >> RHS) & M16) % 13:
            return False
    return True


def null13(rows, shifts):
    """Null space mod 13 (homogeneous system) as vectors over `shifts`, by full reduction of packed rows."""
    rows = list(rows)
    m, rank, piv = len(rows), 0, []
    for ci, sh in enumerate(shifts):
        p = rank
        while p < m and not ((rows[p] >> sh) & M16) % 13:
            p += 1
        if p == m:
            continue
        pr = rows[p]
        pr -= 13 * (((pr * 5041) >> 16) & LOW)
        rows[p] = rows[rank]
        rows[rank] = pr
        f = FAC[((pr >> sh) & M16) % 13]
        for r in range(m):
            if r != rank:
                x = rows[r]
                d = ((x >> sh) & M16) % 13
                if d:
                    x += f[d] * pr
                    rows[r] = x - 13 * (((x * 5041) >> 16) & LOW)
        piv.append(ci)
        rank += 1
        if rank == m:
            break
    pset = set(piv)
    basis = []
    for fi, fs in enumerate(shifts):
        if fi in pset:
            continue
        v = [0] * len(shifts)
        v[fi] = 1
        for r, ci in enumerate(piv):
            pd = ((rows[r] >> shifts[ci]) & M16) % 13
            v[ci] = FAC[pd][((rows[r] >> fs) & M16) % 13]
        basis.append(v)
    return basis


def may_be_injective(basis, shifts, max_dim=3):
    """Cheap test on a null space mod 13: can any vector put at most two letters on each value?"""
    d = len(basis)
    if d == 0:
        return False
    if d > max_dim:
        return True
    li = [k for k, s in enumerate(shifts) if s < LETTER_LIMIT]
    for lead in range(d):
        for rest in itertools.product(range(13), repeat=d - lead - 1):
            v = basis[lead]
            for c, b in zip(rest, basis[lead + 1:]):
                if c:
                    v = [x + c * y for x, y in zip(v, b)]
            cnt = [0] * 13
            for k in li:
                x = v[k] % 13
                if cnt[x] == 2:
                    break
                cnt[x] += 1
            else:
                return True
    return False


# ---------------------------------------------------------------- tables for one ciphertext

_IDX = {}


def phase_tables(L):
    """For a key of length L, per phase: residues, pass numbers and prefix lengths at the clue positions."""
    t = _IDX.get(L)
    if t is None:
        t = ([[(i + phi) % L for i in POS] for phi in range(L)],
             [[(i + phi) // L for i in POS] for phi in range(L)],
             [[i + phi + 1 for i in POS] for phi in range(L)])
        _IDX[L] = t
    return t


class Tables:
    """Everything that depends only on the ciphertext and the clue letters."""

    def __init__(self, ct, cribs):
        self.ct, self.cribs = ct, dict(cribs)
        assert sorted(cribs) == POS
        pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
        self.num = []
        for m in NUMERIC:
            F = [self._fixed(m, c, p) for c, p in zip(cl, pl)]
            for f in F:
                f[EX] = -1
            b = [self._const(m, c, p) for c, p in zip(cl, pl)]
            mat = [[f.get(j, 0) % 26 for j in range(NC)] for f in F]
            fs = []
            for prime in (13, 2):
                tr = [[mat[a][j] for a in range(24)] for j in range(NC)]
                for y in solve_mod_p(tr, [0] * NC, prime)[1]:
                    idx = tuple(a for a in range(24) if y[a])
                    fs.append((idx, tuple((y[a] * m.kn) % prime for a in idx),
                               (-sum(y[a] * b[a] for a in idx)) % prime, prime))
            fs.sort(key=lambda f: (len(f[0]), -f[3]))
            if fs and len(fs[0][0]) == 2:
                (a, c), (ca, cc), tgt, prime = fs[0]
                first, rest = (a, c, ca, cc, tgt, prime), fs[1:]
            else:
                first, rest = (0, 0, 0, 0, 0, 13), fs
            self.num.append((m, first, rest, mat, b, len(fs)))
        self.loc = []
        for m in LOCATED:
            F = [self._fixed(m, c, p) for c, p in zip(cl, pl)]
            b = [self._const(m, c, p) for c, p in zip(cl, pl)]
            q3 = is_q3(m)
            eq, ne = [], []
            for a in range(24):
                for c in range(a + 1, 24):
                    diff = {j: (F[a].get(j, 0) - F[c].get(j, 0)) % 26 for j in set(F[a]) | set(F[c])}
                    diff = sorted(v for v in diff.values() if v)
                    if not diff:
                        (eq if b[a] == b[c] else ne).append((a, c))
                    elif diff == [1, 25] and b[a] == b[c]:
                        ne.append((a, c))
            pf = [pack(f, -x) for f, x in zip(F, b)]
            fixed = sorted({j for f in F for j, v in f.items() if v % 26})
            self.loc.append({"m": m, "q3": q3, "eq": eq, "ne": ne, "pf": pf,
                             "pfc": [r + (25 << SH[EX]) for r in pf],      # with the constant column (-E)
                             "kxp": {ch: (m.kx % 26) << SH[LI[ch]] for ch in AZ}, "kxm": m.kx % 26,
                             "fixed": [SH[j] for j in fixed], "fixedset": {AZ[j] for j in fixed}})

    @staticmethod
    def _fixed(m, c, p):
        f = {}
        if m.cx:
            f[LI[c]] = f.get(LI[c], 0) + m.cx
        if m.px:
            f[LI[p]] = f.get(LI[p], 0) + m.px
        return f

    @staticmethod
    def _const(m, c, p):
        return ((m.cv * VAL[m.vc][c] if m.cv else 0) + (m.pv * VAL[m.vp][p] if m.pv else 0)) % 26

    # ---- numeric models: slow path once every fixed dot product has passed
    def numeric_solutions(self, mi, k):
        m, _, _, mat, b, _ = self.num[mi]
        return solve_injective(mat, [(-(b[a] + m.kn * k[a])) % 26 for a in range(24)])

    def located_rows(self, li, kind, word, phi):
        """The 24 packed rows of a located system (the same rows the fast scan builds)."""
        T = self.loc[li]
        L = len(word)
        if kind == "run":
            return [pf + T["kxp"][word[i + phi]] for pf, i in zip(T["pf"] if T["q3"] else T["pfc"], POS)]
        idx, qs, ns = (t[phi] for t in phase_tables(L))
        if kind == "R":
            return [pf + T["kxp"][word[j]] for pf, j in zip(T["pf"] if T["q3"] else T["pfc"], idx)]
        if kind == "G":
            return [pf + T["kxp"][word[j]] + (((T["kxm"] * q) % 26) << SH[EX]) for pf, j, q in zip(T["pf"], idx, qs)]
        cum = cum_rows(word, max(ns) + 1)
        return [pf + T["kxm"] * (cum[n] + (1 << SH[EX])) for pf, n in zip(T["pf"], ns)]


def cum_rows(word, n):
    """cum[t] = packed count of each letter among the first t letters of the repeated word."""
    out, r, L = [0], 0, len(word)
    for t in range(n):
        r += 1 << SH[LI[word[t % L]]]
        out.append(r)
    return out


def decide_located(rows, shifts, inhom):
    """None if the system has no solution with distinct letters, else (solutions, status)."""
    if not elim13(list(rows), shifts, inhom):
        return None
    if not inhom and not may_be_injective(null13(rows, shifts), shifts):
        return None
    un = [unpack(r) for r in rows]
    sols, status = solve_injective([u[0] for u in un], [u[1] for u in un])
    return (sols, status) if sols or status == "many" else None


# ---------------------------------------------------------------- the scans

def scan_words(T, words, counts, hits):
    """Every word at every phase, every kind and every model. counts: Counter; hits: list of
    (model name, key valuation or None, kind, word, phase, solutions, status)."""
    num, loc = T.num, T.loc
    firsts = [n[1] for n in num]
    exs = SH[EX]
    for w in words:
        L = len(w)
        IDX, QS, NS = phase_tables(L)
        wset = set(w)
        # ---------------- key located on the hidden alphabet
        cum = cum_rows(w, 74 + L)
        priv = [[SH[LI[c]] for c in wset if c not in t["fixedset"]] for t in loc]
        for phi in range(L):
            idx, qs, ns = IDX[phi], QS[phi], NS[phi]
            kl = [w[j] for j in idx]
            prog = qs[0] != qs[-1]
            cm = cp = None
            for li, t in enumerate(loc):
                ok = True
                for a, c in t["eq"]:
                    if kl[a] != kl[c]:
                        ok = False
                        break
                if ok:
                    for a, c in t["ne"]:
                        if kl[a] == kl[c]:
                            ok = False
                            break
                q3 = t["q3"]
                kxp = t["kxp"]
                if ok:
                    counts["solved", li, "R"] += 1
                    rows = [pf + kxp[c] for pf, c in zip(t["pf"] if q3 else t["pfc"], kl)]
                    sh = [SH[LI[c]] for c in set(kl) if c not in t["fixedset"]] + ([] if q3 else [exs]) + t["fixed"]
                    r = decide_located(rows, sh, not q3)
                    if r:
                        hits.append((t["m"].name, None, "R", w, phi, r[0], r[1]))
                if not q3:
                    continue
                sh = priv[li] + [exs] + t["fixed"]
                if t["kxm"] == 1:
                    if cp is None:
                        cp = [cum[n] + (1 << exs) for n in ns]
                    rows = [pf + x for pf, x in zip(t["pf"], cp)]
                else:
                    if cm is None:
                        cm = [25 * (cum[n] + (1 << exs)) for n in ns]
                    rows = [pf + x for pf, x in zip(t["pf"], cm)]
                r = decide_located(rows, sh, False)
                if r:
                    hits.append((t["m"].name, None, "S", w, phi, r[0], r[1]))
                if prog:
                    km = t["kxm"]
                    rows = [pf + kxp[c] + (((km * q) % 26) << exs) for pf, c, q in zip(t["pf"], kl, qs)]
                    sh = [SH[LI[c]] for c in set(kl) if c not in t["fixedset"]] + [exs] + t["fixed"]
                    r = decide_located(rows, sh, False)
                    if r:
                        hits.append((t["m"].name, None, "G", w, phi, r[0], r[1]))
        # ---------------- key letters valued on A-Z or KRYPTOS
        for vn in ("AZ", "KR"):
            vm = VAL[vn]
            vals = [vm[c] for c in w]
            pre = [0]
            for v in vals:
                pre.append(pre[-1] + v)
            tot = pre[-1]
            for phi in range(L):
                kr = [vals[j] for j in IDX[phi]]
                ks = [((n // L) * tot + pre[n % L]) % 26 for n in NS[phi]]
                todo = [("R", kr), ("S", ks)]
                qs = QS[phi]
                if qs[0] != qs[-1]:
                    todo.append(("G+", [(a + q) % 26 for a, q in zip(kr, qs)]))
                    todo.append(("G-", [(a - q) % 26 for a, q in zip(kr, qs)]))
                for kind, k in todo:
                    for mi, (a, c, ca, cc, tgt, prime) in enumerate(firsts):
                        if (ca * k[a] + cc * k[c]) % prime != tgt:
                            continue
                        if _rest(num[mi][2], k):
                            counts["solved", "n%d" % mi, kind] += 1
                            sols, status = T.numeric_solutions(mi, k)
                            if sols or status == "many":
                                hits.append((num[mi][0].name, vn, kind, w, phi, sols, status))
        nprog = sum(1 for q in QS if q[0] != q[-1])
        counts["tested"] += 8 * L + 3 * nprog + 20 * (2 * L + 2 * nprog)
        counts["solved", "q3", "S+G"] += 3 * L + 3 * nprog
    return hits


def _rest(fs, k):
    for idx, cf, tgt, prime in fs:
        s = 0
        for a, c in zip(idx, cf):
            s += c * k[a]
        if s % prime != tgt:
            return False
    return True


def scan_stream(T, t, counts, hits, tag):
    """One long stream used as a running key at every offset (the clue letters must lie inside it).
    Returns the number of offsets tried. hits get (model name, valuation, 'run', (tag, stream), offset, ...)."""
    num, loc = T.num, T.loc
    firsts = [n[1] for n in num]
    exs = SH[EX]
    rel = [i - 21 for i in POS]
    tv = {vn: [VAL[vn][c] for c in t] for vn in VAL}
    n = 0
    for o in range(len(t) - 52):
        n += 1
        kl = [t[o + r] for r in rel]
        for li, x in enumerate(loc):
            ok = True
            for a, c in x["eq"]:
                if kl[a] != kl[c]:
                    ok = False
                    break
            if not ok:
                continue
            for a, c in x["ne"]:
                if kl[a] == kl[c]:
                    ok = False
                    break
            if not ok:
                continue
            counts["solved", li, "run"] += 1
            q3, kxp = x["q3"], x["kxp"]
            rows = [pf + kxp[c] for pf, c in zip(x["pf"] if q3 else x["pfc"], kl)]
            sh = [SH[LI[c]] for c in set(kl) if c not in x["fixedset"]] + ([] if q3 else [exs]) + x["fixed"]
            r = decide_located(rows, sh, not q3)
            if r:
                hits.append((x["m"].name, None, "run", (tag, t), o - 21, r[0], r[1]))
        for vn in ("AZ", "KR"):
            v = tv[vn]
            k = [v[o + r] for r in rel]
            for mi, (a, c, ca, cc, tgt, prime) in enumerate(firsts):
                if (ca * k[a] + cc * k[c]) % prime != tgt:
                    continue
                if _rest(num[mi][2], k):
                    counts["solved", "n%d" % mi, "run"] += 1
                    sols, status = T.numeric_solutions(mi, k)
                    if sols or status == "many":
                        hits.append((num[mi][0].name, vn, "run", (tag, t), o - 21, sols, status))
    counts["tested"] += 25 * n
    return n


def model_by_name(name):
    return next(m for m in NUMERIC + LOCATED if m.name == name)


def readings(hit, ct, cribs):
    """Every reading of a hit: [(plaintext with '?', {letter: position}, E)]. The clue letters must come back."""
    name, vn, kind, word, phi, sols, _ = hit
    m = model_by_name(name)
    if kind == "run":
        word = word[1]
    vals = VAL[vn] if vn else None
    out = []
    for X, E in sols:
        pt = read(m, kind, word, phi, vals, X, E, ct)
        assert all(pt[i] == ch for i, ch in cribs.items()), (name, kind, phi, pt)
        out.append((pt, X, E))
    return out
