"""Idea 121: any linear cipher-feedback rule up to 15 letters back, with free coefficients.

The model. Each cipher letter is the plain letter plus a fixed linear mix of the cipher letters
before it (and, in tests C and D, of the plain letters before it), plus a constant or a short
repeating word:

    nC(C[i]) = s nP(P[i]) + a1 nF(C[i-1]) + ... + aR nF(C[i-R])
                          + b1 nP(P[i-1]) + ... + bS nP(P[i-S]) + w[i mod p]      (mod 26)

nP, nC, nF number the plain, the cipher and the fed cipher letters, each on the tableau alphabet
M, on A-Z or on KRYPTOS; s = +1 or -1. All 97 cipher letters are known, so at each of the 24
clue letters this is one linear equation in the unknown coefficients. The system is solved mod 13
and mod 2 (Z_26 = Z_13 x Z_2); every equation beyond the rank is an exact check.

Speed. For a numbering of the fed letters that does not use M (A-Z or KRYPTOS) the matrix is the
same for every alphabet, so its left null space is computed once and each alphabet only needs a
few dot products. When the matrix uses M it is eliminated once per alphabet, with every right-hand
side (numbering of plain and cipher, sign) carried along as extra columns.

Shapes (all with a constant c unless a word period p is given):
  A  cipher lags 1..15                           24 equations, 16 unknowns, 8 checks
     gauge: cipher lags 1..19                    4 checks (to see chance behave as predicted)
  B  sparse cipher lags {1,w}, {w-1,w,w+1}, {1,w,w+1}, {w,2w} with a lag over 15 (shapes with
     all lags <= 15 are inside A and stricter), only shapes with 7+ checks
  C  cipher lags 1..R plus plain lags 1..S, (S,R) = (1,7) (2,6) (3,5) (4,4) (5,1)
  D  cipher lags 1..R plus plain lags 1..S plus a repeating word of period p = 3, 4, 5 in place of
     the constant, R + S = 6, S = 0..3 (period 2 is inside period 4)
Plain feedback needs the plain letter, so equations whose plain lags reach outside a clue block
are dropped and counted.
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round9 import solutions_mod26, solve_mod_p

POS = list(range(21, 34)) + list(range(63, 74))
BLOCKS = ((21, 34), (63, 74))
NUMS = ("M", "AZ", "KR")
MIN_CHECKS = 7
IZ = {c: i for i, c in enumerate(AZ)}
INV13 = [0] + [pow(v, 11, 13) for v in range(1, 13)]
INV2 = [0, 1]


def amap(alpha):
    """List: AZ index of a letter -> its place in alpha."""
    out = [0] * 26
    for i, c in enumerate(alpha):
        out[IZ[c]] = i
    return out


AZMAP, KRMAP = amap(AZ), amap(KRYPTOS_ALPHABET)


class Shape:
    def __init__(self, test, name, lagc, lagp=(), period=0, gauge=()):
        self.test, self.name = test, name
        self.lagc, self.lagp, self.period, self.gauge = tuple(lagc), tuple(lagp), period, tuple(gauge)
        mx = max(self.lagc + self.lagp + self.gauge)
        self.eqs = []                       # indices j into POS that give an equation
        for j, i in enumerate(POS):
            if i - mx < 0:
                continue
            blk = next(b for b in BLOCKS if b[0] <= i < b[1])
            if self.lagp and i - max(self.lagp) < blk[0]:
                continue
            self.eqs.append(j)
        self.nconst = period if period else 1
        self.nunk = len(self.lagc) + len(self.lagp) + self.nconst
        self.ncols = self.nunk + len(self.gauge)
        self.checks = len(self.eqs) - self.nunk
        self.gchecks = len(self.eqs) - self.ncols

    def keys(self):
        """Numberings that fix the matrix: (nF,) or (nF, nP)."""
        if self.lagp:
            return [(f, p) for f in NUMS for p in NUMS]
        return [(f,) for f in NUMS]

    def rhs_combos(self, key):
        """(nP, nC, sign) that go with a matrix key."""
        ps = (key[1],) if self.lagp else NUMS
        return [(p, c, s) for p in ps for c in NUMS for s in (1, -1)]

    def row(self, i, ctn, ptn, nf, np_):
        r = [nf[ctn[i - d]] for d in self.lagc] + [np_[ptn[i - e]] for e in self.lagp]
        if self.period:
            v = [0] * self.period
            v[i % self.period] = 1
            r += v
        else:
            r.append(1)
        r += [nf[ctn[i - d]] for d in self.gauge]
        return r

    def __repr__(self):
        return self.name


def shapes_a():
    return [Shape("A", "cipher lags 1-15", range(1, 16), gauge=range(16, 20))]


def shapes_b():
    out = []
    for w in range(2, 49):
        for nm, lags in (("{1,%d}" % w, (1, w)), ("{%d,%d,%d}" % (w - 1, w, w + 1), (w - 1, w, w + 1)),
                         ("{1,%d,%d}" % (w, w + 1), (1, w, w + 1)), ("{%d,%d}" % (w, 2 * w), (w, 2 * w))):
            if max(lags) <= 15 or len(set(lags)) < len(lags):
                continue
            s = Shape("B", "cipher lags " + nm, lags)
            if s.checks >= MIN_CHECKS:
                out.append(s)
    return out


def shapes_c():
    return [Shape("C", "cipher lags 1-%d + plain lags 1-%d" % (r, s), range(1, r + 1), range(1, s + 1))
            for s, r in ((1, 7), (2, 6), (3, 5), (4, 4), (5, 1))]


def shapes_d():
    out = []
    for p in (3, 4, 5):
        for s in range(0, 4):
            r = 6 - s
            out.append(Shape("D", "cipher lags 1-%d + plain lags %s + word of %d" % (r, "1-%d" % s if s else "none", p),
                             range(1, r + 1), range(1, s + 1), period=p))
    return out


def all_shapes():
    return {"A": shapes_a(), "B": shapes_b(), "C": shapes_c(), "D": shapes_d()}


# ---------------------------------------------------------------- linear algebra helpers

def reduce_cols(m, c0, c1, start, p, inv):
    """Forward elimination over columns c0..c1-1 among rows m[start:]. Returns rows used as pivots."""
    r, n = start, len(m)
    for c in range(c0, c1):
        s = None
        for i in range(r, n):
            if m[i][c]:
                s = i
                break
        if s is None:
            continue
        if s != r:
            m[r], m[s] = m[s], m[r]
        iv = inv[m[r][c]]
        pr = [(v * iv) % p for v in m[r]] if iv != 1 else m[r]
        m[r] = pr
        for i in range(r + 1, n):
            f = m[i][c]
            if f:
                m[i] = [(a - f * b) % p for a, b in zip(m[i], pr)]
        r += 1
        if r == n:
            break
    return r


def left_null(rows, nmain, nall, p):
    """Left null vectors of rows (mod p) for the first nmain columns and for all nall columns.
    Returns (main, gauge): lists of sparse vectors [(eq index, coef)]."""
    n = len(rows)
    inv = INV13 if p == 13 else INV2
    m = [[v % p for v in r] + [1 if k == j else 0 for k in range(n)] for j, r in enumerate(rows)]
    r = reduce_cols(m, 0, nmain, 0, p, inv)
    main = [[(k, v) for k, v in enumerate(row[nall:]) if v] for row in m[r:]]
    r2 = reduce_cols(m, nmain, nall, r, p, inv) if nall > nmain else r
    gauge = [[(k, v) for k, v in enumerate(row[nall:]) if v] for row in m[r2:]]
    return main, gauge


def nmap(name, alpha_map):
    return alpha_map if name == "M" else (AZMAP if name == "AZ" else KRMAP)


# ---------------------------------------------------------------- the plan (clue letters, fixed null spaces)

class Plan:
    def __init__(self, ct, pt_clues, tests="ABCD"):
        """ct: the 97 cipher letters; pt_clues: {position: plain letter} (the 24 clue letters)."""
        self.ct = ct
        self.ctn = [IZ[c] for c in ct]
        self.cribs = dict(pt_clues)
        self.ptn = [None] * len(ct)
        for i, c in pt_clues.items():
            self.ptn[i] = IZ[c]
        self.cj = [self.ctn[i] for i in POS]
        self.pj = [self.ptn[i] for i in POS]
        sh = all_shapes()
        self.shapes = {t: sh[t] for t in tests}
        self.fixed = {}                    # (shape name, key) -> (N13 main, N2 main, N13 gauge, N2 gauge)
        for t, lst in self.shapes.items():
            for s in lst:
                for key in s.keys():
                    if "M" in key:
                        continue
                    nf = nmap(key[0], None)
                    np_ = nmap(key[1], None) if s.lagp else AZMAP
                    rows = [s.row(POS[j], self.ctn, self.ptn, nf, np_) for j in s.eqs]
                    out = []
                    for p in (13, 2):
                        main, gauge = left_null(rows, s.nunk, s.ncols, p)
                        out.append([[(s.eqs[k], v) for k, v in vec] for vec in main])
                        out.append([[(s.eqs[k], v) for k, v in vec] for vec in gauge])
                    m13, g13, m2, g2 = out
                    self.fixed[s.name, key] = (m13, m2, g13, g2)

    def rhs(self, mp, combo, mod):
        """b_j = nC(C) - s nP(P) at every clue letter, mod `mod`."""
        p, c, s = combo
        npm, ncm = nmap(p, mp), nmap(c, mp)
        return [(ncm[cc] - s * npm[pp]) % mod for cc, pp in zip(self.cj, self.pj)]

    def system(self, shape, mp, setting):
        """Rows and right side over Z (to be reduced mod 26) for one full setting."""
        nP, nC, nF, s = setting
        nf, np_, nc = nmap(nF, mp), nmap(nP, mp), nmap(nC, mp)
        rows, rhs = [], []
        for j in shape.eqs:
            i = POS[j]
            rows.append(shape.row(i, self.ctn, self.ptn, nf, np_)[:shape.nunk])
            rhs.append((nc[self.cj[j]] - s * np_[self.pj[j]]) % 26)
        return rows, rhs


def new_tally():
    return {"settings": {}, "expected": {}, "gauge_settings": 0, "gauge_expected": 0.0, "gauge_mod13": 0,
            "gauge_pass": 0, "deficient": 0, "hits": [], "gauge_hits": []}


def merge(total, part):
    for k in ("settings", "expected"):
        for t, v in part[k].items():
            total[k][t] = total[k].get(t, 0) + v
    for k in ("gauge_settings", "gauge_expected", "gauge_mod13", "gauge_pass", "deficient"):
        total[k] += part[k]
    total["hits"] += part["hits"]
    total["gauge_hits"] += part["gauge_hits"]


def _dot(vec, b):
    return sum(v * b[k] for k, v in vec)


def _mod2_checks(plan, shape, mp, setting, gauge=False):
    """Number of mod 2 checks if consistent mod 2, else None."""
    nP, nC, nF, s = setting
    nf, np_, nc = nmap(nF, mp), nmap(nP, mp), nmap(nC, mp)
    rows, rhs = [], []
    ncol = shape.ncols if gauge else shape.nunk
    for j in shape.eqs:
        rows.append(shape.row(POS[j], plan.ctn, plan.ptn, nf, np_)[:ncol])
        rhs.append(nc[plan.cj[j]] - s * np_[plan.pj[j]])
    sol = solve_mod_p(rows, rhs, 2)
    if sol is None:
        return None
    rank = ncol - len(sol[1])
    return len(rows) - rank


def scan(plan, name, alpha, tests, res, fixed_only=False):
    """All shapes of `tests` for one alphabet. fixed_only: the settings that use no M (run once)."""
    mp = amap(alpha)
    b13, b2 = {}, {}

    def rhs13(combo):
        v = b13.get(combo)
        if v is None:
            v = b13[combo] = plan.rhs(mp, combo, 13)
        return v

    def rhs2(combo):
        v = b2.get(combo)
        if v is None:
            v = b2[combo] = plan.rhs(mp, combo, 2)
        return v

    sett, expd = res["settings"], res["expected"]
    for t in tests:
        for shape in plan.shapes[t]:
            nom = 26.0 ** -shape.checks
            gnom = 26.0 ** -shape.gchecks if shape.gauge else 0.0
            for key in shape.keys():
                keyM = "M" in key
                if fixed_only and keyM:
                    continue
                combos = shape.rhs_combos(key)
                nF = key[0]
                if keyM:
                    todo = combos
                else:
                    todo = [cb for cb in combos if ("M" in cb[:2]) != fixed_only]
                if not todo:
                    continue
                sett[t] = sett.get(t, 0) + len(todo)
                expd[t] = expd.get(t, 0.0) + len(todo) * nom
                if shape.gauge:
                    res["gauge_settings"] += len(todo)
                    res["gauge_expected"] += len(todo) * gnom
                if keyM:
                    _scan_elim(plan, shape, key, mp, todo, rhs13, name, alpha, res)
                else:
                    _scan_fixed(plan, shape, key, mp, todo, rhs13, rhs2, name, alpha, res)


def _record(res, kind, shape, name, alpha, setting, c13, c2):
    res[kind].append((shape.test, shape.name, name, alpha, setting, c13, c2))


def _scan_fixed(plan, shape, key, mp, todo, rhs13, rhs2, name, alpha, res):
    m13, m2, g13, g2 = plan.fixed[shape.name, key]
    nF = key[0]
    for combo in todo:
        b = rhs13(combo)
        setting = (combo[0], combo[1], nF, combo[2])
        if shape.gauge:
            ok = True
            for vec in g13:
                if _dot(vec, b) % 13:
                    ok = False
                    break
            if not ok:
                continue
            res["gauge_mod13"] += 1
            b_2 = rhs2(combo)
            if all(_dot(vec, b_2) % 2 == 0 for vec in g2):
                res["gauge_pass"] += 1
                _record(res, "gauge_hits", shape, name, alpha, setting, len(g13), len(g2))
        ok = True
        for vec in m13:
            if _dot(vec, b) % 13:
                ok = False
                break
        if not ok:
            continue
        b_2 = rhs2(combo)
        if all(_dot(vec, b_2) % 2 == 0 for vec in m2):
            if min(len(m13), len(m2)) < shape.checks:
                res["deficient"] += 1
            _record(res, "hits", shape, name, alpha, setting, len(m13), len(m2))


def _scan_elim(plan, shape, key, mp, todo, rhs13, name, alpha, res):
    nf = nmap(key[0], mp)
    np_ = nmap(key[1], mp) if shape.lagp else AZMAP
    bs = [rhs13(cb) for cb in todo]
    m = []
    for j in shape.eqs:
        r = [v % 13 for v in shape.row(POS[j], plan.ctn, plan.ptn, nf, np_)]
        r += [b[j] for b in bs]
        m.append(r)
    n, nc = len(m), shape.ncols
    r = reduce_cols(m, 0, shape.nunk, 0, 13, INV13)
    c13 = n - r
    if c13 < shape.checks:
        res["deficient"] += 1
    passA = [all(row[nc + k] == 0 for row in m[r:]) for k in range(len(todo))]
    passG = None
    if shape.gauge:
        r2 = reduce_cols(m, shape.nunk, nc, r, 13, INV13)
        passG = [all(row[nc + k] == 0 for row in m[r2:]) for k in range(len(todo))]
        g13 = n - r2
    for k, combo in enumerate(todo):
        setting = (combo[0], combo[1], key[0], combo[2])
        if passG is not None and passG[k]:
            res["gauge_mod13"] += 1
            c2 = _mod2_checks(plan, shape, mp, setting, gauge=True)
            if c2 is not None:
                res["gauge_pass"] += 1
                _record(res, "gauge_hits", shape, name, alpha, setting, g13, c2)
        if passA[k]:
            c2 = _mod2_checks(plan, shape, mp, setting)
            if c2 is not None:
                _record(res, "hits", shape, name, alpha, setting, c13, c2)


# ---------------------------------------------------------------- reading a survivor

def decrypt(ct, shape, mp, setting, sol, seed=None):
    """Run the rule backwards over all 97 letters. '?' where a needed letter is unknown."""
    nP, nC, nF, s = setting
    nf, np_, nc = nmap(nF, mp), nmap(nP, mp), nmap(nC, mp)
    invp = [0] * 26
    for z, v in enumerate(np_):
        invp[v] = z
    la, lp = len(shape.lagc), len(shape.lagp)
    a, b, w = sol[:la], sol[la:la + lp], sol[la + lp:la + lp + shape.nconst]
    ctn = [IZ[c] for c in ct]
    n = len(ct)
    blags = [(e, co) for e, co in zip(shape.lagp, b) if co]

    def fed(i):
        """nC(C[i]) - cipher feedback - word at i, or None if a fed cipher letter is before the start."""
        acc = nc[ctn[i]]
        for d, co in zip(shape.lagc, a):
            if co:
                if i - d < 0:
                    return None
                acc -= co * nf[ctn[i - d]]
        return acc - (w[i % shape.period] if shape.period else w[0])

    out = [None] * n
    if seed:                                    # plain feedback needs a start: the clue letters
        for i, c in seed.items():
            out[i] = IZ[c]
    for i in range(n):                          # forwards
        if out[i] is not None:
            continue
        acc = fed(i)
        if acc is None:
            continue
        ok = True
        for e, co in blags:
            if i - e < 0 or out[i - e] is None:
                ok = False
                break
            acc -= co * np_[out[i - e]]
        if ok:
            out[i] = invp[(s * acc) % 26]
    if blags:                                   # backwards, through the farthest plain lag if it is a unit
        e0, b0 = max(blags)
        if b0 % 2 and b0 % 13:
            ib0 = _inv26(b0)
            for i in range(n - 1, -1, -1):
                t = i + e0
                if out[i] is not None or t >= n or out[t] is None:
                    continue
                acc = fed(t)
                if acc is None:
                    continue
                # s nP(P[t]) = acc - sum b nP(P[t-e])  ->  b0 nP(P[i]) = acc - s nP(P[t]) - other terms
                acc -= s * np_[out[t]]
                ok = True
                for e, co in blags:
                    if e == e0:
                        continue
                    if out[t - e] is None:
                        ok = False
                        break
                    acc -= co * np_[out[t - e]]
                if ok:
                    out[i] = invp[(acc * ib0) % 26]
    return "".join("?" if v is None else AZ[v] for v in out)


def _inv26(v):
    return next(x for x in range(26) if (x * v) % 26 == 1)


def resolve(plan, hit, big=None, limit=20000):
    """All mod 26 solutions of a hit, decrypted; returns (best score, text, coefficients, n solutions)."""
    test, sname, name, alpha, setting, c13, c2 = hit
    shape = next(s for s in plan.shapes[test] if s.name == sname)
    mp = amap(alpha)
    rows, rhs = plan.system(shape, mp, setting)
    sols = solutions_mod26(rows, rhs, limit=limit)
    if sols is None:
        return None
    if sols == "many":
        return (-99.0, "", "too many solutions", "many")
    best = None
    for sol in sols:
        text = decrypt(plan.ct, shape, mp, setting, sol, plan.cribs if shape.lagp else None)
        known = text.replace("?", "")
        sc = big.score(known) if (big is not None and len(known) >= 12) else -99.0
        rank = whole_score(text, big) if big is not None else -known.count("?")
        if best is None or rank > best[0]:
            best = (rank, sc, text, sol, len(sols))
    return best[1:]


def whole_score(text, big, unread=-6.0):
    """Mean big-model log probability over all quadgram windows; a window with an unread letter counts -6."""
    tot, n = 0.0, 0
    for i in range(len(text) - 3):
        q = text[i:i + 4]
        tot += unread if "?" in q else big.logp.get(q, big.floor)
        n += 1
    return tot / n


# ---------------------------------------------------------------- planted encryptor

def encrypt(pt, rule, alpha, setting, rng):
    """rule: {'a': {lag: coef}, 'b': {lag: coef}, 'w': [word values] or 'c': const}.
    Letters before the start (the primer) are random."""
    nP, nC, nF, s = setting
    mp = amap(alpha)
    nf, np_, nc = nmap(nF, mp), nmap(nP, mp), nmap(nC, mp)
    invc = [0] * 26
    for z, v in enumerate(nc):
        invc[v] = z
    a, b = rule.get("a", {}), rule.get("b", {})
    w = rule.get("w") or [rule.get("c", 0)]
    mx = max(list(a) + list(b) + [1])
    primer_c = [rng.randrange(26) for _ in range(mx)]
    primer_p = [rng.randrange(26) for _ in range(mx)]
    ptn = [IZ[c] for c in pt]
    ctn = []
    for i, x in enumerate(ptn):
        acc = s * np_[x] + w[i % len(w)]
        for d, co in a.items():
            z = ctn[i - d] if i - d >= 0 else primer_c[i - d]
            acc += co * nf[z]
        for e, co in b.items():
            z = ptn[i - e] if i - e >= 0 else primer_p[i - e]
            acc += co * np_[z]
        ctn.append(invc[acc % 26])
    return "".join(AZ[v] for v in ctn)


# ---------------------------------------------------------------- pool plumbing

_P = None


def init(ct, cribs, tests):
    global _P
    _P = Plan(ct, cribs, tests)


def work(items):
    res = new_tally()
    for name, alpha, tests in items:
        scan(_P, name, alpha, tests, res)
    return res
