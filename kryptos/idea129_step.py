"""Helpers for idea 129: a repeating key word plus a steady step, on one hidden alphabet.

Key value at place i (0-indexed in K4):

    k_i = w[i mod p] + s * g(i)   (mod 26)
    g(i) = i                       "letter" form: the step is added at every letter
    g(i) = (i + phase) // p        "pass" form: the word is moved on s places once per pass

The word w (p unknown numbers) is free, the alphabet X is any order of the 26 letters. Layouts as
in idea 92 (kryptos/idea92_hidden.py):

  V      X[C] = X[P] + k        B      X[C] = k - X[P]
  hpAZ   A[C] = X[P] + k        hpKR   (cipher side KRYPTOS)
  hcAZ   X[C] = A[P] + k        hcKR   (plain side KRYPTOS)

For fixed (p, s, form, phase) every clue letter gives one equation that is LINEAR in the unknown
places X[letter] and the word values w[r]. We solve the 24 equations mod 13 and mod 2 (round 9), fix
the alphabet's turn (X of one letter = 0: every layout has that freedom), count the loop tests
(equations minus rank) and then ask for a solution where all clue letters sit on different places
(attack 67: a hidden alphabet with all letters in one place always solves the equations).

Note: the letter form with step s is the pass form with step s*p (phase 0), because
s*i = s*(i mod p) + s*p*(i // p) and the first part goes into w. Both are run anyway.
"""
import itertools
import random

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round9 import solve_mod_p

N = 97
LAYOUTS = ("V", "B", "hpAZ", "hpKR", "hcAZ", "hcKR")
FIXED = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
ENUM_CAP = 400_000        # most mod-13 solutions we list exactly; above that we sample
SAMPLES = 60_000


def g(i, p, form, phase=0):
    return i if form == "letter" else (i + phase) // p


def key_stream(w, s, form, phase=0, n=N):
    p = len(w)
    return [(w[i % p] + s * g(i, p, form, phase)) % 26 for i in range(n)]


def hidden_letters(layout, ct, cribs):
    pos = sorted(cribs)
    if layout in ("V", "B"):
        return sorted({cribs[i] for i in pos} | {ct[i] for i in pos})
    if layout.startswith("hp"):
        return sorted({cribs[i] for i in pos})
    return sorted({ct[i] for i in pos})


class System:
    """The coefficient side of the equations for one (layout, ciphertext, p). The step only changes
    the right-hand side, so the elimination is done once and re-used for every (s, form, phase)."""

    def __init__(self, layout, ct, cribs, p):
        self.layout, self.ct, self.cribs, self.p = layout, ct, cribs, p
        self.pos = sorted(cribs)
        self.letters = hidden_letters(layout, ct, cribs)
        self.li = {ch: j for j, ch in enumerate(self.letters)}
        self.nx = len(self.letters)
        self.n = self.nx + p
        fixed = FIXED.get(layout[2:])
        rows, base = [], []
        for i in self.pos:
            r = [0] * self.n
            P, C = cribs[i], ct[i]
            if layout == "V":
                r[self.li[C]] += 1
                r[self.li[P]] -= 1
                b = 0
            elif layout == "B":
                r[self.li[C]] += 1
                r[self.li[P]] += 1
                b = 0
            elif layout.startswith("hp"):
                r[self.li[P]] -= 1
                b = -fixed.index(C)
            else:
                r[self.li[C]] += 1
                b = fixed.index(P)
            r[self.nx + i % p] -= 1          # - w[r]
            rows.append(r)
            base.append(b)
        # gauge: X[first letter] = 0
        g0 = [0] * self.n
        g0[0] = 1
        rows.append(g0)
        base.append(0)
        self.rows, self.base = rows, base
        # rank and loop tests (rhs-independent): solve with zero rhs
        self.tests = {}
        for q in (13, 2):
            sol = solve_mod_p(rows, [0] * len(rows), q)
            rank = self.n - len(sol[1])
            self.tests[q] = len(rows) - rank

    def rhs(self, s, form, phase=0):
        return [(b + s * g(i, self.p, form, phase)) % 26 for b, i in zip(self.base, self.pos)] + [0]

    def solve(self, s, form, phase=0):
        """None if the loop tests fail, else (sol13, sol2)."""
        b = self.rhs(s, form, phase)
        s13 = solve_mod_p(self.rows, b, 13)
        if s13 is None:
            return None
        s2 = solve_mod_p(self.rows, b, 2)
        if s2 is None:
            return None
        return s13, s2


def _xbasis(sol, nx, q):
    """Particular X part and a reduced basis of the X-projection of the null space mod q."""
    part, basis = sol
    vecs = []
    for v in basis:
        x = [a % q for a in v[:nx]]
        if any(x):
            vecs.append(x)
    # row-reduce to independent vectors
    red, piv = [], []
    for v in vecs:
        v = list(v)
        for r, c in zip(red, piv):
            if v[c]:
                f = v[c]
                v = [(a - f * b) % q for a, b in zip(v, r)]
        c = next((j for j, a in enumerate(v) if a), None)
        if c is None:
            continue
        inv = pow(v[c], q - 2, q) if q > 2 else 1
        v = [(a * inv) % q for a in v]
        red2 = []
        for r in red:
            if r[c]:
                f = r[c]
                r = [(a - f * b) % q for a, b in zip(r, v)]
            red2.append(r)
        red = red2 + [v]
        piv.append(c)
    return part[:nx], red


def _pairmask(x):
    m, bit = 0, 1
    n = len(x)
    for a in range(n):
        xa = x[a]
        for b in range(a + 1, n):
            if xa == x[b]:
                m |= bit
            bit <<= 1
    return m


def _span(part, basis, q):
    for coef in itertools.product(range(q), repeat=len(basis)):
        v = list(part)
        for c, b in zip(coef, basis):
            if c:
                v = [(x + c * y) % q for x, y in zip(v, b)]
        yield v


def _csp13(p13, b13, groups, cap, rng=None, nodes=None):
    """Backtrack over the mod-13 coefficients so that letters in the same group (same value mod 2)
    get different values mod 13. Yields value vectors mod 13. Exhaustive unless `budget` nodes run
    out (then raises Budget)."""
    nx, d = len(p13), len(b13)
    last = [-1] * nx                      # basis index after which letter x is fixed
    for x in range(nx):
        for j in range(d):
            if b13[j][x]:
                last[x] = j
    ready = [[x for x in range(nx) if last[x] == j] for j in range(-1, d)]
    group = [0] * nx
    for gi, gr in enumerate(groups):
        for x in gr:
            group[x] = gi
    vals = list(p13)
    used = [set() for _ in groups]
    for x in ready[0]:
        if vals[x] in used[group[x]]:
            return
        used[group[x]].add(vals[x])
    count = [0]
    coef = []
    order = list(range(13))

    def rec(j, vals):
        if count[0] >= cap:
            return
        nodes[0] -= 1
        if nodes[0] < 0:
            raise Budget()
        if j == d:
            count[0] += 1
            yield list(vals), list(coef)
            return
        b = b13[j]
        cs = order[:]
        if rng is not None:
            rng.shuffle(cs)
        for c in cs:
            nv = [(v + c * y) % 13 for v, y in zip(vals, b)] if c else vals
            ok, added = True, []
            for x in ready[j + 1]:
                u = used[group[x]]
                if nv[x] in u:
                    ok = False
                    break
                u.add(nv[x])
                added.append(x)
            if ok:
                coef.append(c)
                for out in rec(j + 1, nv):
                    yield out
                coef.pop()
            for x in added:
                used[group[x]].discard(nv[x])
            if count[0] >= cap:
                return

    for out in rec(0, vals):
        yield out


class Budget(Exception):
    pass


def arrangements(sys_, sols, cap=2000, rng=None, budget=400_000, with_coef=False):
    """Clue-letter placings with all letters on different places (mod 26).

    Returns (status, list of {letter: place}, capped). status 'exact' = the search was complete (an
    empty list then means NO placing exists), 'budget' = the node budget ran out first."""
    nx = sys_.nx
    p13, b13 = _xbasis(sols[0], nx, 13)
    p2, b2 = _xbasis(sols[1], nx, 2)
    out, status = [], "exact"
    nodes = [budget]
    twos = list(_span(p2, b2, 2))
    if rng is not None:
        rng.shuffle(twos)
    for u in twos:
        groups = [[x for x in range(nx) if u[x] == 0], [x for x in range(nx) if u[x] == 1]]
        if max(len(gr) for gr in groups) > 13:
            continue
        try:
            for v, cf in _csp13(p13, b13, groups, cap - len(out), rng, nodes):
                x = tuple((a + 13 * ((a + b) % 2)) % 26 for a, b in zip(v, u))
                d = dict(zip(sys_.letters, x))
                if with_coef:
                    d = (d, cf, u)
                out.append(d)
        except Budget:
            return "budget", out, len(out) >= cap
        if len(out) >= cap:
            return status, out, True
    return status, out, False


def word_values(sys_, placed, s, form, phase=0):
    """The key word the placing forces (every residue is hit by the 13 consecutive clue places)."""
    fixed = FIXED.get(sys_.layout[2:])
    w = [None] * sys_.p
    for i in sys_.pos:
        P, C = sys_.cribs[i], sys_.ct[i]
        if sys_.layout == "V":
            k = placed[C] - placed[P]
        elif sys_.layout == "B":
            k = placed[C] + placed[P]
        elif sys_.layout.startswith("hp"):
            k = fixed.index(C) - placed[P]
        else:
            k = placed[C] - fixed.index(P)
        v = (k - s * g(i, sys_.p, form, phase)) % 26
        r = i % sys_.p
        if w[r] is None:
            w[r] = v
        elif w[r] != v:
            raise ValueError("placing does not satisfy the equations")
    return w


def encrypt(layout, pt, k, x):
    ix = {ch: j for j, ch in enumerate(x)}
    fixed = FIXED.get(layout[2:])
    out = []
    for ch, kk in zip(pt, k):
        if layout == "V":
            out.append(x[(ix[ch] + kk) % 26])
        elif layout == "B":
            out.append(x[(kk - ix[ch]) % 26])
        elif layout.startswith("hp"):
            out.append(fixed[(ix[ch] + kk) % 26])
        else:
            out.append(x[(fixed.index(ch) + kk) % 26])
    return "".join(out)


def settings(p):
    """Every (s, form, phase) for one word length; s = 1..25 (s = 0, the plain repeating key, is
    run separately as a reference)."""
    for s in range(1, 26):
        yield s, "letter", 0
        for ph in range(p if p > 1 else 1):
            if p > 1:
                yield s, "pass", ph


# ------------------------------------------------------------------ reading a fit setting

def _decrypt_fn(layout):
    fixed = FIXED.get(layout[2:])
    if layout == "V":
        return lambda ix, at, C, k: at[(ix[C] - k) % 26]
    if layout == "B":
        return lambda ix, at, C, k: at[(k - ix[C]) % 26]
    if layout.startswith("hp"):
        fi = [fixed.index(ch) for ch in AZ]
        return lambda ix, at, C, k: at[(fi[C] - k) % 26]
    return lambda ix, at, C, k: AZ.index(fixed[(ix[C] - k) % 26])


class Reader:
    """Hill-climb for the best English reading over every placing that fits one setting.

    State: the mod-13 coefficients of the fit space, which mod-2 solution, and where the letters the
    clues do not place go. Moves: change one coefficient, change the mod-2 solution, swap two free
    letters. A move that puts two clue letters on one place is refused."""

    def __init__(self, S, sols, s, form, phase, score):
        self.S, self.s, self.form, self.phase, self.score = S, s, form, phase, score
        self.p13, self.b13 = _xbasis(sols[0], S.nx, 13)
        p2, b2 = _xbasis(sols[1], S.nx, 2)
        self.twos = list(_span(p2, b2, 2)) if len(b2) <= 9 else None
        self.p2, self.b2 = p2, b2
        self.lidx = [AZ.index(ch) for ch in S.letters]
        self.free = [j for j in range(26) if AZ[j] not in S.letters]
        self.ct = [AZ.index(ch) for ch in S.ct]
        p = S.p
        self.G = [g(i, p, form, phase) for i in range(len(S.ct))]
        self.rep = {}
        for i in S.pos:
            self.rep.setdefault(i % p, i)
        self.dec = _decrypt_fn(S.layout)
        fixed = FIXED.get(S.layout[2:])
        self.fi = [fixed.index(ch) for ch in AZ] if fixed else None

    def placing(self, c, u):
        v = list(self.p13)
        for cj, b in zip(c, self.b13):
            if cj:
                v = [(x + cj * y) % 13 for x, y in zip(v, b)]
        x = [(a + 13 * ((a + b) % 2)) % 26 for a, b in zip(v, u)]
        return x if len(set(x)) == len(x) else None

    def reading(self, x, perm):
        S = self.S
        ix = [None] * 26
        for j, pl in zip(self.lidx, x):
            ix[j] = pl
        taken = set(x)
        fp = [q for q in range(26) if q not in taken]
        for j, k in zip(self.free, perm):
            ix[j] = fp[k]
        at = [0] * 26
        for j, q in enumerate(ix):
            at[q] = j
        lay, fi, ct = S.layout, self.fi, self.ct
        w = {}
        for r, i in self.rep.items():
            C, P = ct[i], AZ.index(S.cribs[i])
            if lay == "V":
                k = ix[C] - ix[P]
            elif lay == "B":
                k = ix[C] + ix[P]
            elif lay.startswith("hp"):
                k = fi[C] - ix[P]
            else:
                k = ix[C] - fi[P]
            w[r] = (k - self.s * self.G[i]) % 26
        p, s, G, dec = S.p, self.s, self.G, self.dec
        return "".join(AZ[dec(ix, at, C, w[i % p] + s * G[i])] for i, C in enumerate(ct)), ix

    def climb(self, starts, rng, max_evals=4000):
        """starts: list of (coefficients, mod-2 vector). Returns (score, plaintext, alphabet)."""
        best = (-99.0, None, None)
        nfree = len(self.free)
        for c0, u0 in starts:
            c, u = list(c0), list(u0)
            perm = list(range(nfree))
            rng.shuffle(perm)
            x = self.placing(c, u)
            if x is None:
                continue
            pt, ix = self.reading(x, perm)
            cur = self.score(pt)
            evals, improved = 0, True
            while improved and evals < max_evals:
                improved = False
                moves = [("c", j, v) for j in range(len(c)) for v in range(13) if v != c[j]]
                moves += [("s", a, b) for a in range(nfree) for b in range(a + 1, nfree)]
                if self.twos is not None:
                    moves += [("u", t, 0) for t in range(len(self.twos))]
                else:
                    moves += [("b", t, 0) for t in range(len(self.b2))]
                rng.shuffle(moves)
                for kind, a, b in moves:
                    nc, nu, np_ = c, u, perm
                    if kind == "c":
                        nc = list(c)
                        nc[a] = b
                    elif kind == "s":
                        np_ = list(perm)
                        np_[a], np_[b] = np_[b], np_[a]
                    elif kind == "u":
                        nu = self.twos[a]
                        if nu == u:
                            continue
                    else:
                        nu = [(x1 + y1) % 2 for x1, y1 in zip(u, self.b2[a])]
                    nx_ = self.placing(nc, nu) if kind != "s" else x
                    if nx_ is None:
                        continue
                    evals += 1
                    t, _ = self.reading(nx_, np_)
                    sc = self.score(t)
                    if sc > cur + 1e-12:
                        c, u, perm, x, cur, pt, improved = nc, nu, np_, nx_, sc, t, True
                        if evals >= max_evals:
                            break
            if cur > best[0]:
                _, ix = self.reading(x, perm)
                at = [None] * 26
                for j, q in enumerate(ix):
                    at[q] = AZ[j]
                best = (cur, pt, "".join(at))
        return best


def _placing_raw(self, c, u):
    v = list(self.p13)
    for cj, b in zip(c, self.b13):
        if cj:
            v = [(x + cj * y) % 13 for x, y in zip(v, b)]
    x = [(a + 13 * ((a + b) % 2)) % 26 for a, b in zip(v, u)]
    return x, len(x) - len(set(x))


def _reading_raw(self, x, perm):
    """Like reading(), but clue letters may share a place (the last one wins in the inverse table);
    the free letters go on the places nobody uses, the rest on any."""
    S = self.S
    ix = [None] * 26
    for j, pl in zip(self.lidx, x):
        ix[j] = pl
    taken = set(x)
    fp = [q for q in range(26) if q not in taken] + [q for q in range(26) if q in taken]
    for j, k in zip(self.free, perm):
        ix[j] = fp[k]
    at = [0] * 26
    for j, q in enumerate(ix):
        at[q] = j
    lay, fi, ct = S.layout, self.fi, self.ct
    w = {}
    for r, i in self.rep.items():
        C, P = ct[i], AZ.index(S.cribs[i])
        if lay == "V":
            k = ix[C] - ix[P]
        elif lay == "B":
            k = ix[C] + ix[P]
        elif lay.startswith("hp"):
            k = fi[C] - ix[P]
        else:
            k = ix[C] - fi[P]
        w[r] = (k - self.s * self.G[i]) % 26
    p, s, G, dec = S.p, self.s, self.G, self.dec
    return "".join(AZ[dec(ix, at, C, w[i % p] + s * G[i])] for i, C in enumerate(ct)), ix


def _anneal(self, rng, restarts=20, steps=6000, lam=0.25, t0=0.25, t1=0.01):
    """Simulated annealing over (coefficients, mod-2 vector, free letters) with a penalty `lam` per
    clue-letter clash. Only clash-free states count as results. Returns (score, plaintext, alphabet)."""
    import math
    best = (-99.0, None, None)
    d, nb2, nfree = len(self.b13), len(self.b2), len(self.free)
    p2 = list(self.p2)
    for _ in range(restarts):
        c = [rng.randrange(13) for _ in range(d)]
        u = list(p2)
        for b in self.b2:
            if rng.random() < 0.5:
                u = [(a + y) % 2 for a, y in zip(u, b)]
        perm = list(range(nfree))
        rng.shuffle(perm)
        x, coll = _placing_raw(self, c, u)
        pt, _ = _reading_raw(self, x, perm)
        q = self.score(pt)
        cur = q - lam * coll
        for step in range(steps):
            T = t0 * (t1 / t0) ** (step / steps)
            r = rng.random()
            nc, nu, np_ = c, u, perm
            if d and r < 0.5:
                nc = list(c)
                nc[rng.randrange(d)] = rng.randrange(13)
            elif nb2 and r < 0.6:
                b = self.b2[rng.randrange(nb2)]
                nu = [(a + y) % 2 for a, y in zip(u, b)]
            elif nfree >= 2:
                np_ = list(perm)
                a1, b1 = rng.sample(range(nfree), 2)
                np_[a1], np_[b1] = np_[b1], np_[a1]
            else:
                continue
            nx_, ncoll = _placing_raw(self, nc, nu) if np_ is perm else (x, coll)
            t, _ = _reading_raw(self, nx_, np_)
            nq = self.score(t)
            sc = nq - lam * ncoll
            if sc >= cur or rng.random() < math.exp((sc - cur) / T):
                c, u, perm, x, coll, cur, q, pt = nc, nu, np_, nx_, ncoll, sc, nq, t
                if coll == 0 and q > best[0]:
                    _, ix = _reading_raw(self, x, perm)
                    at = [None] * 26
                    for j, qq in enumerate(ix):
                        at[qq] = AZ[j]
                    best = (q, pt, "".join(at))
    return best


Reader.anneal = _anneal


def perm_climb(layout, ct, cribs, p, s, form, phase, score, rng, restarts=10, steps=20000, lam=0.3):
    """Annealing on the whole hidden alphabet (26 places), for cells the clues do not decide. The
    word value of each class is the most common value its clue letters ask for; every clue letter
    that disagrees costs `lam`. Only readings with every clue letter right count."""
    import math
    fixed = FIXED.get(layout[2:])
    fi = [fixed.index(ch) for ch in AZ] if fixed else None
    C = [AZ.index(ch) for ch in ct]
    G = [g(i, p, form, phase) for i in range(len(ct))]
    pos = sorted(cribs)
    Pc = {i: AZ.index(cribs[i]) for i in pos}
    dec = _decrypt_fn(layout)
    classes = {}
    for i in pos:
        classes.setdefault(i % p, []).append(i)

    def evaluate(ix):
        at = [0] * 26
        for j, q in enumerate(ix):
            at[q] = j
        w, bad = {}, 0
        for r, ii in classes.items():
            cnt = {}
            for i in ii:
                if layout == "V":
                    k = ix[C[i]] - ix[Pc[i]]
                elif layout == "B":
                    k = ix[C[i]] + ix[Pc[i]]
                elif layout.startswith("hp"):
                    k = fi[C[i]] - ix[Pc[i]]
                else:
                    k = ix[C[i]] - fi[Pc[i]]
                v = (k - s * G[i]) % 26
                cnt[v] = cnt.get(v, 0) + 1
            v, n = max(cnt.items(), key=lambda t: t[1])
            w[r] = v
            bad += len(ii) - n
        for r in range(p):
            w.setdefault(r, 0)
        pt = "".join(AZ[dec(ix, at, c, w[i % p] + s * G[i])] for i, c in enumerate(C))
        return pt, bad

    best = (-99.0, None, None)
    for _ in range(restarts):
        ix = list(range(26))
        rng.shuffle(ix)
        pt, bad = evaluate(ix)
        q = score(pt)
        cur = q - lam * bad
        for step in range(steps):
            T = 0.3 * (0.01 / 0.3) ** (step / steps)
            a, b = rng.sample(range(26), 2)
            ix[a], ix[b] = ix[b], ix[a]
            t, nb = evaluate(ix)
            nq = score(t)
            sc = nq - lam * nb
            if sc >= cur or rng.random() < math.exp((sc - cur) / T):
                cur, q, bad, pt = sc, nq, nb, t
                if bad == 0 and q > best[0]:
                    at = [None] * 26
                    for j, qq in enumerate(ix):
                        at[qq] = AZ[j]
                    best = (q, pt, "".join(at))
            else:
                ix[a], ix[b] = ix[b], ix[a]
    return best
