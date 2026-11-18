"""Idea 135: a cipher-fed state device with one side a keyword alphabet.

The device (idea 83's cipher-fed form):

    C_i = F(s_i + h(P_i))        s_(i+1) = s_i + g(C_i)        mod m

Write u = F^-1 (the value that shows a cipher letter). Inside a clue block the state before letter i is
s_i = u(C_i) - h(P_i), so the step taken after letter i is

    step_i = u(C_(i+1)) - u(C_i) - h(P_(i+1)) + h(P_i)

and it must be the same number g(C_i) wherever the same cipher letter is fed. On K4 that gives 8 equations
(F, R, V, Q, N, T twice and P three times among the 22 fed clue letters).

Tools:

  equations       the step equations, split into a u-part and an h-part
  Compiled        an exact solver for ONE side known: every hidden table entry is an unknown in Z_m, the
                  8 equations must hold and different letters must get different values. It is compiled once
                  per text (variable order, closing lists) and then run once per alphabet with new constants.
  check           an independent check of a solution: rebuild g and F and run the device over both clues
  side_vectors    both sides known (two keyword alphabets): the 8 equations split into a value of the
                  cipher alphabet and a value of the plain alphabet, so a hash join decides every pair
  complete        a both-known setting: g is known for the 14 fed clue letters; the other g values are
                  filled in on English (hill climbing), with the gap between the clues as an exact equation
  encrypt         the device itself (for planted texts)
"""
import random
from math import gcd

from .idea83_devices import B1, B2, tables, tables_check

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ------------------------------------------------------------------ equations

def equations(ct, cribs):
    """[(u-part {letter: coef}, h-part {letter: coef})]: sum u-part*u + sum h-part*h == 0 mod m."""
    cons, _ = tables(ct, cribs, "cipher")
    out = []
    for terms, _, eq in cons:
        if not eq:
            continue
        u = {v[1]: c for v, c in terms.items() if v[0] == "u" and c}
        h = {v[1]: c for v, c in terms.items() if v[0] == "h" and c}
        out.append((u, h))
    return out


def clue_letters(ct, cribs):
    return sorted(set(ct[i] for i in B1 + B2)), sorted(set(cribs[i] for i in B1 + B2))


def rank_mod(rows, p):
    """Rank of an integer matrix over GF(p)."""
    m = [[v % p for v in r] for r in rows]
    r = 0
    for c in range(len(m[0]) if m else 0):
        s = next((i for i in range(r, len(m)) if m[i][c]), None)
        if s is None:
            continue
        m[r], m[s] = m[s], m[r]
        inv = pow(m[r][c], p - 2, p)
        m[r] = [(v * inv) % p for v in m[r]]
        for i in range(len(m)):
            if i != r and m[i][c]:
                f = m[i][c]
                m[i] = [(a - f * b) % p for a, b in zip(m[i], m[r])]
        r += 1
    return r


def check_count(ct, cribs, hidden):
    """(equations, unknowns after the shift gauge, rank mod 2/13/29/31, exact linear checks left).
    hidden: 'u' (layout A: plain side known), 'h' (layout B: cipher side known) or '' (both known)."""
    eqs = equations(ct, cribs)
    cl, pl = clue_letters(ct, cribs)
    if not hidden:
        return len(eqs), 0, 0, len(eqs)
    letters = cl if hidden == "u" else pl
    rows = [[(e[0] if hidden == "u" else e[1]).get(L, 0) for L in letters] for e in eqs]
    ranks = [rank_mod(rows, p) for p in (2, 13, 29, 31)] if rows else [0]
    return len(eqs), len(letters) - 1, min(ranks), len(eqs) - min(ranks)


# ------------------------------------------------------------------ one side known: compiled exact solver

class Compiled:
    """Exact test for one side known. hidden = 'u' (h known, F hidden) or 'h' (F known, h hidden).
    run(idx, m) -> ('yes', {letter: value}) or ('no', None) or ('cap', None)."""

    def __init__(self, ct, cribs, hidden, cap=200000):
        self.ct, self.cribs, self.hidden, self.cap = ct, cribs, hidden, cap
        eqs = equations(ct, cribs)
        cl, pl = clue_letters(ct, cribs)
        k = 1 if hidden == "u" else 0                # the known part of each equation
        self.known = [e[k] for e in eqs]
        terms = [e[1 - k] for e in eqs]
        allv = cl if hidden == "u" else pl
        # letters in no equation only need a value no other letter has: there are always enough values
        # (m >= number of letters), so they are left out of the search and filled in afterwards
        hv = sorted(set(v for t in terms for v in t)) or allv[:1]
        self.letters, self.spare = allv, [v for v in allv if v not in hv]
        # order: gauge letter first, then the variable that closes the most equations
        placed, order, left = set(), [], set(hv)
        first = max(hv, key=lambda v: (sum(1 for t in terms if v in t), v))
        order.append(first)
        placed.add(first)
        left.discard(first)
        while left:
            def gain(v):
                closes = sum(1 for t in terms if v in t and all(x in placed or x == v for x in t))
                near = sum(1 for t in terms if v in t)
                return (closes, near, v)
            v = max(sorted(left), key=gain)
            order.append(v)
            placed.add(v)
            left.discard(v)
        self.order = order
        depth = {v: i for i, v in enumerate(order)}
        self.close = [[] for _ in order]           # (eq index, coef of this var, [(depth, coef)])
        self.pure = []                              # equations with no hidden letter left: a direct check
        for j, t in enumerate(terms):
            if not t:
                self.pure.append(j)
                continue
            d = max(depth[v] for v in t)
            v = order[d]
            self.close[d].append((j, t[v], [(depth[x], c) for x, c in t.items() if x != v]))

    def consts(self, idx, m):
        return [sum(c * idx[L] for L, c in kn.items()) % m for kn in self.known]

    def run(self, idx, m):
        n = len(self.order)
        if m < len(self.letters):
            return "no", None
        const = self.consts(idx, m)
        if any(const[j] for j in self.pure):
            return "no", None
        close, cap = self.close, self.cap
        val = [0] * n
        used = [False] * m
        nodes = [0]
        allv = list(range(m))

        def cands(d):
            if d == 0:
                return [0]
            if close[d]:
                j, a, rest = close[d][0]
                b = (-const[j] - sum(val[i] * c for i, c in rest)) % m
                g = gcd(a, m)
                if b % g:
                    return []
                mm = m // g
                x0 = (b // g) * pow(a // g, -1, mm) % mm if mm > 1 else 0
                return [x0 + q * mm for q in range(g)]
            return allv

        def rec(d):
            if d == n:
                return True
            for x in cands(d):
                if used[x]:
                    continue
                nodes[0] += 1
                if nodes[0] > cap:
                    raise OverflowError
                ok = True
                for j, a, rest in close[d][1:] if close[d] else ():
                    if (a * x + const[j] + sum(val[i] * c for i, c in rest)) % m:
                        ok = False
                        break
                if ok:
                    val[d] = x
                    used[x] = True
                    if rec(d + 1):
                        return True
                    used[x] = False
            return False

        try:
            found = rec(0)
        except OverflowError:
            return "cap", None
        if not found:
            return "no", None
        sol = {v: val[i] for i, v in enumerate(self.order)}
        free = (x for x in range(m) if not used[x])
        for v in self.spare:
            sol[v] = next(free)
        return "yes", sol



class Eliminated(Compiled):
    """The same exact test, faster: the equations are solved once per text by integer elimination with
    +-1 pivots (valid in every modulus), so the search runs only over the free places (dimension = unknowns
    minus rank) and checks that all letters land on different values. If a text has no +-1 pivot where one
    is needed, run() falls back to Compiled's search."""

    def __init__(self, ct, cribs, hidden, cap=2000000):
        Compiled.__init__(self, ct, cribs, hidden, cap)
        eqs = equations(ct, cribs)
        k = 1 if hidden == "u" else 0
        terms = [e[1 - k] for e in eqs]
        hv = sorted(set(v for t in terms for v in t))
        rows = [(dict(t), {j: 1}) for j, t in enumerate(terms)]
        piv, done = [], set()
        while True:
            pick = None
            for r, (t, _) in enumerate(rows):
                if r in done:
                    continue
                v = next((v for v in sorted(t) if t[v] in (1, -1)), None)
                if v is not None:
                    pick = (r, v)
                    break
            if pick is None:
                break
            r, v = pick
            t, lam = rows[r]
            if t[v] == -1:
                t = {x: -c for x, c in t.items()}
                lam = {j: -c for j, c in lam.items()}
                rows[r] = (t, lam)
            for i, (ti, li) in enumerate(rows):
                if i != r and ti.get(v):
                    f = ti[v]
                    nt = dict(ti)
                    for x, c in t.items():
                        nt[x] = nt.get(x, 0) - f * c
                    nl = dict(li)
                    for j, c in lam.items():
                        nl[j] = nl.get(j, 0) - f * c
                    rows[i] = ({x: c for x, c in nt.items() if c}, {j: c for j, c in nl.items() if c})
            done.add(r)
            piv.append((r, v))
        rest = [r for r in range(len(rows)) if r not in done]
        self.fallback = any(rows[r][0] for r in rest)
        self.pure_lam = [rows[r][1] for r in rest if not rows[r][0]]
        pv = {v for _, v in piv}
        free = [v for v in hv if v not in pv]
        # pivot v: x_v + sum a_f x_f + sum lam_j K_j == 0
        pivots = [(v, {x: c for x, c in rows[r][0].items() if x != v}, rows[r][1]) for r, v in piv]
        order, placed = [], set()
        left = list(free)
        while left:
            def gain(f):
                return (sum(1 for _, a, _ in pivots if f in a and all(x in placed or x == f for x in a)),
                        sum(1 for _, a, _ in pivots if f in a), f)
            f = max(left, key=gain)
            order.append(f)
            placed.add(f)
            left.remove(f)
        self.free = order
        depth = {f: i for i, f in enumerate(order)}
        self.at = [[] for _ in order]               # pivots completed at each depth
        self.const_piv = []                         # pivots that depend on no free place
        for v, a, lam in pivots:
            if a:
                self.at[max(depth[x] for x in a)].append((v, [(depth[x], c) for x, c in a.items()], lam))
            else:
                self.const_piv.append((v, lam))
        self.rank = len(piv)
        # every pair of letters whose difference does not depend on a free place: a direct check
        lin = {f: ({f: 1}, {}) for f in free}
        for v, a, lam in pivots:
            lin[v] = ({x: -c for x, c in a.items()}, {j: -c for j, c in lam.items()})
        self.const_pairs = []
        names = sorted(lin)
        for x in range(len(names)):
            for y in range(x + 1, len(names)):
                (ax, lx), (ay, ly) = lin[names[x]], lin[names[y]]
                if all(ax.get(k, 0) == ay.get(k, 0) for k in set(ax) | set(ay)):
                    d = dict(lx)
                    for j, c in ly.items():
                        d[j] = d.get(j, 0) - c
                    self.const_pairs.append({j: c for j, c in d.items() if c})

    def run(self, idx, m):
        if self.fallback:
            return Compiled.run(self, idx, m)
        if m < len(self.letters):
            return "no", None
        K = self.consts(idx, m)
        for lam in self.const_pairs:
            if sum(c * K[j] for j, c in lam.items()) % m == 0:
                return "no", None
        for lam in self.pure_lam:
            if sum(c * K[j] for j, c in lam.items()) % m:
                return "no", None
        used = [False] * m
        sol = {}
        for v, lam in self.const_piv:
            x = -sum(c * K[j] for j, c in lam.items()) % m
            if used[x]:
                return "no", None
            used[x] = True
            sol[v] = x
        at = [[(v, a, sum(c * K[j] for j, c in lam.items())) for v, a, lam in lst] for lst in self.at]
        n = len(self.free)
        val = [0] * n
        nodes = [0]
        cap = self.cap

        def rec(d):
            if d == n:
                return True
            for x in ((0,) if d == 0 else range(m)):
                if used[x]:
                    continue
                nodes[0] += 1
                if nodes[0] > cap:
                    raise OverflowError
                val[d] = x
                used[x] = True
                got, ok = [], True
                for v, a, kc in at[d]:
                    y = -(kc + sum(val[i] * c for i, c in a)) % m
                    if used[y]:
                        ok = False
                        break
                    used[y] = True
                    got.append((v, y))
                if ok and rec(d + 1):
                    for v, y in got:
                        sol[v] = y
                    return True
                for _, y in got:
                    used[y] = False
                used[x] = False
            return False

        try:
            found = rec(0)
        except OverflowError:
            return "cap", None
        if not found:
            return "no", None
        for i, f in enumerate(self.free):
            sol[f] = val[i]
        spare = (x for x in range(m) if not used[x])
        for v in self.spare:
            sol[v] = next(spare)
        return "yes", sol


def _check(self, idx, m, sol):
    """Independent check with idea 83's tables_check (rebuilds g and F, runs the device)."""
    cl, pl = clue_letters(self.ct, self.cribs)
    full = {}
    if self.hidden == "u":
        full.update({("u", c): sol[c] for c in cl})
        full.update({("h", p): idx[p] % m for p in pl})
    else:
        full.update({("u", c): idx[c] % m for c in cl})
        full.update({("h", p): sol[p] for p in pl})
    return tables_check(m, full, self.ct, self.cribs, feed="cipher")


Compiled.check = _check


# ------------------------------------------------------------------ both sides known: hash join

def side_vectors(ct, cribs):
    """(u-parts, h-parts) of the equations, as lists of {letter: coef}."""
    eqs = equations(ct, cribs)
    return [e[0] for e in eqs], [e[1] for e in eqs]


def encode(vec, m):
    out = 0
    for v in vec:
        out = out * m + v % m
    return out


def vector(parts, idx, m, sign=1):
    return [sign * sum(c * idx[L] for L, c in p.items()) % m for p in parts]


# ------------------------------------------------------------------ the device

def encrypt(pt, m, u, h, g, s0=0):
    """u: {cipher letter: value} (one-to-one), h: {plain letter: value}, g: {cipher letter: step}.
    Returns the cipher text or None if a value has no letter (m > 26)."""
    f = {v: c for c, v in u.items()}
    s, out = s0 % m, []
    for ch in pt:
        c = f.get((s + h[ch]) % m)
        if c is None:
            return None
        out.append(c)
        s = (s + g[c]) % m
    return "".join(out)


def decrypt(ct, m, u, h, g, s0):
    hinv = {v % m: p for p, v in h.items()}
    s, out = s0 % m, []
    for c in ct:
        p = hinv.get((u[c] - s) % m)
        out.append(p if p else "?")
        s = (s + g[c]) % m
    return "".join(out)


def forced_steps(ct, cribs, m, u, h):
    """Both tables known: g of every fed clue letter, and the state before each clue block.
    Returns (g dict, {block start: state}) or None if the clue letters contradict it."""
    g, st = {}, {}
    for blk in (B1, B2):
        st[blk[0]] = (u[ct[blk[0]]] - h[cribs[blk[0]]]) % m
        for i in blk[:-1]:
            d = (u[ct[i + 1]] - h[cribs[i + 1]] - u[ct[i]] + h[cribs[i]]) % m
            if g.setdefault(ct[i], d) != d:
                return None
    return g, st


def complete(ct, cribs, m, u, h, logp, floor, width=1500, polish=4, order=None):
    """Fill in g for the letters the clues do not fix, so that the text reads best on English.

    Beam search outwards from the clues: walker F goes 34..62, walker A goes 74..96, walker B goes 20..0,
    one letter each per round. A walker that needs the g of a letter not yet fixed branches over all m
    values; the beam keeps the `width` best partial texts by the sum of their finished quadgrams (logp,
    a {quadgram: log10 p} dict, floor for unseen ones). The gap is exact: after 62 the state must be the
    state the second clue needs. For m > 26 a value without a letter kills the branch. The walkers run one
    after another; with order=None three orders are run (FAB, ABF, BFA) and the best reading is kept.
    Returns (mean log10 per quadgram, plaintext, g, s0) or None if nothing survives."""
    fs = forced_steps(ct, cribs, m, u, h)
    if fs is None:
        return None
    g0, st = fs
    n = len(ct)
    hinv = {v % m: p for p, v in h.items()}
    a1, e1, a2, e2 = B1[0], B1[-1], B2[0], B2[-1]
    s_e1 = (u[ct[e1]] - h[cribs[e1]]) % m
    s_e2 = (u[ct[e2]] - h[cribs[e2]]) % m
    s_a2 = st[a2]
    ci = [ord(c) - 65 for c in ct]
    uc = [u[c] for c in ct]
    pt0 = [None] * n
    for i in B1 + B2:
        pt0[i] = cribs[i]
    g_init = [-1] * 26
    for c, v in g0.items():
        g_init[ord(c) - 65] = v

    # events in order: (walker, position, letter whose g is needed)
    # one walker at a time, so a value chosen at a branch is judged on every letter up to the next branch
    walks = {"F": [("F", j, ci[j - 1]) for j in range(e1 + 1, a2)] + [("G", a2, ci[a2 - 1])],
             "A": [("A", j, ci[j - 1]) for j in range(e2 + 1, n)],
             "B": [("B", j, ci[j]) for j in range(a1 - 1, -1, -1)]}
    if order is None:
        best = None
        for o in ("FAB", "ABF", "BFA"):
            r = complete(ct, cribs, m, u, h, logp, floor, width, polish, o)
            if r is not None and (best is None or r[0] > best[0]):
                best = r
        return best
    events = [e for w in order for e in walks[w]]

    def quads(pt, j):
        out = 0.0
        for q in range(max(0, j - 3), min(j, n - 4) + 1):
            w = pt[q:q + 4]
            if None not in w:
                out += logp.get("".join(w), floor)
        return out

    base = 0.0
    for q in range(n - 3):
        w = pt0[q:q + 4]
        if None not in w:
            base += logp.get("".join(w), floor)
    # beam item: (score, g list, {walker: state}, plaintext list)
    beam = [(base, g_init, {"F": s_e1, "A": s_e2, "B": st[a1]}, pt0)]
    for walker, j, L in events:
        if len(beam) > width and any(g[L] < 0 for _, g, _, _ in beam):
            beam.sort(key=lambda r: -r[0])        # prune only just before the beam branches again
            beam = beam[:width]
        nxt = []
        for sc, g, ss, pt in beam:
            vals = [g[L]] if g[L] >= 0 else range(m)
            for v in vals:
                if walker == "B":
                    s = (ss["B"] - v) % m                   # s_j = s_(j+1) - g(C_j)
                else:
                    s = (ss[walker if walker != "G" else "F"] + v) % m
                if walker == "G":
                    if s != s_a2:
                        continue
                    if g[L] < 0:
                        g2 = list(g)
                        g2[L] = v
                    else:
                        g2 = g
                    nxt.append((sc, g2, ss, pt))
                    continue
                p = hinv.get((uc[j] - s) % m)
                if p is None:
                    continue
                pt2 = list(pt)
                pt2[j] = p
                if g[L] < 0:
                    g2 = list(g)
                    g2[L] = v
                else:
                    g2 = g
                ss2 = dict(ss)
                ss2[walker] = s
                nxt.append((sc + quads(pt2, j), g2, ss2, pt2))
        if not nxt:
            return None
        beam = nxt
    beam.sort(key=lambda r: -r[0])
    # polish the best few with full-text hill climbing: one g value at a time, then pairs
    free = sorted(set(ci) - set(ord(c) - 65 for c in g0))
    gap_letters = [ci[k] for k in range(e1, a2)]

    def full(g):
        sv = s_e1                                   # the gap must still close
        for L in gap_letters:
            sv = (sv + g[L]) % m
        if sv != s_a2:
            return None
        s = st[a1]
        for k in range(a1 - 1, -1, -1):
            s = (s - g[ci[k]]) % m
        out = []
        for k in range(n):
            p = hinv.get((uc[k] - s) % m)
            if p is None:
                return None
            out.append(p)
            s = (s + g[ci[k]]) % m
        txt = "".join(out)
        return sum(logp.get(txt[q:q + 4], floor) for q in range(n - 3)), txt, s

    best = None
    seen = set()
    for sc, g, ss, pt in beam:
        key = tuple(g)
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > polish:
            break
        g = list(g)
        cur = full(g)
        if cur is None:
            continue
        improved = True
        while improved:
            improved = False
            for L in free:
                keep = g[L]
                for v in range(m):
                    if v == keep:
                        continue
                    g[L] = v
                    r = full(g)
                    if r is not None and r[0] > cur[0]:
                        cur, keep, improved = r, v, True
                g[L] = keep
            if improved:
                continue
            for x in range(len(free)):
                for y in range(x + 1, len(free)):
                    A, B = free[x], free[y]
                    ka, kb = g[A], g[B]
                    for va in range(m):
                        g[A] = va
                        for vb in range(m):
                            g[B] = vb
                            r = full(g)
                            if r is not None and r[0] > cur[0]:
                                cur, ka, kb, improved = r, va, vb, True
                    g[A], g[B] = ka, kb
                if improved:
                    break
        if best is None or cur[0] > best[0][0]:
            best = (cur, list(g))
    if best is None:
        return None
    (sc, txt, _), g = best
    s0 = st[a1]
    for k in range(a1 - 1, -1, -1):
        s0 = (s0 - g[ci[k]]) % m
    gd = {chr(65 + i): v for i, v in enumerate(g) if v >= 0}
    return sc / (n - 3), txt, gd, s0


def plant(rng, pt, m, cipher_alpha, plain_alpha, sign=1, tries=400000):
    """Encrypt pt with keyword tables on both sides and a random g; for m > 26 g and the start are redrawn
    until the text never lands on a value without a letter. Returns (ct, g, s0, u, h) or None."""
    u = {c: i for i, c in enumerate(cipher_alpha)}
    h = {p: (sign * i) % m for i, p in enumerate(plain_alpha)}
    for _ in range(tries):
        g = {c: rng.randrange(m) for c in AZ}
        s0 = rng.randrange(m)
        ct = encrypt(pt, m, u, h, g, s0)
        if ct is not None:
            return ct, g, s0, u, h
    return None


def plant_hidden(rng, pt, m, known_alpha, hidden, tries=400000):
    """One side a keyword alphabet, the other random (layout A: hidden='u', layout B: hidden='h')."""
    for _ in range(tries):
        vals = rng.sample(range(m), 26)
        if hidden == "u":
            u = {c: v for c, v in zip(AZ, vals)}
            h = {p: i for i, p in enumerate(known_alpha)}
        else:
            u = {c: i for i, c in enumerate(known_alpha)}
            h = {p: v for p, v in zip(AZ, vals)}
        g = {c: rng.randrange(m) for c in AZ}
        s0 = rng.randrange(m)
        ct = encrypt(pt, m, u, h, g, s0)
        if ct is not None:
            return ct, u, h, g, s0
    return None
