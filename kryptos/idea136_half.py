"""Idea 136 helpers: plaintext autokey at lags 5-12 on a half-hidden tableau.

Model (one form covers Vigenere, Beaufort and the variant, see below):

    pos_c(C_i) = pos_p(P_i) + s * num(F_i) + c   (mod 26),   s = +1 or -1

F_i is the plaintext letter d places back (F_i = P_{i-d}) or d places ahead (F_i = P_{i+d}); the first or last
d letters use a primer. pos_p / pos_c are places in the plain / cipher alphabet. num numbers the fed letter on the
plain alphabet ("M"), on A-Z or on KRYPTOS.

Layouts:
  "P"  the plain alphabet is a dictionary alphabet M, the cipher alphabet is free (c is absorbed into it);
  "C"  the cipher alphabet is M, the plain alphabet is free, c is an unknown.

Beaufort (num - pos_p) and the variant (pos_p - num) are the same test as s = -1 once the free alphabet is read
back to front; "-pos_p - num" is s = +1 read back to front. So two signs cover all four forms.

Clue equations. In each class of positions mod d, two clue letters S and T joined by a run t_1..t_m (t_m = T,
in the order the key feeds forward) give one equation:
  layout C, num M:   x(P_T) = sum_k (-s)^(m-k) (pos_M(C_tk) - c) + (-s)^m x(P_S)      (linear in x and c)
  layout P, num M:   pos_M(P_T) = sum_k (-s)^(m-k) y(C_tk) + (-s)^m pos_M(P_S)       (linear in y)
  fixed numbering:   only m = 1 (both letters known), x(P_T) = pos_M(C_T) - c - s n(P_S) (C) or
                     y(C_T) = pos_M(P_T) + s n(P_S) (P): a collision check.
Longer runs with fixed numbering need the free alphabet's letters in the middle, so they are not linear and are
left to the English completion.

Each cell's system is rows * u = W pos_M + H. Its left null space gives exact checks that are linear in the 26
places of M (mod 13 and mod 2), so an alphabet is tested with a few sums. Alphabets passing all checks are solved
with distinct places (idea 93's solver).
"""
import math
import random

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import CRIBS
from .round9 import solve_mod_p
from .idea93_hidden import solve_injective

N = 97
IZ = {c: i for i, c in enumerate(AZ)}
FIXN = {"AZ": IZ, "KR": {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}}
FIXA = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
NUMS = ("M", "AZ", "KR")
LAYOUTS = ("P", "C")
SIGNS = (1, -1)
LAGS = tuple(("back", d) for d in range(5, 13)) + tuple(("ahead", d) for d in range(7, 13))


def cells():
    return [(lay, num, dr, d, s) for lay in LAYOUTS for num in NUMS for dr, d in LAGS for s in SIGNS]


def name(cell):
    lay, num, dr, d, s = cell
    return "%s-known num%s %s%d %s" % ("plain" if lay == "P" else "cipher", num, dr, d, "+" if s > 0 else "-")


def links(dr, d, clue=CRIBS, n=N):
    """(S, [t_1..t_m]) for consecutive clue letters of one class mod d, in the order the key feeds forward."""
    out = []
    for r in range(d):
        cls = list(range(r, n, d))
        if dr == "ahead":
            cls = cls[::-1]
        known = [k for k, t in enumerate(cls) if t in clue]
        for a, b in zip(known, known[1:]):
            out.append((cls[a], cls[a + 1:b + 1]))
    return out


def system(cell, ct, clue=CRIBS):
    """rows (27 columns: 26 letters of the free side + c), W (26 columns over M's places), H (constants)."""
    lay, num, dr, d, s = cell
    rows, W, H = [], [], []
    for S, ts in links(dr, d, clue):
        m = len(ts)
        if num != "M" and m > 1:
            continue
        r, w, h = [0] * 27, [0] * 26, 0
        PS, PT = clue[S], clue[ts[-1]]
        if lay == "C":
            if num == "M":
                r[IZ[PT]] += 1
                r[IZ[PS]] -= (-s) ** m
                for k, t in enumerate(ts, 1):
                    co = (-s) ** (m - k)
                    r[26] += co
                    w[IZ[ct[t]]] += co
            else:
                r[IZ[PT]] += 1
                r[26] += 1
                w[IZ[ct[ts[0]]]] += 1
                h = -s * FIXN[num][PS]
        else:
            if num == "M":
                for k, t in enumerate(ts, 1):
                    r[IZ[ct[t]]] += (-s) ** (m - k)
                w[IZ[PT]] += 1
                w[IZ[PS]] -= (-s) ** m
            else:
                r[IZ[ct[ts[0]]]] += 1
                w[IZ[PT]] += 1
                h = s * FIXN[num][PS]
        rows.append([v % 26 for v in r])
        W.append([v % 26 for v in w])
        H.append(h % 26)
    return rows, W, H


def _rank(vecs, p):
    if not vecs:
        return 0
    m = [list(v) for v in vecs]
    rank, ncol = 0, len(m[0])
    for col in range(ncol):
        piv = next((i for i in range(rank, len(m)) if m[i][col] % p), None)
        if piv is None:
            continue
        m[rank], m[piv] = m[piv], m[rank]
        inv = pow(m[rank][col], p - 2, p) if p > 2 else 1
        m[rank] = [(v * inv) % p for v in m[rank]]
        for i in range(len(m)):
            if i != rank and m[i][col] % p:
                f = m[i][col]
                m[i] = [(a - f * b) % p for a, b in zip(m[i], m[rank])]
        rank += 1
    return rank


class Cell:
    """One (layout, numbering, direction, lag, sign) test for one ciphertext: exact checks on M's places."""

    def __init__(self, cell, ct, clue=CRIBS):
        self.cell, self.ct, self.clue = cell, ct, clue
        self.rows, self.W, self.H = system(cell, ct, clue)
        self.dead = False            # a check with no M-dependence fails: impossible on every alphabet
        self.checks = {}
        ranks = {}
        for p in (13, 2):
            cks = []
            if self.rows:
                T = [[self.rows[e][j] for e in range(len(self.rows))] for j in range(27)]
                sol = solve_mod_p(T, [0] * 27, p)
                basis = sol[1] if sol else []
            else:
                basis = []
            gs = []
            for y in basis:
                g = [sum(y[e] * self.W[e][l] for e in range(len(y))) % p for l in range(26)]
                h0 = sum(y[e] * self.H[e] for e in range(len(y))) % p
                if not any(g):
                    if h0:
                        self.dead = True
                    continue
                gs.append(g)
                cks.append(([(l, v) for l, v in enumerate(g) if v], h0))
            self.checks[p] = cks
            ranks[p] = _rank(gs, p)
        self.r13, self.r2 = ranks[13], ranks[2]
        self.n_eq = len(self.rows)

    def chance(self, n_alphabets):
        """Upper bound on passes expected by chance among n alphabets (consistency only, distinctness ignored)."""
        if self.dead:
            return 0.0
        return n_alphabets * 13.0 ** -self.r13 * 2.0 ** -self.r2

    def consistent(self, pos):
        for p in (13, 2):
            for g, h0 in self.checks[p]:
                t = h0
                for l, v in g:
                    t += v * pos[l]
                if t % p:
                    return False
        return True

    def rhs(self, pos):
        return [(sum(w * pos[l] for l, w in enumerate(row) if w) + h) % 26 for row, h in zip(self.W, self.H)]

    def solve(self, pos, max_points=31000, max_sols=4):
        """(status, solutions): status 'none' | 'ok' | 'capped' | 'many' (too free to list)."""
        rhs = self.rhs(pos)
        if not self.rows or not any(rhs):
            return "many", []          # idea 93's solver lists homogeneous systems up to scaling; count as a pass
        sols, status = solve_injective(self.rows, rhs, max_points=max_points, max_sols=max_sols)
        return status, sols

    def test(self, pos):
        if self.dead or not self.consistent(pos):
            return "none", []
        return self.solve(pos)


# ---------------------------------------------------------------- encrypt / decrypt with both alphabets known

def _fed(i, dr, d):
    return i - d if dr == "back" else i + d


def encrypt(pt, cell, mp, mc, c, primer):
    lay, num, dr, d, s = cell
    n = len(pt)
    ip = {ch: i for i, ch in enumerate(mp)}
    nf = ip if num == "M" else FIXN[num]
    out = []
    for i, p in enumerate(pt):
        f = _fed(i, dr, d)
        F = pt[f] if 0 <= f < n else primer[f + d if f < 0 else f - n]
        out.append(mc[(ip[p] + s * nf[F] + c) % 26])
    return "".join(out)


class Decryptor:
    """Decrypts every class mod d from its clue letters, re-seeding at each clue letter and counting clue letters
    the chain fails to reach (mismatches). Alphabets given as 26-letter strings/lists."""

    def __init__(self, cell, ct, clue=CRIBS):
        self.cell, self.ct, self.clue = cell, ct, clue
        lay, num, dr, d, s = cell
        n = len(ct)
        self.plan = []
        for r in range(d):
            cls = list(range(r, n, d))
            if dr == "ahead":
                cls = cls[::-1]
            k0 = next((k for k, t in enumerate(cls) if t in clue), None)
            self.plan.append((cls, k0))

    def run(self, mp, mc, c):
        lay, num, dr, d, s = self.cell
        ct, clue = self.ct, self.clue
        ip = {ch: i for i, ch in enumerate(mp)}
        ic = {ch: i for i, ch in enumerate(mc)}
        if num == "M":
            nf, inv = ip, mp
        else:
            nf, inv = FIXN[num], FIXA[num]
        pt = ["?"] * len(ct)
        bad = 0
        for cls, k0 in self.plan:
            if k0 is None:
                continue
            cur = clue[cls[k0]]
            pt[cls[k0]] = cur
            for j in range(k0 + 1, len(cls)):
                t = cls[j]
                nxt = mp[(ic[ct[t]] - c - s * nf[cur]) % 26]
                if t in clue:
                    if nxt != clue[t]:
                        bad += 1
                    nxt = clue[t]
                pt[t] = nxt
                cur = nxt
            cur = clue[cls[k0]]
            for j in range(k0 - 1, -1, -1):
                t = cls[j]
                nxt = inv[(s * (ic[ct[cls[j + 1]]] - c - ip[cur])) % 26]
                if t in clue:
                    if nxt != clue[t]:
                        bad += 1
                    nxt = clue[t]
                pt[t] = nxt
                cur = nxt
        return "".join(pt), bad


# ---------------------------------------------------------------- English completion

class Big:
    """Big quadgram model as a flat table indexed by 4-letter numbers."""

    def __init__(self, path):
        from .score import Quadgrams
        q = Quadgrams(path)
        self.floor = q.floor
        self.t = [q.floor] * (26 ** 4)
        for k, v in q.logp.items():
            if len(k) == 4 and k.isalpha():
                a, b, cc, e = (IZ[ch] for ch in k)
                self.t[((a * 26 + b) * 26 + cc) * 26 + e] = v

    def total(self, text):
        x = [IZ.get(ch, 0) for ch in text]
        t = self.t
        return sum(t[((x[i] * 26 + x[i + 1]) * 26 + x[i + 2]) * 26 + x[i + 3]] for i in range(len(x) - 3))

    def mean(self, text):
        return self.total(text) / (len(text) - 3)


PENALTY = 12.0     # per clue letter the chains miss (a quadgram of noise costs about 2.5 more than English)


def complete(cell, ct, M, fixed, c, big, rng, iters=3000, restarts=3, clue=CRIBS, temps=(20.0, 0.5), init=None):
    """Fill the free alphabet by simulated annealing on the big model.

    fixed: {letter: place} known on the free side (from the exact solution); c: the constant (layout C) or None
    to let it float (layout C with no solution listed). Returns (mean score, plaintext, mismatches, free alphabet, c).
    """
    lay = cell[0]
    dec = Decryptor(cell, ct, clue)
    slots = [None] * 26
    for ch, v in fixed.items():
        slots[v] = ch
    open_places = [v for v in range(26) if slots[v] is None]
    rest = [ch for ch in AZ if ch not in fixed]
    float_c = lay == "C" and c is None
    best = (-math.inf, None, None, None, None)

    def build(perm):
        a = list(slots)
        for v, ch in zip(open_places, perm):
            a[v] = ch
        return a

    def value(perm, cc):
        a = build(perm)
        mp, mc = (M, a) if lay == "P" else (a, M)
        pt, bad = dec.run(mp, mc, cc if lay == "C" else 0)
        return big.total(pt) - PENALTY * bad, pt, bad, a

    for rs in range(restarts):
        perm = rng.sample(rest, len(rest))
        if init is not None and rs == 0:
            want = [init[v] if init[v] in rest else None for v in open_places]
            left = [ch for ch in rest if ch not in want]
            rng.shuffle(left)
            perm = [ch if ch is not None else left.pop() for ch in want]
        cc = rng.randrange(26) if float_c else (c or 0)
        cur, pt, bad, a = value(perm, cc)
        if cur > best[0]:
            best = (cur, pt, bad, a, cc)
        t0, t1 = temps
        for it in range(iters):
            t = t0 * (t1 / t0) ** (it / iters)
            nperm, ncc = perm, cc
            if float_c and rng.random() < 0.1:
                ncc = rng.randrange(26)
            elif len(perm) >= 2:
                i, j = rng.sample(range(len(perm)), 2)
                nperm = list(perm)
                nperm[i], nperm[j] = nperm[j], nperm[i]
            else:
                break
            sc, npt, nbad, na = value(nperm, ncc)
            if sc >= cur or rng.random() < math.exp((sc - cur) / t):
                perm, cc, cur = nperm, ncc, sc
                if cur > best[0]:
                    best = (cur, npt, nbad, na, cc)
    sc, pt, bad, a, cc = best
    return (big.total(pt) / (len(pt) - 3), pt, bad, "".join(a), cc)


def free_side(cell, sol):
    """From one exact solution ({letter: place}, E) -> (fixed places on the free side, c or None)."""
    X, E = sol
    return dict(X), (E if cell[0] == "C" else 0)


def forced_direct(cell, M, clue=CRIBS, ct=None):
    """For layout P: the cipher places the one-step links force (used when the system is too free to list)."""
    lay, num, dr, d, s = cell
    if lay != "P":
        return {}
    im = {ch: i for i, ch in enumerate(M)}
    nf = im if num == "M" else FIXN[num]
    out = {}
    for S, ts in links(dr, d, clue):
        if len(ts) == 1:
            T = ts[0]
            v = (im[clue[T]] + s * nf[clue[S]]) % 26
            if out.get(ct[T], v) != v or v in [w for k, w in out.items() if k != ct[T]]:
                return None
            out[ct[T]] = v
    return out


def random_alphabet(rng):
    a = list(AZ)
    rng.shuffle(a)
    return "".join(a)


def plant_text(rng, clue=CRIBS):
    from .round11 import english97
    pt = list(english97(rng))
    for p, ch in clue.items():
        pt[p] = ch
    return "".join(pt)


def distinct_factor(cellobj, rng, n=200, max_points=2000):
    """Share of random consistent right-hand sides (rhs = rows * u, u uniform) whose system still has a solution
    with distinct places ('many' counts as a pass). Multiplies the consistency bound into a chance estimate."""
    rows = cellobj.rows
    if not rows:
        return 1.0
    ok = 0
    for _ in range(n):
        u = [rng.randrange(26) for _ in range(27)]
        rhs = [sum(a * b for a, b in zip(r, u)) % 26 for r in rows]
        sols, status = solve_injective(rows, rhs, max_points=max_points, max_sols=1)
        ok += status != "none"
    return ok / n


# ---------------------------------------------------------------- beam completion (replaces annealing for reading)

class Beam:
    """Reads a setting by beam search. Every key link (fed letter f, keyed letter k) is used once, in an order where
    one end is already decoded: the other end is decoded, choosing a free-side place (plain-known) or letter
    (cipher-known) whenever a new one is needed; links with both ends known are checks. Quadgrams are scored as
    they complete. Clue letters are hard constraints: a branch that misses one is dropped."""

    def __init__(self, cell, ct, M, big, clue=CRIBS):
        self.cell, self.ct, self.M, self.big, self.clue = cell, ct, M, big, clue
        lay, num, dr, d, s = cell
        n = len(ct)
        self.n = n
        self.im = [0] * 26
        for i, ch in enumerate(M):
            self.im[IZ[ch]] = i
        self.mi = [IZ[ch] for ch in M]                       # place -> letter index (known side)
        self.fixed_num = None if num == "M" else [FIXN[num][ch] for ch in AZ]
        self.fixed_inv = None if num == "M" else [IZ[ch] for ch in FIXA[num]]
        self.cx = [IZ[ch] for ch in ct]
        links = [(k - d if dr == "back" else k + d, k) for k in range(n)]
        links = [(f, k) for f, k in links if 0 <= f < n]
        lo, hi = min(clue), max(clue)
        if dr == "back":
            pref = list(range(lo, n)) + list(range(lo - 1, -1, -1))
        else:
            pref = list(range(hi, -1, -1)) + list(range(hi + 1, n))
        rank = {t: r for r, t in enumerate(pref)}
        known = set(clue)
        todo = set(range(len(links)))
        steps = []
        while todo:
            both = [e for e in todo if links[e][0] in known and links[e][1] in known]
            if both:
                e = min(both)
            else:
                avail = [e for e in todo if links[e][0] in known or links[e][1] in known]
                if not avail:
                    break
                e = min(avail, key=lambda e: rank[links[e][1] if links[e][0] in known else links[e][0]])
            todo.discard(e)
            f, k = links[e]
            steps.append((f, k, f in known))
            known.update((f, k))
        self.steps = steps

    def _quads(self, pt, t):
        tb, out = self.big.t, 0.0
        for a in range(max(0, t - 3), min(t, self.n - 4) + 1):
            w = pt[a:a + 4]
            if -1 in w:
                continue
            out += tb[((w[0] * 26 + w[1]) * 26 + w[2]) * 26 + w[3]]
        return out

    def run(self, fixed, c, width=300):
        """fixed: {letter: place} on the free side (cipher letters for plain-known, plain letters for cipher-known)."""
        lay, num, dr, d, s = self.cell
        c = c or 0
        l2p, p2l = [-1] * 26, [-1] * 26
        for ch, v in fixed.items():
            l2p[IZ[ch]], p2l[v] = v, IZ[ch]
        pt = [-1] * self.n
        for t, ch in self.clue.items():
            pt[t] = IZ[ch]
        beam = [(0.0, pt, l2p, p2l)]
        im, mi, cx, clue = self.im, self.mi, self.cx, self.clue
        fnum, finv = self.fixed_num, self.fixed_inv
        for f, k, fwd in self.steps:
            t, kind, o = (k, "f", f) if fwd else (f, "b", k)
            nb = []
            for sc, pt, l2p, p2l in beam:
                was = pt[t]
                for r in self._expand(lay, num, s, c, t, kind, o, pt, l2p, p2l):
                    val, nl2p, np2l = r[:3]
                    pen = PENALTY if len(r) > 3 else 0.0
                    if was >= 0:
                        nb.append((sc - pen, pt, nl2p, np2l))
                    else:
                        npt = pt[:]
                        npt[t] = val
                        nb.append((sc - pen + self._quads(npt, t), npt, nl2p, np2l))
            if not nb:
                return None
            if len(nb) > width:
                nb.sort(key=lambda x: -x[0])
                nb = nb[:width]
            beam = nb
        sc, pt, l2p, p2l = beam[0]
        text = "".join(AZ[x] for x in pt)
        free = "".join(AZ[x] if x >= 0 else "?" for x in p2l)
        return self.big.total(text) / (self.n - 3), text, free

    def _expand(self, lay, num, s, c, t, kind, o, pt, l2p, p2l):
        """Yield (letter index at t, l2p, p2l) for every way to decode position t."""
        im, mi, cx, clue = self.im, self.mi, self.cx, self.clue
        kt = pt[t]
        if lay == "P":
            # free side: cipher letter -> place y
            if kind == "f":                                  # t keyed by fed o (decoded)
                k = im[pt[o]] if num == "M" else self.fixed_num[pt[o]]
                y = l2p[cx[t]]
                if kt >= 0:
                    v = (im[kt] + s * k) % 26
                    if y == v:
                        yield kt, l2p, p2l
                    elif y < 0 and p2l[v] < 0:
                        a, b = l2p[:], p2l[:]
                        a[cx[t]], b[v] = v, cx[t]
                        yield kt, a, b
                    else:
                        yield kt, l2p, p2l, 1
                    return
                if y >= 0:
                    yield mi[(y - s * k) % 26], l2p, p2l
                    return
                for v in range(26):
                    if p2l[v] < 0:
                        a, b = l2p[:], p2l[:]
                        a[cx[t]], b[v] = v, cx[t]
                        yield mi[(v - s * k) % 26], a, b
            else:                                            # t is the fed letter of keyed o (decoded)
                y = l2p[cx[o]]
                base = im[pt[o]]
                def letter(v):
                    kv = (s * (v - base)) % 26
                    return mi[kv] if num == "M" else self.fixed_inv[kv]
                if y >= 0:
                    L = letter(y)
                    if kt < 0 or L == kt:
                        yield L, l2p, p2l
                    else:
                        yield kt, l2p, p2l, 1
                    return
                hit = False
                for v in range(26):
                    if p2l[v] < 0:
                        L = letter(v)
                        if kt >= 0 and L != kt:
                            continue
                        hit = True
                        a, b = l2p[:], p2l[:]
                        a[cx[o]], b[v] = v, cx[o]
                        yield L, a, b
                if kt >= 0 and not hit:
                    yield kt, l2p, p2l, 1
            return
        # lay == "C": free side: plain letter <-> place in Mp; M is the cipher alphabet
        for kval, l2p1, p2l1 in self._num_of(num, pt[o] if kind == "f" else None, l2p, p2l):
            if kind == "f":
                place = (im[cx[t]] - c - s * kval) % 26
                yield from self._letter_at(place, kt, l2p1, p2l1)
            else:
                # o is keyed, its letter pt[o] is known; need its place x in Mp
                for x, l2p2, p2l2 in self._place_of(pt[o], l2p1, p2l1):
                    kv = (s * (im[cx[o]] - c - x)) % 26
                    if num == "M":
                        yield from self._letter_at(kv, kt, l2p2, p2l2)
                    else:
                        L = self.fixed_inv[kv]
                        if kt < 0 or L == kt:
                            yield L, l2p2, p2l2
                        else:
                            yield kt, l2p2, p2l2, 1
            return

    def _num_of(self, num, letter, l2p, p2l):
        if letter is None:
            yield 0, l2p, p2l
            return
        if num != "M":
            yield self.fixed_num[letter], l2p, p2l
            return
        yield from self._place_of(letter, l2p, p2l)

    @staticmethod
    def _place_of(letter, l2p, p2l):
        x = l2p[letter]
        if x >= 0:
            yield x, l2p, p2l
            return
        for v in range(26):
            if p2l[v] < 0:
                a, b = l2p[:], p2l[:]
                a[letter], b[v] = v, letter
                yield v, a, b

    @staticmethod
    def _letter_at(place, kt, l2p, p2l):
        L = p2l[place]
        if L >= 0:
            if kt < 0 or L == kt:
                yield L, l2p, p2l
            else:
                yield kt, l2p, p2l, 1
            return
        if kt >= 0:
            if l2p[kt] < 0:
                a, b = l2p[:], p2l[:]
                a[kt], b[place] = place, kt
                yield kt, a, b
            else:
                yield kt, l2p, p2l, 1
            return
        for L in range(26):
            if l2p[L] < 0:
                a, b = l2p[:], p2l[:]
                a[L], b[place] = place, L
                yield L, a, b


def read(cell, ct, M, starts, big, rng, width=400, iters=2000, restarts=2):
    """Best reading over the exact solutions given (list of (fixed, c)): beam search, then annealing from the beam's
    free alphabet. Returns (mean score, plaintext, mismatches, free alphabet, c)."""
    best = None
    dec = Decryptor(cell, ct)
    for fixed, c in starts:
        cs = [c] if c is not None else [0, 1]
        for cc in cs:
            b = Beam(cell, ct, M, big).run(fixed, cc, width=width)
            init = None
            if b is not None:
                init = b[2]
            r = complete(cell, ct, M, fixed, cc, big, rng, iters=iters, restarts=restarts, init=init)
            if b is not None:
                free = [ch if ch != "?" else None for ch in b[2]]
                rest = [ch for ch in AZ if ch not in free]
                full = "".join(ch if ch is not None else rest.pop() for ch in free)
                mp, mc = (M, full) if cell[0] == "P" else (full, M)
                pt, bad = dec.run(mp, mc, cc if cell[0] == "C" else 0)
                cand = (big.total(pt) / (len(pt) - 3), pt, bad, full, cc)
                if cand[0] - 0.12 * cand[2] > r[0] - 0.12 * r[2]:
                    r = cand
            if best is None or r[0] - 0.12 * r[2] > best[0] - 0.12 * best[2]:
                best = r
    return best


def starts_from(cell, sols, M=None, ct=None):
    """Turn listed exact solutions into reading starts [(fixed places, c)]: per value of c, the places every
    solution agrees on (after the shift that leaves the cipher unchanged: any shift when s = -1, 13 when s = +1,
    cipher-known only). Places the clues leave open are left to the reader."""
    lay, num, dr, d, s = cell
    if not sols:
        if lay == "P":
            return [(forced_direct(cell, M, ct=ct) or {}, 0)]
        return [({}, None)]
    groups = {}
    for X, E in sols:
        groups.setdefault(E if lay == "C" else 0, []).append(dict(X))
    out = []
    for c, xs in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:2]:
        letters = sorted(xs[0])
        best = None
        for anchor in (letters if lay == "C" else [None]):
            norm = []
            for X in xs:
                t = 0 if anchor is None else (xs[0][anchor] - X[anchor]) % 26
                if anchor is not None and s == 1 and t not in (0, 13):
                    continue
                norm.append({ch: (v + t) % 26 for ch, v in X.items()})
            fixed = {ch: norm[0][ch] for ch in letters if all(Y.get(ch) == norm[0][ch] for Y in norm)}
            if best is None or len(fixed) > len(best):
                best = fixed
        out.append((best, c))
    return out
