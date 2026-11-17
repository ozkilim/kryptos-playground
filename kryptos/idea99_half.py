"""Idea 99 helpers: Quagmire IV with one known (dictionary) alphabet and one freely written alphabet.

One equation per clue letter, all of the same shape:

    X[h_i] - S[i mod L] = g_i + (i div L) * W        (mod 26)

  case 1 (cipher alphabet hidden): h = cipher letter, g = place of the plain letter in the known alphabet A
  case 2 (plain alphabet hidden):  h = plain letter,  g = place of the cipher letter in the known alphabet B
  X = places of letters in the hidden alphabet, S = one unknown number per key slot,
  W = 0 for a repeating key; W = the sum of the key word for a sliding key (key = running sum of the word).

The hidden letters and the key slots are the nodes of a graph, every clue letter is an edge. The graph depends
only on the text and L, not on the known alphabet, so it is built once (class Plan): a spanning forest, and for
every other edge a closed loop = one exact check, a fixed +-1 sum of the g's. An alphabet passes when every loop
closes AND the hidden letters can sit on different places.

Vigenere and Beaufort form are the same test here: turning the hidden alphabet back to front and negating the
key maps one onto the other. So each setting is tested once.
"""
import math
from collections import deque

from .ciphers import AZ
from .data import CRIBS

POS = sorted(CRIBS)
N = 97
LMAX = 12         # repeating key lengths 1..LMAX (1-9 is the idea's scope; 10-12 are judged by reading only)
SLIDE_MAX = 9     # sliding key word lengths 1..SLIDE_MAX (1-6 is the idea's scope)
IZ = {c: i for i, c in enumerate(AZ)}

# SOL[q][b] = the W in 1..25 with b + q * W = 0 mod 26
SOL = [[[w for w in range(1, 26) if (b + q * w) % 26 == 0] for b in range(26)] for q in range(26)]


class Plan:
    """The loop structure of the clue equations for one text, one side hidden, one key length."""

    def __init__(self, hidden, L, pos=POS, known=None):
        self.L, self.hidden = L, list(hidden)
        self.res = [i % L for i in pos]
        self.q = [i // L for i in pos]
        adj = {}
        for e, (h, r) in enumerate(zip(self.hidden, self.res)):
            adj.setdefault(("h", h), []).append((e, ("k", r)))
            adj.setdefault(("k", r), []).append((e, ("h", h)))
        self.pot, self.comp, tree = {}, {}, set()
        ncomp = 0
        for start in sorted(adj):
            if start in self.pot:
                continue
            self.pot[start], self.comp[start] = {}, ncomp
            todo = deque([start])
            while todo:
                u = todo.popleft()
                for e, v in adj[u]:
                    if v in self.pot:
                        continue
                    expr = dict(self.pot[u])
                    # edge e says value(h) - value(k) = w_e
                    expr[e] = expr.get(e, 0) + (1 if v[0] == "h" else -1)
                    self.pot[v], self.comp[v] = expr, ncomp
                    tree.add(e)
                    todo.append(v)
            ncomp += 1
        self.ncomp = ncomp
        self.checks = []
        for e, (h, r) in enumerate(zip(self.hidden, self.res)):
            if e in tree:
                continue
            expr = {e: 1}
            for f, c in self.pot[("h", h)].items():
                expr[f] = expr.get(f, 0) - c
            for f, c in self.pot[("k", r)].items():
                expr[f] = expr.get(f, 0) + c
            expr = {f: c for f, c in expr.items() if c}
            assert all(c in (1, -1) for c in expr.values())
            plus = tuple(f for f, c in expr.items() if c == 1)
            minus = tuple(f for f, c in expr.items() if c == -1)
            self.checks.append((plus, minus, sum(c * self.q[f] for f, c in expr.items()) % 26))
        self.nchecks = len(self.checks)
        # What each loop asks of the known alphabet once repeated letters cancel:
        # "same" = nothing (0 = 0), "diff" = two different letters on one place (never true), "open" = a real test.
        self.kinds = []
        for plus, minus, _ in self.checks:
            if known is None:
                self.kinds.append("open")
                continue
            net = {}
            for i in plus:
                net[known[i]] = net.get(known[i], 0) + 1
            for i in minus:
                net[known[i]] = net.get(known[i], 0) - 1
            net = sorted(c for c in net.values() if c)
            self.kinds.append("same" if not net else "diff" if net == [-1, 1] else "open")
        self.sizes = [len({n for n, c in self.comp.items() if c == j and n[0] == "h"}) for j in range(ncomp)]
        self.p_distinct = 1.0
        for s in self.sizes:
            for i in range(s):
                self.p_distinct *= (26 - i) / 26.0

    def _chance(self, w):
        p = self.p_distinct
        for (_, _, qc), kind in zip(self.checks, self.kinds):
            zero = (qc * w) % 26 == 0
            p *= (1.0 if zero else 0.0) if kind == "same" else (0.0 if zero else 1 / 25.0) if kind == "diff" else 1 / 26.0
        return p

    def expected(self, n_alphabets, sliding=False):
        """Rough number of chance survivors over n_alphabets if the known alphabet were random."""
        return n_alphabets * sum(self._chance(w) for w in (range(1, 26) if sliding else (0,)))

    def impossible(self, sliding=False):
        """True if no alphabet at all on the known side can close the loops (a fact about the text alone)."""
        return self.expected(1, sliding) == 0

    def passing(self, g):
        """The W values (0 = repeating key) for which every loop closes."""
        if not self.checks:
            return [0] + (list(range(1, 26)) if self.L <= SLIDE_MAX else [])
        plus, minus, qc = self.checks[0]
        b = 0
        for i in plus:
            b += g[i]
        for i in minus:
            b -= g[i]
        b %= 26
        cand = ([0] if b == 0 else []) + (SOL[qc][b] if self.L <= SLIDE_MAX else [])
        if not cand:
            return cand
        out = []
        for w in cand:
            for plus, minus, qc in self.checks[1:]:
                b = qc * w
                for i in plus:
                    b += g[i]
                for i in minus:
                    b -= g[i]
                if b % 26:
                    break
            else:
                out.append(w)
        return out

    def components(self, g, w):
        """[({hidden letter: place}, {key slot: value})] per connected piece, each relative to its own root."""
        wt = [(x + q * w) % 26 for x, q in zip(g, self.q)]
        comps = [({}, {}) for _ in range(self.ncomp)]
        for node, expr in self.pot.items():
            v = sum(c * wt[e] for e, c in expr.items()) % 26
            comps[self.comp[node]][0 if node[0] == "h" else 1][node[1]] = v
        return comps

    def solve(self, g, w):
        """Components if the hidden letters can sit on different places, else None."""
        comps = self.components(g, w)
        for letters, _ in comps:
            if len(set(letters.values())) != len(letters):
                return None
        return comps if place(comps) is not None else None


def place(comps):
    """Offsets per component that put all hidden letters on different places (first found), or None."""
    order = sorted(range(len(comps)), key=lambda j: -len(comps[j][0]))
    offs, used = [None] * len(comps), set()

    def rec(n):
        if n == len(order):
            return True
        j = order[n]
        vals = list(comps[j][0].values())
        for o in (range(1) if n == 0 else range(26)):
            cells = {(o + v) % 26 for v in vals}
            if cells & used:
                continue
            used.update(cells)
            offs[j] = o
            if rec(n + 1):
                return True
            used.difference_update(cells)
        return False

    return offs if rec(0) else None


def clue_letters(ct, cribs=CRIBS):
    pos = sorted(cribs)
    return [cribs[i] for i in pos], [ct[i] for i in pos]


def plans(ct, cribs=CRIBS, lmax=LMAX):
    """{case: [Plan for L = 1..lmax]}; case 1 hides the cipher alphabet, case 2 the plain alphabet."""
    pl, cl = clue_letters(ct, cribs)
    pos = sorted(cribs)
    return {1: [Plan(cl, L, pos, pl) for L in range(1, lmax + 1)], 2: [Plan(pl, L, pos, cl) for L in range(1, lmax + 1)]}


def scan(pls, pl, cl, alphabets):
    """Test every (name, alphabet). Returns [(case, L, W, checks, pieces, name, alphabet)] and
    {(case, L, sliding): settings whose loops close but whose letters collide}."""
    hits, collide = [], {}
    for name, alpha in alphabets:
        idx = {c: i for i, c in enumerate(alpha)}
        for case, known in ((1, pl), (2, cl)):
            g = [idx[c] for c in known]
            for p in pls[case]:
                for w in p.passing(g):
                    if p.solve(g, w) is None:
                        k = (case, p.L, w != 0)
                        collide[k] = collide.get(k, 0) + 1
                    else:
                        hits.append((case, p.L, w, p.nchecks, p.ncomp, name, alpha))
    return hits, collide


def settings_per_alphabet(lmax=LMAX):
    return 2 * (lmax + 25 * min(lmax, SLIDE_MAX))


# ---------------------------------------------------------------- reading a survivor

class Reader:
    """Fills in what the clues leave free (places of the other hidden letters, how the pieces sit against
    each other) by simulated annealing on the big English model. Clue letters stay right throughout."""

    def __init__(self, hit, ct, cribs, big):
        self.case, self.L, self.W, _, _, self.name, self.alpha = hit
        self.ct, self.big = ct, big
        pl, cl = clue_letters(ct, cribs)
        plan = Plan(cl if self.case == 1 else pl, self.L, sorted(cribs))
        idx = {c: i for i, c in enumerate(self.alpha)}
        self.comps = plan.solve([idx[c] for c in (pl if self.case == 1 else cl)], self.W)
        self.free = sorted(set(AZ) - {c for letters, _ in self.comps for c in letters})
        self.kq = [(i // self.L) * self.W % 26 for i in range(len(ct))]
        self.slot = [i % self.L for i in range(len(ct))]
        self.cidx = [idx[c] for c in ct]

    def build(self, offs, perm):
        at, X, key = [None] * 26, {}, {}
        for (letters, slots), o in zip(self.comps, offs):
            for c, v in letters.items():
                v = (v + o) % 26
                if at[v] is not None:
                    return None
                at[v], X[c] = c, v
            for r, v in slots.items():
                key[r] = (v + o) % 26
        it = iter(perm)
        for v in range(26):
            if at[v] is None:
                c = next(it)
                at[v], X[c] = c, v
        return at, X, key

    def decrypt(self, built):
        at, X, key = built
        if self.case == 1:
            a = self.alpha
            return "".join(a[(X[c] - key.get(r, 0) - k) % 26] for c, r, k in zip(self.ct, self.slot, self.kq))
        return "".join(at[(b + k + key.get(r, 0)) % 26] for b, r, k in zip(self.cidx, self.slot, self.kq))

    def forced(self, offs):
        """The reading with only the clue-forced letters filled in ('?' elsewhere), for these offsets."""
        b = self.build(offs, self.free)
        if b is None:
            return None
        at, X, key = b
        fixed = {c for letters, _ in self.comps for c in letters}
        pt = self.decrypt(b)
        if self.case == 1:
            return "".join(p if c in fixed and r in key else "?" for p, c, r in zip(pt, self.ct, self.slot))
        return "".join(p if p in fixed and r in key else "?" for p, r in zip(pt, self.slot))

    def _valid(self, offs, j):
        used = set()
        for n, ((letters, _), o) in enumerate(zip(self.comps, offs)):
            if n != j:
                used.update((v + o) % 26 for v in letters.values())
        return [o for o in range(26) if all((v + o) % 26 not in used for v in self.comps[j][0].values())]

    def _score(self, pt):
        get, fl = self.big.logp.get, self.big.floor
        return sum(get(pt[i:i + 4], fl) for i in range(len(pt) - 3))

    def anneal(self, rng, iters=6000, restarts=3, t0=3.0, t1=0.05):
        """Returns (score per quadgram, reading, offsets, forced reading)."""
        best = (-math.inf, None, None)
        nq = len(self.ct) - 3
        for _ in range(restarts):
            offs = place(self.comps)
            for j in range(1, len(offs)):
                good = self._valid(offs, j)
                offs[j] = rng.choice(good)
            perm = rng.sample(self.free, len(self.free))
            cur = self._score(self.decrypt(self.build(offs, perm)))
            if cur > best[0]:
                best = (cur, list(offs), list(perm))
            for it in range(iters):
                t = t0 * (t1 / t0) ** (it / iters)
                noffs, nperm = offs, perm
                if len(offs) > 1 and rng.random() < 0.2:
                    j = rng.randrange(len(offs))
                    good = [o for o in self._valid(offs, j) if o != offs[j]]
                    if not good:
                        continue
                    noffs = list(offs)
                    noffs[j] = rng.choice(good)
                elif len(perm) >= 2:
                    a, b = rng.sample(range(len(perm)), 2)
                    nperm = list(perm)
                    nperm[a], nperm[b] = nperm[b], nperm[a]
                else:
                    continue
                built = self.build(noffs, nperm)
                if built is None:
                    continue
                sc = self._score(self.decrypt(built))
                if sc >= cur or rng.random() < math.exp((sc - cur) / t):
                    offs, perm, cur = noffs, nperm, sc
                    if cur > best[0]:
                        best = (cur, list(offs), list(perm))
        sc, offs, perm = best
        return sc / nq, self.decrypt(self.build(offs, perm)), offs, self.forced(offs)


# ---------------------------------------------------------------- a plain textbook encryptor (for planting)

def key_stream(word, sliding=False, n=N):
    """Repeating: the word's letters as numbers (A=0). Sliding: the running sum of those numbers."""
    out, t = [], 0
    for i in range(n):
        v = IZ[word[i % len(word)]]
        t = (t + v) % 26
        out.append(t if sliding else v)
    return out


def quagmire4(pt, plain_alpha, cipher_alpha, key, beaufort=False):
    """C = cipher_alpha[place of P in plain_alpha + key] (or key - place, Beaufort form)."""
    out = []
    for p, k in zip(pt, key):
        a = plain_alpha.index(p)
        out.append(cipher_alpha[(k - a) % 26 if beaufort else (a + k) % 26])
    return "".join(out)
