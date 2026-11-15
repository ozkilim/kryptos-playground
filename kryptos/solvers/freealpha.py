"""Free-alphabet engine: hidden scrambled alphabets, decided exactly by the clues,
then completed by simulated annealing on English.

Many hand ciphers reduce to equations of the form
    value(a) - value(b) = const   (mod 26)
between "nodes": the position of a letter in a hidden plaintext alphabet (P),
the position of a letter in a hidden ciphertext alphabet (C), or a key slot
(K). Each of the 24 clue letters gives one such equation:

  model "gromark"  (key stream known, e.g. from a Gromark primer; both alphabets free)
        C[c] - P[p] = k_i
  model "quag1"    (plaintext alphabet free, ciphertext alphabet fixed, periodic key)
        P[p] + K[r] = fixed_index(c)      -> written as P[p] - N[r] = c,  N = -K
  model "quag2"    (ciphertext alphabet free, plaintext alphabet fixed, periodic key)
        C[c] - K[r] = fixed_index(p)

A weighted union-find solves these exactly: either a contradiction (dead), or
groups ("components") of nodes whose relative values are fixed. Two letters on
the same alphabet side may never share a position (injectivity).

What the clues can't fix (where each component sits, the unconstrained letters,
free key slots) is filled in by simulated annealing that maximises the English
quadgram score of the whole decrypt. The clue letters stay correct by
construction throughout.
"""

import math
import random

from ..ciphers import AZ
from ..score import Quadgrams

N = 97


# --------------------------------------------------------------- exact part

class UF:
    def __init__(self):
        self.parent, self.off = {}, {}

    def find(self, a):
        if a not in self.parent:
            self.parent[a], self.off[a] = a, 0
            return a, 0
        path, o = [], 0
        while self.parent[a] != a:
            path.append(a)
            o += self.off[a]
            a = self.parent[a]
        root, acc = a, o
        for n in path:  # path compression
            nxt = (acc - self.off[n]) % 26
            self.parent[n], self.off[n] = root, acc % 26
            acc = nxt
        return root, o % 26

    def union(self, a, b, d):
        """Impose value(a) - value(b) = d. Returns False on contradiction."""
        ra, oa = self.find(a)
        rb, ob = self.find(b)
        if ra == rb:
            return (oa - ob) % 26 == d % 26
        self.parent[rb] = ra
        self.off[rb] = (oa - d - ob) % 26
        return True

    def components(self):
        comps = {}
        for n in list(self.parent):
            r, o = self.find(n)
            comps.setdefault(r, []).append((n, o))
        return list(comps.values())


def equations(model, ct, cribs, key=None, period=None, fixed=AZ):
    """List of (node_a, node_b, const) meaning value(a) - value(b) = const."""
    fidx = {c: i for i, c in enumerate(fixed)}
    eq = []
    for i, p in cribs.items():
        c = ct[i]
        if model == "gromark":
            eq.append((("C", c), ("P", p), key[i] % 26))
        elif model == "quag1":
            eq.append((("P", p), ("N", i % period), fidx[c]))
        elif model == "quag2":
            eq.append((("C", c), ("K", i % period), fidx[p]))
    return eq


def solve_exact(eqs):
    """Union-find + injectivity. Returns components (list of [(node, rel)]) or None."""
    uf = UF()
    for a, b, d in eqs:
        if not uf.union(a, b, d):
            return None
    comps = uf.components()
    for comp in comps:
        for side in ("P", "C"):
            rels = [o for (s, _), o in comp if s == side]
            if len(rels) != len(set(rels)):
                return None
    return comps


# --------------------------------------------------------------- completion

class Completer:
    """Simulated annealing over everything the clues leave free."""

    def __init__(self, model, ct, comps, key=None, period=None, fixed=AZ, qg=None):
        self.model, self.ct, self.key, self.period = model, ct, key, period
        self.fixed, self.fidx = fixed, {c: i for i, c in enumerate(fixed)}
        self.qg = qg or Quadgrams()
        self.comps = comps
        self.sides = {"gromark": ("P", "C"), "quag1": ("P",), "quag2": ("C",)}[model]
        self.free_letters = {s: sorted(set(AZ) - {n[1] for comp in comps for n, _ in comp if n[0] == s})
                             for s in self.sides}
        self.keyside = {"quag1": "N", "quag2": "K"}.get(model)
        self.free_slots = []
        if self.keyside:
            used = {n[1] for comp in comps for n, _ in comp if n[0] == self.keyside}
            self.free_slots = [r for r in range(period) if r not in used]

    def _occupied(self, offs, skip=None):
        occ = {s: set() for s in self.sides}
        for j, (comp, o) in enumerate(zip(self.comps, offs)):
            if j == skip or o is None:
                continue
            for (side, _), rel in comp:
                if side in occ:
                    occ[side].add((o + rel) % 26)
        return occ

    def valid_offsets(self, offs, j):
        occ = self._occupied(offs, skip=j)
        good = []
        for o in range(26):
            if all((o + rel) % 26 not in occ[side] for (side, _), rel in self.comps[j] if side in occ):
                good.append(o)
        return good

    def random_state(self, rng):
        for _ in range(200):
            offs = [None] * len(self.comps)
            order = list(range(len(self.comps)))
            rng.shuffle(order)
            ok = True
            for j in order:
                good = self.valid_offsets(offs, j)
                if not good:
                    ok = False
                    break
                offs[j] = rng.choice(good)
            if not ok:
                continue
            st = {"off": offs,
                  "free": {s: rng.sample(self.free_letters[s], len(self.free_letters[s])) for s in self.sides},
                  "keys": {r: rng.randrange(26) for r in self.free_slots}}
            if self.build(st) is not None:
                return st
        return None

    def build(self, st):
        """State -> (pos_of per side, letter_at per side, key values) or None if components collide."""
        pos_of, at = {}, {}
        for s in self.sides:
            pos_of[s], at[s] = {}, [None] * 26
        keyvals = dict(st["keys"])
        for comp, o in zip(self.comps, st["off"]):
            for (side, name), rel in comp:
                v = (o + rel) % 26
                if side in at:
                    if at[side][v] is not None:
                        return None
                    at[side][v], pos_of[side][name] = name, v
                elif side == "N":
                    keyvals[name] = (-v) % 26
                elif side == "K":
                    keyvals[name] = v
        for s in self.sides:
            free_pos = [k for k in range(26) if at[s][k] is None]
            for k, letter in zip(free_pos, st["free"][s]):
                at[s][k], pos_of[s][letter] = letter, k
        return pos_of, at, keyvals

    def decrypt(self, built):
        pos_of, at, keyvals = built
        out = []
        for i, c in enumerate(self.ct):
            if self.model == "gromark":
                out.append(at["P"][(pos_of["C"][c] - self.key[i]) % 26])
            elif self.model == "quag1":
                out.append(at["P"][(self.fidx[c] - keyvals[i % self.period]) % 26])
            else:
                out.append(self.fixed[(pos_of["C"][c] - keyvals[i % self.period]) % 26])
        return "".join(out)

    def score(self, st):
        b = self.build(st)
        if b is None:
            return None, None
        pt = self.decrypt(b)
        return self.qg.score(pt) * (N - 3), pt

    def anneal(self, rng, iters=20000, t0=3.0, t1=0.05, restarts=4):
        best = (-math.inf, None, None)
        for _ in range(restarts):
            st = self.random_state(rng)
            if st is None:
                return best
            cur, pt = self.score(st)
            for it in range(iters):
                t = t0 * (t1 / t0) ** (it / iters)
                new = {"off": list(st["off"]), "free": {s: list(v) for s, v in st["free"].items()},
                       "keys": dict(st["keys"])}
                mv = rng.random()
                if mv < 0.25 and self.comps:
                    j = rng.randrange(len(self.comps))
                    good = [o for o in self.valid_offsets(new["off"], j) if o != new["off"][j]]
                    if not good:
                        continue
                    new["off"][j] = rng.choice(good)
                elif mv < 0.85 or not self.free_slots:
                    s = rng.choice(self.sides)
                    f = new["free"][s]
                    if len(f) >= 2:
                        a, b_ = rng.sample(range(len(f)), 2)
                        f[a], f[b_] = f[b_], f[a]
                else:
                    r = rng.choice(self.free_slots)
                    new["keys"][r] = rng.randrange(26)
                sc, npt = self.score(new)
                if sc is None:
                    continue
                if sc >= cur or rng.random() < math.exp((sc - cur) / t):
                    st, cur, pt = new, sc, npt
                    if cur > best[0]:
                        best = (cur, pt, st)
        return (best[0] / (N - 3) if best[1] else -math.inf), best[1], best[2]


# --------------------------------------------------------------- key streams

def gromark_stream(primer, base=10, n=N):
    """Chain addition: each new digit = sum of the first two digits of the window."""
    k = list(primer)
    m = len(primer)
    while len(k) < n:
        k.append((k[-m] + k[-m + 1]) % base)
    return k


# --------------------------------------------------------------- planting (tests)

def plant(model, pt, rng, key=None, period=None, fixed=AZ):
    """Encrypt pt under random hidden alphabets. Returns (ct, secrets)."""
    PA = "".join(rng.sample(AZ, 26)) if model in ("gromark", "quag1") else fixed
    CA = "".join(rng.sample(AZ, 26)) if model in ("gromark", "quag2") else fixed
    if model != "gromark":
        key = [rng.randrange(26) for _ in range(period)]
    out = []
    for i, p in enumerate(pt):
        k = key[i] if model == "gromark" else key[i % period]
        out.append(CA[(PA.index(p) + k) % 26])
    return "".join(out), {"PA": PA, "CA": CA, "key": key}
