"""Two stacked repeating keys ("LAYER TWO"): K = A[i mod L1] + B[i mod L2].

Encrypting twice with the same tableau (K1/K2 style, plain or KRYPTOS
alphabet) adds the two keys, so the effective key repeats only every
lcm(L1, L2) letters, often longer than K4 itself. That would explain why
every single-repeating-key test fails. Paradigm built PK3 and PK8 exactly
this way.

Each clue letter fixes the sum A[r] + B[s] at one (r, s), an equation between
two unknowns, so the same weighted union-find as freealpha decides it
exactly: write it as A[r] - NB[s] = k with NB = -B. Pairs the clues can't
decide are completed by simulated annealing on English. Note the gauge
freedom: inside one component, adding c to every A and subtracting c from
every B changes nothing, so only offsets *between* components matter.
"""

import math
import random

from ..ciphers import KEY_FROM, PLAIN_FROM
from ..score import Quadgrams
from .freealpha import UF

N = 97


def equations(ct, cribs, alpha, variant, L1, L2):
    idx = {c: i for i, c in enumerate(alpha)}
    f = KEY_FROM[variant]
    return [(("A", i % L1), ("NB", i % L2), f(idx[ct[i]], idx[p])) for i, p in cribs.items()]


def solve_exact(eqs):
    uf = UF()
    for a, b, d in eqs:
        if not uf.union(a, b, d):
            return None
    return uf.components()


class KeyCompleter:
    def __init__(self, ct, alpha, variant, L1, L2, comps, qg=None):
        self.ct, self.alpha, self.variant, self.L1, self.L2 = ct, alpha, variant, L1, L2
        self.idx = {c: i for i, c in enumerate(alpha)}
        self.dec = PLAIN_FROM[variant]
        self.comps = comps
        used = {n for comp in comps for n, _ in comp}
        self.freeA = [r for r in range(L1) if ("A", r) not in used]
        self.freeB = [s for s in range(L2) if ("NB", s) not in used]
        self.qg = qg or Quadgrams()

    def keys(self, st):
        A, B = [0] * self.L1, [0] * self.L2
        for comp, o in zip(self.comps, st["off"]):
            for (kind, r), rel in comp:
                v = (o + rel) % 26
                if kind == "A":
                    A[r] = v
                else:
                    B[r] = (-v) % 26
        for r, v in st["A"].items():
            A[r] = v
        for s, v in st["B"].items():
            B[s] = v
        return A, B

    def decrypt(self, st):
        A, B = self.keys(st)
        return "".join(self.alpha[self.dec(self.idx[c], (A[i % self.L1] + B[i % self.L2]) % 26)]
                       for i, c in enumerate(self.ct))

    def anneal(self, rng, iters=30000, t0=3.0, t1=0.05, restarts=4):
        best = (-math.inf, None, None)
        nmov = len(self.comps) + len(self.freeA) + len(self.freeB)
        for _ in range(restarts):
            st = {"off": [rng.randrange(26) for _ in self.comps],
                  "A": {r: rng.randrange(26) for r in self.freeA},
                  "B": {s: rng.randrange(26) for s in self.freeB}}
            pt = self.decrypt(st)
            cur = self.qg.score(pt) * (N - 3)
            if nmov == 0:
                return cur / (N - 3), pt, st
            for it in range(iters):
                t = t0 * (t1 / t0) ** (it / iters)
                new = {"off": list(st["off"]), "A": dict(st["A"]), "B": dict(st["B"])}
                j = rng.randrange(nmov)
                if j < len(self.comps):
                    new["off"][j] = rng.randrange(26)
                elif j < len(self.comps) + len(self.freeA):
                    new["A"][self.freeA[j - len(self.comps)]] = rng.randrange(26)
                else:
                    new["B"][self.freeB[j - len(self.comps) - len(self.freeA)]] = rng.randrange(26)
                npt = self.decrypt(new)
                sc = self.qg.score(npt) * (N - 3)
                if sc >= cur or rng.random() < math.exp((sc - cur) / t):
                    st, cur, pt = new, sc, npt
                    if cur > best[0]:
                        best = (cur, pt, st)
        return best[0] / (N - 3), best[1], best[2]


def plant(pt, rng, alpha, variant, L1, L2):
    """Encrypt pt with two random stacked keys (for tests and power estimates)."""
    A = [rng.randrange(26) for _ in range(L1)]
    B = [rng.randrange(26) for _ in range(L2)]
    enc = {"vigenere": lambda p, k: (p + k) % 26, "beaufort": lambda p, k: (k - p) % 26,
           "variant_beaufort": lambda p, k: (p - k) % 26}[variant]
    idx = {c: i for i, c in enumerate(alpha)}
    return "".join(alpha[enc(idx[p], (A[i % L1] + B[i % L2]) % 26)] for i, p in enumerate(pt)), (A, B)
