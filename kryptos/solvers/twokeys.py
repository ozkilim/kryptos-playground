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
    def __init__(self, ct, alpha, variant, L1, L2, comps, qg=None, key_weight=0.0):
        self.ct, self.alpha, self.variant, self.L1, self.L2 = ct, alpha, variant, L1, L2
        self.idx = {c: i for i, c in enumerate(alpha)}
        self.dec = PLAIN_FROM[variant]
        self.comps = comps
        used = {n for comp in comps for n, _ in comp}
        self.freeA = [r for r in range(L1) if ("A", r) not in used]
        self.freeB = [s for s in range(L2) if ("NB", s) not in used]
        self.qg = qg or Quadgrams()
        self.key_weight = key_weight  # >0: reward keys that read as English (hand keys are words/phrases)

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

    def total(self, st, pt):
        s = self.qg.score(pt) * (N - 3)
        if self.key_weight:
            A, B = self.keys(st)
            ka = "".join(self.alpha[k] for k in A)
            kb = "".join(self.alpha[k] for k in B)
            s += self.key_weight * (self.qg.score(ka) * max(1, len(ka) - 3) + self.qg.score(kb) * max(1, len(kb) - 3))
        return s

    def anneal(self, rng, iters=30000, t0=3.0, t1=0.05, restarts=4):
        best = (-math.inf, None, None)
        nmov = len(self.comps) + len(self.freeA) + len(self.freeB)
        for _ in range(restarts):
            st = {"off": [rng.randrange(26) for _ in self.comps],
                  "A": {r: rng.randrange(26) for r in self.freeA},
                  "B": {s: rng.randrange(26) for s in self.freeB}}
            pt = self.decrypt(st)
            cur = self.total(st, pt)
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
                sc = self.total(new, npt)
                if sc >= cur or rng.random() < math.exp((sc - cur) / t):
                    st, cur, pt = new, sc, npt
                    if cur > best[0]:
                        best = (cur, pt, st)
        if best[1] is None:
            return -math.inf, None, None
        return self.qg.score(best[1]), best[1], best[2]


def plant(pt, rng, alpha, variant, L1, L2):
    """Encrypt pt with two random stacked keys (for tests and power estimates)."""
    A = [rng.randrange(26) for _ in range(L1)]
    B = [rng.randrange(26) for _ in range(L2)]
    enc = {"vigenere": lambda p, k: (p + k) % 26, "beaufort": lambda p, k: (k - p) % 26,
           "variant_beaufort": lambda p, k: (p - k) % 26}[variant]
    idx = {c: i for i, c in enumerate(alpha)}
    return "".join(alpha[enc(idx[p], (A[i % L1] + B[i % L2]) % 26)] for i, p in enumerate(pt)), (A, B)


def parallel_tempering(comp, rng, sweeps=60000, temps=(0.15, 0.3, 0.6, 1.2, 2.4, 4.8), swap_every=10):
    """Replica-exchange annealing for a KeyCompleter: several copies at fixed
    temperatures, swapping neighbours now and then, so hot copies explore and
    cold copies refine. Returns (mean quadgram score, plaintext, state)."""
    nmov = len(comp.comps) + len(comp.freeA) + len(comp.freeB)
    reps = []
    for _ in temps:
        st = {"off": [rng.randrange(26) for _ in comp.comps],
              "A": {r: rng.randrange(26) for r in comp.freeA},
              "B": {s: rng.randrange(26) for s in comp.freeB}}
        pt = comp.decrypt(st)
        reps.append([st, comp.total(st, pt), pt])
    best = max(reps, key=lambda r: r[1])[:]
    if nmov == 0:
        return comp.qg.score(best[2]), best[2], best[0]
    for it in range(sweeps):
        for k, t in enumerate(temps):
            st, cur, pt = reps[k]
            new = {"off": list(st["off"]), "A": dict(st["A"]), "B": dict(st["B"])}
            j = rng.randrange(nmov)
            if j < len(comp.comps):
                new["off"][j] = rng.randrange(26)
            elif j < len(comp.comps) + len(comp.freeA):
                new["A"][comp.freeA[j - len(comp.comps)]] = rng.randrange(26)
            else:
                new["B"][comp.freeB[j - len(comp.comps) - len(comp.freeA)]] = rng.randrange(26)
            npt = comp.decrypt(new)
            sc = comp.total(new, npt)
            if sc >= cur or rng.random() < math.exp((sc - cur) / t):
                reps[k] = [new, sc, npt]
                if sc > best[1]:
                    best = [new, sc, npt]
        if it % swap_every == 0:
            for k in range(len(temps) - 1):
                a, b = reps[k], reps[k + 1]
                d = (b[1] - a[1]) * (1 / temps[k] - 1 / temps[k + 1])
                if d >= 0 or rng.random() < math.exp(d):
                    reps[k], reps[k + 1] = b, a
    return comp.qg.score(best[2]), best[2], best[0]
