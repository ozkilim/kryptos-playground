"""Fast two-stacked-key completion: heat-bath annealing with incremental scoring.

Diagnosis (campaign 6): in the long-key region the TRUE answer scores far
above what Metropolis annealing finds, so the bottleneck is search, not
information. This solver:
  * treats each free quantity (a component's offset, a free A slot, a free B
    slot) as a variable with 26 values;
  * updates one variable at a time by trying ALL 26 values (heat-bath), scoring
    only the plaintext letters it touches (incremental quadgram deltas);
  * anneals the heat-bath temperature, with restarts;
  * optionally adds an English-key prior (hand keys are words/phrases).
"""

import math

from ..ciphers import PLAIN_FROM

N = 97


class FastTwoKey:
    def __init__(self, ct, alpha, variant, L1, L2, comps, qg, key_weight=0.0):
        self.alpha, self.L1, self.L2, self.qg = alpha, L1, L2, qg
        self.idx = {c: i for i, c in enumerate(alpha)}
        self.cv = [self.idx[c] for c in ct]
        dec = PLAIN_FROM[variant]
        self.dec_table = [[dec(c, k) for k in range(26)] for c in range(26)]
        self.kw = key_weight
        used = {n for comp in comps for n, _ in comp}
        # variables: ("comp", j, members) / ("A", r) / ("B", s)
        self.vars = [("comp", j, comp) for j, comp in enumerate(comps)]
        self.vars += [("A", r) for r in range(L1) if ("A", r) not in used]
        self.vars += [("B", s) for s in range(L2) if ("NB", s) not in used]
        self.touch = []
        for v in self.vars:
            if v[0] == "comp":
                ar = {r for (kind, r), _ in v[2] if kind == "A"}
                bs = {s for (kind, s), _ in v[2] if kind == "NB"}
            elif v[0] == "A":
                ar, bs = {v[1]}, set()
            else:
                ar, bs = set(), {v[1]}
            pos = sorted(i for i in range(N) if (i % L1 in ar) != (i % L2 in bs))  # positions whose key sum moves
            self.touch.append((ar, bs, pos))
        self.logp, self.floor = qg.logp, qg.floor

    # ---- state: value per variable -> keys A, B
    def keys(self, vals):
        A, B = [0] * self.L1, [0] * self.L2
        for v, x in zip(self.vars, vals):
            if v[0] == "comp":
                for (kind, r), rel in v[2]:
                    w = (x + rel) % 26
                    if kind == "A":
                        A[r] = w
                    else:
                        B[r] = (-w) % 26
            elif v[0] == "A":
                A[v[1]] = x
            else:
                B[v[1]] = x
        return A, B

    def plain(self, A, B):
        dt, L1, L2 = self.dec_table, self.L1, self.L2
        return [dt[c][(A[i % L1] + B[i % L2]) % 26] for i, c in enumerate(self.cv)]

    def window_sum(self, p, lo, hi):
        lp, fl, al = self.logp, self.floor, self.alpha
        s = 0.0
        for i in range(max(0, lo), min(N - 4, hi) + 1):
            s += lp.get(al[p[i]] + al[p[i + 1]] + al[p[i + 2]] + al[p[i + 3]], fl)
        return s

    def key_score(self, A, B):
        if not self.kw:
            return 0.0
        q = self.qg
        ka = "".join(self.alpha[k] for k in A)
        kb = "".join(self.alpha[k] for k in B)
        return self.kw * (q.score(ka) * max(1, len(ka) - 3) + q.score(kb) * max(1, len(kb) - 3))

    def total(self, vals):
        A, B = self.keys(vals)
        p = self.plain(A, B)
        return self.window_sum(p, 0, N - 4) + self.key_score(A, B), p

    def solve(self, rng, sweeps=400, t0=2.0, t1=0.02, restarts=6):
        best = (-math.inf, None)
        if not self.vars:
            s, p = self.total([])
            return s, "".join(self.alpha[x] for x in p)
        for _ in range(restarts):
            vals = [rng.randrange(26) for _ in self.vars]
            A, B = self.keys(vals)
            p = self.plain(A, B)
            for sw in range(sweeps):
                t = t0 * (t1 / t0) ** (sw / max(1, sweeps - 1))
                order = list(range(len(self.vars)))
                rng.shuffle(order)
                for j in order:
                    v = self.vars[j]
                    ar, bs, pos = self.touch[j]
                    if not pos and not self.kw:
                        continue
                    old = vals[j]
                    scores = []
                    for x in range(26):
                        vals[j] = x
                        A2, B2 = self.keys(vals) if v[0] == "comp" else (A, B)
                        if v[0] == "A":
                            A2 = A[:]
                            A2[v[1]] = x
                        elif v[0] == "B":
                            B2 = B[:]
                            B2[v[1]] = x
                        p2 = p[:]
                        for i in pos:
                            p2[i] = self.dec_table[self.cv[i]][(A2[i % self.L1] + B2[i % self.L2]) % 26]
                        s = 0.0
                        last = -10
                        for i in pos:  # quadgram windows touching changed letters (merged ranges)
                            lo = max(i - 3, last + 1)
                            s += self.window_sum(p2, lo, i)
                            last = i
                        s += self.key_score(A2, B2)
                        scores.append((s, A2, B2, p2))
                    m = max(sc for sc, _, _, _ in scores)
                    w = [math.exp((sc - m) / t) for sc, _, _, _ in scores]
                    r = rng.random() * sum(w)
                    for x, wx in enumerate(w):
                        r -= wx
                        if r <= 0:
                            break
                    vals[j] = x
                    _, A, B, p = scores[x]
            s, p_full = self.total(vals)
            if s > best[0]:
                best = (s, "".join(self.alpha[x] for x in p_full))
        return self.qg.score(best[1]), best[1]
