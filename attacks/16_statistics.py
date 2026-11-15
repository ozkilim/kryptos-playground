"""Idea 16: are the two famous K4 oddities real? (analysis, not an attack)

  * Stehle (2000): in DIAWINFBN, each letter minus the letter 4 to its right
    is the same (5) five times running. How often does a run that long (any
    lag 1-20, any constant) appear in a shuffled K4?
  * Doublets: 5 of K4's 6 doubled letters share a position mod 7. How often
    does a shuffled K4 put that many doublets on one residue for SOME modulus
    2-12?
Both p-values correct for having looked at every lag / modulus.
"""
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4  # noqa: E402
from kryptos.campaign import report, shuffled, SMOKE  # noqa: E402

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def longest_constant_diff_run(t, max_lag=20):
    v = [AZ.index(c) for c in t]
    best = (0, None, None)
    for lag in range(1, max_lag + 1):
        d = [(v[i] - v[i + lag]) % 26 for i in range(len(v) - lag)]
        run = 1
        for i in range(1, len(d)):
            run = run + 1 if d[i] == d[i - 1] else 1
            if run > best[0]:
                best = (run, lag, i - run + 1)
    return best


def doublet_concentration(t):
    dbl = [i + 1 for i in range(len(t) - 1) if t[i] == t[i + 1]]
    if len(dbl) < 2:
        return 0, len(dbl), None
    best = (0, None)
    for m in range(2, 13):
        counts = {}
        for d in dbl:
            counts[d % m] = counts.get(d % m, 0) + 1
        c = max(counts.values())
        # how unusual is c of len(dbl) landing on one residue mod m (chance ~ 1/m each)
        score = c - len(dbl) / m
        if score > best[0]:
            best = (score, m)
    return best[0], len(dbl), best[1]


if __name__ == "__main__":
    t0 = time.time()
    N_SIM = 300 if SMOKE else 200_000
    k_run = longest_constant_diff_run(K4)
    k_dbl = doublet_concentration(K4)
    ge_run = ge_dbl = ge_dbl_given6 = n6 = 0
    for s in range(N_SIM):
        f = shuffled(K4, 10_000 + s)
        if longest_constant_diff_run(f)[0] >= k_run[0]:
            ge_run += 1
        sc, nd, _ = doublet_concentration(f)
        if sc >= k_dbl[0]:
            ge_dbl += 1
        if nd >= k_dbl[1]:
            n6 += 1
            if sc >= k_dbl[0]:
                ge_dbl_given6 += 1
    p_run = (ge_run + 1) / (N_SIM + 1)
    p_dbl = (ge_dbl + 1) / (N_SIM + 1)
    verdict = (f"Stehle run (length {k_run[0]} at lag {k_run[1]}): p={p_run:.4f} vs shuffles; "
               f"doublet mod-{k_dbl[2]} clustering: p={p_dbl:.4f} "
               f"({ge_dbl_given6}/{n6} shuffles with >=6 doublets match it)")
    report("16", name="statistics: Stehle run and doublet clustering", stehle=k_run, doublets=k_dbl,
           p_stehle=p_run, p_doublets=p_dbl, simulations=N_SIM, verdict=verdict,
           minutes=round((time.time() - t0) / 60, 1))
    print("[16]", verdict)
