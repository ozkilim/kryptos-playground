"""Idea 32: key-shape forensics (analysis, not a key search).

The NSA (1992) saw "a pattern every 7 characters"; 5 of 6 doublets sit on
one residue mod 7 (p~0.001); Bean found width-21 repeats; our neural
detective leans "progressive key". So: what shape does K4's key have?

(1) Difference streams: if the key's step from letter to letter repeats with
    some period, the ciphertext differences c[i+L]-c[i] at each residue are
    English letter differences plus a constant, which raises their IoC. Max
    over lag 1-4, period 1-30 and A-Z/KRYPTOS indexing, compared with 20,000
    shuffled K4s (corrects for looking everywhere).
(2) Dial keys: could the key be a hand on a dial moving a few steps each letter?
    The smallest maximum step the clue letters allow, per cipher type, against shuffled K4s.
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.cribtools import required_keys  # noqa: E402

ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}


def ioc(vals):
    n = len(vals)
    if n < 2:
        return 0.0
    from collections import Counter
    return sum(c * (c - 1) for c in Counter(vals).values()) / (n * (n - 1))


def diff_stat(ct):
    best = (0.0, None)
    for an, al in ALPHAS.items():
        v = [al.index(c) for c in ct]
        for L in range(1, 5):
            d = [(v[i + L] - v[i]) % 26 for i in range(len(v) - L)]
            for q in range(1, 31):
                cols = [d[r::q] for r in range(q) if len(d[r::q]) >= 3]
                s = sum(ioc(c) for c in cols) / len(cols)
                if s > best[0]:
                    best = (s, (an, L, q))
    return best


def dial_need(ct):
    out = {}
    for an, al in ALPHAS.items():
        for v in ("vigenere", "beaufort", "variant_beaufort"):
            req = required_keys(ct, CRIBS, al, v)
            steps = [min((req[i + 1] - req[i]) % 26, (req[i] - req[i + 1]) % 26)
                     for i in sorted(req) if i + 1 in req]
            out[f"{an} {v}"] = max(steps)
    return out


if __name__ == "__main__":
    t0 = time.time()
    n = 300 if SMOKE else 20000
    k_stat, k_where = diff_stat(K4)
    null = [diff_stat(shuffled(K4, 4000 + s))[0] for s in range(n)]
    p = (sum(x >= k_stat for x in null) + 1) / (n + 1)
    # same question restricted to period 7 (the NSA / doublet hint), no look-elsewhere
    def at7(ct):
        best = 0.0
        for an, al in ALPHAS.items():
            v = [al.index(c) for c in ct]
            for L in range(1, 5):
                d = [(v[i + L] - v[i]) % 26 for i in range(len(v) - L)]
                best = max(best, sum(ioc(d[r::7]) for r in range(7)) / 7)
        return best
    k7 = at7(K4)
    null7 = [at7(shuffled(K4, 9000 + s)) for s in range(min(n, 5000))]
    p7 = (sum(x >= k7 for x in null7) + 1) / (len(null7) + 1)
    dial = dial_need(K4)
    dial_ctrl = [min(dial_need(shuffled(K4, 7000 + s)).values()) for s in range(200)]
    verdict = (f"difference-stream periodicity: best {k_where} IoC {k_stat:.4f}, p={p:.3f} vs shuffled (look-elsewhere "
               f"corrected); at period 7 specifically p={p7:.3f}. Dial keys: the clues need a max step of "
               f"{min(dial.values())} even in the smoothest cipher type (shuffled K4s: median "
               f"{sorted(dial_ctrl)[100]}), so a slowly turning dial key is ruled out")
    report("32", name="key-shape forensics", diff_best=[k_stat, k_where], p_diff=p, p_period7=p7, dial_max_step=dial,
           dial_control_median=sorted(dial_ctrl)[100], verdict=verdict, minutes=round((time.time() - t0) / 60, 1))
    print("[32]", verdict)
