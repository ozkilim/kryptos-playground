"""Idea 19: Gromark / chain-addition keys with BOTH alphabets hidden.

Gromark: a short digit primer grows into a key stream by chain addition
(each new digit = sum of the first two digits of the window, mod base). The
plaintext letter's position in a hidden plain alphabet, plus the key digit,
gives a position in a hidden cipher alphabet. Gromark ranks among the
most K4-like families in our fingerprint ranking, and it is Gillogly's and
Bean's favourite.

Others found that ~39 five-digit primers survive the clues (Bean 2021,
Barney) but "survivors can be completed several ways, so passing the clues
means nothing". This idea does the completion: for every surviving primer,
simulated annealing fills in both alphabets to maximise English, and K4's
best is compared with the same pipeline on shuffled K4s.

Primers: base 10, lengths 2-6 (1.11M); base 26, lengths 2-4 (476k).
"""
import random
import sys
import time
from itertools import product
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.solvers import freealpha as F  # noqa: E402

PRIMER_SPACES = [(10, n) for n in range(2, 7)] + [(26, n) for n in range(2, 5)]
if SMOKE:
    PRIMER_SPACES = [(10, 2), (10, 3)]
_W = {}


def _init(ct):
    _W["ct"] = ct


def _exact(job):
    base, n, first = job  # all primers of this base/length starting with digit `first`
    ct = _W["ct"]
    out, consistent = [], 0
    for rest in product(range(base), repeat=n - 1):
        primer = (first,) + rest
        key = F.gromark_stream(primer, base)
        uf = F.UF()
        ok = all(uf.union(a, b, d) for a, b, d in F.equations("gromark", ct, CRIBS, key=key))
        if not ok:
            continue
        consistent += 1
        if F.solve_exact(F.equations("gromark", ct, CRIBS, key=key)) is not None:
            out.append((base, primer))
    return consistent, out


def _complete(job):
    ct, base, primer, seed = job
    key = F.gromark_stream(primer, base)
    comps = F.solve_exact(F.equations("gromark", ct, CRIBS, key=key))
    c = F.Completer("gromark", ct, comps, key=key)
    q, pt, _ = c.anneal(random.Random(seed), iters=8000 if SMOKE else 100000, restarts=2 if SMOKE else 6)
    return q, pt, base, primer


def _plant(seed):
    """Planted Gromark message through the identical pipeline: detection power."""
    from kryptos import load
    r = random.Random(seed)
    text = load("k3")["plaintext"] + load("k2")["plaintext_corrected"]
    s0 = r.randrange(0, len(text) - 97)
    pt = "".join(ch for ch in text[s0:s0 + 97] if ch.isalpha())[:97]
    primer = tuple(r.randrange(10) for _ in range(5))
    key = F.gromark_stream(primer)
    ct, _ = F.plant("gromark", pt, r, key=key)
    cribs = {i: pt[i] for i in CRIBS}
    comps = F.solve_exact(F.equations("gromark", ct, cribs, key=key))
    q, got, _ = F.Completer("gromark", ct, comps, key=key).anneal(
        random.Random(seed + 7), iters=8000 if SMOKE else 100000, restarts=2 if SMOKE else 6)
    return round(q, 3), sum(a == b for a, b in zip(got, pt))


def survivors(ct, pool):
    jobs = [(b, n, f) for b, n in PRIMER_SPACES for f in range(b)]
    consistent, surv = 0, []
    for c, s in pool.imap_unordered(_exact, jobs):
        consistent += c
        surv += s
    return consistent, surv


def complete(ct, surv, pool, cap):
    rng = random.Random(5)
    picked = surv if len(surv) <= cap else rng.sample(surv, cap)
    res = pool.map(_complete, [(ct, b, p, k) for k, (b, p) in enumerate(picked)])
    res.sort(key=lambda r: -r[0])
    return res


if __name__ == "__main__":
    t0 = time.time()
    cap = 20 if SMOKE else 1500
    with Experiment("gromark-free-alphabets+english-completion", puzzle="k4", cribs_forced=True,
                    notes="chain-addition keys, base 10 primers len 2-6 and base 26 len 2-4; both alphabets free; "
                          "exact clue equations (union-find + injectivity), survivors completed by annealing") as ex:
        with Pool(cpu_count(), initializer=_init, initargs=(K4,)) as pool:
            n_cons, surv = survivors(K4, pool)
            five = sum(1 for b, p in surv if b == 10 and len(p) == 5)
            res = complete(K4, surv, pool, cap)
        ex.count(sum(b ** n for b, n in PRIMER_SPACES))
        for q, pt, b, p in res[:30]:
            ex.add(pt, base=b, primer="".join(map(str, p)), completion_q=round(q, 3))
        ctrl = []
        for s in range(2):
            fake = shuffled(K4, 300 + s)
            with Pool(cpu_count(), initializer=_init, initargs=(fake,)) as pool:
                c_cons, c_surv = survivors(fake, pool)
                c_res = complete(fake, c_surv, pool, min(cap, 400))
            ctrl.append({"consistent": c_cons, "survivors": len(c_surv),
                         "best_q": round(c_res[0][0], 3) if c_res else None})
        with Pool(cpu_count()) as pool:
            planted = pool.map(_plant, range(2 if SMOKE else 10))
        best = res[0][0] if res else None
        cbest = max((c["best_q"] for c in ctrl if c["best_q"] is not None), default=None)
        if not surv:
            verdict = "dead: no primer survives the clue equations"
        elif best is not None and (cbest is None or best - cbest > 0.3):
            verdict = "WORTH A LOOK: a completion reads like English and beats the controls"
        else:
            pq = sorted(q for q, _ in planted)
            verdict = (f"dead: {len(surv)} primers survive the clues but their best English completion "
                       f"({best:.2f}) is no better than shuffled K4s ({cbest}); planted Gromark texts reach "
                       f"{pq[0]:.2f}..{pq[-1]:.2f} through the same pipeline")
        ex.notes += f"; {n_cons} clue-consistent, {len(surv)} survive injectivity ({five} five-digit base 10); {verdict}"
    report("19", name="gromark-free-alphabets", hypotheses=sum(b ** n for b, n in PRIMER_SPACES),
           crib_consistent=n_cons, survivors=len(surv), five_digit_base10_survivors=five,
           completed=len(res), best_quadgram=best, control=ctrl,
           planted_power=[{"q": q, "letters_right": a} for q, a in planted],
           top=[{"q": round(q, 3), "base": b, "primer": "".join(map(str, p)), "plaintext": pt} for q, pt, b, p in res[:5]],
           verdict=verdict, minutes=round((time.time() - t0) / 60, 1))
    print(f"[19] consistent {n_cons}, survivors {len(surv)} (5-digit base10: {five}), best {best} vs controls {ctrl} -> {verdict}")
