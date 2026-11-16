"""Idea 38: the long stacked-key region again, with a stronger solver.

Campaign 3 left two stacked keys open at ~54 long length pairs (e.g. 22+26,
25+26) where annealing couldn't recover planted messages. Campaign 6 found
why: the TRUE answer scores far higher than what annealing finds, so it's a
search problem, not an information limit. This rerun uses
  * heat-bath annealing with incremental scoring (kryptos/solvers/twokeys_fast.py)
  * an English-key prior: hand-made keys are words or phrases (PALIMPSEST, ABSCISSA),
    so both keys should read as English too.
K4's best completion at each long pair vs a planted English message with
English-phrase keys (power) and a shuffled K4 (chance).
"""
import json
import random
import sys
import time
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, letters, load  # noqa: E402
from kryptos.campaign import CAMPAIGN, SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402
from kryptos.solvers import twokeys as T  # noqa: E402
from kryptos.solvers.twokeys_fast import FastTwoKey  # noqa: E402

ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
SWEEPS, RESTARTS, KW = (20, 1, 0.7) if SMOKE else (400, 8, 0.7)
_Q = {}


def _solve(job):
    tag, ct, cribs, an, v, L1, L2, seed, truth = job
    if "q" not in _Q:
        _Q["q"] = Quadgrams()
    comps = T.solve_exact(T.equations(ct, cribs, ALPHAS[an], v, L1, L2))
    if comps is None:
        return None
    q, pt = FastTwoKey(ct, ALPHAS[an], v, L1, L2, comps, _Q["q"], key_weight=KW).solve(
        random.Random(seed), sweeps=SWEEPS, restarts=RESTARTS)
    acc = sum(a == b for a, b in zip(pt, truth)) if truth else None
    return tag, an, v, L1, L2, q, pt, acc


if __name__ == "__main__":
    t0 = time.time()
    r23 = json.loads((CAMPAIGN / "results" / "23.json").read_text())
    long_pairs = sorted(tuple(map(int, k.split("x"))) for k, v in r23["planted"].items()
                        if v["letters_right"] is not None and v["letters_right"] < 80)
    if SMOKE:
        long_pairs = long_pairs[:2]
    fake = shuffled(K4, 3800)
    texts = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4, 5, 6, 8, 9))
    keysrc = letters(load("k2")["plaintext_corrected"] + load("k1")["plaintext"] + load("k3")["plaintext"])
    rng = random.Random(38)
    jobs = []
    for k, (L1, L2) in enumerate(long_pairs):
        for an in ALPHAS:
            for v in VARIANTS:
                jobs.append(("k4", K4, CRIBS, an, v, L1, L2, k, None))
                jobs.append(("control", fake, CRIBS, an, v, L1, L2, 5000 + k, None))
        s0 = rng.randrange(0, len(texts) - 100)
        pt = texts[s0:s0 + 97]
        al = ALPHAS[rng.choice(list(ALPHAS))]
        o1, o2 = rng.randrange(0, len(keysrc) - 30), rng.randrange(0, len(keysrc) - 30)
        A = [al.index(c) for c in keysrc[o1:o1 + L1]]
        B = [al.index(c) for c in keysrc[o2:o2 + L2]]
        pct = "".join(al[(al.index(p) + A[i % L1] + B[i % L2]) % 26] for i, p in enumerate(pt))
        jobs.append(("planted", pct, {i: pt[i] for i in CRIBS}, "AZ" if al == AZ else "KRYPTOS", "vigenere",
                     L1, L2, 9000 + k, pt))
    with Experiment("long-stacked-keys v2 (heat-bath + English-key prior)", puzzle="k4", cribs_forced=True,
                    notes=f"{len(long_pairs)} long length pairs left open by idea 23; heat-bath annealing, "
                          "keys rewarded for reading as English; vs planted and shuffled") as ex:
        with Pool(cpu_count()) as pool:
            res = [r for r in pool.map(_solve, jobs) if r]
        k4 = sorted([r for r in res if r[0] == "k4"], key=lambda r: -r[5])
        ctrl = [r for r in res if r[0] == "control"]
        planted = [r for r in res if r[0] == "planted"]
        for r in k4[:30]:
            ex.add(r[6], alphabet=r[1], variant=r[2], L1=r[3], L2=r[4], q=round(r[5], 3))
        ex.count(len(jobs))
        k4b = k4[0][5] if k4 else None
        cb = max((r[5] for r in ctrl), default=None)
        accs = [r[7] for r in planted]
        power = sum(a >= 80 for a in accs) / len(accs) if accs else 0
        pq = sorted(r[5] for r in planted)
        beat = sum(q > k4b for q in pq) if k4b is not None else 0
        flag = k4b is not None and cb is not None and k4b - cb > 0.3
        verdict = ("WORTH A LOOK: K4's best beats the shuffled controls by >0.3" if flag else
                   f"no signal: K4 best {k4b:.2f} vs shuffled {cb:.2f}; planted recovered >=80/97 at "
                   f"{power:.0%} of pairs (median {sorted(accs)[len(accs) // 2]} letters, was ~35); "
                   f"{beat}/{len(pq)} planted score above K4's best")
        ex.notes += f"; {verdict}"
    report("38", name="long stacked keys v2", long_pairs=[list(p) for p in long_pairs], best_quadgram=k4b,
           control_best=cb, planted_letters=accs, planted_q=pq, power_80=power, verdict=verdict,
           top=[{"alphabet": r[1], "variant": r[2], "L1": r[3], "L2": r[4], "q": round(r[5], 3), "plaintext": r[6]}
                for r in k4[:5]], minutes=round((time.time() - t0) / 60, 1))
    print("[38]", verdict)
