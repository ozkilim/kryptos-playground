"""Idea 20: Quagmire I and II (one hidden scrambled alphabet + a repeating
key) at every key length 1-26.

Step 1, exact: the clue letters become equations (union-find); at most key
lengths they contradict outright. This should reproduce keithadler's result
(dead at 1-12, 14, 15, 17, 18, 21, 22, 25), which validates the engine.
Step 2, the lengths the clues can't decide (13, 16, 19, 20, 23, 24, 26):
simulated annealing completes alphabet + key for maximum English, on K4, on
a planted English control (detection power), and on 3 shuffled K4s
(chance level). The fixed alphabet is plain A-Z or KRYPTOS.
"""
import random
import sys
import time
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, load  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.solvers import freealpha as F  # noqa: E402

FIXED = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
ITERS, RESTARTS = (6000, 2) if SMOKE else (80000, 8)


def _sa(job):
    tag, ct, cribs, model, fixed, L, seed, truth = job
    comps = F.solve_exact(F.equations(model, ct, cribs, period=L, fixed=FIXED[fixed]))
    if comps is None:
        return tag, model, fixed, L, None, None, None
    c = F.Completer(model, ct, comps, period=L, fixed=FIXED[fixed])
    q, pt, _ = c.anneal(random.Random(seed), iters=ITERS, restarts=RESTARTS)
    acc = sum(a == b for a, b in zip(pt, truth)) if truth and pt else None
    return tag, model, fixed, L, q, pt, acc


if __name__ == "__main__":
    t0 = time.time()
    exact = {}
    for model in ("quag1", "quag2"):
        for fixed, alpha in FIXED.items():
            for L in range(1, 27):
                exact[(model, fixed, L)] = F.solve_exact(F.equations(model, K4, CRIBS, period=L, fixed=alpha)) is not None
    open_cfg = [k for k, v in exact.items() if v]
    if SMOKE:
        open_cfg = open_cfg[:2]
    plant_pt = load("k3")["plaintext"][40:137]
    plant_cribs = {i: plant_pt[i] for i in CRIBS}
    jobs = []
    for k, (model, fixed, L) in enumerate(open_cfg):
        jobs.append(("k4", K4, CRIBS, model, fixed, L, k, None))
        pct, _ = F.plant(model, plant_pt, random.Random(k), period=L, fixed=FIXED[fixed])
        jobs.append(("plant", pct, plant_cribs, model, fixed, L, k, plant_pt))
        for s in range(1 if SMOKE else 3):
            jobs.append((f"ctrl{s}", shuffled(K4, 500 + s), CRIBS, model, fixed, L, k * 10 + s, None))
    with Experiment("quagmire-I-II-free-alphabet+english", puzzle="k4", cribs_forced=True,
                    notes="Quagmire I/II, one free alphabet (other A-Z or KRYPTOS), key length 1-26; exact clue "
                          "equations, undecidable lengths completed by annealing vs planted and shuffled controls") as ex:
        with Pool(cpu_count()) as pool:
            res = pool.map(_sa, jobs)
        rows = {}
        for tag, model, fixed, L, q, pt, acc in res:
            r = rows.setdefault((model, fixed, L), {})
            r[tag] = (q, pt, acc)
            if tag == "k4" and pt:
                ex.add(pt, model=model, fixed=fixed, period=L, q=round(q, 3))
        ex.count(len(exact) + len(jobs))
        table, flagged = [], []
        for (model, fixed, L), r in sorted(rows.items()):
            k4q = r.get("k4", (None,))[0]
            ctrl = [v[0] for t, v in r.items() if t.startswith("ctrl") and v[0] is not None]
            plant = r.get("plant", (None, None, None))
            detect = plant[0] is not None and plant[0] > -5.0 and (not ctrl or plant[0] - max(ctrl) > 0.3)
            beat = k4q is not None and ctrl and k4q - max(ctrl) > 0.3
            if beat:
                flagged.append((model, fixed, L, k4q, r["k4"][1]))
            table.append({"model": model, "fixed": fixed, "L": L, "k4_q": k4q and round(k4q, 3),
                          "ctrl_best": ctrl and round(max(ctrl), 3), "plant_q": plant[0] and round(plant[0], 3),
                          "plant_acc": plant[2], "engine_can_detect": detect, "k4_beats_controls": bool(beat)})
        dead_exact = sorted({L for (m, f, L), ok in exact.items() if not ok and f == "AZ" and m == "quag1"})
        verdict = ("WORTH A LOOK: K4 beats controls at " + str([(m, f, L) for m, f, L, _, _ in flagged])) if flagged \
            else "dead: at every undecidable length K4's best completion scores like shuffled K4s"
        ex.notes += f"; clues kill lengths {dead_exact} (Quag I, A-Z); {verdict}"
    report("20", name="quagmire-I-II-free-alphabet", exact_open=[list(k) for k in open_cfg],
           exact_dead_quag1_AZ=dead_exact, table=table, verdict=verdict,
           top=[{"model": m, "fixed": f, "L": L, "q": round(q, 3), "plaintext": pt} for m, f, L, q, pt in flagged[:5]],
           minutes=round((time.time() - t0) / 60, 1))
    print("[20]", verdict)
    for t in table:
        print("  ", t)
