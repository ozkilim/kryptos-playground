"""Idea 23: "LAYER TWO" = two stacked repeating keys.

K2 ends "X LAYER TWO"; Sanborn said the lower half uses two separate systems;
Paradigm built PK3 and PK8 by stacking keys. Encrypting twice on the same
tableau adds the keys: K[i] = A[i mod L1] + B[i mod L2], which repeats only
every lcm(L1, L2) letters. That is often longer than K4, which explains why
single repeating keys all fail, while keeping the plain or near-plain
alphabet the fingerprint favours.

Others ruled out the pairs the clues can decide; the rest ("472 pairs
undecidable", keithadler/Barney) were never completed. Here: exact clue
equations for every pair 2 <= L1 < L2 <= 26 (L2 not a multiple of L1), x
Vigenere/Beaufort/variant x A-Z/KRYPTOS. Every consistent configuration is
completed by annealing for maximum English (fully determined ones are just
decrypted), against planted two-key messages (power) and shuffled K4s
(chance). Top candidates also get a dictionary word-coverage check.
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
from kryptos.score import word_coverage  # noqa: E402
from kryptos.solvers import twokeys as T  # noqa: E402

ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
PAIRS = [(a, b) for a in range(2, 27) for b in range(a + 1, 27) if b % a != 0]
ITERS, RESTARTS = (4000, 1) if SMOKE else (60000, 4)


def consistent(ct, cribs):
    out = []
    for an, al in ALPHAS.items():
        for v in VARIANTS:
            for L1, L2 in PAIRS:
                comps = T.solve_exact(T.equations(ct, cribs, al, v, L1, L2))
                if comps is not None:
                    out.append((an, v, L1, L2))
    return out


def _complete(job):
    tag, ct, cribs, an, v, L1, L2, seed, truth = job
    comps = T.solve_exact(T.equations(ct, cribs, ALPHAS[an], v, L1, L2))
    c = T.KeyCompleter(ct, ALPHAS[an], v, L1, L2, comps)
    q, pt, _ = c.anneal(random.Random(seed), iters=ITERS, restarts=RESTARTS)
    acc = sum(a == b for a, b in zip(pt, truth)) if truth else None
    free = len(c.freeA) + len(c.freeB) + max(0, len(comps) - 1)
    return tag, an, v, L1, L2, q, pt, acc, free


if __name__ == "__main__":
    t0 = time.time()
    cfg = consistent(K4, CRIBS)
    ctrl_cts = [shuffled(K4, 700 + s) for s in range(2)]
    ctrl_cfg = [consistent(c, CRIBS) for c in ctrl_cts]
    if SMOKE:
        cfg, ctrl_cfg = cfg[:3], [c[:2] for c in ctrl_cfg]
    plant_text = load("k3")["plaintext"] + load("k2")["plaintext_corrected"]
    jobs = [("k4", K4, CRIBS, an, v, L1, L2, k, None) for k, (an, v, L1, L2) in enumerate(cfg)]
    for s, (cct, cc) in enumerate(zip(ctrl_cts, ctrl_cfg)):
        jobs += [(f"ctrl{s}", cct, CRIBS, an, v, L1, L2, 10_000 * (s + 1) + k, None) for k, (an, v, L1, L2) in enumerate(cc)]
    rng = random.Random(23)
    plant_pairs = sorted({(L1, L2) for _, _, L1, L2 in cfg})
    for k, (L1, L2) in enumerate(plant_pairs[: (3 if SMOKE else len(plant_pairs))]):
        s0 = rng.randrange(0, len(plant_text) - 120)
        pt = "".join(ch for ch in plant_text[s0:] if ch.isalpha())[:97]
        an = rng.choice(list(ALPHAS))
        v = rng.choice(VARIANTS)
        pct, _ = T.plant(pt, rng, ALPHAS[an], v, L1, L2)
        jobs.append(("plant", pct, {i: pt[i] for i in CRIBS}, an, v, L1, L2, 50_000 + k, pt))
    with Experiment("two-stacked-keys+english-completion", puzzle="k4", cribs_forced=True,
                    notes=f"K = A[i mod L1] + B[i mod L2], {len(PAIRS)} length pairs <=26, vig/beau/varbeau, "
                          "A-Z/KRYPTOS; exact clue equations, consistent configs completed by annealing") as ex:
        with Pool(cpu_count()) as pool:
            res = pool.map(_complete, jobs)
        k4 = sorted([r for r in res if r[0] == "k4"], key=lambda r: -r[5])
        ctrl = [r for r in res if r[0].startswith("ctrl")]
        plants = [r for r in res if r[0] == "plant"]
        for r in k4[:40]:
            ex.add(r[6], alphabet=r[1], variant=r[2], L1=r[3], L2=r[4], q=round(r[5], 3))
        ex.count(len(PAIRS) * len(ALPHAS) * len(VARIANTS) * 3)
        detect = {(r[3], r[4]): (r[5], r[7]) for r in plants}
        ctrl_best = max((r[5] for r in ctrl), default=None)
        k4_best = k4[0][5] if k4 else None
        top = []
        for r in k4[:10]:
            top.append({"alphabet": r[1], "variant": r[2], "L1": r[3], "L2": r[4], "q": round(r[5], 3),
                        "free": r[8], "words": round(word_coverage(r[6]), 2), "plaintext": r[6],
                        "planted_at_this_pair": detect.get((r[3], r[4]))})
        good_pairs = sorted(p for p, (q, acc) in detect.items() if acc is not None and acc >= 80)
        flag = k4_best is not None and ctrl_best is not None and k4_best - ctrl_best > 0.3
        verdict = ("WORTH A LOOK: K4's best completion beats every shuffled control by >0.3" if flag else
                   f"dead where we have power: K4's best completion {k4_best:.2f} vs shuffled {ctrl_best:.2f}; "
                   f"planted messages recovered (>=80/97 letters) at {len(good_pairs)}/{len(detect)} pairs")
        ex.notes += f"; {len(cfg)} consistent configs (controls {[len(c) for c in ctrl_cfg]}); {verdict}"
    report("23", name="two stacked keys (LAYER TWO)", pairs=len(PAIRS), consistent_configs=len(cfg),
           control_consistent=[len(c) for c in ctrl_cfg], best_quadgram=k4_best, control_best=ctrl_best,
           planted={f"{a}x{b}": {"q": round(q, 3), "letters_right": acc} for (a, b), (q, acc) in detect.items()},
           pairs_with_power=[list(p) for p in good_pairs], top=top, verdict=verdict,
           control_words=round(word_coverage(max(ctrl, key=lambda r: r[5])[6]), 2) if ctrl else None,
           minutes=round((time.time() - t0) / 60, 1))
    print("[23]", verdict)
    for t in top[:5]:
        print("  ", {k: t[k] for k in ("alphabet", "variant", "L1", "L2", "q", "free", "words", "planted_at_this_pair")})
        print("    ", t["plaintext"])
