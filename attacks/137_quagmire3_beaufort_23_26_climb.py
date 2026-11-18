"""Idea 137: Quagmire III, Beaufort form, repeating key of length 23 or 26, ANY alphabet: judged by English.

K1 and K2 are Quagmire III: one keyed alphabet on both sides. With x[ch] the place of a letter in that
unknown alphabet, the Beaufort form is key[i mod L] = x[C_i] + x[P_i] (mod 26). Idea 130 decided this
exactly for every alphabet at every length 1-26: empty everywhere except L = 23 (7 clue equations on 17
letters, >= 100,000 solutions) and L = 26 (1 equation). There the clues do not fix the alphabet, so only
an English score can judge them. That is this script.

Search (kryptos/idea137_anneal.py): parallel tempering over full alphabets (all 26! permutations) and
the key values of the residue classes that hold no clue letter (6 at L=23, 3 at L=26). The key of every
residue that does hold a clue letter is fixed by the alphabet. The clue equations are hard: every move
(swap two letters) is followed by putting each letter an equation forces back on its forced place,
and the move is dropped if any equation still fails. So every state visited decrypts all 24 clue letters
exactly. Score: big quadgram model over the full 97 letters; each run ends with a greedy polish.

The Vigenere form (x[C] - x[P]) at 23 and 26 needs no search: the clue equations force x[P] = x[R]
(L=23) and x[F] = x[E] (L=26), so no alphabet exists (checked here with idea 130's certificate).

Controls: 10 shuffled K4s that are satisfiable at the same length (exact check), same budget.
Planted: 4 English texts per length (K4's clue words in place), random alphabet and key, Beaufort form,
same budget. Two planted tests: (1) mechanics, which must pass: started one swap away from the
truth with random free keys, the climber gets back to at least the truth's score; (2) the real one,
from a cold start: 'recovered' = the search finds a score at or above the planted truth AND reads back at
least 80 of 97 letters. The script reports the rate; it does not require it (the idea's own plan
is to log 'no signal within annealer power' with the rate if it is low).

  python attacks/137_quagmire3_beaufort_23_26_climb.py
"""
import random
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea130_exact import Budget, certificate, decide, equations  # noqa: E402
from kryptos.idea137_anneal import (AZ, Problem, encrypt, load_table, near_truth, polish, tempering,
                                    truth_score, witness_alpha)  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, english97  # noqa: E402
from kryptos.score import word_coverage  # noqa: E402

LENGTHS = (23, 26)
N_CTRL = 2 if SMOKE else 10
N_PLANT = 1 if SMOKE else 4
RUNS = 1 if SMOKE else 3          # independent tempering runs per text
SWEEPS = 60 if SMOKE else 2500    # exchange rounds per run (200 moves per replica per round, 8 replicas)
PROCS = 12
BIG = DATA_DIR / "english" / "quadgrams_big.txt"

_TABLE = None


def _init():
    global _TABLE
    _TABLE = load_table(BIG)


def _work(task):
    label, ct, L, seed = task
    prob = Problem(ct, CRIBS, L, "beau")
    rng = random.Random(seed)
    q, al, kf = tempering(prob, _TABLE, rng, SWEEPS, start=witness_alpha(prob))
    q, al, kf = polish(prob, _TABLE, al, kf)
    txt, br = prob.text(al, kf)
    assert br == 0
    return label, L, seed, q / (prob.n - 3), txt, "".join(chr(65 + a) for a in al), kf


def planted(rng, L):
    alpha = "".join(rng.sample(AZ, 26))
    key = [rng.randrange(26) for _ in range(L)]
    pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(english97(rng)))
    return pt, alpha, key, encrypt(pt, alpha, key, "beau")


def _prefilter_encrypt(pt, rng):
    return encrypt(pt, "".join(rng.sample(AZ, 26)), [rng.randrange(26) for _ in range(23)], "beau")


def main():
    t0 = time.time()
    from kryptos.clues import prefilter
    prefilter("137 Quagmire III Beaufort, repeating key 23/26", encrypt=_prefilter_encrypt,
              n=100 if SMOKE else 300)
    table = load_table(BIG)
    with Experiment("Quagmire III Beaufort L=23/26 any alphabet, English tempering", puzzle="k4",
                    notes="one unknown alphabet both sides, repeating key 23/26; clue equations hard; parallel "
                          "tempering %d runs x %d sweeps x 8 replicas x 200 moves; %d satisfiable shuffled K4s "
                          "and %d plants per length" % (RUNS, SWEEPS, N_CTRL, N_PLANT),
                    cribs_forced=True) as ex:
        print("== Vigenere form (x[C] - x[P]) at 23 and 26: exact certificate")
        for L in LENGTHS:
            rows = equations(K4, CRIBS, L, "vig")
            cert = certificate(rows)
            print("  L=%d: %d equations, forced equal places %s -> %s" % (
                L, len(rows), cert, "no alphabet" if cert else "SAT?"))
            assert cert
            ex.count()

        tasks, meta = [], {}
        rng = random.Random(137)
        for L in LENGTHS:
            assert decide(equations(K4, CRIBS, L, "beau"))[0] == "SAT"
            ctrls, s = [], 0
            while len(ctrls) < N_CTRL:
                s += 1
                ct = shuffled_control(s)
                try:
                    sat = decide(equations(ct, CRIBS, L, "beau"), 10 ** 6)[0] == "SAT"
                except Budget:
                    sat = False   # undecided within budget: skipped, not used as a control
                if sat:
                    ctrls.append((s, ct))
            print("L=%d: satisfiable shuffle seeds %s" % (L, [c[0] for c in ctrls]))
            texts = [("K4", K4)] + [("shuf%d" % s, ct) for s, ct in ctrls]
            for j in range(N_PLANT):
                pt, alpha, key, ct = planted(rng, L)
                label = "plant%d" % j
                prob = Problem(ct, CRIBS, L, "beau")
                ts, ttxt, br = truth_score(prob, table, alpha, key)
                assert br == 0 and ttxt == pt
                # mechanics check (must pass): from the truth with one swap and random free keys,
                # the climber must get back to at least the truth's score
                nq, ntxt = near_truth(prob, table, random.Random(j), alpha, key, swaps=1)
                nright = sum(a == b for a, b in zip(ntxt, pt))
                print("  L=%d %s: truth %.3f; near-truth climb %.3f, %d/97 letters" % (L, label, ts, nq, nright))
                assert nq >= ts - 0.005 and nright >= 80, "near-truth planted check failed"
                meta[(label, L)] = (pt, ts)
                texts.append((label, ct))
            for label, ct in texts:
                for r in range(RUNS):
                    tasks.append((label, ct, L, 1000 * L + 17 * r + len(tasks)))
        print("%d tempering runs on %d processes" % (len(tasks), PROCS), flush=True)

        best = {}
        with Pool(PROCS, initializer=_init) as pool:
            for label, L, seed, q, txt, al, kf in pool.imap_unordered(_work, tasks):
                ex.count(SWEEPS * 8 * 200)
                print("  L=%d %-7s seed=%-6d %.3f %s" % (L, label, seed, q, txt), flush=True)
                b = best.get((label, L))
                if b is None or q > b[0]:
                    best[(label, L)] = (q, txt, al, kf)

        summary = {}
        for L in LENGTHS:
            print("\n== L=%d" % L)
            k = best[("K4", L)]
            ctrl = sorted(((v[0], lab) for (lab, LL), v in best.items() if LL == L and lab.startswith("shuf")),
                          reverse=True)
            print("  K4 best %.3f  cover %.2f  %s  alphabet %s free keys %s" % (
                k[0], word_coverage(k[1]), k[1], k[2], k[3]))
            ex.add(k[1], L=L, alphabet=k[2], kfree=k[3], kind="K4 best")
            for q, lab in ctrl:
                print("  %-7s %.3f  cover %.2f  %s" % (lab, q, word_coverage(best[(lab, L)][1]), best[(lab, L)][1]))
            above = sum(1 for q, _ in ctrl if q >= k[0])
            print("  controls: min %.3f median %.3f max %.3f; controls at or above K4: %d/%d" % (
                ctrl[-1][0], ctrl[len(ctrl) // 2][0], ctrl[0][0], above, len(ctrl)))
            rec = 0
            for j in range(N_PLANT):
                lab = "plant%d" % j
                pt, ts = meta[(lab, L)]
                q, txt = best[(lab, L)][:2]
                right = sum(a == b for a, b in zip(txt, pt))
                ok = q >= ts - 0.005 and right >= 80
                rec += ok
                print("  %s truth %.3f found %.3f (%s) letters right %d/97 %s\n     found %s\n     truth %s" % (
                    lab, ts, q, "above truth" if q >= ts - 0.005 else "below truth", right,
                    "RECOVERED" if ok else "not recovered", txt, pt))
                ex.add(txt, L=L, kind="planted", recovered=ok)
            print("  planted recovered %d/%d" % (rec, N_PLANT))
            summary[L] = (k[0], ctrl, above, rec)
        print("\n== summary")
        for L, (kq, ctrl, above, rec) in summary.items():
            print("  L=%d: K4 %.3f; controls %.3f..%.3f, %d/%d at or above K4; planted %d/%d" % (
                L, kq, ctrl[-1][0], ctrl[0][0], above, len(ctrl), rec, N_PLANT))
        print("total %.0f s" % (time.time() - t0))


if __name__ == "__main__":
    main()
