"""Idea 39: Scheidt's "matrix codes" / "shifting matrices" / changing the number base.

Sanborn: "I did use some matrix codes Ed gave me". Scheidt: "I could have moved
to a different math base". Put the letters in a grid (3x3x3, 5x6, 6x5, 6x6,
4x7, 7x4; letters in A-Z or KRYPTOS order, forward or reversed; spare cells
empty), turn each plaintext letter into coordinates, shift EACH coordinate on
its own repeating schedule ("wheel", period 1-30), and read the letter at the
new cell. Ciphertext letters must land on letter cells, which is itself a
constraint. Others tried the base-3 cube with simple keys; independent
per-coordinate wheels and the other grid shapes are new.

Exact per coordinate: a wheel length survives if all clue letters agree on
each wheel slot (at least 5 checks). Combinations where every coordinate's
wheel is pinned are decrypted and scored against shuffled K4s.
"""
import sys
import time
from itertools import product
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import quadgram_score  # noqa: E402

SHAPES = [(3, 3, 3), (5, 6), (6, 5), (6, 6), (4, 7), (7, 4)]
ORDERS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET, "AZ reversed": AZ[::-1], "KRYPTOS reversed": KRYPTOS_ALPHABET[::-1]}
MAXP = 15 if SMOKE else 30


def grid(shape, order):
    coords = list(product(*[range(d) for d in shape]))
    to_c = {ch: coords[k] for k, ch in enumerate(order)}
    to_l = {coords[k]: ch for k, ch in enumerate(order)}
    return to_c, to_l


def wheels(ct, shape, to_c, min_tests=5):
    req = {i: tuple((to_c[ct[i]][j] - to_c[p][j]) % shape[j] for j in range(len(shape))) for i, p in CRIBS.items()}
    allowed = []
    for j, dim in enumerate(shape):
        ok_p = {}
        for q in range(1, MAXP + 1):
            seen, tests, ok = {}, 0, True
            for i, d in req.items():
                r = i % q
                if r in seen:
                    tests += 1
                    if seen[r] != d[j]:
                        ok = False
                        break
                else:
                    seen[r] = d[j]
            if ok and tests >= min_tests:
                ok_p[q] = seen
        allowed.append(ok_p)
    return allowed


def run(ct):
    out, tested, survivors = [], 0, []
    for shape in SHAPES:
        for oname, order in ORDERS.items():
            to_c, to_l = grid(shape, order)
            allowed = wheels(ct, shape, to_c)
            tested += len(shape) * MAXP
            if not all(allowed):
                continue
            survivors.append((shape, oname, [sorted(a) for a in allowed]))
            for combo in product(*[list(a.items()) for a in allowed]):
                pt, ok = [], True
                for i, c in enumerate(ct):
                    shift = []
                    for (q, seen) in combo:
                        if i % q not in seen:
                            ok = False
                            break
                        shift.append(seen[i % q])
                    if not ok:
                        break
                    cell = tuple((to_c[c][j] - shift[j]) % shape[j] for j in range(len(shape)))
                    if cell not in to_l:
                        ok = False
                        break
                    pt.append(to_l[cell])
                if ok:
                    s = "".join(pt)
                    out.append((quadgram_score(s), s, shape, oname, [q for q, _ in combo]))
    out.sort(key=lambda x: -x[0])
    return tested, survivors, out


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("shifting matrices (grid coordinates, per-coordinate wheels)", puzzle="k4", cribs_forced=True,
                    notes=f"grids {SHAPES} x letter orders {list(ORDERS)}; each coordinate shifted by its own wheel "
                          f"(period 1-{MAXP}); pinned combinations decrypted") as ex:
        tested, surv, dec = run(K4)
        ex.count(tested)
        for q, pt, shape, o, ps in dec[:20]:
            ex.add(pt, shape=str(shape), order=o, wheels=ps)
        ctrl = []
        for s in range(3):
            t, sv, d = run(shuffled(K4, 3900 + s))
            ctrl.append({"grid_survivors": len(sv), "decrypts": len(d), "best_q": round(d[0][0], 3) if d else None})
        best = dec[0][0] if dec else None
        cb = max((c["best_q"] for c in ctrl if c["best_q"] is not None), default=None)
        if not surv:
            verdict = "dead: in every grid at least one coordinate has no wheel the clue letters allow"
        elif not dec:
            verdict = f"dead: {len(surv)} grid/order settings allow wheels on every coordinate, but no pinned combination decrypts to letters"
        elif cb is not None and best - cb > 0.3:
            verdict = "WORTH A LOOK: a pinned matrix decrypt beats the shuffled controls"
        else:
            verdict = f"dead: {len(dec)} pinned decrypts, best {best:.2f} vs shuffled {cb}"
        ex.notes += f"; {verdict}"
    report("39", name="shifting matrices", grid_survivors=[[str(s[0]), s[1], s[2]] for s in surv], decrypts=len(dec),
           best_quadgram=best, control=ctrl, verdict=verdict, hypotheses=tested,
           top=[{"q": round(q, 3), "shape": str(sh), "order": o, "wheels": ps, "plaintext": pt} for q, pt, sh, o, ps in dec[:5]],
           minutes=round((time.time() - t0) / 60, 1))
    print("[39]", verdict)
