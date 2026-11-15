"""Idea 30: Sanborn's "visual systems": shape-based letter transforms.

Letters as flag-semaphore arm positions (two hands on a dial, very Berlin
Clock), rotated or mirrored; or as Morse code, reversed or with dots and
dashes swapped. These give letter permutations nobody has tried on K4.

(a) Visual transform alone with a schedule: one fixed transform, a repeating
    schedule (period <=26), or a ticking clock (rotation advances s steps per
    letter). Exact test: each clue letter allows only the transforms that map
    its plaintext to its ciphertext.
(b) Visual transform + a K1/K2-style key layer, in either order: repeating,
    progressive, autokey and small-shift keys (stack engine), A-Z and KRYPTOS.
"""
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.solvers import stack as S  # noqa: E402
from kryptos.visual import transforms  # noqa: E402


def schedules_alone(ct, T):
    """Return the number of (schedule) hypotheses and any that fit every clue letter."""
    names = list(T)
    allowed = {i: {n for n in names if T[n].get(p) == ct[i]} for i, p in CRIBS.items()}
    empty = [i + 1 for i, a in allowed.items() if not a]
    hits, tested = [], 0
    for n in names:  # one fixed transform
        tested += 1
        if all(n in a for a in allowed.values()):
            hits.append(("fixed", n))
    for q in range(2, 27):  # repeating schedule of transforms
        tested += 1
        slots = {}
        for i, a in allowed.items():
            slots[i % q] = slots.get(i % q, set(names)) & a
        if all(slots.values()) and len(CRIBS) - len(slots) >= 6:
            hits.append(("periodic", q))
    for mirror in (False, True):  # clock-like ticking rotation
        for r0 in range(8):
            for s in range(1, 8):
                tested += 1
                pre = "semaphore mirror" if mirror else "semaphore"
                if all(f"{pre} rot{(r0 + s * i) % 8}" in a for i, a in allowed.items()):
                    hits.append(("ticking", mirror, r0, s))
    return tested, hits, empty


def stacked(ct, T, kinds):
    """Transform + key layer via the stack engine, in both orders."""
    tested, hits = 0, []
    ident = [("maps", [(("identity",), list(range(97)))])]
    for name, g in T.items():
        if len(g) < 26:
            inv = None
        else:
            inv = {v: k for k, v in g.items()}
        # order 1: C = key(g(P))  -> transformed clue letters, same ciphertext
        if all(p in g for p in CRIBS.values()):
            cr = {i: g[p] for i, p in CRIBS.items()}
            t, h = S.scan(ct, cr, ident, kinds, places=("after",), procs=1)
            tested += t
            hits += [(name, "transform-then-key") + x[1:] for x in h]
        # order 2: C = g(key(P)) -> undo g on the ciphertext (needs g to be a full permutation)
        if inv is not None:
            ct2 = "".join(inv[c] for c in ct)
            t, h = S.scan(ct2, CRIBS, ident, kinds, places=("after",), procs=1)
            tested += t
            hits += [(name, "key-then-transform") + x[1:] for x in h]
    return tested, hits


if __name__ == "__main__":
    t0 = time.time()
    T = transforms()
    kinds = {"periodic", "progressive", "ctauto", "ptauto", "shift"}
    if SMOKE:
        T = dict(list(T.items())[:3])
    with Experiment("visual-transforms (semaphore/morse) x schedules and key layers", puzzle="k4",
                    notes=f"{len(T)} visual transforms (semaphore rotations/mirrors, Morse reverse/invert); alone with "
                          "fixed/periodic/ticking schedules, and stacked with periodic/progressive/autokey/shift keys "
                          "in both orders, A-Z/KRYPTOS") as ex:
        ta, ha, empty = schedules_alone(K4, T)
        tb, hb = stacked(K4, T, kinds)
        ex.count(ta + tb)
        ctrl = []
        for s in range(2):
            fake = shuffled(K4, 1500 + s)
            ctrl.append({"alone": len(schedules_alone(fake, T)[1]), "stacked": len(stacked(fake, T, kinds)[1])})
        verdict = ("dead: no visual-transform schedule or stack fits all clue letters" if not ha and not hb else
                   f"{len(ha)} schedule fits + {len(hb)} stacked fits (shuffled controls {ctrl}): check")
        ex.notes += f"; clue positions no transform can explain alone: {len(empty)}/24; {verdict}"
    report("30", name="visual transforms", transforms=list(T), hypotheses=ta + tb, alone_fits=[str(h) for h in ha],
           stacked_fits=[str(h) for h in hb[:20]], survivors=len(ha) + len(hb), control=ctrl,
           clue_positions_unexplainable_alone=empty, verdict=verdict, minutes=round((time.time() - t0) / 60, 1))
    print("[30]", verdict, "| unexplainable alone:", len(empty))
