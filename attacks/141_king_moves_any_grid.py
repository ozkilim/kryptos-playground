"""Idea 141: king moves on ANY hidden letter grid.

The sculpture has a compass rose and the plaintext names compass directions. Idea 123 wrote listed
alphabets (keyword, theme, old scripts) into grids and asked whether every one of the 24 clue pairs
(plain letter, cipher letter) is one compass step apart, or a stay. No listed grid did it (best: 2
pairs broken). A hand-made grid is not on any list, so here the grid is free.

With a free grid only the clue graph matters: the clue letters are points, every clue pair with two
different letters is a line between them, and the letters must go on different cells so that every
line joins two cells a king move apart. The other letters fill the cells left over. So the question
"is there ANY arrangement of the 26 letters" is decided exactly by backtracking over the clue letters
(kryptos/idea141_anygrid.py), for every grid of width 3-13 with 26 or 27 cells (rows filled left to
right, last row short; with 27 cells any one cell may be empty) and three wrap conventions (flat,
columns wrap, both wrap): 66 grids.

Per grid and text: feasible / impossible / undecided (node limit), and the smallest number D of
different moves any grid needs (stay counts as a move, as in idea 123), searched upward from an exact
lower bound (moves out of one plain letter to different cipher letters must differ, likewise moves
into one cipher letter). Every placement found is re-checked by a separate function.

Run on K4 and 200 shuffled K4s. Measures: number of feasible grids, smallest D on any grid, and the
number of grids reaching each D. Planted: English texts moved by random king moves on random hidden
grids must come out feasible, the true grid must pass the check, D must not exceed the true grid's,
and with most letters pinned to their true cells the full list of solutions must contain the truth.

Feasible is not a decryption: where a grid exists the clues leave thousands of them and the key is
free, so nothing can be read. Scope: one grid for plain and cipher letters, moves of one cell.

  python attacks/141_king_moves_any_grid.py
"""
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea141_anygrid as A  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, english97, pmap  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA141_PROCS", "4" if SMOKE else "8"))
NCTRL = int(os.environ.get("IDEA141_CONTROLS", "6" if SMOKE else "200"))
LIMIT_F = int(os.environ.get("IDEA141_LIMIT_F", "300000" if SMOKE else "3000000"))
LIMIT_D = int(os.environ.get("IDEA141_LIMIT_D", "100000" if SMOKE else "400000"))
COUNT_CAP = 2000 if SMOKE else 20000


def gname(g):
    return "%d cells w%-2d %s" % g


def judge(pairs, g):
    """(verdict, lo, hi, nodes, bad): feasibility and the range of the smallest D on one grid."""
    bad = 0
    v, sols, nodes = A.solve(pairs, *g, limit=LIMIT_F)
    if v == "UNSAT":
        return "no", None, None, nodes, 0
    if v == "SAT" and A.check(sols[0], pairs, *g) is None:
        bad += 1
    lo, hi, place = A.min_dirs(pairs, *g, limit=LIMIT_D)
    if hi is not None:
        if A.check(place, pairs, *g) != hi:
            bad += 1
        return "yes", lo, hi, nodes, bad
    if v == "SAT":
        hi = A.check(sols[0], pairs, *g)
        return "yes", lo, hi, nodes, bad
    return "undecided", lo, None, nodes, bad


def init():
    pass


def work(chunk):
    out = []
    for label, pairs in chunk:
        out.append((label, {g: judge(pairs, g) for g in A.GRIDS}))
    return out


def summary(res):
    """feasible grids, undecided grids, smallest D (upper end), grids at that D, D per grid."""
    feas = [g for g in A.GRIDS if res[g][0] == "yes"]
    und = [g for g in A.GRIDS if res[g][0] == "undecided"]
    ds = [res[g][2] for g in feas]
    best = min(ds) if ds else 99
    return len(feas), len(und), best, sum(d == best for d in ds), ds


def planted(ex):
    """Random hidden grids, random king-move keys. Returns (ok, total)."""
    rng = random.Random(14100)
    plants = [(26, 5, "flat", None), (26, 7, "flat", None), (27, 9, "flat", None), (26, 6, "cwrap", None),
              (27, 7, "twrap", None), (26, 4, "flat", None), (27, 3, "flat", None), (26, 13, "flat", None),
              (26, 7, "flat", [(0, 1), (1, 0), (-1, 1)]), (27, 9, "twrap", [(0, 0), (0, 1), (1, 1), (-1, 0)]),
              (26, 5, "cwrap", [(0, 0), (1, 0), (0, -1), (1, 1)])]
    if SMOKE:
        plants = plants[:3] + plants[-2:]
    ok = 0
    for n, w, conv, steps in plants:
        g = (n, w, conv)
        grid = A.random_grid(n, rng)
        text = english97(rng)
        ct = A.encrypt(text, grid, w, conv, rng, steps)
        pairs = [(text[i], ct[i]) for i in POS]
        truth = A.grid_place(grid, pairs)
        td = A.check(truth, pairs, *g)
        v, lo, hi, nodes, bad = judge(pairs, g)
        # the truth must be in the complete list of solutions once most letters are pinned to it
        letters = A.graph(pairs)[0]
        free = set(rng.sample(letters, min(7, len(letters))))
        pinned = {ch: truth[ch] for ch in letters if ch not in free}
        vv, sols, _ = solve_pinned(pairs, g, pinned)
        listed = truth in sols
        good = (v == "yes" and td is not None and hi is not None and hi <= td and bad == 0
                and vv != "LIMIT" and listed)
        ok += good
        print("planted %-22s %-28s feasible=%s  true grid D=%s  smallest D found %s (exact: %s)  truth in the"
              " list of %d solutions with %d letters free: %s -> %s"
              % (gname(g), "moves " + ("any" if steps is None else str(len(steps)) + " fixed"), v, td, hi,
                 lo == hi, len(sols), len(free), listed, "ok" if good else "FAIL"))
        ex.add(text, plant=gname(g), grid=grid)
    return ok, len(plants)


def solve_pinned(pairs, g, pinned):
    """All solutions that agree with the pinned letters: clue pairs between pinned letters are kept as
    they are, so this is the same search started from a known partial grid."""
    n, w, conv = g
    v, sols, nodes = A.solve(pairs, n, w, conv, limit=5000000, want=10 ** 9, pinned=pinned)
    return v, sols, nodes


def dist(vals):
    c = Counter(vals)
    return " ".join("%s:%d" % (k, c[k]) for k in sorted(c))


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("king moves on any hidden grid: exact feasibility of the 24 clue pairs and fewest directions",
                    puzzle="k4",
                    notes="free arrangement of 26 letters; widths 3-13; 26 or 27 cells (any cell empty); flat/cwrap/"
                          "twrap; backtracking over the clue letters; %d shuffled K4s; planted random grids" % NCTRL,
                    cribs_forced=True) as ex:
        ok, total = planted(ex)
        print("planted recovered: %d/%d\n" % (ok, total))
        if ok < total:
            raise SystemExit("planted test failed")

        k4pairs = A.clue_pairs(K4, CRIBS)
        letters, edges, loop = A.graph(k4pairs)
        print("K4 clue graph: %d letters, %d different pairs (R->P twice), stays: S->S, K->K; lower bound on D: %d"
              % (len(letters), len(edges), A.lower_bound(k4pairs)))
        items = [("K4", k4pairs)] + [("s%d" % s, A.clue_pairs(shuffled_control(s), CRIBS))
                                     for s in range(1, NCTRL + 1)]
        res = {}
        for part in pmap(work, items, init, (), chunk=1, procs=PROCS):
            for label, r in part:
                res[label] = r
        tested = len(items) * len(A.GRIDS)
        ex.count(tested)
        bad = sum(r[g][4] for r in res.values() for g in A.GRIDS)
        print("grid x text cases decided: %d; placements that failed the separate check: %d  (%.0f s)"
              % (tested, bad, time.time() - t0))
        if bad:
            raise SystemExit("a placement failed the independent check")

        ctrl = [res["s%d" % s] for s in range(1, NCTRL + 1)]
        k4 = res["K4"]
        print("\nPER GRID: K4 verdict and smallest D; shuffled K4s feasible / impossible / undecided and their D")
        for g in A.GRIDS:
            v, lo, hi, nodes, _ = k4[g]
            cv = Counter(c[g][0] for c in ctrl)
            cd = [c[g][2] for c in ctrl if c[g][0] == "yes"]
            inexact = sum(1 for c in ctrl if c[g][0] == "yes" and c[g][1] != c[g][2])
            dtxt = "-" if hi is None else ("%d" % hi if lo == hi else "%d..%d" % (lo, hi))
            le = sum(d <= hi for d in cd) if hi is not None else 0
            print("  %-22s K4 %-9s D %-5s | shuffles yes %3d no %3d undecided %2d | D {%s}%s | shuffles with D <= K4:"
                  " %d" % (gname(g), v, dtxt, cv["yes"], cv["no"], cv["undecided"], dist(cd),
                           " (%d not exact)" % inexact if inexact else "", le))

        kf, ku, kb, knb, kds = summary(k4)
        cs = [summary(c) for c in ctrl]
        n = float(len(cs))
        print("\nSUMMARY (66 grids per text)")
        print("  feasible grids: K4 %d (undecided %d); shuffles min %d median %d max %d; share with >= K4: %.3f"
              % (kf, ku, min(c[0] for c in cs), sorted(c[0] for c in cs)[len(cs) // 2], max(c[0] for c in cs),
                 sum(c[0] >= kf for c in cs) / n))
        print("  undecided grids per shuffle: {%s}" % dist([c[1] for c in cs]))
        print("  smallest D on any grid: K4 %d (on %d grids); shuffles {%s}; share with <= K4: %.3f"
              % (kb, knb, dist([c[2] for c in cs]), sum(c[2] <= kb for c in cs) / n))
        for d in (4, 5, 6):
            kk = sum(x <= d for x in kds)
            cc = [sum(x <= d for x in c[4]) for c in cs]
            print("  grids with D <= %d: K4 %d; shuffles mean %.1f max %d; share with >= K4: %.3f"
                  % (d, kk, sum(cc) / n, max(cc), sum(x >= kk for x in cc) / n))
        klb = A.lower_bound(k4pairs)
        clb = [A.lower_bound(p) for lab, p in items[1:]]
        print("  lower bound on D from the pairs alone: K4 %d; shuffles {%s}" % (klb, dist(clb)))
        gap = [c[2] - b for c, b in zip(cs, clb) if c[2] < 99]
        print("  smallest D minus lower bound: K4 %d; shuffles {%s}; share with <= K4: %.3f"
              % (kb - klb, dist(gap), sum(x <= kb - klb for x in gap) / float(len(gap) or 1)))
        ne = [len(A.graph(p)[1]) for lab, p in items[1:]]
        print("  different clue pairs (lines of the graph): K4 %d; shuffles {%s}" % (len(edges), dist(ne)))
        kr = A.rings(k4pairs)
        cr = [A.rings(p) for lab, p in items[1:]]
        print("  closed rings in the clue graph: K4 %d; shuffles {%s}" % (kr, dist(cr)))
        for r in sorted(set(cr)):
            sub = [c for c, x in zip(cs, cr) if x == r]
            print("    shuffles with %d rings (%d): smallest D {%s}; D minus lower bound {%s}; feasible grids"
                  " median %d; grids at the lower bound: mean %.1f"
                  % (r, len(sub), dist([c[2] for c in sub]),
                     dist([c[2] - b for c, b, x in zip(cs, clb, cr) if x == r and c[2] < 99]),
                     sorted(c[0] for c in sub)[len(sub) // 2],
                     sum(sum(d == b for d in c[4]) for c, b, x in zip(cs, clb, cr) if x == r) / float(len(sub))))
        print("    K4 grids at its lower bound: %d" % sum(d == klb for d in kds))
        same = [c for c, e in zip(cs, ne) if e <= len(edges)]
        if same:
            print("  shuffles with no more lines than K4 (%d of them): smallest D {%s}; feasible grids {%s}"
                  % (len(same), dist([c[2] for c in same]), dist([c[0] for c in same])))

        # ---- how many grids: count placements of the clue letters at K4's smallest D
        print("\nHOW MANY GRIDS (placements of the %d clue letters; the other 5 letters are free on top)" % len(letters))
        shown = 0
        for g in A.GRIDS:
            v, lo, hi, nodes, _ = k4[g]
            if v != "yes":
                continue
            vv, sols, nn = A.solve(k4pairs, *g, maxdirs=hi, limit=2000000, want=COUNT_CAP)
            vv2, sols2, nn2 = A.solve(k4pairs, *g, limit=2000000, want=COUNT_CAP)
            ex.count(2)
            print("  %-22s at D = %d: %s%d placements%s; any D: %s%d%s"
                  % (gname(g), hi, ">= " if len(sols) >= COUNT_CAP or vv == "LIMIT" else "", len(sols),
                     " (search cut)" if vv == "LIMIT" else "",
                     ">= " if len(sols2) >= COUNT_CAP or vv2 == "LIMIT" else "", len(sols2),
                     " (search cut)" if vv2 == "LIMIT" else ""))
            if hi == kb and shown < 3 and sols:
                shown += 1
                grid = A.complete(sols[0], g[0])
                moves = sorted({A.move(sols[0][p], sols[0][c], *g) if p != c else A.STAY for p, c in k4pairs})
                print("    one such grid (other letters put in A-Z order; '.' = empty cell), moves used %s:" % moves)
                for line in A.show(grid, g[1]).split("\n"):
                    print("      " + line)
        print("\nNo decryption is possible from feasibility alone: the grid and the key are both free.")
        print("(%.0f s)" % (time.time() - t0))
