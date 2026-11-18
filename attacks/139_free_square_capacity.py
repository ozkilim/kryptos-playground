"""Idea 139: four-square and two-square on 2x13 / 13x2 / 3x9 / 9x3 with ALL squares free (no key list).

Sanborn said he used "matrix codes Ed gave me". Idea 103 put two-square and four-square on rectangles that
hold all 26 letters (or 26 letters and the carved ?). It closed two-square for ANY squares with a quick
necessary test, but four-square only with plain squares A-Z or KRYPTOS. Here all four squares are free.

With free squares, every clue letter pair is a statement about positions only. Four-square, plain pair
(a, b), cipher (x, y): x sits in the row of a and the column of b; y in the row of b and the column of a.
Two-square has a similar rule. So the question "can ANY squares of this shape give these clue pairs?" is a
puzzle about rows and columns: give every letter of every square a row and a column so that all the
equalities hold and no two letters of one square share a cell. A row has C cells, a column R. If the puzzle
has a solution, the other letters fill the empty cells and real squares exist; if not, the cipher is
impossible on that grid with any squares. kryptos/idea139_freesquares.py decides it exactly by
backtracking (with a node limit; a case that hits the limit is reported as undecided).

Run: every pairing w = 1..48 (letter i with letter i + w in blocks of 2w), every block start, both output
orders, four grids, four-square and two-square; on K4 and 100 shuffled K4s. Feasible solutions are rebuilt
into real squares and checked by decrypting the clue letters. Planted: random-square four-square and
two-square encryptions of English must all come out feasible.

Note: 13x2 is 2x13 turned on its side. For four-square that only swaps the cipher squares and the output
order, so the two grids must give the same counts (and 3x9 the same as 9x3): a built-in consistency check.

  python attacks/139_free_square_capacity.py
"""
import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea139_freesquares as F  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea103_matrix import all_pairings, pair_substitution_ok  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import english97, pmap  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA139_PROCS", "4" if SMOKE else "8"))
NCTRL = int(os.environ.get("IDEA139_CONTROLS", "2" if SMOKE else "100"))
WMAX = int(os.environ.get("IDEA139_WMAX", "7" if SMOKE else "48"))
LIMIT = int(os.environ.get("IDEA139_LIMIT", "300000"))
CIPHERS = ("four", "two")
GNAME = {g: "%dx%d" % g for g in F.GRIDS}


def settings():
    return [(w, o, g, c, order) for w, o in all_pairings(WMAX) for g in F.GRIDS for c in CIPHERS for order in "AB"]


def init():
    pass


def work(chunk):
    """chunk: [(label, ct)]. Returns [(label, {setting: verdict}, part1 dead pairings, bad checks)]."""
    out = []
    for label, ct in chunk:
        res, bad = {}, 0
        p1 = {(w, o): pair_substitution_ok(ct, CRIBS, w, o)[0] for w, o in all_pairings(WMAX)}
        for s in settings():
            w, o, g, c, order = s
            v, a = F.decide(ct, CRIBS, w, o, g, c, order, LIMIT)
            if v and not F.check_assignment(ct, CRIBS, w, o, g, c, order, a, random.Random(1)):
                bad += 1
            res[s] = v
        out.append((label, res, sum(not x for x in p1.values()), bad))
    return out


def tally(res, wsel=None):
    """{(cipher, grid): [feasible, impossible, undecided]} over the chosen widths."""
    t = defaultdict(lambda: [0, 0, 0])
    for (w, o, g, c, order), v in res.items():
        if wsel is not None and w not in wsel:
            continue
        t[c, GNAME[g]][0 if v else 1 if v is False else 2] += 1
    return {"%s %s" % k: v for k, v in sorted(t.items())}


def message(rng):
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


def planted(rng, n_per):
    """Random squares, English text, encrypt; the solver must say feasible. Returns (ok, total, failures)."""
    ok = tot = 0
    fails = []
    for g in F.GRIDS:
        for c in CIPHERS:
            for k in range(n_per):
                w = [1, 7, 21][k] if k < 3 else rng.choice([x for x in range(1, 49) if not 22 <= x <= 34])
                o = rng.randrange(2 * w)
                order = rng.choice("AB")
                sq = F.random_squares(g, c, rng)
                pt = message(rng)
                f = F.four_square if c == "four" else F.two_square
                ct = f(pt, w, o, g, sq, order)
                if "?" in ct:          # like K4: 97 letters (the ? can only stand in for a letter we drop)
                    sq = F.random_squares(g, c, rng)
                    ct = f(pt, w, o, g, sq, order)
                    if "?" in ct:
                        continue
                assert f(ct, w, o, g, sq, order, decrypt=True) == pt
                v, a = F.decide(ct, CRIBS, w, o, g, c, order, LIMIT * 10)
                tot += 1
                good = bool(v) and F.check_assignment(ct, CRIBS, w, o, g, c, order, a)
                ok += good
                if not good:
                    fails.append((c, GNAME[g], w, o, order, v))
    return ok, tot, fails


if __name__ == "__main__":
    t0 = time.time()
    n_set = len(settings())
    texts = [("K4", K4)] + [("shuffled #%d" % (s + 1), shuffled_control(13900 + s)) for s in range(NCTRL)]
    with Experiment("four-square / two-square on 26/27-cell rectangles with all squares free (exact row/column "
                    "capacity test)", puzzle="k4", cribs_forced=True,
                    notes="w=1..%d every start x 2 orders x grids 2x13 13x2 3x9 9x3 x four/two-square; "
                          "K4 + %d shuffled; node limit %d" % (WMAX, NCTRL, LIMIT)) as ex:
        rng = random.Random(139)
        ok, tot, fails = planted(rng, 2 if SMOKE else 12)
        print("planted: %d/%d feasible and rebuilt into squares that give the clue letters%s"
              % (ok, tot, "" if not fails else "; FAILURES %s" % fails))
        print("   (%.1f min)" % ((time.time() - t0) / 60))
        results = {}
        for part in pmap(work, texts, init, (), chunk=1, procs=PROCS):
            for label, res, p1dead, bad in part:
                results[label] = (res, p1dead, bad)
                assert bad == 0, "a feasible assignment did not rebuild into working squares (%s)" % label
        print("%d settings per text, %d texts (%.1f min)" % (n_set, len(texts), (time.time() - t0) / 60))
        ex.count(n_set * len(texts))
        bands = {"w=1": {1}, "w=7": {7}, "w=21": {21}, "w=1..28": set(range(1, 29)), "all w": None}
        k4res = results["K4"][0]
        summary = {"K4": {b: tally(k4res, ws) for b, ws in bands.items()}}
        for b, ws in bands.items():
            print("K4 %s: %s" % (b, json.dumps(summary["K4"][b])))
        feas_k4 = sorted(s for s, v in k4res.items() if v and s[0] <= 28)
        print("K4 feasible settings with w <= 28:")
        for w, o, g, c, order in feas_k4:
            print("   %s-square %s w=%d start=%d order %s" % (c, GNAME[g], w, o, order))
        und_k4 = sorted(s for s, v in k4res.items() if v is None)
        print("K4 undecided settings: %d %s" % (len(und_k4), und_k4[:20]))
        # controls: per band and cell, the feasible count in each control, and how many controls have any
        ctrl = [results[l][0] for l, _ in texts[1:]]
        comp = {}
        for b, ws in bands.items():
            comp[b] = {}
            for c in CIPHERS:
                for g in F.GRIDS:
                    key = "%s %s" % (c, GNAME[g])

                    def nf(res):
                        return sum(1 for (w, o, gg, cc, od), v in res.items()
                                   if v and gg == g and cc == c and (ws is None or w in ws))
                    k = nf(k4res)
                    cs = [nf(r) for r in ctrl]
                    comp[b][key] = {"K4_feasible": k, "controls_mean": round(sum(cs) / max(1, len(cs)), 2),
                                    "controls_with_any": sum(x > 0 for x in cs), "controls_max": max(cs) if cs else None,
                                    "controls_at_or_below_K4": sum(x <= k for x in cs)}
            print("controls %s: %s" % (b, json.dumps(comp[b])))
        und_ctrl = sum(1 for r in ctrl for v in r.values() if v is None)
        p1 = {"K4": results["K4"][1], "controls": [results[l][1] for l, _ in texts[1:]]}
        # four-square and its turned grid must agree (13x2 = 2x13 with cipher squares and order swapped)
        turned_mismatch = 0
        for r in [k4res] + ctrl:
            for (w, o, g, c, od), v in r.items():
                if c == "four" and g in ((2, 13), (3, 9)):
                    v2 = r[w, o, (g[1], g[0]), c, "B" if od == "A" else "A"]
                    if v is not None and v2 is not None and v != v2:
                        turned_mismatch += 1
        print("four-square turned-grid disagreements (should be 0): %d" % turned_mismatch)
        print("undecided: K4 %d, controls %d (of %d each)" % (len(und_k4), und_ctrl, n_set))
        verdict = ("K4 four-square feasible at w=1: %s; two-square w=1: %s; w=7: four %s two %s; w=21: four %s two %s"
                   % (sum(v[0] for k, v in summary["K4"]["w=1"].items() if k.startswith("four")),
                      sum(v[0] for k, v in summary["K4"]["w=1"].items() if k.startswith("two")),
                      sum(v[0] for k, v in summary["K4"]["w=7"].items() if k.startswith("four")),
                      sum(v[0] for k, v in summary["K4"]["w=7"].items() if k.startswith("two")),
                      sum(v[0] for k, v in summary["K4"]["w=21"].items() if k.startswith("four")),
                      sum(v[0] for k, v in summary["K4"]["w=21"].items() if k.startswith("two"))))
        print("RESULT " + json.dumps({"K4": summary["K4"], "compare": comp, "planted": "%d/%d" % (ok, tot),
                                      "part1_dead": p1, "undecided_k4": len(und_k4), "undecided_controls": und_ctrl,
                                      "turned_mismatch": turned_mismatch,
                                      "k4_feasible_w_le_28": ["%s %s w=%d o=%d %s" % (c, GNAME[g], w, o, od)
                                                              for w, o, g, c, od in feas_k4], "settings_per_text": n_set,
                                      "texts": len(texts), "minutes": round((time.time() - t0) / 60, 1)}))
        print("VERDICT:", verdict)
        ex.notes += "; " + verdict + "; planted %d/%d" % (ok, tot)
    if ok != tot or turned_mismatch:
        sys.exit("planted answers not all feasible, or turned grids disagree")
