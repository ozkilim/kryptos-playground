"""Idea 129: a repeating key word that is moved on by a steady step, on one hidden alphabet.

The hand Vigenere with a step. A person keeps a short key word (p letters) and, to stop it repeating,
adds a fixed step s: either at every letter, or once per pass through the word ("move the word on s
places each time round"). The tableau alphabet is anything at all. Bean found the clue key values close
together, and this is the simplest key a person remembers that is not periodic.

    k_i = w[i mod p] + s * g(i)  (mod 26)      g(i) = i              letter form
                                               g(i) = (i + phase)//p  pass form (phase = where the word starts)

Layouts (as idea 92): V  X[C] = X[P] + k,  B  X[C] = k - X[P]  (one hidden alphabet X on both sides),
hpAZ / hpKR  A[C] = X[P] + k  (hidden plain side), hcAZ / hcKR  X[C] = A[P] + k  (hidden cipher side).

For fixed (p, s, form, phase) the 24 clue letters give 24 equations LINEAR in the 26 places and the p word
values. We solve them mod 13 and mod 2 (kryptos/round9.py), with the turn of the alphabet fixed. Equations
minus rank = the loop tests (two clue letters in one residue class make one loop with constant
s*(g(i) - g(j))). A setting survives only if the loops close AND a solution puts every clue letter on a
different place (attack 67: all letters in one place always solves the equations). The second step is an
exact backtracking search over the solution space (kryptos/idea129_step.py), with a node budget.

What the clues decide (K4): layouts V and B have 3 loop tests at p = 1, 2 at p = 2, 1 at p = 3-5 and NONE
from p = 6 (the word values soak them up), so there only the different-places rule can kill. The half-hidden
layouts keep 12 - p or so tests (hp: 11 at p = 1 down to 4-5 at p = 8-9; hc: 10 down to 3 at p = 9) and have
2 or fewer from p = 10. A cell with fewer than 3 loop tests where fits exist is UNDECIDED: it is reported, not
claimed. Fits in decided cells are completed on the big English model (idea 92's fill).

Symmetry used: in V and B, multiplying X, w and s by a unit gives the same reading, so s = 1, 2 and 13 stand
for all 25 steps (12 + 12 + 1). The half-hidden layouts run every s. The letter form with step s equals
the pass form with step s*p, phase 0; both are run.

Controls: 20 shuffled K4s, same search; the loop structure changes from shuffle to shuffle, so the script
prints how many shuffles have K4's number of tests in each cell. Planted: K4's clue words in English text,
random alphabet, random word: (1) V, word of 7, step 3 per pass; (2) B, word of 11, step 1 per letter;
(3) hcKR, word of 5, step 2 per pass; plus hpKR word 5 step 2 per pass, V word 1 step 7 and hpAZ word 9
step 4 per letter. Plant 2 lies in an undecided cell (0 loop tests), so for it the script checks only that
the true setting survives the exact test (soundness); it can not read it back (see the result card).

Not covered: p over 13, steps that change, two different hidden alphabets, a key word that is not
moved by a constant.

  python attacks/129_stepped_word_hidden_alphabet.py            (--prefilter for the clue card)
"""
import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import english97, pmap  # noqa: E402
from kryptos import idea129_step as h  # noqa: E402
from kryptos.idea92_hidden import fill, partial, partial_score  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA129_PROCS", "4" if SMOKE else "12"))
NCTRL = 2 if SMOKE else 20
PMAX = 13
ENGLISH = -5.1
DECIDED = 3              # loop tests (mod 13) a cell needs to count as decided
READ_CAP = 40            # a setting with more fits than this is left to the reading (undecided) ...
READ_CAP_LOOPS = 3000    # ... except in cells with 3+ loop tests, where every fit is listed
FILL_TOP = 3001          # fits per setting completed on English (all of them: completion is fast)
BUDGET = 60_000 if SMOKE else 150_000
RIGHT = 90
REPS = {1: 12, 2: 12, 13: 1}     # V/B: step classes under unit scaling, with how many steps each stands for
BIG = DATA_DIR / "english" / "quadgrams_big.txt"
_SC = {}


def scorer():
    if "s" not in _SC:
        from kryptos.score import Quadgrams
        from kryptos.idea92_hidden import Scorer
        _SC["s"] = Scorer(Quadgrams(BIG))
    return _SC["s"]


def settings(layout, p):
    """(s, form, phase, weight). weight = how many real settings this one stands for."""
    steps = REPS if layout in ("V", "B") else {s: 1 for s in range(1, 26)}
    for s, wgt in steps.items():
        yield s, "letter", 0, wgt
        if p > 1:
            for ph in range(p):
                yield s, "pass", ph, wgt


def cell(task):
    """One (ciphertext, cribs, layout, p). Returns a summary dict (and readings in decided cells)."""
    tag, ct, cribs, layout, p, read = task
    S = h.System(layout, ct, cribs, p)
    t13, t2 = S.tests[13], S.tests[2]
    out = dict(tag=tag, layout=layout, p=p, tests=t13, tests2=t2, settings=0, passes=0, fits=0, undecided=0, listed_settings=0,
               listed=0, best=None, ref_fit=None)
    rng = random.Random(hash((tag, layout, p)) & 0xffff)
    # s = 0: the plain repeating key, as a reference (not counted in the idea's settings)
    sol = S.solve(0, "letter", 0)
    if sol is not None:
        st, arr, _ = h.arrangements(S, sol, cap=1, rng=rng, budget=BUDGET)
        out["ref_fit"] = "yes" if arr else ("budget" if st == "budget" else "no")
    else:
        out["ref_fit"] = "loops fail"
    reads = []
    for s, form, ph, wgt in settings(layout, p):
        out["settings"] += wgt
        sol = S.solve(s, form, ph)
        if sol is None:
            continue
        out["passes"] += wgt
        cap = READ_CAP_LOOPS if t13 >= DECIDED else READ_CAP
        st, arr, capped = h.arrangements(S, sol, cap=cap + 1, rng=rng, budget=BUDGET)
        if arr:
            out["fits"] += wgt
        if st == "budget" or len(arr) > cap:
            out["undecided"] += wgt          # fits not all listed: the reading would have to decide
            continue
        out["listed"] += len(arr)
        if arr:
            out["listed_settings"] += wgt
        if read and arr:
            sc = scorer()
            cand = []
            for placed in arr:
                w = h.word_values(S, placed, s, form, ph)
                k = h.key_stream(w, s, form, ph, len(ct))
                cand.append((partial_score(partial(layout, ct, k, placed), sc), placed, w, k))
            cand.sort(key=lambda c: -c[0])
            for _, placed, w, k in cand[:FILL_TOP]:
                bs, pt, x = fill(layout, ct, k, placed, sc, rng, restarts=3)
                reads.append((bs, pt, x, s, form, ph, w))
    if reads:
        reads.sort(key=lambda r: -r[0])
        out["best"] = reads[0]
    return out


def _init():
    pass


def _work(chunk):
    return [cell(t) for t in chunk]


def run_texts(texts, read=True, layouts=h.LAYOUTS, ps=range(1, PMAX + 1)):
    tasks = [(tag, ct, cribs, lay, p, read) for tag, ct, cribs in texts for lay in layouts for p in ps]
    # the slow cells (V/B, long words) first
    tasks.sort(key=lambda t: -(t[4] if t[3] in ("V", "B") else 0))
    res = []
    for r in pmap(_work, tasks, _init, (), chunk=1, procs=PROCS):
        res.extend(r)
    return res


def plant(layout, p, s, form, ph, seed):
    rng = random.Random(seed)
    pt = list(english97(rng))
    for i, c in CRIBS.items():
        pt[i] = c
    pt = "".join(pt)
    x = "".join(rng.sample(h.AZ, 26))
    w = [rng.randrange(26) for _ in range(p)]
    k = h.key_stream(w, s, form, ph)
    return h.encrypt(layout, pt, k, x), pt, x, w


PLANTS = [("V", 7, 3, "pass", 0, 12901), ("B", 11, 1, "letter", 0, 12902), ("hcKR", 5, 2, "pass", 0, 12903),
          ("hpKR", 5, 2, "pass", 0, 12904), ("V", 1, 7, "letter", 0, 12905), ("hpAZ", 9, 4, "letter", 0, 12906)]


def true_setting_survives(layout, p, s, form, ph, ct, x):
    """Soundness: the true key passes the loop tests and the true placing satisfies the equations."""
    S = h.System(layout, ct, CRIBS, p)
    sol = S.solve(s, form, ph)
    if sol is None:
        return False
    placed = {ch: x.index(ch) for ch in S.letters}
    sh = placed[S.letters[0]]
    placed = {ch: (v - sh) % 26 for ch, v in placed.items()}
    try:
        h.word_values(S, placed, s, form, ph)
    except ValueError:
        return False
    return len(set(placed.values())) == len(placed)


def prefilter_encrypt(pt, rng):
    p = rng.randint(1, 13)
    s = rng.randint(1, 25)
    form = rng.choice(["letter", "pass"])
    x = "".join(rng.sample(h.AZ, 26))
    w = [rng.randrange(26) for _ in range(p)]
    return h.encrypt("V", pt, h.key_stream(w, s, form, 0, len(pt)), x)


def fmt_cell(r):
    return "%-4s p=%2d tests %d+%d | settings %4d pass loops %4d | fit %4d | undecided %4d | s=0 ref: %s" % (
        r["layout"], r["p"], r["tests"], r["tests2"], r["settings"], r["passes"], r["fits"], r["undecided"],
        r["ref_fit"])


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("stepped repeating key word on one hidden alphabet", encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "a key word and a step, done with a paper tableau")})
        sys.exit(0)
    t0 = time.time()
    with Experiment("idea 129: repeating key word plus a steady step on one hidden alphabet", puzzle="k4",
                    notes="k_i = w[i mod p] + s*i or s*((i+phase)//p), p 1-13, s 1-25; V/B one hidden alphabet, "
                          "half-hidden vs A-Z/KRYPTOS; exact linear solve mod 13/2 + distinct places; "
                          "20 shuffled controls; planted", cribs_forced=True) as ex:
        # ---------------- planted
        ok, nplant_dec = 0, 0
        plant_lines = []
        for lay, p, s, form, ph, seed in PLANTS:
            ct, pt, x, w = plant(lay, p, s, form, ph, seed)
            sound = true_setting_survives(lay, p, s, form, ph, ct, x)
            r = run_texts([("plant", ct, CRIBS)], read=True, layouts=(lay,), ps=(p,))[0]
            b = r["best"]
            right = sum(a == c for a, c in zip(b[1], pt)) if b else 0
            decided = r["undecided"] == 0
            found = bool(b) and right >= RIGHT and b[0] > ENGLISH
            if decided:
                nplant_dec += 1
                ok += found
            line = ("planted %-4s p=%d s=%d %s: tests %d, true setting survives exact test: %s, fits %d, "
                    "best reading %s, %d/97 right -> %s" % (
                        lay, p, s, form, r["tests"], sound, r["fits"], "%.3f" % b[0] if b else "-", right,
                        "FOUND" if found else ("not read: cell undecided (%d settings with too many fits)"
                                               % r["undecided"] if not decided else "MISSED")))
            print(line, flush=True)
            plant_lines.append((lay, p, found, sound))
        print("planted recovered in decided cells: %d/%d; all plants survive the exact test: %s (%.0f s)" % (
            ok, nplant_dec, all(l[3] for l in plant_lines), time.time() - t0), flush=True)

        # ---------------- K4 and controls
        texts = [("K4", K4, CRIBS)] + [("seed%d" % sd, shuffled_control(sd), CRIBS) for sd in range(1, NCTRL + 1)]
        res = run_texts(texts, read=True)
        by = defaultdict(dict)
        for r in res:
            by[r["tag"]][(r["layout"], r["p"])] = r
        k4 = by["K4"]
        tested = sum(r["settings"] for r in k4.values())
        ex.count(tested)
        print("\nK4 (%.0f s): settings %d" % (time.time() - t0, tested))
        best4 = None
        for key in sorted(k4, key=lambda k: (h.LAYOUTS.index(k[0]), k[1])):
            r = k4[key]
            same = sum(by[t][key]["tests"] == r["tests"] for t in by if t != "K4")
            cfits = [by[t][key]["fits"] for t in by if t != "K4"]
            cpass = [by[t][key]["passes"] for t in by if t != "K4"]
            nset = r["settings"]
            chance = nset * 13.0 ** -r["tests"] * 2.0 ** -r["tests2"]
            tag = ("UNDECIDED (%d settings)" % r["undecided"] if r["undecided"] else
                   "decided by loops" if r["tests"] >= DECIDED else "decided by places")
            print("  %s | chance passes %.2f | %s | controls: %d/%d same tests, passes mean %.1f, fits mean %.1f "
                  "(max %d)" % (fmt_cell(r), chance, tag, same, len(cfits), sum(cpass) / len(cpass),
                                sum(cfits) / len(cfits), max(cfits)))
            if r["best"]:
                bs, pt, x, s, form, ph, w = r["best"]
                ex.add(pt, layout=r["layout"], p=r["p"], s=s, form=form, phase=ph, alphabet=x)
                print("      best reading %.3f  s=%d %s phase %d  %s" % (bs, s, form, ph, pt))
                if best4 is None or bs > best4:
                    best4 = bs
        print("\ncontrols:")
        cbest = []
        for t in sorted(by, key=lambda t: (t != "K4", len(t), t)):
            if t == "K4":
                continue
            rs = by[t].values()
            dec_fits = sum(r["listed_settings"] for r in rs)
            und = sum(1 for r in rs if r["undecided"])
            b = max([r["best"][0] for r in rs if r["best"]] or [None], key=lambda v: -99 if v is None else v)
            cbest.append(b)
            print("  %s: fully listed fit settings %d; cells with undecided settings %d; best reading %s" % (
                t, dec_fits, und, "%.3f" % b if b is not None else "-"))
        k4_dec = sum(r["listed_settings"] for r in k4.values())
        k4_und = [(k, r["undecided"]) for k, r in sorted(k4.items()) if r["undecided"]]
        print("\nK4: fully listed fit settings %d; undecided (layout, p): settings %s" % (k4_dec, k4_und))
        cb = [b for b in cbest if b is not None]
        english = best4 is not None and best4 > ENGLISH
        beats = english and all(best4 > b + 0.3 for b in cb)
        print("VERDICT:", "K4 reading beats controls and reads as English - inspect" if beats else
              "no signal in decided cells (K4 best reading %s; controls best %s)" % (best4, max(cb) if cb else None))
        if ok != nplant_dec:
            print("WARNING: a planted answer in a decided cell was missed - the negative does not stand")
        print("total time %.0f s" % (time.time() - t0))
