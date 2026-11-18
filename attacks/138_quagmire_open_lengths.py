"""Idea 138: decide the community's open Quagmire I / II / IV key lengths exactly, for every alphabet pair.

keithadler's arbitrary-alphabet search lists Quagmire I/II at 13, 16, 19, 20, 23, 24, 26 and Quagmire IV at
8, 13, 16, 19, 20, 23, 24, 26 as satisfiable but undecided. Idea 130 showed that a linear certificate (the
clue equations force two letters onto one place) settles such cases in under a second.

ACA definitions, x = places in the plain-side alphabet, y = places in the cipher-side alphabet:

    Quagmire I    plain side keyed, cipher side A-Z      key = C - x[P]       (C = the letter's number)
    Quagmire II   plain side A-Z, cipher side keyed      key = y[C] - P
    Quagmire IV   both sides keyed, independent          key = y[C] - x[P]
    (Beaufort form: key = y[C] + x[P]; for I, II, IV this is the Vigenere form with a reversed alphabet,
     so the verdicts must agree; they are computed both ways as a check.)

Two clue positions in one residue class mod L share the key value, so each pair gives a linear equation.
For Quagmire I and II the straight side gives a constant (x[P_a] - x[P_b] = C_a - C_b); for IV the equation
has four unknowns and no constant. Each system is decided two independent ways (kryptos/idea138_quag.py):

  certificate  linear algebra mod 2 and mod 13: inconsistent, or two different letters of one alphabet
               forced to the same place mod 26. Then no alphabet (pair) exists for any key.
  decide       complete backtracking, all places in one alphabet different, gauge fixed only where the rows
               allow it. SAT with a witness (checked by re-deriving a consistent key from the full
               alphabets), or UNSAT after exhausting the search.

Quagmire III (one alphabet both sides) is run too, as a regression against idea 130.

Run on: K4 at L = 1..26, four models, both forms; 50 shuffled K4s at L = 1..26 for I, II, IV (Vigenere form;
the first 5 also in the Beaufort form to confirm the equivalence on other texts). Planted: for each of I, II,
IV and each listed open length, random alphabet(s), random key, English 97 letters with K4's clue words,
alternating forms. Each must come out SAT with no certificate (a false certificate would show here).

Scope: decides consistency of the 24 carved clue letters only, not English. Repeating key only.

  python attacks/138_quagmire_open_lengths.py
"""
import random
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea138_quag import (MODELS, Budget, alphabets, certificate, clue_key, decide, encrypt,  # noqa: E402
                                  equations, fmt_row, random_pair, read, vars_of)
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, english97  # noqa: E402

NODES = 2 * 10 ** 5 if SMOKE else 5 * 10 ** 6
N_SHUF = 4 if SMOKE else 50
N_BOTH = 2 if SMOKE else 5        # shuffles also run in the Beaufort form
LENGTHS = range(1, 27)
OPEN = {"QI": (13, 16, 19, 20, 23, 24, 26), "QII": (13, 16, 19, 20, 23, 24, 26),
        "QIV": (8, 13, 16, 19, 20, 23, 24, 26)}
CTRL_MODELS = ("QI", "QII", "QIV")


def solve(ct, L, model, form):
    rows = equations(ct, CRIBS, L, model, form)
    cert = certificate(rows)
    try:
        verdict, wit, nodes = decide(rows, NODES)
    except Budget:
        verdict, wit, nodes = "BUDGET", None, NODES
    if cert and verdict == "SAT":
        raise AssertionError("certificate and search disagree: %s %s L=%d" % (model, form, L))
    if verdict == "SAT":                         # independent check of the witness
        pa, ca = alphabets(model, wit)
        assert len(set(pa)) == 26 and len(set(ca)) == 26
        assert clue_key(pa, ca, ct, CRIBS, L, form)[1], "witness fails the clues"
    final = "UNSAT" if cert else verdict
    how = "cert" if cert else ("search" if verdict == "UNSAT" else "")
    return {"rows": rows, "nvars": len(vars_of(rows)), "cert": cert, "search": verdict, "final": final,
            "how": how, "nodes": nodes, "wit": wit}


def shuffle_job(s):
    ct = shuffled_control(s)
    out = {}
    forms = ("vig", "beau") if s <= N_BOTH else ("vig",)
    for model in CTRL_MODELS:
        for form in forms:
            for L in LENGTHS:
                r = solve(ct, L, model, form)
                out[(model, form, L)] = (r["final"], r["how"])
    return s, out


def cert_text(cert):
    if not cert:
        return "-"
    c = cert[0]
    if c[0] == "inconsistent":
        return "inconsistent mod %d" % c[1]
    return "%s[%s]=%s[%s]" % (c[1][0], c[1][1], c[2][0], c[2][1]) + ("(+%d)" % (len(cert) - 1) if len(cert) > 1 else "")


def planted(rng, model, L, form):
    pa, ca = random_pair(model, rng)
    key = [rng.randrange(26) for _ in range(L)]
    pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(english97(rng)))
    ct = encrypt(pt, pa, ca, key, form)
    r = solve(ct, L, model, form)
    # true alphabets must satisfy every equation
    xa = {("x", ch): i for i, ch in enumerate(pa)}
    ya = {("y", ch): i for i, ch in enumerate(ca)}
    aa = {("a", ch): i for i, ch in enumerate(pa)}
    val = {**xa, **ya, **aa}
    eq_ok = all((sum(val[v] * c for v, c in d.items()) + k) % 26 == 0 for d, k in r["rows"])
    back, ok = read(pa, ca, ct, CRIBS, L, form)
    back_ok = ok and all(a == b or a == "?" for a, b in zip(back, pt))
    good = r["final"] == "SAT" and not r["cert"] and eq_ok and back_ok
    return {"model": model, "L": L, "form": form, "final": r["final"], "cert": r["cert"], "eq_ok": eq_ok,
            "back_ok": back_ok, "good": good, "neq": len(r["rows"]), "nodes": r["nodes"], "read": back}


def _prefilter_encrypt(pt, rng):
    pa, ca = random_pair("QIV", rng)
    return encrypt(pt, pa, ca, [rng.randrange(26) for _ in range(rng.choice(OPEN["QIV"]))], "vig")


def main():
    t0 = time.time()
    from kryptos.clues import prefilter
    prefilter("138 Quagmire IV, repeating key at the open lengths", encrypt=_prefilter_encrypt,
              n=100 if SMOKE else 300)
    with Experiment("Quagmire I/II/IV open lengths exact, every alphabet pair", puzzle="k4",
                    notes="ACA Quagmire I, II, IV (+III regression), repeating key L=1-26, both forms; linear "
                          "certificate mod 2/13 + complete backtracking with distinct places; %d shuffled K4s; "
                          "planted at every open length" % N_SHUF, cribs_forced=True) as ex:
        print("== K4, every model, form and length (UNSAT = no alphabet at all)")
        k4 = {}
        for model in MODELS:
            for form in ("vig", "beau"):
                for L in LENGTHS:
                    r = solve(K4, L, model, form)
                    k4[(model, form, L)] = r
                    ex.tried += 1
                    is_open = L in OPEN.get(model, ())
                    if is_open or SMOKE:
                        print("  %-4s %-4s L=%-2d eq=%-2d vars=%-2d search=%-6s nodes=%-8d cert=%-24s -> %s%s" % (
                            model, form, L, len(r["rows"]), r["nvars"], r["search"], r["nodes"],
                            cert_text(r["cert"]), r["final"], "   [open length]" if is_open else ""), flush=True)
                    if r["final"] == "SAT" and is_open and form == "vig":
                        pa, ca = alphabets(model, r["wit"])
                        p, ok = read(pa, ca, K4, CRIBS, L, form)
                        ex.add(p.replace("?", "X"), model=model, form=form, L=L, plain=pa, cipher=ca, kind="witness")
                sat = [L for L in LENGTHS if k4[(model, form, L)]["final"] == "SAT"]
                srch = [L for L in LENGTHS if k4[(model, form, L)]["how"] == "search"]
                bud = [L for L in LENGTHS if k4[(model, form, L)]["final"] == "BUDGET"]
                print("  %-4s %-4s satisfiable at %s; closed by search only (no linear certificate) at %s; budget %s"
                      % (model, form, sat, srch, bud), flush=True)
        for model in MODELS[:2] + MODELS[3:]:
            for L in LENGTHS:
                a, b = k4[(model, "vig", L)]["final"], k4[(model, "beau", L)]["final"]
                assert a == b, "Vigenere/Beaufort disagree %s L=%d" % (model, L)
        print("  Vigenere and Beaufort forms agree for I, II, IV at every length (as the reflection argument says)")
        for model, L in (("QI", 20), ("QII", 13)):
            r = k4[(model, "vig", L)]
            print("\n  %s L=%d equations:\n    %s\n  certificate: %s" % (
                model, L, "\n    ".join(fmt_row(x) for x in r["rows"]), r["cert"]))

        # --- controls
        print("\n== %d shuffled K4s, models I, II, IV, L = 1..26" % N_SHUF, flush=True)
        ctrl = {}
        with Pool(4) as pool:
            for s, out in pool.imap_unordered(shuffle_job, range(1, N_SHUF + 1)):
                ctrl[s] = out
                ex.tried += len(out)
        for s in range(1, N_BOTH + 1):
            for model in CTRL_MODELS:
                for L in LENGTHS:
                    assert ctrl[s][(model, "vig", L)][0] == ctrl[s][(model, "beau", L)][0], (s, model, L)
        print("  Beaufort = Vigenere verdicts on the first %d shuffles too" % N_BOTH)
        nbud = sum(1 for o in ctrl.values() for v in o.values() if v[0] == "BUDGET")
        print("  control systems out of budget: %d" % nbud)
        for model in CTRL_MODELS:
            print("  %s: per open length, shuffled K4s satisfiable (K4's verdict):" % model)
            for L in OPEN[model]:
                n_sat = sum(1 for s in ctrl if ctrl[s][(model, "vig", L)][0] == "SAT")
                n_srch = sum(1 for s in ctrl if ctrl[s][(model, "vig", L)][1] == "search")
                print("     L=%-2d  %2d/%d SAT, %2d closed by search only   K4: %s" % (
                    L, n_sat, N_SHUF, n_srch, k4[(model, "vig", L)]["final"]))
            k4c = sum(1 for L in LENGTHS if k4[(model, "vig", L)]["final"] == "UNSAT")
            cl = sorted(sum(1 for L in LENGTHS if ctrl[s][(model, "vig", L)][0] == "UNSAT") for s in ctrl)
            print("     lengths 1-26 closed: K4 %d; shuffled min %d, median %d, max %d; shuffles >= K4: %d/%d" % (
                k4c, cl[0], cl[len(cl) // 2], cl[-1], sum(1 for c in cl if c >= k4c), len(cl)), flush=True)

        # --- planted
        print("\n== planted: random alphabet(s) + random key, English with K4's clue words")
        rng = random.Random(138)
        plan = [(m, L) for m in CTRL_MODELS for L in OPEN[m]]
        if SMOKE:
            plan = plan[::4]
        good = 0
        for j, (m, L) in enumerate(plan):
            form = "vig" if j % 2 == 0 else "beau"
            p = planted(rng, m, L, form)
            good += p["good"]
            print("  %-4s %-4s L=%-2d eq=%-2d -> %s cert=%s eq_ok=%s read_back=%s %s" % (
                m, form, L, p["neq"], p["final"], cert_text(p["cert"]), p["eq_ok"], p["back_ok"],
                "OK" if p["good"] else "FAIL"), flush=True)
            ex.add(p["read"].replace("?", "X"), kind="planted", model=m, L=L)
        print("  planted recovered %d/%d" % (good, len(plan)))
        assert good == len(plan), "planted test failed"
        print("\ntotal %.0f s" % (time.time() - t0))


if __name__ == "__main__":
    main()
