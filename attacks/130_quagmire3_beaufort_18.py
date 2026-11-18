"""Idea 130: close Quagmire III, Beaufort form, repeating key of length 18, for EVERY alphabet.

K1 and K2 are Quagmire III: one keyed alphabet on both sides of the tableau. Written with the
place x[ch] of each letter in that unknown alphabet, the Beaufort form is

    key[i mod L] = x[C_i] + x[P_i]   (mod 26)

(the Vigenere form is key = x[C] - x[P]). Two clue letters whose positions agree mod L share a key
value, so each such pair is one linear equation in at most four letter places. An alphabet exists
exactly when some assignment of DIFFERENT places 0..25 to the letters satisfies all equations.

The community's exact arbitrary-alphabet search closed the Beaufort form at every length except
13, 18, 23, 26; idea 86 closed 13 for every alphabet, but 18 only for keyword alphabets of up to
16 letters (budget). Here the question is decided exactly, two independent ways
(kryptos/idea130_exact.py):

  certificate  linear algebra mod 2 and mod 13: do the equations force x[X] = x[Y] for two
               different letters? Then no alphabet exists (a two-line proof).
  decide       complete backtracking over the letters in the equations, every place distinct,
               gauge fixed (one letter at 0, the next at 1, 2 or 13: shift and unit multiple keep
               the equations). SAT with a witness, or UNSAT after exhausting the search.

At L = 18 the clue positions share 7 residue classes (27-33 with 63-69). Two of them are

    class 9:  pos 27 (C=P, P=R) and pos 63 (C=N, P=B):  x[P] + x[R] = x[N] + x[B]
    class 11: pos 29 (C=N, P=H) and pos 65 (C=P, P=R):  x[N] + x[H] = x[P] + x[R]

so x[B] = x[H]: no alphabet, whatever the key. (The repeated pair R->P at 27 and 65 and the shared
N at 63 and 29 do it.) The same two classes coincide whenever L divides 36, so L = 36 dies too.

Run on: K4 at L = 1..48, both forms; 50 shuffled K4s at L = 18, 23, 26 (and all of 1..26, Beaufort)
so it is clear whether "satisfiable" or "closed" means anything; satisfiable systems are counted up to
COUNT_CAP gauge-fixed solutions on the letters in the equations.

Planted: random alphabet, random key of length 18 (and 13, 23, 26), Beaufort form, an English
97-letter text carrying K4's clue words. Every one must come out SAT (a false 'no alphabet' would
show here), the true alphabet must pass the equations, and when 5 of its letters are freed the
search must list it and its reading must give back the planted text.

Not covered: Quagmire I, II, IV at 18; any key rule other than a repeating key; gap slack.

  python attacks/130_quagmire3_beaufort_18.py
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea130_exact import (AZ, Budget, certificate, check, count, decide, encrypt,  # noqa: E402
                                   enumerate_fixed, equations, letters_of, read)
from kryptos.round9 import POS, shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, english97  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

NODES = 10 ** 6 if SMOKE else 5 * 10 ** 6   # backtracking steps per system before giving up
COUNT_CAP = 10 ** 4 if SMOKE else 10 ** 5   # count solutions of satisfiable systems up to this
N_SHUF = 5 if SMOKE else 50
K4_LENGTHS = range(1, 27) if SMOKE else range(1, 49)
FOCUS = (18, 23, 26)
FREE = 5                                    # planted: letters of the equations freed and searched


def solve(ct, L, form, do_count=False):
    rows = equations(ct, CRIBS, L, form)
    cert = certificate(rows)
    try:
        verdict, wit, nodes = decide(rows, NODES)
    except Budget:
        verdict, wit, nodes = "BUDGET", None, NODES
    if cert and verdict == "SAT":
        raise AssertionError("certificate and search disagree at L=%d %s" % (L, form))
    cnt = None
    if do_count and verdict == "SAT":
        try:
            c, capped, _ = count(rows, COUNT_CAP, 10 * NODES)
            cnt = ">=%d" % c if capped else str(c)
        except Budget:
            cnt = "budget"
    final = "UNSAT" if cert else verdict
    return {"rows": rows, "letters": len(letters_of(rows)), "cert": cert, "search": verdict,
            "final": final, "nodes": nodes, "wit": wit, "count": cnt}


def complete(wit):
    """A full alphabet from a witness (letters outside the equations fill the free places)."""
    a = [None] * 26
    for ch, v in wit.items():
        a[v] = ch
    rest = iter(ch for ch in AZ if ch not in wit)
    return "".join(c if c else next(rest) for c in a)


def fmt_rows(rows):
    def term(ch, c):
        return ("+" if c < 13 else "-") + ("" if c in (1, 25) else str(min(c, 26 - c))) + "x" + ch
    return "; ".join(" ".join(term(ch, c) for ch, c in sorted(r.items())) + " = 0" for r in rows)


def planted(rng, L, big):
    alpha = "".join(rng.sample(AZ, 26))
    word = [rng.randrange(26) for _ in range(L)]
    pt = english97(rng)
    pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(pt))
    ct = encrypt(pt, alpha, word, "beau")
    rows = equations(ct, CRIBS, L, "beau")
    cert = certificate(rows)
    verdict, wit, nodes = decide(rows, NODES)
    ok_eq = check(alpha, rows)
    lets = letters_of(rows)
    free = rng.sample(lets, min(FREE, len(lets)))
    listed = enumerate_fixed(rows, alpha, free)
    reads = []
    for al in listed:
        p, ok = read(al, ct, CRIBS, L, "beau")
        assert ok
        body = "".join(ch for i, ch in enumerate(p) if i not in CRIBS and ch != "?")
        reads.append((big.score(body), al, p))
    reads.sort(reverse=True)
    rank = next((j + 1 for j, r in enumerate(reads) if r[1] == alpha), None)
    p_true, _ = read(alpha, ct, CRIBS, L, "beau")
    back = all(a == b or a == "?" for a, b in zip(p_true, pt))
    english = sum(1 for r in reads if r[0] > -5.1)
    good = verdict == "SAT" and not cert and ok_eq and rank is not None and back
    return {"L": L, "verdict": verdict, "cert": cert, "eq_ok": ok_eq, "listed": len(listed), "rank": rank,
            "read_back": back, "unknown": p_true.count("?"), "score": reads[0][0] if reads else None,
            "english": english, "good": good, "pt": pt, "read": p_true, "nodes": nodes}


def _prefilter_encrypt(pt, rng):
    alpha = "".join(rng.sample(AZ, 26))
    return encrypt(pt, alpha, [rng.randrange(26) for _ in range(18)], "beau")


def main():
    t0 = time.time()
    from kryptos.clues import prefilter
    prefilter("130 Quagmire III Beaufort, repeating key 18", encrypt=_prefilter_encrypt, n=100 if SMOKE else 300)
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    with Experiment("Quagmire III Beaufort L=18 exact, every alphabet", puzzle="k4",
                    notes="one unknown alphabet both sides, repeating key; exact linear certificate mod 2/13 + "
                          "complete backtracking; K4 L=1-%d both forms; %d shuffled K4s; planted" % (
                              max(K4_LENGTHS), N_SHUF),
                    cribs_forced=True) as ex:
        # --- K4
        print("== K4, every length, both forms (UNSAT = no alphabet at all)")
        k4 = {}
        for form in ("beau", "vig"):
            for L in K4_LENGTHS:
                r = solve(K4, L, form, do_count=(form == "beau" and L in FOCUS))
                k4[(form, L)] = r
                ex.tried += 1
                print("  %-4s L=%-2d eq=%-2d letters=%-2d search=%-6s cert=%-28s -> %s%s" % (
                    form, L, len(r["rows"]), r["letters"], r["search"],
                    ",".join("%s=%s" % p for p in r["cert"][:3]) or "-", r["final"],
                    "  solutions(gauge-fixed)=%s" % r["count"] if r["count"] else ""), flush=True)
                if r["final"] == "SAT" and r["wit"] is not None:
                    al = complete(r["wit"])
                    p, ok = read(al, K4, CRIBS, L, form)
                    assert ok
                    ex.add(p.replace("?", "X"), form=form, L=L, alphabet=al, kind="witness")
        r18 = k4[("beau", 18)]
        print("\n  L=18 Beaufort equations: " + fmt_rows(r18["rows"]))
        print("  forced equal places: %s" % r18["cert"])
        sat_b = [L for L in K4_LENGTHS if k4[("beau", L)]["final"] == "SAT"]
        sat_v = [L for L in K4_LENGTHS if k4[("vig", L)]["final"] == "SAT"]
        print("  K4 Beaufort satisfiable at: %s; Vigenere at: %s" % (sat_b, sat_v))
        print("  search budget hit (decided by certificate): %s" % [
            k for k, r in k4.items() if r["search"] == "BUDGET"])

        # --- shuffled controls
        print("\n== %d shuffled K4s, Beaufort form" % N_SHUF)
        focus = {L: {"SAT": 0, "UNSAT": 0, "BUDGET": 0, "counts": []} for L in FOCUS}
        closed = []
        for s in range(1, N_SHUF + 1):
            ct = shuffled_control(s)
            nclosed, line = 0, []
            for L in range(1, 27):
                r = solve(ct, L, "beau", do_count=(L in FOCUS and s <= 5))
                ex.tried += 1
                nclosed += r["final"] == "UNSAT"
                if L in FOCUS:
                    focus[L][r["final"]] += 1
                    if r["count"]:
                        focus[L]["counts"].append(r["count"])
                    line.append("L%d:%s%s" % (L, r["final"], "(%s)" % r["count"] if r["count"] else ""))
            closed.append(nclosed)
            print("  shuf%-2d closed at %2d of 26 lengths; %s" % (s, nclosed, " ".join(line)), flush=True)
        k4_closed = sum(1 for L in range(1, 27) if k4[("beau", L)]["final"] == "UNSAT")
        print("\n  lengths 1-26 closed for every alphabet: K4 %d; shuffled min %d, median %d, max %d" % (
            k4_closed, min(closed), sorted(closed)[len(closed) // 2], max(closed)))
        print("  shuffled with >= K4's count of closed lengths: %d/%d" % (
            sum(1 for c in closed if c >= k4_closed), len(closed)))
        for L in FOCUS:
            f = focus[L]
            print("  L=%d: shuffled SAT %d, UNSAT %d, budget %d (K4: %s); counts on first 5: %s" % (
                L, f["SAT"], f["UNSAT"], f["BUDGET"], k4[("beau", L)]["final"], f["counts"]))

        # --- planted
        print("\n== planted: random alphabet + random key, Beaufort form, English with K4's clue words")
        rng = random.Random(130)
        lengths = [18] * (3 if SMOKE else 10) + ([13, 23, 26] if not SMOKE else [23])
        good = 0
        for L in lengths:
            p = planted(rng, L, big)
            good += p["good"]
            print("  L=%-2d %s eq_ok=%s listed=%d (English %d) true rank=%s read_back=%s (%d '?') best=%.2f %s" % (
                L, p["verdict"], p["eq_ok"], p["listed"], p["english"], p["rank"], p["read_back"], p["unknown"],
                p["score"] or 0, "OK" if p["good"] else "FAIL"))
            ex.add(p["read"].replace("?", "X"), kind="planted", L=L)
        print("  planted recovered %d/%d" % (good, len(lengths)))
        assert good == len(lengths), "planted test failed"
        print("\ntotal %.0f s" % (time.time() - t0))


if __name__ == "__main__":
    main()
