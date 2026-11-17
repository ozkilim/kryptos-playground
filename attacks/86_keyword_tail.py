"""Idea 86: keywords outside the dictionary. Solve ANY keyword alphabet from its alphabetical tail.

Scheidt: K4 runs "with the correct key word/s", and K1's own keyword was a misspelling
(PALIMPCEST). Every keyword-tableau test so far took its alphabets from about 220,000 dictionary
words, so a name, a German word, a misspelling or a short phrase was never tried.

A keyword alphabet is far from arbitrary: after the m keyword letters the other letters run in
A-Z order. So the unknown is small (which m letters, in which order), and every clue equation
can be tested exactly, with no word list:

  repeating key of length L = 1..26   two clue letters at the same place mod L share a key letter
  sliding key, period p = 1..26       the step from one key letter to the next repeats every p
                                       (plus the jump between the two clue blocks when it is known)

on five tableau layouts (plaintext side / ciphertext side):

  M/M          Quagmire III: the unknown keyword alphabet on both sides
  M/AZ, M/KR   Quagmire I:   unknown alphabet for the plaintext, A-Z or KRYPTOS for the ciphertext
  AZ/M, KR/M   Quagmire II:  the other way round

each in the Vigenere form (key = C - P; variant Beaufort is the same test) and the Beaufort form
(key = C + P). For each of these 520 systems the keyword length m climbs 1, 2, 3, ... 25 until the
system has used NODES search steps (m = 25 is every alphabet there is). The solutions at
level m include those at m - 1, so "0 at m = 12" means no keyword of 1 to 12 different letters.

Every solution is listed while there are at most CAP of them; for each the plaintext the clues
force is filled in and scored on the big English model outside the clue words. A hit needs English
there (and then a keyword a person would call a word).

Controls: the same on 3 shuffled K4s. Planted: SANBORN, SCHEIDT and a random 6-letter keyword at
key lengths 13, 19 and 23 (Quagmire III, Beaufort form), plus two other systems; the true alphabet
must be listed and must read best.

Not covered: two different unknown keywords (Quagmire IV), transposition-mixed alphabets.

  python attacks/86_keyword_tail.py
"""
import math
import random
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea86_tail import (FORMS, LAYOUTS, climb, encrypt, equations, extra_score,  # noqa: E402
                                 keyword_alphabet, minimal_keyword, read)
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, english97  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

MMAX = 9 if SMOKE else 25
NODES = 10 ** 6 if SMOKE else 6 * 10 ** 6    # search steps allowed for one system, all levels m together
CAP = 20000 if SMOKE else 50000          # list and read every solution while there are at most this many
ENGLISH = -5.1                           # big-model score per quadgram that a reading must beat
MIN_Q = 20                               # ... over at least this many quadgrams outside the clues
LENGTHS = (5, 13, 19, 23, 26) if SMOKE else tuple(range(1, 27))
_S = {}


def init(texts):
    _S["texts"] = texts
    _S["big"] = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")


def job(arg):
    tid, layout, form, rule, n = arg
    ct, cribs = _S["texts"][tid]
    eqs, imp = equations(ct, cribs, layout, form, rule, n)
    rows, done, list_m, alphas = climb(eqs, imp, MMAX, NODES, CAP)
    reads = []
    for al in alphas:
        pt, _, ok = read(al, ct, cribs, layout, form, rule, n)
        assert ok, (arg, al)                 # the solver and the plain decryption must agree
        sc, cnt = extra_score(pt, _S["big"])
        reads.append((sc if sc is not None and cnt >= MIN_Q else -99.0, cnt, al, pt))
    reads.sort(reverse=True)
    return {"arg": arg, "eq": len(eqs), "imp": imp, "rows": rows, "done": done, "list_m": list_m,
            "listed": len(alphas), "judged": sum(1 for r in reads if r[1] >= MIN_Q),
            "english": sum(1 for r in reads if r[0] > ENGLISH), "top": reads[:5],
            "all": [(r[2], r[0]) for r in reads] if tid.startswith("planted") else None}


def systems():
    return [(lay, form, rule, n) for rule in ("rep", "slide") for lay in LAYOUTS for form in FORMS for n in LENGTHS]


def run(pool, jobs):
    out, t0 = {}, time.time()
    for r in pool.imap_unordered(job, jobs, chunksize=2):
        out[r["arg"]] = r
        if len(out) % 100 == 0:
            print("  ... %d/%d systems, %.0f s" % (len(out), len(jobs), time.time() - t0), flush=True)
    return out


def first_solution(r):
    return next((m for m, c, _ in r["rows"] if c), None)


def chance(m, eq):
    """Keyword alphabets with m keyword letters, times the chance of passing eq random equations."""
    return math.factorial(26) / math.factorial(26 - m) / 26.0 ** eq


def summarise(tid, res):
    """One line per system; returns the totals."""
    tot = {"systems": 0, "levels": 0, "closed25": 0, "closed9": 0, "with_sol": 0, "listed": 0, "judged": 0,
           "english": 0, "best": (-99.0, 0, "", "", None), "nodes": 0}
    for s in systems():
        r = res[(tid,) + s]
        f = first_solution(r)
        cnt = dict((m, c) for m, c, _ in r["rows"])
        tot["systems"] += 1
        tot["levels"] += r["done"]
        tot["nodes"] += sum(x[2] for x in r["rows"])
        tot["closed25"] += f is None and r["done"] >= MMAX
        tot["closed9"] += (f is None or f > 9) and r["done"] >= min(9, MMAX)
        tot["with_sol"] += f is not None
        tot["listed"] += r["listed"]
        tot["judged"] += r["judged"]
        tot["english"] += r["english"]
        if r["top"] and r["top"][0][0] > tot["best"][0]:
            tot["best"] = r["top"][0] + (s,)
        if f is None:
            what = "0 solutions"
        else:
            what = "first solutions at m=%d: %s" % (f, ", ".join(
                "m=%d:%d" % (m, cnt[m]) for m in range(f, min(f + 4, r["done"] + 1))))
            what += "; chance predicts %.2g at m=%d" % (chance(f, r["eq"]), f)
            what += "; read all %d at m<=%d" % (r["listed"], r["list_m"])
            if r["top"]:
                what += ", best English %.2f over %d quadgrams (%s)" % (
                    r["top"][0][0], r["top"][0][1], minimal_keyword(r["top"][0][2]))
        print("  %-8s %-5s %-4s %-5s n=%-2d eq=%-2d decided to m=%-2d %s" % (
            (tid,) + s[:3] + (s[3], r["eq"], r["done"], "(impossible) " + what if r["imp"] else what)))
    return tot


def table(tid, res, lay, form, rule, ms=(3, 5, 7, 9, 12, 15, 20, 25)):
    print("  solutions per (length, m) for %s %s %s on %s ('-' = level not reached)" % (lay, form, rule, tid))
    print("    n  eq  " + " ".join("m=%-9d" % m for m in ms))
    for n in LENGTHS:
        r = res[(tid, lay, form, rule, n)]
        cnt = dict((m, c) for m, c, _ in r["rows"])
        print("   %2d  %2d  " % (n, r["eq"]) + " ".join(
            "%-11s" % ("-" if m not in cnt else ("%d" % cnt[m] if cnt[m] < 10 ** 9 else "%.1e" % cnt[m])) for m in ms))


def planted_cases(rng):
    rnd = "".join(rng.sample("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 6))
    cases = [(kw, "M/M", "beau", "rep", L) for kw in ("SANBORN", "SCHEIDT", rnd) for L in (13, 19, 23)]
    cases += [("PALIMPCEST", "M/M", "beau", "slide", 7), ("SCHEIDT", "M/KR", "vig", "rep", 19),
              ("WELTZEITUHR", "AZ/M", "beau", "rep", 13)]
    texts, meta = {}, []
    for j, (kw, lay, form, rule, n) in enumerate(cases):
        al = keyword_alphabet(kw)
        pt = english97(rng)
        pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(pt))
        word = [rng.randrange(26) for _ in range(n)]
        tid = "planted%d" % j
        texts[tid] = (encrypt(pt, al, lay, form, rule, word), CRIBS)
        meta.append((tid, kw, al, pt, (lay, form, rule, n)))
    return texts, meta


if __name__ == "__main__":
    t0 = time.time()
    seeds = (1,) if SMOKE else (1, 2, 3)
    rng = random.Random(86)
    ptexts, pmeta = planted_cases(rng)
    texts = {"K4": (K4, CRIBS)}
    for s in seeds:
        texts["shuf%d" % s] = (shuffled_control(s), CRIBS)
    texts.update(ptexts)
    jobs = [(tid,) + s for tid in ["K4"] + ["shuf%d" % s for s in seeds] for s in systems()]
    jobs += [(tid,) + s for tid, _, _, _, s in pmeta]
    with Experiment("any keyword alphabet solved from its alphabetical tail (no dictionary)", puzzle="k4",
                    notes="keyword of m = 1..%d different letters in any order then A-Z; Quagmire III/I/II "
                          "(M/M, M/AZ, M/KR, AZ/M, KR/M), Vigenere and Beaufort forms; repeating key 1-26 and "
                          "sliding key period 1-26; exact; up to %d steps per system" % (MMAX, NODES),
                    cribs_forced=True) as ex:
        with Pool(None, initializer=init, initargs=(texts,)) as pool:
            res = run(pool, jobs)
        print("systems per text: %d (%d layouts x 2 forms x 2 key rules x %d lengths); %.0f s" % (
            len(systems()), len(LAYOUTS), len(LENGTHS), time.time() - t0))
        totals = {}
        for tid in ["K4"] + ["shuf%d" % s for s in seeds]:
            print("\n== %s" % tid)
            totals[tid] = summarise(tid, res)
        print()
        for tid in ["K4"] + ["shuf%d" % s for s in seeds]:
            table(tid, res, "M/M", "beau", "rep")
        print("  chance estimate for M/M beau rep on K4: keyword alphabets at level m / 26^equations")
        print("    n  eq  " + " ".join("m=%-9d" % m for m in (3, 5, 7, 9, 12, 15, 20, 25)))
        for n in LENGTHS:
            e = res[("K4", "M/M", "beau", "rep", n)]["eq"]
            print("   %2d  %2d  " % (n, e) + " ".join("%-11.2g" % chance(m, e) for m in (3, 5, 7, 9, 12, 15, 20, 25)))
        table("K4", res, "M/M", "beau", "slide")
        table("K4", res, "M/M", "vig", "slide")
        print("\nTOTALS (per text: systems, levels (system, m) decided, systems with 0 solutions up to m=%d, systems "
              "with 0 solutions up to m=9, systems with solutions, solutions read, of those with %d+ quadgrams "
              "outside the clues, readings above %.1f, best reading)" % (MMAX, MIN_Q, ENGLISH))
        for tid, t in totals.items():
            b = t["best"]
            print("  %-6s systems=%d levels=%d closed_to_%d=%d closed_to_9=%d with_solutions=%d read=%d judged=%d "
                  "english=%d steps=%d best=%.2f over %d quadgrams, keyword %s, %s\n         %s" % (
                      tid, t["systems"], t["levels"], MMAX, t["closed25"], t["closed9"], t["with_sol"], t["listed"],
                      t["judged"], t["english"], t["nodes"], b[0], b[1], minimal_keyword(b[2]) if b[2] else "-",
                      b[4], b[3]))
        k4 = totals["K4"]
        ex.count(k4["levels"])
        for s in systems():
            for sc, cnt, al, pt in res[("K4",) + s]["top"][:2]:
                if "." not in pt:
                    ex.add(pt, system=" ".join(map(str, s)), keyword=minimal_keyword(al))
        ok = 0
        print("\nPLANTED")
        for tid, kw, al, pt, s in pmeta:
            r = res[(tid,) + s]
            mine = dict(r["all"] or []).get(al)
            listed = mine is not None
            # rank among different scores: several alphabets can give the same reading
            rank = 1 + len({sc for _, sc in r["all"] if sc > mine}) if listed else None
            top = r["top"][0] if r["top"] else (-99.0, 0, "", "")
            good = listed and rank == 1 and top[0] > ENGLISH
            ok += good
            cnt = dict((m, c) for m, c, _ in r["rows"])
            m0 = len(minimal_keyword(al))
            print("  %-11s (%d letters) %s: listed=%s, %d solutions at m=%d (chance predicts %.2g), read %d at m<=%d, "
                  "rank by English %s, score %.2f -> %s" % (
                      kw, m0, " ".join(map(str, s)), listed, cnt.get(m0, -1), m0, chance(m0, r["eq"]), r["listed"],
                      r["list_m"], rank, top[0], "FOUND" if good else "MISSED"))
            if good:
                print("       " + top[3])
        print("planted recovered: %d/%d" % (ok, len(pmeta)))
        cb = max(totals[t]["best"][0] for t in totals if t != "K4")
        hit = k4["english"] > 0 and k4["best"][0] > cb
        print("VERDICT:", "ENGLISH READING - inspect by hand" if hit else
              "no signal (K4 best reading %.2f, shuffled best %.2f, English needs %.1f; K4 readings above the bar: %d)" % (
                  k4["best"][0], cb, ENGLISH, k4["english"]))
        print("total %.0f s" % (time.time() - t0))
