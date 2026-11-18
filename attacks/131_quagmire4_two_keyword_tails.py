"""Idea 131: Quagmire IV where both alphabets come from keywords that need not be words.

Scheidt said K4 runs "with the correct key word/s". In a Quagmire IV the plain and cipher alphabets
would then be keyword alphabets, but the keywords need not be dictionary words (K1's PALIMPCEST was
a misspelling). Idea 113 searched Quagmire IV at key length 8 with both alphabets completely free
and had no power (about 1e8 settings, planted 1/4). Idea 86 showed that one keyword alphabet can be
solved exactly from its alphabetical tail, with no word list. This script does the same for TWO
keyword alphabets at once, which gives the both-hidden Quagmire IV the strong prior it lacked.

Model (per side, independently): a keyword of m = 1..9 different letters, then the other letters in
A-Z order ("kw"); or that alphabet written in rows of m and read off by columns ("cols", round 11's
first transposition-mixed form). Key: repeating, length L = 1..16, Vigenere form c(C) - p(P) = k
and Beaufort form c(C) + p(P) = k. Every pair of alphabets that meets all clue equations is found
exactly by `kryptos/idea131_two.py` (idea 86's solver extended to two sides; checked against brute
force in tests/test_idea_131.py). For "kw" a level m includes every shorter keyword, so only the
largest m of each cell is run; "cols" depends on m itself, so every m = 3..9 is run.

Cells: the plan says to run only (L, m1, m2) where the expected number of chance solutions,
P(26,m1) * P(26,m2) / 26^equations, is below 1 ("decisive"). Those are run in full. Cells with
1 <= expected < EXT are also run with a step budget ("extended"): a chance solution is expected
there, so they are judged by reading, not by counting.

Reading: every solution found is completed (letters in no equation fill the rest of each keyword
in every possible way, capped per side), decrypted with the key the clues force, and scored on the
big quadgram model outside the clue words (idea 86's measure; English needs about -5.1).

Controls: 3 shuffled K4s drawn as idea 113 drew them (same loop structure at key length 8).
Planted: 4 English messages with the clue words in place: random 6- and 8-letter non-word keywords
at key 8 (two layouts), SANBORN with a misspelled KRYPTOS (KRIPTOS) at key 11 (two layouts). Each
text runs through the same cells as K4 at its key length and both forms, and the true reading
must rank first among all readings of that text.

Not covered: keywords of more than 9 letters, the keyed-column transposition form, alphabets not
built from keywords, sliding or other key rules, key lengths over 16.

  python attacks/131_quagmire4_two_keyword_tails.py [--prefilter]
"""
import random
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea113_both as B113  # noqa: E402
from kryptos import idea131_two as T  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea86_tail import Budget, extra_score, keyword_alphabet  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, english97  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LENGTHS = (8, 11, 13) if SMOKE else tuple(range(1, 17))
MMAX = 7 if SMOKE else 9
EXT = 100                                   # extended cells: 1 <= expected chance solutions < EXT
NODES_DEC = 10 ** 9                         # decisive cells: run to the end
NODES_EXT = 10 ** 7                         # extended cells: step budget
KEEP = 400                                  # solutions (leaves) kept and read per cell
SIDE_CAP = 30000                            # completions listed per side per leaf
READ_SEC = 150                              # reading time allowed per cell
ENGLISH = -5.1
MIN_Q = 20
LAYOUTS = (("kw", "kw"), ("kw", "cols"), ("cols", "kw"), ("cols", "cols"))
FORMS = ("vig", "beau")
_S = {}


def prefilter_encrypt(pt, rng):
    w1 = "".join(rng.sample(AZ, rng.randint(3, 9)))
    w2 = "".join(rng.sample(AZ, rng.randint(3, 9)))
    L = rng.randint(1, 16)
    key = [rng.randrange(26) for _ in range(L)]
    return T.encrypt(pt, keyword_alphabet(w1), keyword_alphabet(w2), rng.choice(FORMS), key)


def ms_range(f):
    return range(1, MMAX + 1) if f == "kw" else range(3, MMAX + 1)


def cells(neq, layout, lo, hi):
    """(m1, m2) with lo <= expected chance solutions < hi; a 'kw' side keeps only its largest m
    (smaller keywords are included in it)."""
    def ok(a, b):
        return a <= MMAX and b <= MMAX and T.chance((a, b), neq) < hi
    out = []
    for a in ms_range(layout[0]):
        for b in ms_range(layout[1]):
            if not ok(a, b):
                continue
            if layout[0] == "kw" and ok(a + 1, b):
                continue
            if layout[1] == "kw" and ok(a, b + 1):
                continue
            if T.chance((a, b), neq) >= lo or lo == 0:
                out.append((a, b))
    return out


def init(texts):
    _S["texts"] = texts
    _S["big"] = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")


def best_reading(ct, cribs, L, form, plains, ciphers):
    """Coordinate ascent over the two completion lists; returns (score, quadgrams, pt, pa, ca)."""
    big = _S["big"]

    def sc(pa, ca):
        pt = T.decrypt(ct, pa, ca, form, L, cribs)
        if pt is None:
            return (-99.0, 0, "", pa, ca)
        s, n = extra_score(pt, big)
        return ((s if s is not None and n >= MIN_Q else -99.0), n, pt, pa, ca)

    best = None
    for start in {0, len(ciphers) // 2}:
        ca = ciphers[start]
        cur = max((sc(pa, ca) for pa in plains), key=lambda r: r[0])
        for _ in range(3):
            nxt = max((sc(cur[3], c) for c in ciphers), key=lambda r: r[0])
            nxt = max((sc(p, nxt[4]) for p in plains), key=lambda r: r[0])
            if nxt[0] <= cur[0]:
                break
            cur = nxt
        if best is None or cur[0] > best[0]:
            best = cur
    return best


def job(arg):
    tid, L, form, layout, ms, kind = arg
    ct, cribs = _S["texts"][tid]
    eqs, _ = T.equations(ct, cribs, L, form)
    t0 = time.time()
    try:
        r = T.solve(eqs, ms, layout, NODES_DEC if kind == "dec" else NODES_EXT, KEEP)
        done = True
    except Budget:
        return {"arg": arg, "eq": len(eqs), "done": False, "count": None, "nodes": None, "read": 0,
                "all_read": False, "top": [], "sec": time.time() - t0}
    reads, all_read = [], len(r["partials"]) >= r["count"] or len(r["partials"]) < KEEP
    for part in r["partials"]:
        if time.time() - t0 > READ_SEC:
            all_read = False
            break
        pl, cl = T.expand(part, ms, layout, SIDE_CAP)
        if part["count"][0] > len(pl) or part["count"][1] > len(cl):
            all_read = False
        reads.append(best_reading(ct, cribs, L, form, pl, cl))
    reads.sort(key=lambda x: -x[0])
    return {"arg": arg, "eq": len(eqs), "done": done, "count": r["count"], "nodes": r["nodes"],
            "read": len(reads), "all_read": all_read, "top": reads[:3], "sec": time.time() - t0}


def jobs_for(tid, lengths):
    out = []
    ct, cribs = _texts_cache[tid]
    for L in lengths:
        for form in FORMS:
            neq = len(T.equations(ct, cribs, L, form)[0])
            for lay in LAYOUTS:
                for ms in cells(neq, lay, 0, 1):
                    out.append((tid, L, form, lay, ms, "dec"))
                for ms in cells(neq, lay, 1, EXT):
                    out.append((tid, L, form, lay, ms, "ext"))
    # slow cells first so the pool stays busy
    out.sort(key=lambda a: -(a[1] == 8) * (a[4][0] + a[4][1]))
    return out


def plant(rng, w1, w2, L, form, layout, want):
    """English message, keyword alphabets w1 / w2 in the given layout, random key of L; for key 8
    redrawn until the clue letters have K4's structure (as idea 113's plants)."""
    pt = english97(rng)
    pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(pt))
    m1, m2 = len(set(w1)), len(set(w2))
    pa = T.apply_form(keyword_alphabet(w1), layout[0], m1)
    ca = T.apply_form(keyword_alphabet(w2), layout[1], m2)
    for _ in range(20000):
        key = [rng.randrange(26) for _ in range(L)]
        ct = T.encrypt(pt, pa, ca, form, key)
        if L != 8:
            break
        sy = B113.System(ct, CRIBS, 0)
        if sy.shape() == want and sy.open_checks():
            break
    return ct, pt, pa, ca, (m1, m2)


_texts_cache = {}


def clash(ct, L, cribs=CRIBS):
    """True if some clue equation at key length L has only two places on one side (cannot hold)."""
    return any(len(e[0]) < 4 for f in FORMS for e in T.equations(ct, cribs, L, f)[0])


def summarise(tid, res):
    rows = [r for r in res if r["arg"][0] == tid]
    tot = {"dec": 0, "dec_sol": 0, "ext": 0, "ext_sol": 0, "ext_budget": 0, "read": 0, "english": 0,
           "best": (-99.0, 0, "", "", "", None), "nodes": 0, "dec_with": [], "all_read": True}
    for r in rows:
        k = r["arg"][5]
        tot[k] += 1
        if not r["done"]:
            tot["ext_budget"] += 1
            continue
        tot["nodes"] += r["nodes"]
        tot[k + "_sol"] += r["count"]
        if k == "dec" and r["count"]:
            tot["dec_with"].append((r["arg"][1:5], r["count"]))
        tot["read"] += r["read"]
        tot["all_read"] &= r["all_read"]
        for x in r["top"]:
            if x[0] > ENGLISH:
                tot["english"] += 1
        if r["top"] and r["top"][0][0] > tot["best"][0]:
            tot["best"] = r["top"][0] + (r["arg"][1:5],)
    return tot


def per_length(tid, res):
    print("  %s: per key length (decisive cells / alphabet pairs found; extended cells / pairs / over budget)" % tid)
    for L in LENGTHS:
        d = [r for r in res if r["arg"][0] == tid and r["arg"][1] == L]
        dec = [r for r in d if r["arg"][5] == "dec"]
        ext = [r for r in d if r["arg"][5] == "ext"]
        print("    L=%-2d eq=%-2d  dec %3d cells %6d pairs   ext %3d cells %8d pairs %3d over budget   best %.2f" % (
            L, d[0]["eq"] if d else -1, len(dec), sum(r["count"] for r in dec if r["done"]), len(ext),
            sum(r["count"] for r in ext if r["done"]), sum(1 for r in ext if not r["done"]),
            max([r["top"][0][0] for r in d if r["top"]] or [-99])))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("Quagmire IV, two non-word keyword alphabets, repeating key 1-16", encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "two keyword alphabets on paper, a repeating key")})
        sys.exit()
    t0 = time.time()
    want = B113.System(K4, CRIBS, 0).shape()
    texts = {"K4": (K4, CRIBS)}
    # Controls must be as open as K4: no direct clash (same cipher letter in the same key slot over
    # two different plain letters, or the reverse) at any key length where K4 has none, and idea 113's
    # loop structure at key 8. Plain shuffles mostly clash at once and would be no test at all.
    open_k4 = [L for L in range(1, 17) if not clash(K4, L)]
    seed = 13100
    for c in range(1 if SMOKE else 3):
        s = seed + 1
        while True:
            ct = shuffled_control(s)
            if not any(clash(ct, L) for L in open_k4):
                sy = B113.System(ct, CRIBS, 0)
                if sy.shape() == want and sy.open_checks():
                    break
            s += 1
        seed = s
        texts["shuf%d(seed %d)" % (c + 1, s)] = (ct, CRIBS)
    rng = random.Random(131)
    r6, r8 = "".join(rng.sample(AZ, 6)), "".join(rng.sample(AZ, 8))
    pcases = [(r6, r8, 8, "vig", ("kw", "kw")), (r8, r6, 8, "beau", ("cols", "kw")),
              ("SANBORN", "KRIPTOS", 11, "beau", ("kw", "kw")), ("KRIPTOS", "SANBORN", 11, "vig", ("kw", "cols"))]
    if SMOKE:
        pcases = [(r6, "SANBORN", 8, "vig", ("kw", "kw")), ("SANBORN", "KRIPTOS", 11, "beau", ("kw", "cols"))]
    pmeta = []
    for j, (w1, w2, L, form, lay) in enumerate(pcases):
        ct, pt, pa, ca, ms = plant(rng, w1, w2, L, form, lay, want)
        tid = "planted%d" % (j + 1)
        texts[tid] = (ct, CRIBS)
        pmeta.append((tid, w1, w2, L, form, lay, ms, pt, pa, ca))
    _texts_cache.update(texts)
    controls = [t for t in texts if t.startswith("shuf")]
    jobs = []
    for tid in ["K4"] + controls:
        jobs += jobs_for(tid, LENGTHS)
    for tid, w1, w2, L, form, lay, ms, *_ in pmeta:
        jobs += jobs_for(tid, (L,))
    print("jobs: %d (texts %d)" % (len(jobs), len(texts)), flush=True)
    with Experiment("Quagmire IV, two non-word keyword alphabets (kw / column-mixed), repeating key 1-16",
                    puzzle="k4", cribs_forced=True,
                    notes="both alphabets keyword alphabets of m=1..%d letters (any letters, no dictionary), plain or "
                          "read off by columns of width m; Vigenere and Beaufort forms; exact two-sided tail solver; "
                          "cells with expected chance < 1 run in full, 1..%d with a step budget" % (MMAX, EXT)) as ex:
        res = []
        with Pool(None, initializer=init, initargs=(texts,)) as pool:
            for r in pool.imap_unordered(job, jobs, chunksize=1):
                res.append(r)
                if len(res) % 200 == 0:
                    print("  ... %d/%d jobs, %.0f s" % (len(res), len(jobs), time.time() - t0), flush=True)
        print("all jobs %.0f s" % (time.time() - t0))
        totals = {}
        for tid in ["K4"] + controls:
            totals[tid] = summarise(tid, res)
            per_length(tid, res)
        print("\nTOTALS")
        for tid, t in totals.items():
            b = t["best"]
            cov = word_coverage(b[2]) if b[2] and "." not in b[2] else None
            print("  %-18s decisive cells %d with %d alphabet pairs %s; extended cells %d (over budget %d) with %d pairs;"
                  " leaves read %d (all completions read: %s); readings above %.1f: %d; steps %d" % (
                      tid, t["dec"], t["dec_sol"], t["dec_with"][:6], t["ext"], t["ext_budget"], t["ext_sol"],
                      t["read"], t["all_read"], ENGLISH, t["english"], t["nodes"]))
            print("      best %.3f over %d quadgrams at %s, coverage %s\n      %s\n      plain %s cipher %s" % (
                b[0], b[1], b[5], "%.2f" % cov if cov is not None else "-", b[2], b[3], b[4]))
        k4 = totals["K4"]
        ex.count(sum(1 for r in res if r["arg"][0] == "K4"))      # solver cells run on K4
        for r in res:
            if r["arg"][0] == "K4":
                for x in r["top"][:1]:
                    if x[2] and "." not in x[2]:
                        ex.add(x[2], system=str(r["arg"][1:5]), plain=x[3], cipher=x[4])
        print("\nPLANTED")
        ok = 0
        for tid, w1, w2, L, form, lay, ms, pt, pa, ca in pmeta:
            rr = [r for r in res if r["arg"][0] == tid and r["done"]]
            alltops = sorted((x for r in rr for x in r["top"]), key=lambda x: -x[0])
            mine = [r for r in rr if r["arg"][2] == form and r["arg"][3] == lay and
                    r["arg"][4][0] >= ms[0] and r["arg"][4][1] >= ms[1] and
                    (lay[0] == "kw" or r["arg"][4][0] == ms[0]) and (lay[1] == "kw" or r["arg"][4][1] == ms[1])]
            top = alltops[0] if alltops else (-99, 0, "", "", "")
            agree = sum(a == b for a, b in zip(top[2], pt))
            good = agree >= 95
            ok += good
            print("  %s: %s / %s (m %d, %d), key %d, %s, %s: true cells %s; %d readings, best %.3f agrees %d/97 -> %s" % (
                tid, w1, w2, ms[0], ms[1], L, form, "/".join(lay),
                [(r["arg"][4], r["count"]) for r in mine], len(alltops), top[0], agree, "FOUND" if good else "MISSED"))
            print("      " + top[2])
        print("planted recovered (true reading ranked first of all readings of its text): %d/%d" % (ok, len(pmeta)))
        cb = max(totals[t]["best"][0] for t in controls)
        hit = k4["english"] > 0 and k4["best"][0] > cb
        print("VERDICT:", "ENGLISH READING - inspect by hand" if hit else
              "no signal (K4 best %.3f, shuffled best %.3f, English needs %.1f; K4 decisive pairs %d)" % (
                  k4["best"][0], cb, ENGLISH, k4["dec_sol"]))
        print("total %.0f s" % (time.time() - t0))
