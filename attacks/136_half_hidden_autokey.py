"""Idea 136: plaintext autokey 5-12 letters back (7-12 ahead) on a half-hidden tableau.

Idea 117 left plaintext autokey at lags 5-12 back and 7-12 ahead alive on every Latin-square tableau. Ideas 90 and
100 tested it only on tableaux whose two sides are both known. This run tests the case between: one side of the
tableau is a dictionary keyword alphabet (what Scheidt would know), the other is written down freely (Sanborn's
"modified so Scheidt couldn't decipher it").

  pos_c(C_i) = pos_p(P_i) + s * num(F_i) + c        F_i = P_{i-d} (back) or P_{i+d} (ahead), primer at the edge

s = +1 or -1 covers Vigenere, Beaufort and the variant (the free alphabet read back to front). The fed letter is
numbered on the plain alphabet, on A-Z or on KRYPTOS.

  layout "plain-known"  : plain alphabet = one of 666,993 dictionary alphabets, cipher alphabet free.
  layout "cipher-known" : cipher alphabet = a dictionary alphabet, plain alphabet free, c unknown.

The test is exact (kryptos/idea136_half.py). Every two clue letters of one class mod d, joined by the run of
cipher letters between them, give one equation. With the fed letter numbered on the plain alphabet the equation is
linear in the free side's places even across the 29-letter gap (cipher-known: in the 13 clue plain letters and c;
plain-known: in the cipher letters along the run). With A-Z or KRYPTOS numbering only the one-step links are linear
(both letters in the clues): a collision check on forced places. The left null space of each cell's system gives
checks that are linear in the dictionary alphabet's 26 places, so each alphabet costs a few sums; alphabets that
pass are solved with all letters in different places (idea 93's solver).

How many chance passes each cell allows is printed (a bound from the check ranks times the measured share of
consistent systems with distinct places). Cells are then handled by that number:
  A  under 0.5 chance passes: decided exactly;
  B  up to 350: every pass is listed and read on the big English model (quick pass, long pass for the best);
  C  more, but at least one check: passes are only counted (K4 against the controls);
  D  no check at all (most lags 8-12 ahead on the plain-known side, A-Z/KRYPTOS numbering at long lags): not run.

Reading: a beam search decodes the text in key-feed order with the clue letters as constraints (a missed clue
letter costs a penalty), then simulated annealing polishes the free alphabet (kryptos/idea136_half.py: read).

Controls: 3 shuffled K4s on all alphabets. Planted (searched, each among 9,000 alphabets, found and read back):
plain-known lag 7 back (plain numbering), cipher-known lag 9 ahead, cipher-known lag 5 back (A-Z numbering).
Read back only (5 each, not searched): plain-known lag 9 ahead and cipher-known lag 11 back (the plan's other two,
tiers D and C), and plain-known lag 7 back/ahead with A-Z numbering (to measure how well those cells read).

  python attacks/136_half_hidden_autokey.py
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
from kryptos import idea136_half as H  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import dictionary_alphabets, pmap  # noqa: E402
from kryptos.score import word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA136_PROCS", "4" if SMOKE else "12"))
NCTRL = 1 if SMOKE else 3
TIER_A, TIER_B = 0.5, 350.0
QUICK = (150, 800)             # beam width, annealing steps for every listed pass
DEEP = (800, 3000)             # for the best readings
NDEEP = 25 if not SMOKE else 4
ENGLISH = -5.1                 # big-model mean per quadgram that English reaches (planted: about -4.5)
BIG = DATA_DIR / "english" / "quadgrams_big.txt"
OUT = Path(__file__).resolve().parent.parent / "results" / "idea136_summary.json"
G = {}


# ---------------------------------------------------------------- tiers

def tiers(ct=K4, rng=None, n=666993):
    rng = rng or random.Random(136)
    out = {}
    for cell in H.cells():
        c = H.Cell(cell, ct)
        if c.dead:
            out[cell] = ("dead", 0.0, c)
            continue
        if c.r13 + c.r2 == 0:
            out[cell] = ("D", float("inf"), c)
            continue
        est = c.chance(n) * H.distinct_factor(c, rng, n=200)
        out[cell] = ("A" if est < TIER_A else "B" if est <= TIER_B else "C", est, c)
    return out


# ---------------------------------------------------------------- the exact scan (workers)

def init(cts, cells_ab, cells_c):
    """cells_ab / cells_c: one list of cells per text (each text has its own tiers)."""
    G["cts"] = cts
    G["ab"] = [[H.Cell(cell, ct) for cell in ab] for ct, ab in zip(cts, cells_ab)]
    G["c"] = [[H.Cell(cell, ct) for cell in cc] for ct, cc in zip(cts, cells_c)]


def work(chunk):
    hits, counts = [], Counter()
    for nm, M in chunk:
        pos = [M.index(ch) for ch in AZ]
        for t, (ab, cc) in enumerate(zip(G["ab"], G["c"])):
            for j, c in enumerate(ab):
                if c.consistent(pos):
                    st, sols = c.solve(pos, max_points=2000, max_sols=64)
                    if st != "none":
                        hits.append((t, j, nm, M, st, sols))
            for j, c in enumerate(cc):
                if c.consistent(pos):
                    counts[(t, j)] += 1
    return hits, counts, len(chunk)


def scan(cts, cells_ab, cells_c, alphas, procs=PROCS, chunk=2000):
    hits, counts, done = [], Counter(), 0
    t0 = time.time()
    for h, cn, n in pmap(work, alphas, init, (cts, cells_ab, cells_c), chunk=chunk, procs=procs):
        hits += h
        counts.update(cn)
        done += n
        if done % 100000 < chunk:
            print("   scanned %d/%d alphabets, %d passes listed, %.0fs" % (done, len(alphas), len(hits),
                                                                         time.time() - t0), flush=True)
    return hits, counts


# ---------------------------------------------------------------- English completion (workers)

def init_read(cts):
    G["cts"] = cts
    G["big"] = H.Big(BIG)


def read_one(job, steps):
    t, cell, nm, M, st, sols, seed = job
    ct = G["cts"][t]
    rng = random.Random(seed)
    r = H.read(cell, ct, M, H.starts_from(cell, sols, M, ct), G["big"], rng, width=steps[0], iters=steps[1])
    return (t, cell, nm, st) + tuple(r)


def work_read(chunk):
    return [_read(j) for j in chunk]


def _read(job):
    *core, steps = job
    return read_one(tuple(core), steps)


def read_all(cts, jobs, procs=PROCS):
    out = []
    for r in pmap(work_read, jobs, init_read, (cts,), chunk=20, procs=procs):
        out += r
    return out


# ---------------------------------------------------------------- planted answers

def plant(rng, cell, alphas, n_alpha=None):
    """Encrypt an English text with a dictionary alphabet on the known side and a random free side; return the
    ciphertext, the true alphabet name and an alphabet list of n_alpha that holds it."""
    n_alpha = n_alpha or (2000 if SMOKE else 9000)
    pt = H.plant_text(rng)
    sample = rng.sample(alphas[1:], n_alpha - 1)
    nm, M = rng.choice(sample)
    free = H.random_alphabet(rng)
    mp, mc = (M, free) if cell[0] == "P" else (free, M)
    c = rng.randrange(26) if cell[0] == "C" else 0
    primer = "".join(rng.choice(AZ) for _ in range(cell[3]))
    ct = H.encrypt(pt, cell, mp, mc, c, primer)
    return pt, ct, nm, M, [("(A-Z)", AZ)] + sample


def planted_search(rng, alphas, cell):
    pt, ct, nm, M, al = plant(rng, cell, alphas)
    hits, _ = scan([ct], [[cell]], [[]], al, procs=PROCS, chunk=500)
    names = {h[2] for h in hits}
    found = nm in names
    jobs = [(h[0], cell, h[2], h[3], h[4], h[5], rng.randrange(10 ** 9), QUICK) for h in hits]
    reads = read_all([ct], jobs)
    reads.sort(key=lambda r: -r[4])
    best = None
    for r in reads[:3]:
        h = next(x for x in hits if x[2] == r[2])
        rr = _readlocal(ct, cell, h, rng)
        if best is None or rr[0] > best[0]:
            best = rr + (r[2],)
    agree = sum(a == b for a, b in zip(best[1], pt)) if best else 0
    ok = found and best is not None and best[-1] == nm and agree >= 85
    return {"cell": H.name(cell), "true": nm, "found": found, "passes": len(hits), "best_alphabet": best and best[-1],
            "score": best and round(best[0], 2), "agree": agree, "ok": ok, "pt": pt, "read": best and best[1]}


def _readlocal(ct, cell, h, rng):
    big = G.setdefault("big_main", H.Big(BIG))
    t, j, nm, M, st, sols = h
    return H.read(cell, ct, M, H.starts_from(cell, sols, M, ct), big, rng, width=DEEP[0], iters=DEEP[1])


def planted_readback(rng, alphas, cell):
    """Tier C/D cells: the true setting passes the exact test and reads back (no search)."""
    pt, ct, nm, M, al = plant(rng, cell, alphas, n_alpha=10)
    c = H.Cell(cell, ct)
    st, sols = c.solve([M.index(ch) for ch in AZ], max_points=2000, max_sols=64)
    r = _readlocal(ct, cell, (0, 0, nm, M, st, sols), rng)
    agree = sum(a == b for a, b in zip(r[1], pt))
    return {"cell": H.name(cell), "passes_exact": st != "none", "agree": agree, "score": round(r[0], 2)}


# ---------------------------------------------------------------- main

def main():
    t0 = time.time()
    alphas = dictionary_alphabets(mixed=True)
    print("alphabets: %d" % len(alphas))
    cts = [K4] + [shuffled_control(1000 + k) for k in range(NCTRL)]
    labels = ["K4"] + ["shuffled #%d" % (k + 1) for k in range(NCTRL)]
    tks = [tiers(ct, n=len(alphas)) for ct in cts]
    tk = tks[0]
    print("K4 cells by tier: " + ", ".join("%s %d" % (k, v) for k, v in sorted(Counter(v[0] for v in tk.values()).items())))
    print("\nchance passes allowed per cell (bound x distinct share), all %d alphabets (K4's clue letters):" % len(alphas))
    for cell, (tier, est, c) in tk.items():
        print("  %-32s eq %2d  checks %d/%d  chance %-9.3g tier %s" % (H.name(cell), c.n_eq, c.r13, c.r2, est, tier))
    sys.stdout.flush()

    # planted answers first: the script must find them
    rng = random.Random(1360)
    planted = []
    for cell in (("P", "M", "back", 7, 1), ("C", "M", "ahead", 9, -1), ("C", "AZ", "back", 5, 1)):
        r = planted_search(rng, alphas, cell)
        planted.append(r)
        print("planted %-30s true %-22s found %s passes %d best %s score %s agree %d/97 -> %s"
              % (r["cell"], r["true"], r["found"], r["passes"], r["best_alphabet"], r["score"], r["agree"],
                 "OK" if r["ok"] else "MISSED"))
    readback = [planted_readback(rng, alphas, cell) for cell in
                (("P", "M", "ahead", 9, 1), ("C", "M", "back", 11, 1), ("P", "AZ", "ahead", 7, -1), ("P", "AZ", "back", 7, -1))
                for _ in range(1 if SMOKE else 5)]
    for r in readback:
        print("read-back only %-28s passes exact %s agree %d/97 score %s" % (r["cell"], r["passes_exact"],
                                                                             r["agree"], r["score"]))
    n_ok = sum(r["ok"] for r in planted)
    if n_ok < len(planted):
        print("PLANTED ANSWER MISSED: %d/%d" % (n_ok, len(planted)))

    # the scan: K4 and controls, each text with its own tiers
    cells_ab = [[c for c, v in t.items() if v[0] in "AB"] for t in tks]
    cells_c = [[c for c, v in t.items() if v[0] == "C"] for t in tks]
    for lab, ab, cc in zip(labels, cells_ab, cells_c):
        print("%-12s %d cells listed (A+B), %d counted (C)" % (lab, len(ab), len(cc)))
    hits, counts = scan(cts, cells_ab, cells_c, alphas)
    tested = len(alphas) * sum(len(a) + len(c) for a, c in zip(cells_ab, cells_c))
    k4_tested = len(alphas) * (len(cells_ab[0]) + len(cells_c[0]))

    pc = Counter((h[0], h[1]) for h in hits)
    table = []
    for t in range(len(cts)):
        for j, cell in enumerate(cells_ab[t]):
            table.append({"text": labels[t], "cell": H.name(cell), "tier": tks[t][cell][0],
                          "chance": tks[t][cell][1], "passes": pc[(t, j)]})
        for j, cell in enumerate(cells_c[t]):
            table.append({"text": labels[t], "cell": H.name(cell), "tier": "C", "chance": tks[t][cell][1],
                          "passes": counts[(t, j)], "consistent_only": True})
    print("\npasses per cell (A/B: distinct solutions; C: consistent only), K4:")
    for row in table:
        if row["text"] == "K4":
            print("  %-32s %s chance %-9.3g passes %6d" % (row["cell"], row["tier"], row["chance"], row["passes"]))
    print("\ntotals per text and tier: passes (expected by chance)")
    for lab in labels:
        parts = []
        for tier in "ABC":
            rows = [r for r in table if r["text"] == lab and r["tier"] == tier]
            parts.append("%s %d (%.1f, %d cells)" % (tier, sum(r["passes"] for r in rows),
                                                     sum(r["chance"] for r in rows), len(rows)))
        print("  %-12s %s" % (lab, "   ".join(parts)))

    # read every listed pass (tiers A and B)
    rng = random.Random(7)
    jobs = [(h[0], cells_ab[h[0]][h[1]], h[2], h[3], h[4], h[5], rng.randrange(10 ** 9), QUICK) for h in hits]
    print("\nreading %d listed passes (quick)" % len(jobs), flush=True)
    reads = read_all(cts, jobs)
    best_by_t = defaultdict(list)
    for r in reads:
        best_by_t[r[0]].append(r)
    deep_jobs = []
    for t in range(len(cts)):
        best_by_t[t].sort(key=lambda r: -(r[4] - 0.05 * r[6]))
        for r in best_by_t[t][:NDEEP]:
            h = next(x for x in hits if x[0] == t and cells_ab[t][x[1]] == r[1] and x[2] == r[2])
            deep_jobs.append((t, r[1], r[2], h[3], h[4], h[5], rng.randrange(10 ** 9), DEEP))
    print("deep reading %d" % len(deep_jobs), flush=True)
    deep = read_all(cts, deep_jobs)
    summary = {}
    with Experiment("idea136-half-hidden-autokey", puzzle="k4", cribs_forced=True,
                    notes="idea 136: plain autokey lag 5-12 back / 7-12 ahead, one dictionary alphabet + one free "
                          "side, exact linear clue checks + big-model completion; K4 vs 3 shuffled") as ex:
        ex.count(tested)
        for t in range(len(cts)):
            rs = sorted([r for r in deep if r[0] == t] or best_by_t[t], key=lambda r: -r[4])
            top = rs[0] if rs else None
            summary[labels[t]] = {
                "listed_passes": len(best_by_t[t]),
                "best": None if top is None else {
                    "cell": H.name(top[1]), "alphabet": top[2], "score": round(top[4], 3), "mismatches": top[6],
                    "coverage": round(word_coverage(top[5]), 2), "text": top[5]}}
            if t == 0:
                for r in rs[:50]:
                    ex.add(r[5], cell=H.name(r[1]), alphabet=r[2], mismatches=r[6], free=r[7])
    print("\nbest readings (English needs about %.1f):" % ENGLISH)
    for k, v in summary.items():
        b = v["best"]
        if b:
            print("  %-12s passes read %5d  best %.2f cov %.2f miss %d  %s %s\n      %s"
                  % (k, v["listed_passes"], b["score"], b["coverage"], b["mismatches"], b["cell"], b["alphabet"],
                     b["text"]))
        else:
            print("  %-12s no listed passes" % k)
    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w") as f:
        json.dump({"tiers": {lab: {H.name(c): [v[0], v[1] if v[1] != float("inf") else None] for c, v in t.items()}
                             for lab, t in zip(labels, tks)}, "k4_tested": k4_tested,
                   "table": table, "planted": planted, "readback": readback, "summary": summary,
                   "tested": tested, "seconds": round(time.time() - t0)}, f, indent=1)
    print("\nplanted %d/%d; tested %d settings over all texts (K4 %d); %.0fs" % (n_ok, len(planted), tested, k4_tested, time.time() - t0))


if __name__ == "__main__":
    main()
