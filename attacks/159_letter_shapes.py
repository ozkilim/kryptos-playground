"""Idea 159: letter shapes. Is the cipher letter the plain letter with a stroke added or cut away?

Sanborn cut every letter out of copper by hand. Seven of the 24 clue pairs are the same letter or one stroke
apart in a stencil alphabet: E->F, O->Q, R->P (twice), I->T, S->S, K->K. No test here has looked at shapes.

Part A (statistic). Three shape codings fixed in kryptos/idea159_shapes.py (16-segment display, 5x7 dot
matrix, a stroke list for block capitals). For each: how many clue pairs are within one stroke, and the mean
shape distance. Compared with
  (i)    the same plain and cipher letters paired at random,
  (ii-a) same plain letter and same alphabet distance, direction (+/-) random,
  (ii-b) any letter, same alphabet distance, direction random,
  (ii-c) the same letters paired at random among pairings with the same alphabet-distance profile
         (pairs at distance 0, 1-2, 3-5, 6-13): the literal "matched for alphabet distance" control.
Each control gives a p per statistic and one corrected p for the best of the six.
GATE, fixed before the run: part B counts as called for only if the corrected p under (ii-c) is below 0.01.
Part B is cheap, so it is run either way and labelled.

Part B (model: two systems by place). At masked places the cipher letter is the plain letter with at most
one stroke changed; elsewhere an ordinary repeating key (length 1-12, Vigenere or Beaufort, A-Z / KRYPTOS
strips, key numbered by text position or by unmasked letters).
  B0  every place masked: read K4 by choosing among shape neighbours (quadgram Viterbi), no clue forced.
  B1  do the shape-near clue places form a pattern (every p-th place, p 2-31, which includes carved columns
      at p = 31)? Against the same number of near places thrown at random on the 24 clue places.
  B2  mask = any set of residue classes mod p (p 2-13) whose clue places are all near; the other clue
      places must give one repeating key. Exact. Survivors are read in full.
  B3  no pattern at all: ANY set of near clue places masked, the rest must give one repeating key. Exact.
Controls: shuffled K4s, and K4 with its 24 clue pairs moved to random clue places (keeps the 7 near pairs).
Planted: English texts masked at a period-3/4/5 pattern, repeating key elsewhere; must be found and read.

Shape ciphers that move every letter by one fixed operation (rotate, mirror, pigpen turns) are dead without
any run: the clue pairs link 21 letters into one chain, and T goes to three different letters.

  python3 attacks/159_letter_shapes.py
"""
import json
import os
import random
import sys
import time
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4  # noqa: E402
from kryptos import idea159_shapes as S  # noqa: E402
from kryptos.clues import prefilter  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import english97  # noqa: E402
from kryptos.score import quadgram_score, word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
NPERM = int(os.environ.get("IDEA159_PERMS", "5000" if SMOKE else "100000"))
NCTRL = int(os.environ.get("IDEA159_CONTROLS", "6" if SMOKE else "200"))
NPLANT = int(os.environ.get("IDEA159_PLANTS", "6" if SMOKE else "36"))
PROCS = int(os.environ.get("IDEA159_PROCS", "4" if SMOKE else "8"))
PLACES = sorted(CRIBS)
GATE = 0.01


def pairs_of(ct, cribs):
    return [(cribs[i], ct[i]) for i in sorted(cribs)]


def flags_of(ct, cribs, coding):
    return [S.near(coding, cribs[i], ct[i]) for i in sorted(cribs)]


def pattern_p(flags, rng, n):
    """B1: best pattern count against the same number of near places at random clue places."""
    obs, per = S.pattern_stat(flags, PLACES)
    f, ge = list(flags), 0
    for _ in range(n):
        rng.shuffle(f)
        ge += S.pattern_stat(f, PLACES)[0] >= obs
    return obs, per, (1 + ge) / (1 + n)


def all_masked(ct):
    """B0: best reading per coding when every place is a shape change."""
    return {c: S.viterbi([S.NEAR[c][ch] for ch in ct]) for c in S.NAMES}


def one_text(job):
    """Everything in part B for one text. job = (label, ct, cribs)."""
    label, ct, cribs = job
    b0 = all_masked(ct)
    b1 = {c: S.pattern_stat(flags_of(ct, cribs, c), sorted(cribs))[0] for c in S.NAMES}
    b2 = S.attack(ct, cribs)
    b3 = S.free_attack(ct, cribs)
    return {"label": label,
            "near": {c: sum(flags_of(ct, cribs, c)) for c in S.NAMES},
            "b0": {c: round(v[0], 3) for c, v in b0.items()},
            "b0_text": {c: v[1] for c, v in b0.items()},
            "b1": b1,
            "b2_tested": b2["tested"], "b2_judged": b2["judged"], "b2_surv": b2["survivors"],
            "b2_strong": len(b2["strong"]),
            "b2_reads": [(round(r[0], 3), r[1], list(r[2]), r[3]) for r in b2["reads"][:5]],
            "b3_tested": b3["tested"], "b3_judged": b3["judged"], "b3_surv": len(b3["survivors"]),
            "b3_list": [list(s) for s in sorted(b3["survivors"], reverse=True)[:5]],
            "b3_reads": [(round(r[0], 3), r[1], list(r[2])) for r in b3["reads"][:5]]}


def plant(seed):
    """One planted text: English, masked at a period-3/4/5 pattern, repeating key elsewhere.
    Found = B2 lists the true setting with 5+ checks and its reading has at most 9 wrong letters, and B3
    lists the true masked clue places with the true key length, numbering, strips and sign."""
    rng = random.Random(1590000 + seed)
    pt = english97(rng)
    coding = S.NAMES[seed % 3]
    p = (3, 3, 3, 4, 5, 3)[seed % 6]
    ct, want = S.encrypt(pt, rng, coding=coding, p=p)
    cribs = {i: pt[i] for i in PLACES}
    changed = sum(a != b for i, (a, b) in enumerate(zip(pt, ct)) if i % p in want[2])
    b2 = S.attack(ct, cribs)
    hit = [r for r in b2["strong"] if tuple(r[2][1:8]) == want]
    wrong = sum(a != b for a, b in zip(hit[0][1], pt)) if hit else None
    top_ok = bool(b2["reads"]) and sum(a != b for a, b in zip(b2["reads"][0][1], pt)) <= 9
    masked = tuple(i for i in PLACES if i % p in want[2])
    b3 = S.free_mask_test(ct, cribs, coding)[2]
    hit3 = any(s[2] == masked and (s[3], s[4], s[6], s[7]) == (want[3], want[4], want[5], want[6]) for s in b3)
    st = S.stats(pairs_of(ct, cribs))
    return {"seed": seed, "want": list(want), "changed": changed, "b2_found": bool(hit), "wrong": wrong,
            "top_is_truth": top_ok, "b2_strong": len(b2["strong"]), "b3_found": hit3,
            "near": st[2 * S.NAMES.index(coding)], "stats": st}


def _enc(pt, rng):
    return S.encrypt(pt, rng, coding="STROKE", p=3)[0]


def part_a(rng, out):
    pairs = pairs_of(K4, CRIBS)
    obs = S.stats(pairs)
    print("\n== Part A: are the clue pairs close in shape? ==")
    for c in S.NAMES:
        d = S.DIST[c]
        nearp = ["%s>%s@%d" % (p, q, i) for i, (p, q) in zip(PLACES, pairs) if d[p + q] <= S.THR[c]]
        print("%-6s one stroke = distance <= %d; %d letter pairs of the alphabet are that close: %s"
              % (c, S.THR[c], len(S.near_pairs(c)), " ".join(S.near_pairs(c))))
        print("       K4 near pairs (%d of 24): %s" % (len(nearp), " ".join(nearp)))
        print("       distances of the 24 pairs: %s" % " ".join(str(d[p + q]) for p, q in pairs))
        close = [x for x in S.near_pairs(c) if S.alpha_dist(x[0], x[1]) <= 2]
        print("       near pairs that are also within 2 places in the alphabet: %d of %d (%s)"
              % (len(close), len(S.near_pairs(c)), " ".join(close)))
    print("alphabet-distance profile of the clue pairs (0 / 1-2 / 3-5 / 6-13):", S.profile(pairs))
    out["A"] = {"obs": dict(zip(["%s_%s" % s for s in S.STATS], obs)), "controls": {}}
    nulls = [("i    same letters, random pairing", S.null_permute),
             ("ii-a same plain letter and alphabet distance, random direction", S.null_sign),
             ("ii-b any letter, same alphabet distance", S.null_any_letter),
             ("ii-c same letters, same alphabet-distance profile (Markov chain)", S.null_matched)]
    print("\nstatistics (near count, minus mean distance) for SEG16, DOT57, STROKE; K4 =",
          [round(x, 3) for x in obs])
    for name, fn in nulls:
        t = time.time()
        if fn is S.null_matched:        # four separate chains, so that their agreement can be seen
            chains = [[S.stats(x) for x in fn(pairs, random.Random(rng.random()), NPERM // 4, thin=200)]
                      for _ in range(4)]
            sample = [r for ch in chains for r in ch]
            agree = [round(S.p_values(obs, ch)[1], 4) for ch in chains]
        else:
            sample = [S.stats(x) for x in fn(pairs, rng, NPERM)]
            agree = None
        ps, corr, means = S.p_values(obs, sample)
        key = name.split()[0]
        out["A"]["controls"][key] = {"p": [round(p, 5) for p in ps], "corrected_p": round(corr, 5),
                                     "null_means": [round(m, 3) for m in means], "n": len(sample),
                                     "chains_corrected_p": agree}
        print("control %s  (n=%d, %.0fs)" % (name, len(sample), time.time() - t))
        print("    null means: %s" % [round(abs(m), 2) for m in means])
        print("    p: %s" % ["%s_%s %.5f" % (s[0], s[1], p) for s, p in zip(S.STATS, ps)])
        print("    corrected p (best of six): %.5f%s" % (corr, "  per chain: %s" % agree if agree else ""))
    # every threshold, for the record (not part of the corrected family)
    print("\nnear counts at every threshold against control (i), descriptive only:")
    pl, cl = [p for p, _ in pairs], [c for _, c in pairs]
    n2 = max(2000, NPERM // 5)
    perms = []
    for _ in range(n2):
        rng.shuffle(cl)
        perms.append(list(cl))
    for c in S.NAMES:
        d, row = S.DIST[c], []
        for thr in range(0, 9):
            o = sum(d[p + q] <= thr for p, q in pairs)
            ge = sum(sum(d[p + q] <= thr for p, q in zip(pl, x)) >= o for x in perms)
            row.append("<=%d: %d (p %.4f)" % (thr, o, (1 + ge) / (1 + n2)))
        print("  %-6s %s" % (c, "  ".join(row)))
    gate = out["A"]["controls"]["ii-c"]["corrected_p"]
    out["A"]["gate_passed"] = gate < GATE
    print("\nGATE: corrected p under control ii-c = %.5f; needed below %.2f -> %s"
          % (gate, GATE, "PASSED" if gate < GATE else "NOT passed (part B is run for the record only)"))
    return out


def summarise(rows, k4, tag, out):
    print("\n-- controls: %s (%d texts) --" % (tag, len(rows)))
    res = {}
    for c in S.NAMES:
        nc = sorted(r["near"][c] for r in rows)
        b0 = sorted(r["b0"][c] for r in rows)
        b1 = sorted(r["b1"][c] for r in rows)
        res[c] = {"near_max": nc[-1], "near_ge_k4": sum(x >= k4["near"][c] for x in nc),
                  "b0_min": b0[0], "b0_median": b0[len(b0) // 2], "b0_max": b0[-1],
                  "b0_ge_k4": sum(x >= k4["b0"][c] for x in b0),
                  "b1_ge_k4": sum(x >= k4["b1"][c] for x in b1), "b1_max": b1[-1]}
        print("  %-6s near pairs: median %d max %d, %d of %d >= K4's %d | all-masked reading: min %.3f median "
              "%.3f max %.3f, %d >= K4's %.3f | pattern count: max %d, %d >= K4's %d"
              % (c, nc[len(nc) // 2], nc[-1], res[c]["near_ge_k4"], len(rows), k4["near"][c], b0[0],
                 b0[len(b0) // 2], b0[-1], res[c]["b0_ge_k4"], k4["b0"][c], b1[-1], res[c]["b1_ge_k4"],
                 k4["b1"][c]))
    for part in ("b2", "b3"):
        sv = Counter(r[part + "_surv"] for r in rows)
        tested = sorted(r[part + "_tested"] for r in rows)
        res[part] = {"survivor_counts": dict(sv), "texts_with_survivors": sum(v for k, v in sv.items() if k),
                     "tested_median": tested[len(tested) // 2], "tested_max": tested[-1],
                     "tested_sum": sum(tested)}
        print("  %s: settings tested median %d max %d; texts with a survivor: %d of %d (survivor counts %s)"
              % (part.upper(), tested[len(tested) // 2], tested[-1], res[part]["texts_with_survivors"],
                 len(rows), dict(sorted(sv.items()))))
    best = sorted(((r["b2_reads"][0][0], r["label"], r["b2_reads"][0][1], r["b2_reads"][0][2])
                   for r in rows if r["b2_reads"]), reverse=True)[:3]
    for b in best:
        print("    best B2 control reading %.3f %s %s %s" % b)
    res["b2_strong_texts"] = sum(1 for r in rows if r["b2_strong"])
    res["best_b2_reads"] = best
    res["best_b3_reads"] = sorted(((r["b3_reads"][0][0], r["label"], r["b3_reads"][0][1])
                                   for r in rows if r["b3_reads"]), reverse=True)[:3]
    out["controls_" + tag.split()[0]] = res


def main():
    rng = random.Random(159)
    out = {}
    t0 = time.time()
    print("== pre-filter ==")
    card = prefilter("159 shape change at every third place, repeating key elsewhere", encrypt=_enc,
                     n=60 if SMOKE else 300)[0]
    out["prefilter"] = {"verdict": card["verdict"], "score": card["score"]}
    with Experiment("159 letter shapes: clue pairs one stroke apart; shape mask plus repeating key",
                    notes="A: 3 shape codings vs random and alphabet-distance-matched pairings. B: shape change "
                          "at pattern places (period 2-13 classes, or any near clue places), repeating key "
                          "1-12 elsewhere, vig/beau, AZ/KRYPTOS strips; exact clue test, quadgram readings",
                    cribs_forced=True) as ex:
        part_a(rng, out)

        print("\n== Part B on K4 ==")
        k4 = one_text(("K4", K4, CRIBS))
        out["K4"] = k4
        for c in S.NAMES:
            txt = k4["b0_text"][c]
            ex.add(txt, part="B0 all places masked", coding=c, english_big=k4["b0"][c])
            print("B0 %-6s big %.3f small %.3f words %.2f  %s"
                  % (c, k4["b0"][c], quadgram_score(txt), word_coverage(txt), txt))
            obs, per, p = pattern_p(flags_of(K4, CRIBS, c), rng, 2000 if SMOKE else 20000)
            k4.setdefault("b1_p", {})[c] = round(p, 5)
            print("B1 %-6s near places %s; best pattern count %d (periods %s); p against random places %.4f; "
                  "periods 2-13 with a perfect split: %s"
                  % (c, [i for i, f in zip(PLACES, flags_of(K4, CRIBS, c)) if f], obs,
                     [q for q, v in per.items() if v == obs and obs], p,
                     S.perfect_periods(flags_of(K4, CRIBS, c), PLACES)))
        print("B2 mask classes + repeating key: %d settings, %d with 2+ checks, %d survivors, %d with 5+ checks"
              % (k4["b2_tested"], k4["b2_judged"], k4["b2_surv"], k4["b2_strong"]))
        for sc, txt, s, unk in k4["b2_reads"]:
            ex.add(txt, part="B2", setting=str(s), english_big=sc)
            print("   %.3f words %.2f %s %s" % (sc, word_coverage(txt), txt, s))
        print("B3 any near clue places masked + repeating key: %d settings, %d with 4+ checks, %d survivors"
              % (k4["b3_tested"], k4["b3_judged"], k4["b3_surv"]))
        for s in k4["b3_list"]:
            print("   ", s)
        for sc, txt, s in k4["b3_reads"]:
            ex.add(txt, part="B3", setting=str(s), english_big=sc)
            print("   %.3f words %.2f %s" % (sc, word_coverage(txt), txt))
        ex.count(k4["b2_tested"] + k4["b3_tested"])

        jobs1 = [("shuffle %d" % s, shuffled_control(s), CRIBS) for s in range(1, NCTRL + 1)]
        jobs2 = [("pairs moved %d" % s,) + S.shuffle_pairs(K4, CRIBS, s) for s in range(1, NCTRL + 1)]
        with Pool(PROCS) as pool:
            r1 = pool.map(one_text, jobs1, chunksize=2)
            r2 = pool.map(one_text, jobs2, chunksize=2)
            plants = pool.map(plant, range(NPLANT), chunksize=1)
        summarise(r1, k4, "shuffled K4s", out)
        summarise(r2, k4, "moved clue pairs (K4's 24 clue pairs at random clue places, rest shuffled)", out)
        ex.count(sum(r["b2_tested"] + r["b3_tested"] for r in r1 + r2))

        print("\n== planted ==")
        ok = 0
        for r in plants:
            good = r["b2_found"] and r["wrong"] is not None and r["wrong"] <= 9 and r["b3_found"]
            ok += good
            print("  %s plant %2d %s: %d letters changed, near pairs %d; B2 %s (wrong letters %s, %d strong "
                  "survivors, top reading is the truth: %s); B3 %s"
                  % ("ok  " if good else "MISS", r["seed"], r["want"], r["changed"], r["near"],
                     "found" if r["b2_found"] else "missed", r["wrong"], r["b2_strong"], r["top_is_truth"],
                     "found" if r["b3_found"] else "missed"))
        pairs = pairs_of(K4, CRIBS)
        sample = [S.stats(x) for x in S.null_permute(pairs, rng, 5000)]
        cols = [sorted(row[j] for row in sample) for j in range(6)]
        # part A on the planted texts: how often is the near count above the 99th percentile of control (i)
        # for K4's letters (a rough gauge that the statistic sees a period-3 mask)
        seen = sum(1 for r in plants if r["near"] > cols[2 * S.NAMES.index(r["want"][0])][int(0.99 * 5000)])
        print("planted: %d/%d found by both exact tests and read with <= 9 wrong letters; "
              "part A near count above the 99%% point of control (i): %d/%d" % (ok, len(plants), seen, len(plants)))
        out["planted"] = {"ok": ok, "n": len(plants), "partA_seen": seen, "rows": plants}
        out["tested"] = ex.tried
        out["seconds"] = round(time.time() - t0, 1)
        print("\nSUMMARY " + json.dumps({k: v for k, v in out.items() if k != "planted"}, default=str))
        if ok != len(plants):
            print("PLANTED TEST FAILED")
            sys.exit(1)


if __name__ == "__main__":
    main()
