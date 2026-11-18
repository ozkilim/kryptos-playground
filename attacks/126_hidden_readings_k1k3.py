"""Idea 126: instructions hidden in the solved K1-K3 text, read as acrostics and skip readings.

Sanborn (2005): he left instructions in the earlier text that refer to later text. (2006): the
answers to the first three passages contain clues to the fourth. Letter codes of the war years hid a
message in the first or n-th letters of words. Earlier rounds used such letters only as K4 KEYS
(attacks 85, idea 106, round 9 column/skip keys: all dead). Nobody here asked whether they READ as a
message. That needs no K4 and no cipher model, and would hand over the method directly.

Texts (all from kryptos/idea106_words.py, checked against data/sculpture): K1, K2, K3 and the Morse
text alone, and K1-K3 joined; spelling as carved or corrected; X separators (and K3's closing Q) kept
or dropped; K2 ending ID BY ROWS or X LAYER TWO. Duplicate styles are dropped (24 units).

Readings (kryptos/idea126_hidden.py): from each unit's letter string and its four word lines (first,
second, third and last letter of each word): every k-th item for k = 1..40 (letters 2..40) from every
start; the K2 coordinate digits 3 8 5 7 6 5 7 7 8 4 4 and the numbers 38 57 6 5 77 8 44 as repeating
step counts from every start in one cycle (later starts give suffixes); the first and last letter and
each column of the plaintext laid under the 25 carved cipher rows; sentence initials and finals;
the letter of each doubled pair and the letter after it. Each forwards and backwards; only readings
of 12+ letters are scored. Too-short items (misspelt letters, raised YAR, letters next to each X)
are printed for a human read only.

Scores: big-model quadgram mean and best 20-letter window (raw, and as z-scores against 500
reference controls), word coverage, longest dictionary word of 5+, method-word count, and the
longest stretch that splits wholly into common English words (2,000 most frequent words of
data/english/words_big.txt plus the method and compass words). Readings are grouped in three
families (letters from words; letters of the running text; carved rows). Controls: the same text
with word order shuffled inside each section. For each family and score the largest value over all
its readings is compared with 1,500 test controls; a combined statistic (the largest of the 21
maxima, each standardised by the controls) gives one p-value that pays for every reading.

Tuning note: the plain quadgram scores cannot find a 20-letter instruction among ~46,000 readings
(chance letter salad such as AREDTEMONTHANTAIEWA scores as well); planted 0/3 at 150 controls. The
word-run score with the three families finds them (3/3 at 300 controls). Combining the 21 maxima by
mean and sd let one control in 1,000 beat planted 3 (7.27 against 7.17); the combination now uses a
Gumbel tail per channel. The plants were never changed.

Planted: three K1-K3 texts in which word initials at skip 1 (K2), word initials at skip 3 (K3) and
second letters (K2) spell a 20-letter instruction. Each must put a reading holding the message first
and beat every one of 1,000 test controls (p < 0.001).

  python attacks/126_hidden_readings_k1k3.py
"""
import json
import os
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos.harness import Experiment
from kryptos.idea126_hidden import PLANTS, describe, plant, readings_text, real_sections, run_test
from kryptos.round11 import SMOKE

N_REF, N_TEST = (30, 60) if SMOKE else (500, 1500)
P_REF, P_TEST = (30, 60) if SMOKE else (500, 1000)
PROCS = 12
if os.environ.get("IDEA126_N"):          # quick tuning runs: IDEA126_N=ref,test
    N_REF, N_TEST = P_REF, P_TEST = tuple(map(int, os.environ["IDEA126_N"].split(",")))


def log(*a):
    print(*a, flush=True)


def report(sections, res, label):
    specs = res["specs"]
    log("\n== %s: %d readings, %d channels; %d reference + %d test controls" %
        (label, res["n_readings"], res["n_channels"], res["n_ref"], res["n_test"]))
    for ps in res["per_channel"]:
        lab, txt = describe(sections, specs, ps["reading"])
        log("  %-15s text %7.3f  (controls: min %7.3f median %7.3f max %7.3f; %4d >= text; p = %.4f)  %s: %s" %
            (ps["channel"], ps["real"], ps["ctrl_min"], ps["ctrl_median"], ps["ctrl_max"], ps["ge"], ps["p"],
             lab, txt[:70]))
    log("  combined (-log10 smallest Gumbel tail): text %.2f, controls median %.2f max %.2f, %d >= text, p = %.4f" %
        (res["real_comb"], res["ctrl_comb_median"], res["ctrl_comb_max"], res["comb_ge"], res["p_comb"]))
    log("  top readings (tail = -log10 Gumbel tail probability against the controls' best per channel;"
        " p1 = share of controls at least as high on that same reading):")
    for t in res["top"][:15]:
        lab, txt = describe(sections, specs, t["reading"])
        log("    tail %5.2f  %-15s %7.3f  p1 %.4f  %s: %s" % (t["std"], t["channel"], t["value"], t["p_single"],
                                                          lab, txt[:60]))


def short_items():
    """Readings too short to score, printed for a human read."""
    from kryptos.idea106_words import K1_WORDS, K2_WORDS, K3_WORDS
    words = (K1_WORDS + " " + K2_WORDS + " ID BY ROWS " + K3_WORDS).split()
    after = "".join(words[i + 1][0] for i, w in enumerate(words[:-1]) if w == "X")
    before = "".join(words[i - 1][-1] for i, w in enumerate(words) if w == "X" and i)
    log("\nShort items (human read only):")
    log("  misspelt letters as carved  IQLUSION UNDERGRUUND DESPARATLY DIGETAL INTERPRETATIU: Q U A E U")
    log("  ... the letters they replace:                                                    L O E I ON")
    log("  raised letters on the copper (K3 ciphertext row 15): Y A R")
    log("  first letter of the word after each X: %s; last letter of the word before each X: %s" % (after, before))


def main():
    t0 = time.time()
    sec = real_sections()
    results = {}
    with Experiment("126_hidden_readings_k1k3", puzzle="k1-k3", keep=60,
                    notes="acrostic/skip readings of K1-K3 vs word-shuffle controls") as ex:
        # ---- planted answers first: the test must find them
        planted_ok = 0
        for pi, (msg, s, pick, skip, start) in enumerate(PLANTS):
            ptext = plant(sec, msg, s, pick, skip, start, random.Random(126 + pi))
            log("\nPlanted %d: %r in %s, letter %d of every %d-th word from word %d" % (pi + 1, msg, s, pick, skip, start))
            res = run_test(ptext, P_REF, P_TEST, seed0=10000 * (pi + 1), procs=PROCS, log=log)
            report(ptext, res, "planted %d" % (pi + 1))
            first = res["top"][0]
            lab, txt = describe(ptext, res["specs"], first["reading"])
            holds = msg in txt or msg[::-1] in txt
            ok = holds and res["comb_ge"] == 0
            planted_ok += ok
            log("  -> first reading %s holds the message: %s; beats all %d controls: %s; p = %.4f => %s" %
                (lab, holds, res["n_test"], res["comb_ge"] == 0, res["p_comb"], "FOUND" if ok else "MISSED"))
            results["planted_%d" % (pi + 1)] = {"ctrl_maxima": res["ctrl_maxima"], "real_maxima": res["real_maxima"],
                                                "comb": res["real_comb"], "ctrl_comb_max": res["ctrl_comb_max"],"msg": msg, "first": lab, "holds": holds, "p": res["p_comb"],
                                                "per_channel": [(p["channel"], round(p["real"], 3), p["p"])
                                                                for p in res["per_channel"]]}
            ex.count(res["n_readings"] * (1 + res["n_ref"] + res["n_test"]))
        log("\nPLANTED: %d/%d found" % (planted_ok, len(PLANTS)))
        if planted_ok < len(PLANTS):
            log("planted test FAILED")

        # ---- the real text
        log("\n==== K1-K3 as carved and corrected ====")
        res = run_test(sec, N_REF, N_TEST, seed0=1, procs=PROCS, log=log)
        report(sec, res, "K1-K3 + Morse")
        ex.count(res["n_readings"] * (1 + res["n_ref"] + res["n_test"]))
        for t in res["top"][:40]:
            lab, txt = describe(sec, res["specs"], t["reading"])
            ex.add(txt, rule=lab, channel=t["channel"], tail=round(t["std"], 2), p_single=round(t["p_single"], 4))
        short_items()
        results["k123"] = {"ctrl_maxima": res["ctrl_maxima"], "real_maxima": res["real_maxima"],
                           "channels": [p["channel"] for p in res["per_channel"]],
                           "n_readings": res["n_readings"], "p_comb": res["p_comb"], "comb_ge": res["comb_ge"],
                           "real_comb": res["real_comb"], "ctrl_comb_max": res["ctrl_comb_max"],
                           "per_channel": [dict(p, reading=describe(sec, res["specs"], p["reading"]))
                                           for p in res["per_channel"]],
                           "top": [dict(t, rule=describe(sec, res["specs"], t["reading"])) for t in res["top"]]}
        # the plain-sight check: the best method-word readings and longest words, for a human read
        allr = readings_text(sec, res["specs"])
        log("\nLongest dictionary words found in any reading (text):")
        from kryptos.idea126_hidden import Scorer
        sc = Scorer()
        best = sorted(((sc.stats(r)[3], lab, r) for lab, r in allr), reverse=True)[:10]
        for L, lab, r in best:
            log("  %2d  %s: %s" % (L, lab, r[:70]))
        results["planted_found"] = planted_ok
        results["seconds"] = round(time.time() - t0)
        out = Path(__file__).resolve().parent.parent / "results" / "idea126_summary.json"
        if SMOKE:
            out = Path(SMOKE) / "idea126_summary.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        json.dump(results, open(out, "w"), indent=1, default=str)
        log("\nsummary written to %s (%.0f s)" % (out, time.time() - t0))


if __name__ == "__main__":
    main()
