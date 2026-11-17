"""Idea 107: one word per worksheet line. A column key plus a free key letter for each line.

The K4 plaintext survives as strips cut from a handwritten sheet, the K1 worksheet is written in
short clusters, and the Cyrillic Projector restarts its key at each block. Suppose the worksheet
had ONE WORD PER LINE. Then the key letter of a plaintext letter depends on its place inside the
word (its column), and each line may bring a letter of its own (a row word written down the
side). Idea 66 tested a key that restarts at each word with nothing added; idea 65 tested a row
word plus a column word on grids of fixed width only. Lines of ragged length were never tested.

Four models (K = key value of a letter, arithmetic mod 26 in the tableau's own numbering):
  add       K = a[line] + b[column]          column key b, one free letter a per line
  speed     K = a[line] x column + b0        one start letter; each word has its own speed
                                             (column counted from 0 or from 1)
  ownspeed  K = a[line] x column + s[line]   each word has its own speed and its own start
  slide     K_i = K_(i-1) + d[column]        the strip is MOVED by the column key and never put
                                             back, no line letter. (With a line letter the
                                             sliding form is the add model again: differences
                                             inside a word depend only on the column.)
The column is counted from the start of the word or from its end. Lines are all Vigenere, all
Beaufort, or take turns (every second line Beaufort; block 2 may start on either).

Word breaks inside the clues: EAST|NORTH|EAST, EAST|NORTHEAST or EASTNORTHEAST, with
BERLIN|CLOCK or BERLINCLOCK: 6 parsings, 262 tests in all, each with 9 to 21 exact checks
(EAST|NORTH|EAST + BERLIN|CLOCK, add: 10 unknown key letters against 24 clue letters, 14 checks).
A test passes only if ALL its checks hold, so every pass has 9+ checks (the idea asked for 7+).

Key streams: A-Z, KRYPTOS, every dictionary keyword alphabet and its two transposition-mixed
forms (about 667,000 alphabets), five layouts, Vigenere and Beaufort values. The checks are sums
of clue key values that must be 0 mod 26 (kryptos/idea107_lines.py); they are derived by
substitution, need no division, and are checked in the tests against the mod-13 / mod-2 solver.

One part needs no dictionary: EAST is enciphered twice, FLRV and GKSS. If the two EASTs stand in
the same columns of their lines and the lines have the same form, a line letter moves all four
cipher letters by one amount, so R->S and V->S would put R and V on one place. That kills 68 of
the 262 tests for ANY pair of alphabets, hidden or not; the script prints which.

Gauge: for the tests that pass their first 3 checks the script counts how many checks hold before
the first failure, and compares the counts with chance (26^-d) and with shuffled K4s.
Survivors: the column key and the line letters are printed (do they spell anything) and the text
is filled in by a search over word breaks (Reader: dictionary words only, each word weighed by
how unlikely chance is to give it; the same reading is done on the survivor with the letters
outside the clues shuffled, to show what chance reads).
Controls: 3 shuffled K4s, a third of the alphabets each, and 8 more on all alphabets (the run is
cheap) so the near-miss counts can be compared like for like. Planted: six English texts set one word
per line (add with an 11-letter column key and a row word; column counted from the word end;
speed per word; lines taking turns; slide; own speed and start), each on a dictionary tableau
among decoy alphabets, found by the exact test and read back.

  python attacks/107_one_word_per_line.py            (--prefilter for the clue card)
"""
import json
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea107_lines as H  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, dictionary_alphabets, pmap, streams  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA107_PROCS", "4" if SMOKE else "8"))
NCTRL = 3
NFULL = 8               # extra shuffled K4s on ALL alphabets, for the near-miss gauge
ENGLISH = -5.1          # big-model score per quadgram a reading must beat
READ_OK = 35            # letters outside the clues (of 73) a planted text must be read back with
BIG = DATA_DIR / "english" / "quadgrams_big.txt"
G = {}

# K1-K3 plaintext with its word breaks (misspellings and the X / Q marks as carved): the planted texts.
SOURCE = (
    "BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION "
    "IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS "
    "GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD "
    "ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY "
    "EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY "
    "FOUR SECONDS WEST X LAYER TWO "
    "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS "
    "REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE "
    "HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME "
    "TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q").split()


def init(ct, cribs):
    G["pl"], G["cl"] = [cribs[i] for i in POS], [ct[i] for i in POS]
    G["sc"] = H.Scanner()


def work(chunk):
    sc, pl, cl = G["sc"], G["pl"], G["cl"]
    sc.hist.clear()
    sc.near = []
    hits, n = [], 0
    for name, m in chunk:
        it = streams(m, pl, cl)
        for lay, _, kv, _, _ in it:
            kb = next(it)[2]
            n += 1
            sc.cur = (name, lay)
            for tid in sc.scan(kv + kb):
                hits.append((name, m, lay, tid))
    return hits, dict(sc.hist), n, sc.near


def search(ct, cribs, alphabets, chunk=1500):
    hits, hist, n, near = [], Counter(), 0, []
    for h, hs, k, nr in pmap(work, alphabets, init, (ct, cribs), chunk=chunk, procs=PROCS):
        hits.extend(h)
        hist.update(hs)
        n += k
        near.extend(nr)
    G["near"] = sorted(near, key=lambda e: (-e[2], e[1], e[0]))
    return sorted(hits, key=lambda h: (h[3], h[0], h[2])), hist, n


def key_values(m, lay, ct, cribs):
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    it = streams(m, pl, cl)
    for name, _, kv, _, _ in it:
        kb = next(it)[2]
        if name == lay:
            return kv + kb
    raise KeyError(lay)


def scramble(ct, seed):
    """The same ciphertext with the letters outside the clues in random order."""
    out = [i for i in range(len(ct)) if i not in CRIBS]
    vals = [ct[i] for i in out]
    random.Random(seed).shuffle(vals)
    s = list(ct)
    for i, v in zip(out, vals):
        s[i] = v
    return "".join(s)


def read_hit(hit, ct, cribs, tests, vocab, big, noise=2):
    """Solve and read one survivor. Also reads it with the outside letters shuffled (what chance reads)."""
    name, m, lay, tid = hit
    t = tests[tid]
    x = key_values(m, lay, ct, cribs)
    p = H.solve(t, x)
    pa, ca = H.layout(lay, m)
    kv = [x[t.var(li, j)] for li, (_, js) in enumerate(t.lines) for j in js]
    rd, ev, words = H.Reader(t, p, pa, ca, ct, vocab).read(cribs, kv)
    sc, nq = H.known_score(rd, big)
    chance = [H.Reader(t, p, pa, ca, scramble(ct, 1070 + s), vocab).read(cribs, kv)[1] for s in range(noise)]
    keys = {}
    if t.model == "add":
        keys = {"column key (first line letter = A)": H.letters_of(p["b"][c] for c in sorted(p["b"])),
                "line letters": H.letters_of(p["a"][li] for li in sorted(p["a"]))}
    elif t.model == "speed":
        keys = {"start letter": AZ[p["b0"]], "speeds": [p["a"][li] for li in sorted(p["a"])]}
    elif t.model == "ownspeed":
        keys = {"starts": H.letters_of(p["s"][li] for li in sorted(p["s"])),
                "speeds": [p["a"][li] for li in sorted(p["a"])]}
    else:
        keys = {"moves by column": H.letters_of(p["d"][c] for c in sorted(p["d"]))}
    return {"alphabet": name, "layout": lay, "test": t.name(), "tid": tid, "checks": len(t.checks),
            "keys": keys, "reading": rd, "evidence": round(ev, 1), "chance_evidence": [round(c, 1) for c in chance],
            "known_letters": sum(ch != "?" for i, ch in enumerate(rd) if i not in CRIBS),
            "score": round(sc, 3), "quadgrams": nq, "words": words}


def show_hist(hist, lead, n_streams, ntests):
    return ", ".join("%d: %d (chance %.3g)" % (d, hist.get(d, 0), lead[d]) for d in sorted(lead) if d <= 8
                     or hist.get(d, 0))


def run_text(label, ct, cribs, alphabets, tests, sc, vocab, big, verbose=True):
    hits, hist, n = search(ct, cribs, alphabets)
    near = G["near"]
    lead, full = sc.chance(n)
    rows = [read_hit(h, ct, cribs, tests, vocab, big) for h in hits[:200]]
    rows.sort(key=lambda r: -r["evidence"])
    s = {"alphabets": len(alphabets), "key_streams": n, "tests": n * len(tests), "passes": len(hits),
         "chance_passes": float("%.3g" % full),
         "stopped_after_d_checks": {str(d): hist.get(d, 0) for d in sorted(set(hist) | {3, 4, 5, 6, 7})},
         "chance_stopped": {str(d): float("%.3g" % lead[d]) for d in (3, 4, 5, 6, 7)},
         "most_checks_held_by_a_failed_test": max(hist) if hist else None,
         "best_evidence": rows[0]["evidence"] if rows else None,
         "best_score": max([r["score"] for r in rows if r["quadgrams"] >= 15], default=None),
         "english": sum(1 for r in rows if r["quadgrams"] >= 15 and r["score"] > ENGLISH)}
    print("%s: %d alphabets, %d key streams x %d tests = %d tests; %d pass every check (chance %.3g)"
          % (label, len(alphabets), n, len(tests), n * len(tests), len(hits), full))
    print("   tests stopped after d checks held: " + show_hist(hist, lead, n, len(tests)))
    for (name, lay), tid, d in near[:8 if verbose else 3]:
        print("   near miss: %d of %d checks held, then one failed | %s | %s %s"
              % (d, len(tests[tid].checks), tests[tid].name(), name, lay))
    by_test = Counter(tests[tid].name() for _, tid, _ in near)
    by_alpha = Counter(name.split("~")[0][:5] for (name, _), _, _ in near)
    s["near_misses_5plus"] = len(near)
    s["near_misses_distinct_tests"] = len(by_test)
    s["near_misses_top_tests"] = by_test.most_common(6)
    s["near_misses_top_alphabet_stems"] = by_alpha.most_common(6)
    print("   near misses (5+ checks held): %d over %d different tests; most on one test: %s; most on one "
          "5-letter keyword stem: %s" % (len(near), len(by_test), by_test.most_common(3), by_alpha.most_common(3)))
    s["near_miss_list"] = [[tests[tid].name(), name, lay, d] for (name, lay), tid, d in near[:12]]
    for r in rows[:10 if verbose else 3]:
        print("   PASS %s | %s %s | %d checks | %s\n        evidence %.1f (same key, outside letters shuffled: %s), "
              "%d letters read, big model %.2f over %d quadgrams, word cover %.2f\n        %s"
              % (r["test"], r["alphabet"], r["layout"], r["checks"], json.dumps(r["keys"]), r["evidence"],
                 r["chance_evidence"], r["known_letters"], r["score"], r["quadgrams"],
                 word_coverage(r["reading"].replace("?", "")), r["reading"]))
    return s, rows


# ---------------------------------------------------------------- planted answers

PLANTS = [  # model, column from, base, block 1, block 2, forms, layout, column key / row word
    ("add", "start", 0, "EAST|NORTHEAST", "BERLINCLOCK", "V", "M/M", "UNDERGROUND", "LANGLEY"),
    ("add", "end", 0, "EAST|NORTH|EAST", "BERLIN|CLOCK", "B", "M/AZ", "INFORMATION", "KRYPTOS"),
    ("speed", "start", 1, "EAST|NORTHEAST", "BERLIN|CLOCK", "V", "KR/M", "K", "MAGNETIC"),
    ("add", "start", 0, "EAST|NORTH|EAST", "BERLIN|CLOCK", "turns", "AZ/M", "CHECKPOINTS", "SHADOW"),
    ("slide", "start", 0, "EAST|NORTH|EAST", "BERLIN|CLOCK", "V", "M/KR", "TRANSMITTED", "Q"),
    ("ownspeed", "start", 0, "EASTNORTHEAST", "BERLIN|CLOCK", "B", "M/M", "PALIMPSEST", "ABSCISSA"),
]


def fill(rng, n):
    """Consecutive words of the source text with exactly n letters in all."""
    while True:
        i = rng.randrange(len(SOURCE))
        out, tot = [], 0
        while tot < n and i < len(SOURCE):
            out.append(SOURCE[i])
            tot += len(SOURCE[i])
            i += 1
        if tot == n:
            return out


def plant(rng, spec, m):
    """(ciphertext, plaintext, forms of the clue lines) for one planted text on keyword alphabet m."""
    model, align, base, b1, b2, fmode, lay, w1, w2 = spec
    head, mid, tail = fill(rng, 21), fill(rng, 29), fill(rng, 23)
    c1, c2 = b1.split("|"), b2.split("|")
    words = head + c1 + mid + c2 + tail
    nl = len(words)
    if fmode == "turns":
        f0 = rng.randrange(2)
        forms = [(f0 + i) % 2 for i in range(nl)]
    else:
        forms = [0 if fmode == "V" else 1] * nl
    v = lambda w: [AZ.index(c) for c in w]  # noqa: E731
    cyc = lambda w: [v(w)[i % len(w)] for i in range(nl)]  # noqa: E731
    if model == "add":
        key = {"a": cyc(w2), "b": v(w1)}
    elif model == "speed":
        key = {"a": cyc(w2), "b0": v(w1)[0]}
    elif model == "ownspeed":
        key = {"a": cyc(w2), "s": cyc(w1)}
    else:
        key = {"d": v(w1), "start": v(w2)[0]}
    pa, ca = H.layout(lay, m)
    pt = "".join(words)
    ct = H.encrypt_words(words, pa, ca, model, align, base, forms, key)
    i1, i2 = len(head), len(head) + len(c1) + len(mid)
    return ct, pt, tuple(forms[i1:i1 + len(c1)] + forms[i2:i2 + len(c2)])


def true_test(tests, spec, clue_forms):
    model, align, base, b1, b2 = spec[:5]
    for t in tests:
        if (t.parsing == b1 + " + " + b2 and t.model == model and t.base == base and t.forms == clue_forms
                and (t.align == align or model == "ownspeed")):
            return t
    raise KeyError(spec)


def planted_case(rng, spec, alphabets, decoys, tests, vocab, big):
    name, m = alphabets[rng.randrange(2, len(alphabets))]
    ct, pt, clue_forms = plant(rng, spec, m)
    assert all(pt[i] == c for i, c in CRIBS.items())
    t = true_test(tests, spec, clue_forms)
    hits, hist, n = search(ct, CRIBS, decoys + [(name, m)], chunk=500)
    rows = [read_hit(h, ct, CRIBS, tests, vocab, big) for h in hits[:60]]
    good = lambda r: sum(a == b for i, (a, b) in enumerate(zip(r["reading"], pt)) if i not in CRIBS)  # noqa: E731
    bad = lambda r: sum(a != b and a != "?" for a, b in zip(r["reading"], pt))  # noqa: E731
    mine = [r for r in rows if r["alphabet"] == name and r["layout"] == spec[6] and r["tid"] == t.id]
    right = good(mine[0]) if mine else 0
    wrong = bad(mine[0]) if mine else 0
    # another survivor counts against us only if it reads something else and looks better
    better = [r for r in rows if mine and r not in mine and good(r) < READ_OK and r["evidence"] > mine[0]["evidence"]]
    ok = bool(mine) and right >= READ_OK and not better
    print("planted %-8s col-from-%-5s %-15s + %-12s %-5s on %s %s -> found=%s (%d checks); %d survivors of %d tests "
          "(%d others)\n        read %d of 73 letters right, %d wrong; evidence %s (shuffled outside letters: %s); "
          "big model %s over %s quadgrams; best other reading: evidence %s\n        %s\n        %s"
          % (spec[0], spec[1], spec[3], spec[4], spec[5], name, spec[6], bool(mine), len(t.checks), len(hits),
             n * len(tests), len(hits) - len(mine), right, wrong, mine[0]["evidence"] if mine else None,
             mine[0]["chance_evidence"] if mine else None, mine[0]["score"] if mine else None,
             mine[0]["quadgrams"] if mine else None,
             max([r["evidence"] for r in rows if r not in mine and good(r) < READ_OK], default=None),
             mine[0]["reading"] if mine else "", pt))
    for r in rows:
        if r not in mine:
            print("        also passes: %s | %s %s (reads %d letters right, evidence %.1f)"
                  % (r["test"], r["alphabet"], r["layout"], good(r), r["evidence"]))
    return ok, {"spec": list(spec), "found": bool(mine), "checks": len(t.checks), "survivors": len(hits),
                "right": right, "wrong": wrong, "evidence": mine[0]["evidence"] if mine else None,
                "chance_evidence": mine[0]["chance_evidence"] if mine else None,
                "score": mine[0]["score"] if mine else None}


def prefilter_encrypt(pt, rng):
    """For the clue pre-filter: KRYPTOS tableau, words of 2-9 letters, column key of 11 + a letter per line."""
    kr = KRYPTOS_ALPHABET
    b = [rng.randrange(26) for _ in range(11)]
    out, i = [], 0
    while i < len(pt):
        n, a = rng.randrange(2, 10), rng.randrange(26)
        for c, ch in enumerate(pt[i:i + n]):
            out.append(kr[(kr.index(ch) + a + b[c]) % 26])
        i += n
    return "".join(out)


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("one word per line: column key + a free letter per line", encrypt=prefilter_encrypt)
        sys.exit(0)
    t0 = time.time()
    alphabets = dictionary_alphabets(mixed=True)
    tests = H.tests()
    sc = H.Scanner(tests)
    vocab = H.reading_vocab()
    big = Quadgrams(BIG)
    with Experiment("one word per worksheet line: column key plus a free key letter per line (ragged lines)",
                    puzzle="k4", cribs_forced=True,
                    notes="%d alphabets x 5 layouts x %d exact tests (add / speed / own speed / slide; 6 clue "
                          "parsings; column from word start or end; Vigenere, Beaufort, lines taking turns), "
                          "9-21 checks each" % (len(alphabets), len(tests))) as ex:
        w1, w2, possible = H.east_clash(K4)
        dead = [t for t in tests if H.clash_dead(t)]
        print("%d tests, checks per test %d-%d" % (len(tests), min(len(t.checks) for t in tests),
                                                  max(len(t.checks) for t in tests)))
        print("EAST is enciphered as %s and as %s: one line letter between them is %s for any alphabets -> %d of "
              "%d tests cannot pass on K4 whatever the tableau (by model: %s)"
              % (w1, w2, "possible" if possible else "impossible", 0 if possible else len(dead), len(tests),
                 dict(Counter(t.model for t in dead))))
        k4, rows = run_text("K4", K4, CRIBS, alphabets, tests, sc, vocab, big)
        ex.count(k4["tests"])
        for r in rows[:20]:
            ex.add(r["reading"].replace("?", "X"), test=r["test"], alphabet=r["alphabet"], layout=r["layout"],
                   evidence=r["evidence"], english_big=r["score"])
        dead_pass = [r for r in rows if H.clash_dead(tests[r["tid"]])]
        assert possible or not dead_pass, "a test passed that the EAST clash forbids"
        print("   (%.1f min)" % ((time.time() - t0) / 60))
        ctrl = []
        head, rest = alphabets[:2], alphabets[2:]
        for s in range(NCTRL):
            c, _ = run_text("shuffled K4 #%d" % (s + 1), shuffled_control(10700 + s), CRIBS,
                            head + rest[s::NCTRL], tests, sc, vocab, big, verbose=False)
            ctrl.append(c)
            print("   (%.1f min)" % ((time.time() - t0) / 60))
        full_ctrl = []
        for s in range(0 if SMOKE else NFULL):
            c, _ = run_text("shuffled K4 #%d, all alphabets" % (NCTRL + s + 1), shuffled_control(10710 + s), CRIBS,
                            alphabets, tests, sc, vocab, big, verbose=False)
            full_ctrl.append(c)
        rng = random.Random(107)
        decoys = alphabets[::200] if SMOKE else alphabets[::20]
        ok, plants = 0, []
        for spec in PLANTS:
            good, info = planted_case(rng, spec, alphabets, decoys, tests, vocab, big)
            ok += good
            plants.append(info)
            print("   (%.1f min)" % ((time.time() - t0) / 60))
        print("planted recovered: %d/%d among %d decoy alphabets" % (ok, len(PLANTS), len(decoys)))
        cbest = [c["best_evidence"] for c in ctrl if c["best_evidence"] is not None]
        signal = k4["english"] > 0 and (not cbest or k4["best_evidence"] > max(cbest))
        ctrl_all = ctrl + full_ctrl
        verdict = ("K4 has a survivor that reads better than every control - inspect by eye" if signal else
                   "no one-word-per-line key fits: K4 %d passes of %d tests (chance %.3g), most checks held by a "
                   "failed test %s; shuffled K4s %s passes, most checks held %s"
                   % (k4["passes"], k4["tests"], k4["chance_passes"], k4["most_checks_held_by_a_failed_test"],
                      [c["passes"] for c in ctrl_all], [c["most_checks_held_by_a_failed_test"] for c in ctrl_all]))
        print("RESULT " + json.dumps({"k4": k4, "controls": ctrl, "controls_all_alphabets": full_ctrl, "planted": "%d/%d" % (ok, len(PLANTS)),
                                      "plants": plants, "tests_per_stream": len(tests),
                                      "clash_dead_tests": 0 if possible else len(dead),
                                      "k4_rows": [{k: v for k, v in r.items() if k != "words"} for r in rows[:20]],
                                      "minutes": round((time.time() - t0) / 60, 1)}))
        print("VERDICT:", verdict)
        ex.notes += "; " + verdict + "; planted %d/%d" % (ok, len(PLANTS))
        assert ok == len(PLANTS), "a planted answer was not recovered"
