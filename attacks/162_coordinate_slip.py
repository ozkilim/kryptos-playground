"""Idea 162: "shifting matrices" taken literally - the coordinate slip.

Sanborn spoke of "matrix codes Ed gave me"; Scheidt taught "shifting matrices". By hand: put the alphabet in
a hidden grid, write every plain letter as two digits (its row above its column, the bifid worksheet), slide
the lower line of digits a few places along, and turn each column of two digits back into a letter. Every
cipher letter then has one coordinate from the plain letter under it and the other from a plain letter s
places away. Idea 39 added wheels to the digits and ideas 103/139 took the letters in separate pairs; no
test let one coordinate come from a neighbouring letter.

Model (kryptos/idea162_slip.py), one grid of R x C cells, 26 letters, spare cells empty:
  straight:  row(c_i) = row(p_{i+u}) + a,   col(c_i) = col(p_{i+w}) + b
  crossed:   row(c_i) = col(p_{i+u}),       col(c_i) = row(p_{i+w})

Part A, the idea as stated: one line stays at home ((u, w) = (0, s) or (s, 0), s = -45..45 except 0), straight
or crossed (the four role assignments), every constant a, b on the straight lines, grids 2x13 13x2 3x9 9x3
4x7 7x4 5x6 6x5. Part B, a natural extra: both lines slid (u, w = -45..45, u != w, no constants), which is
the same cipher with the cipher text displaced. Each setting is decided exactly for ANY grid of that shape:
the clue letters say "X is in the row of Y", and a backtracking search looks for a placing with no two
letters in one cell. Two end rules: "open" uses only the statements whose letters are both inside the text
(true whatever happens at the ends), "wrap" lets the digit lines wrap round the 97 letters.

Hand fact for the straight home line: a cipher letter shares a row (or column) with its own plain letter, so
the 24 clue pairs chain 21 letters into ONE row. No grid has a line of 21. With a constant added, K = K at
letter 74 and S = S at letter 33 force the constant back to 0.

For every setting that survives on K4 (and on 5 of the controls) all dictionary keyword grids are tried
(by rows, by columns, spare cells last or first) and the hits are decrypted and read on the big model.
Before all that the script measures the index of coincidence this cipher gives on English, and how often an
English message lands on an empty cell (K4 has 97 letters and no other mark).

  python attacks/162_coordinate_slip.py
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
from kryptos import idea162_slip as S  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA162_PROCS", "4" if SMOKE else "8"))
NCTRL = int(os.environ.get("IDEA162_CONTROLS", "3" if SMOKE else "50"))
NDICT = int(os.environ.get("IDEA162_DICT_CONTROLS", "1" if SMOKE else "5"))
SMAX = int(os.environ.get("IDEA162_SMAX", "8" if SMOKE else "45"))
LIMIT = int(os.environ.get("IDEA162_LIMIT", "200000"))
READ_MIN = 40                                   # letters with both digits inside the text needed to read
SLIPS = [s for s in range(-SMAX, SMAX + 1) if s]
K4_IOC = S.ioc(K4)


def settings_a():
    out = []
    for g in S.GRIDS:
        for s in SLIPS:
            for u, w in ((0, s), (s, 0)):
                out.append((g, "CR", u, w, 0, 0))
                for a in range(g[0]):
                    for b in range(g[1]):
                        out.append((g, "RC", u, w, a, b))
    return out


def settings_b():
    return [(g, mode, u, w, 0, 0) for g in S.GRIDS for u in SLIPS for w in SLIPS if u != w for mode in ("RC", "CR")]


# ---------------------------------------------------------------- scan (one text per task)

def init_scan():
    pass


def scan(chunk):
    out = []
    for label, ct in chunk:
        res = {}
        for part, sets in (("A", settings_a()), ("B", settings_b())):
            for wrap in (False, True):
                surv, und, bad = [], 0, 0
                for g, mode, u, w, a, b in sets:
                    v, place = S.decide(ct, CRIBS, g, mode, u, w, a, b, LIMIT, wrap)
                    if v is None:
                        und += 1
                    elif v:
                        if not S.check_grid(ct, CRIBS, S.build_grid(place, g), g, mode, u, w, a, b, wrap):
                            bad += 1
                        surv.append((g, mode, u, w, a, b))
                res[part, wrap] = (surv, und, bad, len(sets))
        out.append((label, res))
    return out


# ---------------------------------------------------------------- dictionary grids for survivors

_ALPHA = None
_BIG = None


def big():
    global _BIG
    if _BIG is None:
        _BIG = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    return _BIG


def init_dict():
    global _ALPHA
    _ALPHA = dictionary_alphabets()
    big()


def read_segment(ct, cells, g, mode, u, w, a, b):
    """The letters that can be read without wrapping, as one run."""
    return S.decrypt(ct, cells, g, mode, u, w, a, b, wrap=False).strip("?")


def dict_work(chunk):
    out = []
    q = big()
    for label, ct, (g, mode, u, w, a, b) in chunk:
        hits = S.dictionary_hits(ct, CRIBS, _ALPHA, g, mode, u, w, a, b)
        best = None
        if S.overlap(u, w) >= READ_MIN:
            for name, fill, cells in hits:
                seg = read_segment(ct, cells, g, mode, u, w, a, b)
                if "?" in seg:
                    continue                    # an empty cell inside the text: not a message
                sc = q.score(seg)
                if best is None or sc > best[0]:
                    best = (sc, seg, name, fill)
        out.append((label, (g, mode, u, w, a, b), len(hits), best))
    return out


# ---------------------------------------------------------------- what the cipher does to English

def ioc_table(rng, n):
    rows = {}
    for g in S.GRIDS:
        vals, clean, crossed_ok = [], 0, 0
        for _ in range(n):
            pt = english97(rng)
            cells = S.random_grid(g, rng)
            s = rng.choice(SLIPS)
            ct = S.encrypt(pt, cells, g, "RC", 0, s)
            vals.append(S.ioc(ct))
            clean += "." not in ct
            crossed_ok += S.encrypt(pt, cells, g, "CR", 0, s) is not None
        vals.sort()
        rows[S.gname(g)] = {"mean": round(sum(vals) / n, 4), "min": round(vals[0], 4),
                            "p05": round(vals[n // 20], 4), "p95": round(vals[-(n // 20) - 1], 4),
                            "share_at_or_below_K4": round(sum(v <= K4_IOC for v in vals) / n, 3),
                            "no_empty_cell": round(clean / n, 3), "crossed_possible": round(crossed_ok / n, 3)}
    # crossed digits only work as a 5x5 square with one letter set aside: 5x6 filled by columns, Z alone in
    # the last column (a message with a Z cannot be enciphered)
    vals, tried = [], 0
    while len(vals) < n and tried < 50 * n:
        tried += 1
        pt = english97(rng)
        sq = list(S.AZ[:25])
        rng.shuffle(sq)
        ct = S.encrypt(pt, S.keyword_grid("".join(sq) + "Z", (5, 6), "cols"), (5, 6), "CR", 0, rng.choice(SLIPS))
        if ct:
            vals.append(S.ioc(ct))
    vals.sort()
    m = len(vals)
    rows["5x6 crossed (5x5 square, Z aside)"] = {
        "mean": round(sum(vals) / m, 4), "min": round(vals[0], 4), "p05": round(vals[m // 20], 4),
        "p95": round(vals[-(m // 20) - 1], 4), "share_at_or_below_K4": round(sum(v <= K4_IOC for v in vals) / m, 3),
        "messages_without_Z": round(m / tried, 3)}
    return rows


# ---------------------------------------------------------------- planted answers

def message(rng):
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


PLANTS = (((5, 6), "RC", 0, 3, 0, 0, "rows"), ((3, 9), "RC", 0, 21, 0, 0, "rows"),
          ((6, 5), "RC", -7, 0, 0, 0, "cols"), ((4, 7), "RC", 0, 5, 0, 3, "rows"),
          ((2, 13), "RC", 0, -2, 0, 6, "rows"), ((5, 6), "RC", 2, -4, 0, 0, "rows.first"),
          ((5, 6), "CR", 0, 3, 0, 0, "cols"), ((6, 5), "CR", 11, 0, 0, 0, "rows"))


def plant(rng, alphabets, spec, tries=20000):
    """A keyword grid and an English message that the cipher turns into 97 plain letters (no empty cell)."""
    g, mode, u, w, a, b, fill = spec
    pool = alphabets[1:3000]
    for t in range(tries):
        name, alpha = rng.choice(pool)
        cells = S.keyword_grid(alpha, g, fill)
        pt = message(rng)
        ct = S.encrypt(pt, cells, g, mode, u, w, a, b)
        if ct and "." not in ct:
            return name, cells, pt, ct, t + 1
    return None


def planted(rng, alphabets, specs=PLANTS):
    ok, rows = 0, []
    for spec in specs:
        g, mode, u, w, a, b, fill = spec
        made = plant(rng, alphabets, spec)
        if made is None:
            rows.append((S.gname(g), mode, u, w, a, b, "no message without an empty cell"))
            continue
        name, cells, pt, ct, tries = made
        v, place = S.decide(ct, CRIBS, g, mode, u, w, a, b, LIMIT * 10)
        vw, _ = S.decide(ct, CRIBS, g, mode, u, w, a, b, LIMIT * 10, True)
        hits = S.dictionary_hits(ct, CRIBS, alphabets, g, mode, u, w, a, b, wrap=True) if v and vw else []
        reads = [(n, f) for n, f, c in hits if S.decrypt(ct, c, g, mode, u, w, a, b) == pt]
        good = bool(v) and bool(vw) and any(c == cells for _, _, c in hits) and bool(reads)
        ok += good
        rows.append((S.gname(g), mode, u, w, a, b, name, fill, "tries %d" % tries, "feasible %s/%s" % (v, vw),
                     "grids fitting %d" % len(hits), "read back 97/97" if reads else "NOT read", round(big().score(pt), 2)))
    return ok, len(specs), rows


def tally(surv):
    c = Counter("%s %s" % (m, S.gname(g)) for g, m, u, w, a, b in surv)
    return dict(sorted(c.items()))


if __name__ == "__main__":
    t0 = time.time()
    rng = random.Random(162)
    texts = [("K4", K4)] + [("shuffled #%d" % (s + 1), shuffled_control(16200 + s)) for s in range(NCTRL)]
    na, nb = len(settings_a()), len(settings_b())
    with Experiment("coordinate slip on one hidden grid (row digit from one letter, column digit from a letter "
                    "s places on): exact any-grid test, then dictionary grids", puzzle="k4", cribs_forced=True,
                    notes="grids 2x13 13x2 3x9 9x3 4x7 7x4 5x6 6x5; slips -%d..%d; part A one line at home x 4 roles "
                          "x constants (%d settings), part B both lines slid (%d settings); open and wrapped ends; "
                          "K4 + %d shuffled" % (SMAX, SMAX, na, nb, NCTRL)) as ex:
        # 1. what the cipher does to English
        table = ioc_table(rng, 60 if SMOKE else 1000)
        print("K4 index of coincidence %.4f. Coordinate slip on English (random grid, home row, random slip):" % K4_IOC)
        for k, v in table.items():
            print("   %-5s %s" % (k, json.dumps(v)))
        # 2. planted answers
        alphabets = dictionary_alphabets()
        print("%d dictionary alphabets (%.1f min)" % (len(alphabets), (time.time() - t0) / 60))
        ok, tot, prow = planted(rng, alphabets)
        for r in prow:
            print("   planted:", r)
        print("planted: %d/%d survive the any-grid test, are found among the dictionary grids and read back (%.1f min)"
              % (ok, tot, (time.time() - t0) / 60))
        # 3. the scan
        results = {}
        for part in pmap(scan, texts, init_scan, (), chunk=1, procs=PROCS):
            for label, res in part:
                results[label] = res
        ex.count(2 * (na + nb) * len(texts))
        print("scan done: %d settings x 2 end rules x %d texts (%.1f min)" % (na + nb, len(texts), (time.time() - t0) / 60))
        bad = sum(r[k][2] for r in results.values() for k in r)
        und = {l: sum(r[k][1] for k in r) for l, r in results.items()}
        assert bad == 0, "a feasible placing did not rebuild into a working grid"
        summary = {}
        for key, nm in ((("A", False), "A open"), (("A", True), "A wrap"), (("B", False), "B open"), (("B", True), "B wrap")):
            k = results["K4"][key][0]
            cs = [len(results[l][key][0]) for l, _ in texts[1:]]
            ov = [S.overlap(u, w) for g, m, u, w, a, b in k]
            cov = [max([S.overlap(u, w) for g, m, u, w, a, b in results[l][key][0]] or [0]) for l, _ in texts[1:]]
            summary[nm] = {"settings": results["K4"][key][3], "K4_survive": len(k), "K4_by_grid": tally(k),
                           "K4_most_letters_inside": max(ov or [0]),
                           "controls_survive_min_median_max": [min(cs), sorted(cs)[len(cs) // 2], max(cs)],
                           "controls_mean": round(sum(cs) / len(cs), 1),
                           "controls_at_or_above_K4": sum(c >= len(k) for c in cs),
                           "controls_with_any": sum(c > 0 for c in cs),
                           "controls_most_letters_inside_max": max(cov)}
            print("%s: %s" % (nm, json.dumps(summary[nm])))
        print("undecided: K4 %d, controls %d" % (und["K4"], sum(v for l, v in und.items() if l != "K4")))
        # 4. dictionary grids for the open-end survivors of K4 and the first controls
        ctd = dict(texts)
        jobs = []
        for label in [t[0] for t in texts[:1 + NDICT]]:
            for key in (("A", False), ("B", False)):
                jobs += [(label, ctd[label], s) for s in results[label][key][0]]
        dres = {t[0]: [] for t in texts[:1 + NDICT]}
        for part in pmap(dict_work, jobs, init_dict, (), chunk=4, procs=PROCS):
            for label, s, nh, best in part:
                dres[label].append((s, nh, best))
        ex.count(len(jobs) * len(alphabets) * 3)
        dsum = {}
        for label, rows in dres.items():
            readable = [r for r in rows if r[2]]
            top = max(readable, key=lambda r: r[2][0]) if readable else None
            dsum[label] = {"survivors": len(rows), "with_a_dictionary_grid": sum(r[1] > 0 for r in rows),
                           "dictionary_grids": sum(r[1] for r in rows),
                           "long_enough_to_read": sum(S.overlap(r[0][2], r[0][3]) >= READ_MIN for r in rows),
                           "best_big_model": round(top[2][0], 2) if top else None,
                           "best_text": top[2][1] if top else None,
                           "best_word_cover": round(word_coverage(top[2][1]), 2) if top else None,
                           "best_setting": ("%s %s u=%d w=%d key %s %s" % (S.gname(top[0][0]), top[0][1], top[0][2],
                                                                            top[0][3], top[2][2], top[2][3])) if top else None}
            print("dictionary stage %s: %s" % (label, json.dumps(dsum[label])))
        verdict = ("idea as stated (part A): K4 %d of %d settings survive (open ends), %d wrapped; both lines slid "
                   "(part B): %d of %d open, %d wrapped; planted %d/%d"
                   % (summary["A open"]["K4_survive"], na, summary["A wrap"]["K4_survive"],
                      summary["B open"]["K4_survive"], nb, summary["B wrap"]["K4_survive"], ok, tot))
        print("RESULT " + json.dumps({"ioc": table, "k4_ioc": round(K4_IOC, 4), "summary": summary, "dictionary": dsum,
                                      "planted": "%d/%d" % (ok, tot), "undecided_k4": und["K4"],
                                      "undecided_controls": sum(v for l, v in und.items() if l != "K4"),
                                      "alphabets": len(alphabets), "texts": len(texts),
                                      "minutes": round((time.time() - t0) / 60, 1)}))
        print("VERDICT:", verdict)
        ex.notes += "; " + verdict
    if ok != tot:
        sys.exit("planted answers not all recovered")
