"""Idea 123: compass steps on a letter grid - is every clue letter a short move from its plain letter?

The first clue is two compass bearings (EAST, NORTHEAST), the site has a compass rose, Sanborn
used matrix codes and Scheidt taught shifting matrices, and Bean found the clue plain and cipher
letters unusually close in the alphabet. Picture the alphabet written in a grid, and the key as a
string of compass moves (N, NE, E, ... or stay). A sideways move changes a letter by one place;
an up or down move changes it by the row width. If that is how K4 was made, then on the right grid
every one of the 24 clue pairs is a king's move apart (or the same letter: S->S and K->K).

Grids: an alphabet written in rows of width w = 3..13, 26 cells, or 27 with the '?' as the last
cell; the last row is short. Alphabets: A-Z, KRYPTOS, 84 theme-word keyword alphabets, 12 old
script orders (the "small" set), and every dictionary keyword alphabet (about 220,000).
Conventions: flat (no wrap), cwrap (columns wrap), twrap (rows and columns wrap).
For each grid and each clue pair the shortest move (rows, columns) from plain to cipher letter is
read off. Statistics (kryptos/idea123_compass.py):
  R  the largest king distance of any of the 24 moves   (exact hit: R = 1)
  D  the number of different moves                     (exact hit: D <= 8)
  Q  how many moves lie on one of the 8 compass lines (row, column or diagonal)
Each also for each clue block alone (13 and 11 pairs; the first block has the small shifts).

Controls: 200 shuffled K4s on the small set; 3 shuffled K4s each on a different third of the
dictionary alphabets. K4 is shown on the same thirds so the numbers compare directly.
Survivors with R = 1 are decoded: each cipher letter has at most 9 plain candidates, so the best
reading is found by an exact Viterbi on the big quadgram model and by a word split, both polished
on quadgrams + word coverage, and printed for a human read.

Planted: English texts moved by random compass steps on KRYPTOS at width 7 (flat), on a dictionary
alphabet at width 5 (flat) and at width 9 with 27 cells and both wraps. Each must give R = 1 at
the planted grid (the exact test) and its reading is compared with chance.

Scope: moves of two or more cells in a small grid reach most letters and cannot be judged; a
grid alphabet outside the lists, a grid filled other than row by row, or a '?' cell elsewhere
than last are not covered.

  python attacks/123_compass_steps_on_grid.py
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers.substitution import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import word_coverage  # noqa: E402
from kryptos import wordkeys, historic_alphabets  # noqa: E402
from kryptos import idea123_compass as C  # noqa: E402

SMALL_SEEDS = tuple(range(1, 6)) if SMOKE else tuple(range(1, 201))
DICT_SEEDS = (1001, 1002, 1003)
PARTS = ("all", "b1", "b2")
PL = [CRIBS[i] for i in POS]
G = {}


def small_alphabets():
    out, seen = [], set()
    for name, a in ([("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)]
                    + [(w, keyword_alphabet(w)) for w in wordkeys.theme_words()]
                    + sorted(historic_alphabets.alphabets().items())):
        if a not in seen:
            seen.add(a)
            out.append((name, a))
    return out


def new_acc():
    # per part: [best R, best D, best Q, #R==1, #D<=8, R histogram]
    return {p: [99, 99, -1, 0, 0, {}] for p in PARTS}


def update(acc, st, hits, tag):
    for p, (r, d, q) in zip(PARTS, st):
        a = acc[p]
        if r < a[0]:
            a[0] = r
        if d < a[1]:
            a[1] = d
        if q > a[2]:
            a[2] = q
        a[5][r] = a[5].get(r, 0) + 1
        if r <= 1:
            a[3] += 1
        if d <= 8:
            a[4] += 1
        if p == "all" and (r <= 1 or d <= 8 or q >= 22):
            hits.append((tag, r, d, q))
        elif p != "all" and r <= 1:
            hits.append((tag + (p,), r, d, q))


def merge(dst, src):
    for p in PARTS:
        a, b = dst[p], src[p]
        a[0], a[1], a[2] = min(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2])
        a[3] += b[3]
        a[4] += b[4]
        for r, c in b[5].items():
            a[5][r] = a[5].get(r, 0) + c


def scan(alpha, cl, acc, hits, name):
    n_done = 0
    for n, w, conv in C.GRIDS:
        st = C.stats(C.keys(alpha, n, PL, cl), C.tables(n, w, conv))
        update(acc, st, hits, (name, n, w, conv))
        n_done += 1
    return n_done


def init(cts):
    G["cts"] = cts


def work(chunk):
    """chunk of (index, name, alpha) dictionary alphabets: K4 on all, shuffle t on third t."""
    cts = G["cts"]
    res = {}
    hits = {}
    done = 0
    for idx, name, alpha in chunk:
        third = idx % 3
        for label in ("K4", "S%d" % third):
            key = (label, third)
            acc = res.setdefault(key, new_acc())
            done += scan(alpha, cts[label], acc, hits.setdefault(label, []), name)
    return res, hits, done


def chance_sum(alphas):
    return sum(C.chance_r1(a, n, w, conv, PL) for _, a in alphas for n, w, conv in C.GRIDS)


def fmt(a):
    hist = " ".join("%d:%d" % (r, a[5][r]) for r in sorted(a[5])[:4])
    return "R=%d D=%2d Q=%2d #R1=%d #D<=8=%d  [R hist %s]" % (a[0], a[1], a[2], a[3], a[4], hist)


def qscore(t, model):
    return sum(model.q.get(t[i:i + 4], model.floor) for i in range(len(t) - 3)) / (len(t) - 3)


def planted(models, ex):
    rng = random.Random(12300)
    dict_alpha = keyword_alphabet("UNDERGROUND")
    plants = [("KRYPTOS w7 flat", KRYPTOS_ALPHABET, 26, 7, "flat"),
              ("UNDERGROUND w5 flat", dict_alpha, 26, 5, "flat"),
              ("PALIMPSEST w9 27 cells twrap", keyword_alphabet("PALIMPSEST"), 27, 9, "twrap")]
    ok = 0
    out = []
    for label, alpha, n, w, conv in plants:
        text = english97(rng)
        ct = C.encrypt(text, alpha, n, w, conv, rng)
        st = C.stats(C.keys(alpha, n, [text[i] for i in POS], [ct[i] for i in POS]), C.tables(n, w, conv))
        cand = C.candidates(alpha, n, w, conv)
        cribs = {i: text[i] for i in POS}
        t = C.decode(ct, cribs, cand, *models)
        right = sum(a == b for a, b in zip(t, text))
        # chance: a random candidate per letter
        r2 = random.Random(1)
        rnd = [sum((cribs[i] if i in cribs else r2.choice(cand[c])) == text[i] for i, c in enumerate(ct))
               for _ in range(200)]
        base = sum(rnd) / 200.0
        found = st[0][0] == 1
        good = found and right >= base + 10
        ok += good
        print("planted %-30s R=%d D=%d Q=%d at the planted grid; read back %d/97 (random choice among the"
              " candidates: %.1f); big-model %.2f, words %.2f -> %s"
              % (label, st[0][0], st[0][1], st[0][2], right, base, qscore(t, models[0]), word_coverage(t),
                 "ok" if good else "FAIL"))
        print("     truth %s\n     read  %s" % (text, t))
        ex.add(t, plant=label, right=right)
        out.append((label, found, right, base))
    return ok, out


if __name__ == "__main__":
    t0 = time.time()
    models = (C.Model(DATA_DIR / "english" / "quadgrams_big.txt"), C.Words(DATA_DIR / "english" / "words_big.txt"))
    small = small_alphabets()
    dic = [a for a in dictionary_alphabets() if a[1] not in {x[1] for x in small}]
    if SMOKE:
        dic = dic[:3000]
    with Experiment("compass steps on a letter grid: king distance / distinct moves of the 24 clue pairs",
                    puzzle="k4",
                    notes="alphabets: %d small (A-Z, KRYPTOS, theme, old scripts) + %d dictionary keyword; widths 3-13; "
                          "26 or 27 cells; flat/cwrap/twrap; R, D, Q per grid, each block alone; %d shuffles on small, "
                          "3 on dictionary thirds; planted 3" % (len(small), len(dic), len(SMALL_SEEDS)),
                    cribs_forced=True) as ex:
        print("grids per alphabet: %d (2 sizes x %d widths x 3 conventions); small set %d alphabets; dictionary %d"
              % (len(C.GRIDS), len(C.WIDTHS), len(small), len(dic)))

        # ---- planted first: the script must pass these
        ok, plant_info = planted(models, ex)
        print("planted recovered: %d/3\n" % ok)
        if ok < 3:
            raise SystemExit("planted test failed")

        k4cl = [K4[i] for i in POS]
        tested = 0
        # ---- small set: K4 and 200 shuffles
        small_res = {}
        hits_small = {}
        cts_small = {"K4": k4cl}
        for s in SMALL_SEEDS:
            sc = shuffled_control(s)
            cts_small["s%d" % s] = [sc[i] for i in POS]
        for label, cl in cts_small.items():
            acc = small_res[label] = new_acc()
            hl = hits_small[label] = []
            for name, a in small:
                tested += scan(a, cl, acc, hl, name)
        print("SMALL SET (%d alphabets, %d grids per text)  (%.0f s)" % (len(small), len(small) * len(C.GRIDS),
                                                                       time.time() - t0))
        print("expected chance grids with R=1 on the small set: %.2e" % chance_sum(small))
        for p in PARTS:
            k = small_res["K4"][p]
            print("  %-3s K4: %s" % (p, fmt(k)))
            ctr = [small_res["s%d" % s][p] for s in SMALL_SEEDS]
            for j, nm, low in ((0, "best R", True), (1, "best D", True), (2, "best Q", False), (3, "#R=1", False),
                               (4, "#D<=8", False)):
                vals = [c[j] for c in ctr]
                if low:
                    pv = sum(v <= k[j] for v in vals) / float(len(vals))
                else:
                    pv = sum(v >= k[j] for v in vals) / float(len(vals))
                dist = " ".join("%d:%d" % (v, vals.count(v)) for v in sorted(set(vals)))
                print("        %-6s K4 %3d  shuffles {%s}  share at least as extreme %.3f" % (nm, k[j], dist, pv))
        for h in hits_small["K4"]:
            print("  K4 small-set notable grid:", h)
        bl = [sum(1 for h in hits_small["s%d" % s] if len(h[0]) == 5) for s in SMALL_SEEDS]
        print("  block-alone R=1 grids on the small set: K4 %d; shuffles mean %.2f, max %d, share >= K4 %.3f"
              % (sum(1 for h in hits_small["K4"] if len(h[0]) == 5), sum(bl) / float(len(bl)), max(bl),
                 sum(b >= sum(1 for h in hits_small["K4"] if len(h[0]) == 5) for b in bl) / float(len(bl))))

        # ---- dictionary: K4 and 3 shuffles on thirds
        cts = {"K4": k4cl}
        for t, s in enumerate(DICT_SEEDS):
            sc = shuffled_control(s)
            cts["S%d" % t] = [sc[i] for i in POS]
        items = [(i, name, a) for i, (name, a) in enumerate(dic)]
        dres, dhits = {}, {}
        for res, hits, done in pmap(work, items, init, (cts,), chunk=1500, procs=12):
            tested += done
            for key, acc in res.items():
                merge(dres.setdefault(key, new_acc()), acc)
            for label, hl in hits.items():
                dhits.setdefault(label, []).extend(hl)
        print("\nDICTIONARY (%d alphabets, %d grids)  (%.0f s)" % (len(dic), len(dic) * len(C.GRIDS), time.time() - t0))
        r2 = random.Random(7)
        samp = r2.sample(dic, min(2000, len(dic)))
        est = chance_sum(samp) * len(dic) / float(len(samp))
        print("expected chance grids with R=1 on the dictionary (from a sample of %d alphabets): %.2e" % (len(samp), est))
        for t in range(3):
            for p in PARTS:
                print("  third %d %-3s K4        : %s" % (t, p, fmt(dres[("K4", t)][p])))
                print("  third %d %-3s shuffle %d : %s" % (t, p, DICT_SEEDS[t], fmt(dres[("S%d" % t, t)][p])))
        for label in ["K4", "S0", "S1", "S2"]:
            hl = [h for h in dhits.get(label, []) if len(h[0]) == 4]
            bh = [h for h in dhits.get(label, []) if len(h[0]) == 5]
            print("  %s block-alone R=1 grids on the dictionary: b1 %d, b2 %d; first few: %s" % (
                label, sum(h[0][4] == "b1" for h in bh), sum(h[0][4] == "b2" for h in bh), [h[0] for h in bh[:6]]))
            print("  %s notable grids (R<=1, D<=8 or Q>=22) on the dictionary: %d" % (label, len(hl)))
            for h in sorted(hl, key=lambda x: (x[1], x[2], -x[3]))[:10]:
                print("     ", h)
        ex.count(tested)
        print("\ngrids x texts tested: %d" % tested)

        # ---- survivors: decode every K4 grid with R = 1
        surv = [h for h in hits_small["K4"] + dhits.get("K4", []) if h[1] <= 1 and len(h[0]) == 4]
        print("K4 grids with R = 1 on all 24 clue pairs: %d" % len(surv))
        alpha_of = dict(small)
        alpha_of.update(dict(dic))
        for (name, n, w, conv), r, d, q in surv:
            a = alpha_of[name]
            t = C.decode(K4, CRIBS, C.candidates(a, n, w, conv), *models)
            print("  %s n=%d w=%d %s: %s  big-model %.2f words %.2f" % (name, n, w, conv, t, qscore(t, models[0]),
                                                                       word_coverage(t)))
            ex.add(t, alphabet=name, cells=n, width=w, conv=conv)
        print("\n(%.0f s)" % (time.time() - t0))
