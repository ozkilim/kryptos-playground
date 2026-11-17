"""Idea 103: "matrix codes" on rectangles that hold all 26 letters (or 26 letters and the ?).

Sanborn (2005) said he used matrix codes Ed Scheidt gave him. Playfair, two-square and four-square are
logged dead only because a 5x5 square cannot produce 26 different letters, and K4 has all 26. A square
drawn as a 2x13 or 13x2 rectangle keeps all 26, and with the carved ? K4 has 98 symbols = 49 pairs and
27 = 3x9 symbols. These ciphers work on fixed pairs of letters, so the clue letters stay where they are.

Part 1, no key at all. ANY cipher that replaces letter pairs by letter pairs, one to one. Letter i is
paired with letter i + w inside blocks of 2w (w = 1 is ordinary pairs, w = 7 or 21 is Bean's seriated
test), w = 1..48, every block start, counted from the first letter or from the ?. K4's ciphertext is
known everywhere, so: two equal cipher pairs must hide equal plain pairs (their known clue letters must
agree), and one plain clue pair cannot give two cipher pairs. A pairing that fails is dead for every
pair cipher whatever its squares.

Part 2, on the Part 1 survivors with 6 or more full clue pairs.
 * Two-square. Each clue letter gives a condition on one square alone (order A: cipher letter 2 shares a
   column with plain letter 1 in the left square, cipher letter 1 with plain letter 2 in the right
   square), and a row link between the squares. First a test with no key list: can ANY two squares on
   the grid satisfy them (a column holds R letters, a row C, two letters cannot share a cell)? Then every
   listed square is filtered alone on its column conditions, and the two survivor lists are hash-joined
   on the row links. Both output orders. "One above the other" is the same cipher turned on its side,
   and the list of grids and fills is closed under that turn, so it is covered (planted answer 2 shows it).
 * Four-square, plain squares A-Z or KRYPTOS by rows (and the ? first or last on 27 cells): each full
   clue pair fixes one cell in each cipher square. First: do two letters land on one cell (dead for any
   cipher squares)? Then every listed square is tested against the fixed cells. Both output orders.
 * Grids 2x13, 13x2, 3x9, 9x3. Squares: A-Z, KRYPTOS, every dictionary keyword alphabet and its two
   transposition-mixed forms, written by rows or by columns, on 27 cells with the ? first or last.
 * Playfair on a rectangle never leaves a letter as it is (each letter moves to another cell), and K4
   has plain K -> cipher K at letter 74. Not run.

Survivors are decrypted in full and scored on the big English model. Controls: 3 shuffled K4s through
the same code. Planted: four messages (two-square side by side on 2x13; one above the other on 2x13;
two-square on 3x9 with the ?; four-square on 3x9 with the ? enciphered as symbol 0), found and read back.

  python attacks/103_matrix_codes_on_rectangles.py
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
from kryptos import idea103_matrix as M  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA103_PROCS", "4" if SMOKE else "8"))
NCTRL = int(os.environ.get("IDEA103_CONTROLS", "1" if SMOKE else "3"))
ENGLISH = -5.1        # big-model score per quadgram a reading must beat
READ_OK = 80          # letters of 97 right for a reading to count as the planted message
BIG = DATA_DIR / "english" / "quadgrams_big.txt"
G = {}


def init(plan):
    G["plan"] = plan


def work(chunk):
    return M.scan(G["plan"], chunk)


def reading(text, paired):
    """The letters that were actually deciphered (unpaired letters and a plain ? are left out)."""
    return "".join(text[i + 1] for i in paired if text[i + 1] != "?")


def run_text(label, ct, cribs, alphabets, big, verbose=True):
    """Parts 1 and 2 on one text. Returns (summary, rows best first, plan)."""
    ct = M.stream(ct)                       # 98 symbols: the ? and the 97 letters
    plan = M.Plan(ct[1:], cribs)
    items = [(i, a) for i, (_, a) in enumerate(alphabets)]
    hits2, hits4 = [], []
    for a, b in pmap(work, items, init, (plan,), chunk=4000, procs=PROCS):
        hits2.extend(a)
        hits4.extend(b)
    rows = []
    for gi, lid, h1, h2 in M.join2(hits2):
        g = M.GRIDS[gi]
        w, o, order, _ = plan.ts[lid]
        (n1, a1), (n2, a2) = alphabets[h1[4]], alphabets[h2[4]]
        c1, c2 = plan.cfgs[g][h1[5]], plan.cfgs[g][h2[5]]
        text, paired = M.two_square(ct, w, o, g, M.cells(a1, g, c1), M.cells(a2, g, c2), order, decrypt=True)
        rows.append({"cipher": "two-square", "grid": g, "w": w, "o": o, "order": order,
                     "squares": [(n1,) + c1, (n2,) + c2], "alphas": [(a1,) + c1, (a2,) + c2],
                     "text": text, "paired": paired})
    for sid, h1, h2 in M.join4(hits4):
        w, o, g, pn1, pn2, order, _, _ = plan.fs[sid]
        (n1, a1), (n2, a2) = alphabets[h1[2]], alphabets[h2[2]]
        c1, c2 = plan.cfgs[g][h1[4]], plan.cfgs[g][h2[4]]
        ps = dict(M.plain_squares(g))
        text, paired = M.four_square(ct, w, o, g, ps[pn1], ps[pn2], M.cells(a1, g, c1), M.cells(a2, g, c2),
                                     order, decrypt=True)
        rows.append({"cipher": "four-square", "grid": g, "w": w, "o": o, "order": order, "plain": [pn1, pn2],
                     "squares": [(n1,) + c1, (n2,) + c2], "alphas": [(a1,) + c1, (a2,) + c2],
                     "text": text, "paired": paired})
    for r in rows:
        # a joined survivor must give back every clue letter that has a partner
        assert all(r["text"][i + 1] == cribs[i] for i in r["paired"] if i in cribs), r
        r["reading"] = reading(r["text"], r["paired"])
        r["score"] = round(big.score(r["reading"]), 3)
    rows.sort(key=lambda r: -r["score"])
    c = plan.counts()
    dead1 = [x for x in plan.part1 if not x[2]]
    live_w = Counter(x[0] for x in plan.part1 if x[2])
    s = dict(c)
    s.update({
        "part1_dead": len(dead1),
        "part1_widths_fully_dead": [w for w in range(1, M.WMAX + 1) if not live_w.get(w)],
        "two_square_possible_by_grid": {"%dx%d" % g: sum(1 for (lid, gg), d in plan.ts_dead.items() if gg == g and not d)
                                        for g in M.GRIDS},
        "four_square_possible_by_grid": {"%dx%d" % g: sum(1 for v in plan.fs.values() if v[2] == g) for g in M.GRIDS},
        "two_square_single_square_survivors": len(hits2),
        "two_square_joined": sum(r["cipher"] == "two-square" for r in rows),
        "four_square_single_square_hits": len(hits4),
        "four_square_joined": sum(r["cipher"] == "four-square" for r in rows),
        "english": sum(r["score"] > ENGLISH for r in rows),
        "best": rows[0]["score"] if rows else None})
    print("%s: %s" % (label, json.dumps(s)))
    if verbose:
        for w in (1, 7, 21):
            print("   Part 1, w=%d: %d of %d block starts survive%s" % (
                w, live_w.get(w, 0), 2 * w,
                "" if live_w.get(w) else " (e.g. %s)" % next(x[4] for x in dead1 if x[0] == w)))
        for (lid, g), d in sorted(plan.ts_dead.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            if not d:
                w, o, order, conds = plan.ts[lid]
                print("   two-square still possible for some squares: grid %dx%d w=%d start=%d order %s "
                      "(%d full clue pairs; %d + %d column conditions, %d row links)"
                      % (g + (w, o, order, len(M.full_pairs(w, o, cribs)), len(conds[0]), len(conds[1]), len(conds[2]))))
    for r in rows[:8 if verbose else 3]:
        print("   %6.2f word cover %.2f  %s %dx%d w=%d start=%d order %s squares %s %s\n          %s"
              % (r["score"], word_coverage(r["reading"]), r["cipher"], r["grid"][0], r["grid"][1], r["w"], r["o"],
                 r["order"], r["squares"], r.get("plain", ""), r["text"]))
    return s, rows, plan


def all_pairings_two_square(ct, cribs):
    """The no-key two-square test on EVERY pairing (not only those with 6+ full clue pairs).

    Returns {grid: (pairing-and-order settings still possible, the smallest w among them)}."""
    out = {}
    for g in M.GRIDS:
        live = []
        for w, o in M.all_pairings():
            if not M.pair_substitution_ok(ct, cribs, w, o)[0]:
                continue
            for order in "AB":
                if M.ts_any_square(M.ts_conditions(ct, cribs, w, o, order), g):
                    live.append(w)
        out["%dx%d" % g] = (len(live), min(live) if live else None)
    return out


def tested(n_alph, plan):
    """Single-square checks decided: every listed square against every two-square column list and every
    four-square cell list of the Part 2 pairings (lists that no square can fit count as decided)."""
    n = 0
    for g in M.GRIDS:
        nsq = n_alph * len(M.configs(g))
        nps = len(M.plain_squares(g))
        n += nsq * 2 * len(plan.ts) + nsq * 2 * len(plan.ts) * nps * nps
    return n


# ---------------------------------------------------------------- planted answers

def message(rng):
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


PLANTS = [  # (kind, grid, w, start, order, (word 1, config 1), (word 2, config 2))
    ("two-square", (2, 13), 1, 0, "A", ("PALIMPSEST", ("rows", "")), ("SHADOW", ("rows", ""))),
    ("vertical", (2, 13), 1, 1, "", ("LODESTONE", ("rows", "")), ("COMPASS", ("cols", ""))),
    ("two-square", (3, 9), 5, 3, "B", ("ABSCISSA", ("cols", "last")), ("MEDUSA", ("rows", "first"))),
    ("four-square", (3, 9), 1, 1, "A", ("BERLIN", ("rows", "last")), ("ILLUSION", ("cols", "first"))),
]


def plant(rng, spec):
    """Returns (cipher stream, plain stream, what the search should report)."""
    kind, g, w, o, order, (w1, c1), (w2, c2) = spec
    a1, a2 = keyword_alphabet(w1), keyword_alphabet(w2)
    s1, s2 = M.cells(a1, g, c1), M.cells(a2, g, c2)
    for _ in range(20000):
        pt = message(rng)
        if kind == "two-square":
            ct, _ = M.two_square(pt, w, o, g, s1, s2, order)
            want = ("two-square", g, w, o, order, None, [(a1,) + c1, (a2,) + c2])
        elif kind == "vertical":
            # the search should find it as side by side, order B, on the grid turned on its side
            ct, _ = M.vertical_encrypt(pt, w, o, g, s1, s2)
            turn = {"rows": "cols", "cols": "rows"}
            want = ("two-square", (g[1], g[0]), w, o, "B", None,
                    [(a1, turn[c1[0]], c1[1]), (a2, turn[c2[0]], c2[1])])
        else:
            pn = ["KR+?last", "AZ+?first"]
            ps = dict(M.plain_squares(g))
            ct, _ = M.four_square(pt, w, o, g, ps[pn[0]], ps[pn[1]], s1, s2, order)
            want = ("four-square", g, w, o, order, pn, [(a1,) + c1, (a2,) + c2])
            if ct[0] != "?":          # the cipher's symbol 0 must be the carved ?
                continue
        if "?" not in ct[1:]:         # like K4: 97 letters after the ?
            return ct, M.stream(pt), want
    raise RuntimeError("could not plant " + kind)


def planted_case(rng, spec, alphabets, big):
    ct, pt, want = plant(rng, spec)
    cribs = {i: pt[i + 1] for i in CRIBS}
    have = {a for _, a in alphabets}
    extra = [(wd, keyword_alphabet(wd)) for wd, _ in spec[5:7] if keyword_alphabet(wd) not in have]
    s, rows, plan = run_text("planted %s %dx%d" % (spec[0], spec[1][0], spec[1][1]), ct, cribs, alphabets + extra,
                             big, verbose=False)
    mine = [r for r in rows if (r["cipher"], r["grid"], r["w"], r["o"], r["order"], r.get("plain"), r["alphas"]) == want]
    read = bool(mine) and mine[0]["text"] == pt

    def right(r):
        return sum(a == b for a, b in zip(r["text"][1:], pt[1:]))
    # a square from a similar word can give the same message with a few letters off: that is the planted
    # answer found again, not a wrong reading. A wrong reading is English-looking text that is NOT the message.
    near = [r for r in rows if r not in mine and right(r) >= READ_OK]
    wrong = [r for r in rows if right(r) < READ_OK and r["score"] > ENGLISH]
    top = bool(mine) and mine[0]["score"] >= rows[0]["score"] - 1e-9
    ok = read and top and not wrong
    print("   -> found=%s read back=%s best of all=%s (English %s); %d other joined settings: %d near-copies of the "
          "answer (%d+ of 97 letters right, from look-alike squares), %d others, %d of those read as English"
          % (bool(mine), read, top, mine[0]["score"] if mine else None, len(rows) - len(mine), len(near), READ_OK,
             len(rows) - len(mine) - len(near), len(wrong)))
    return ok


if __name__ == "__main__":
    t0 = time.time()
    alphabets = dictionary_alphabets(mixed=True)
    big = Quadgrams(BIG)
    with Experiment("matrix codes on 26/27-cell rectangles: any pair substitution, two-square, four-square",
                    puzzle="k4", cribs_forced=True,
                    notes="pairings w=1..48 x every block start; grids 2x13 13x2 3x9 9x3; %d dictionary and "
                          "transposition-mixed alphabets by rows or columns, ? first or last" % len(alphabets)) as ex:
        print("%d alphabets" % len(alphabets))
        assert K4[73] == "K" and CRIBS[73] == "K"      # the letter that stays: rules out Playfair on any rectangle
        k4, rows, plan = run_text("K4", K4, CRIBS, alphabets, big)
        n_tested = tested(len(alphabets), plan)
        ex.count(n_tested)
        for r in rows[:20]:
            ex.add(r["reading"], english_big=r["score"], cipher=r["cipher"], grid=r["grid"], w=r["w"], o=r["o"],
                   order=r["order"], squares=str(r["squares"]))
        k4_all = all_pairings_two_square(K4, CRIBS)
        print("   two-square with any squares, all 2352 pairings x 2 orders: still possible (count, smallest w) %s"
              % json.dumps(k4_all))
        print("   (%.1f min)" % ((time.time() - t0) / 60))
        ctrl, ctrl_all = [], []
        for s in range(NCTRL):
            sh = shuffled_control(10300 + s)
            c, _, _ = run_text("shuffled K4 #%d" % (s + 1), sh, CRIBS, alphabets, big, verbose=False)
            ctrl.append(c)
            ctrl_all.append(all_pairings_two_square(sh, CRIBS))
            print("   two-square with any squares, all pairings: %s" % json.dumps(ctrl_all[-1]))
            print("   (%.1f min)" % ((time.time() - t0) / 60))
        rng = random.Random(103)
        decoys = alphabets[::40] if SMOKE else alphabets[::int(os.environ.get("IDEA103_DECOY_STEP", "1"))]
        ok = 0
        for spec in PLANTS:
            ok += planted_case(rng, spec, decoys, big)
            print("   (%.1f min)" % ((time.time() - t0) / 60))
        print("planted recovered: %d/%d among %d decoy alphabets" % (ok, len(PLANTS), len(decoys)))
        cbest = [c["best"] for c in ctrl if c["best"] is not None]
        signal = k4["english"] > 0 and (not cbest or k4["best"] > max(cbest) + 0.3)
        verdict = ("K4 has a survivor that reads better than every control - inspect by eye" if signal else
                   "no matrix code on a 26/27-cell rectangle fits: K4 Part 1 %d of %d pairings dead; two-square %d of %d "
                   "settings possible for some squares, %d single-square survivors, %d joined; four-square %d of %d "
                   "possible for some cipher squares, %d square hits, %d joined; best reading %s. Shuffled K4s: joined "
                   "two-square %s, four-square %s, best %s"
                   % (k4["part1_dead"], k4["pairings"], k4["two_square_possible_for_some_squares"],
                      k4["two_square_settings"], k4["two_square_single_square_survivors"], k4["two_square_joined"],
                      k4["four_square_possible_for_some_cipher_squares"], k4["four_square_settings"],
                      k4["four_square_single_square_hits"], k4["four_square_joined"], k4["best"],
                      [c["two_square_joined"] for c in ctrl], [c["four_square_joined"] for c in ctrl],
                      [c["best"] for c in ctrl]))
        print("RESULT " + json.dumps({"k4": k4, "k4_two_square_any_squares_all_pairings": k4_all, "controls": ctrl,
                                      "controls_two_square_any_squares_all_pairings": ctrl_all,
                                      "planted": "%d/%d" % (ok, len(PLANTS)), "alphabets": len(alphabets),
                                      "tested": n_tested, "minutes": round((time.time() - t0) / 60, 1)}))
        print("VERDICT:", verdict)
        ex.notes += "; " + verdict + "; planted %d/%d" % (ok, len(PLANTS))
    if ok != len(PLANTS):
        sys.exit("planted answers not all recovered")
