"""Idea 118: close the holes the idea-105 audit found in attacks 90, 59, 88, 60C, 61, 69B and 57.

Idea 105 fed K4-shaped messages from textbook encryptors to twenty attacks. In seven of them it found
settings that the negatives say were tested, but where K4 never really was (a simple remembered-key
cipher, Scheidt 2011, could still sit in any of them). The old attacks are left as they are; fixed
copies of their test functions live in kryptos/idea118_holes.py, and this script runs K4 on exactly
the settings the old code missed:

  90   bug: runs of clue pairs were split on the clue index, not the position. New: cipher feed 30-33
       back with a word of 2-4 on top, 666,993 alphabets x 5 layouts x Vig/Beau x feed numbered on
       M/A-Z/KRYPTOS x sign (11 (lag, word) settings per view).
  59   lags with fewer than 12 usable clue letters were skipped. New: autokey + repeating key on
       A-Z/KRYPTOS, cipher feed 34-60 back, plain feed 7-8 back, multiplier 1-25, key length 1-26.
  88   progressive key when word breaks leave no two clue letters p apart in one run. New: lengths 6-12
       with EAST|NORTH|EAST + BERLIN|CLOCK, 9-12 with EAST|NORTHEAST + BERLIN|CLOCK, 11-12 with
       BERLINCLOCK unbroken; every start, offset 0-25, any step 1-25; 220,318 keyword alphabets.
       (Two stacked keys for 88 were already closed by idea 104, part "breaks"; only re-checked here on
       the audit's plants.)
  60C  Slidefair with the ACA same-column rule allowed in any clue pair.
  61   the scrambled key turned clockwise (and double turns in every mix of directions), 97 and 98 cells.
  69B  rows of 21, a different tableau per row, joined on the key LETTERS read off each row's own
       cipher strip (26 offsets per row), every pair of the 2.2 million (alphabet, layout, form) streams.
  57   English running key with the key letter read as M[s + c] or KRYPTOS[s + c] (key set under any
       plain letter, e.g. A) on M/M, M/KR, KR/M; the forced 13 + 11 key letters scored as English.

Exact tests need 7 or more checks (59 and 61 also list their own 6); every count is printed with the
number of passes chance predicts. Controls: three shuffled K4s, each on a different third of the
alphabets (10 shuffles where no alphabet list is involved). Planted: every idea-105 plant of these
holes (24 messages per cell) must now be found, and the cells found before must still be found.

  python attacks/118_close_audit_holes.py
"""
import random
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea118_holes as H  # noqa: E402
from kryptos import idea90_rowkey as R  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
A57 = sorted((ROOT / "attacks").glob("57_*.py"))[0]
N_PLANT = 4 if SMOKE else 24
SEEDS = (1, 2, 3)
SEEDS10 = (1, 2) if SMOKE else tuple(range(1, 11))
ENGLISH = -5.1          # big-model score per quadgram that English reaches


def line(name, n_set, hits, chance, thr=7):
    n7 = sum(1 for h in hits if h[0] >= thr)
    best = max((h[0] for h in hits), default=0)
    print("  %-34s settings %14s  pass %d+: %d (chance %.2g)  best checks %d" % (name, "{:,}".format(n_set), thr, n7, chance, best))
    return n7, best


# ------------------------------------------------------------------ parts

def part90(ct, alphas, big, by_name, label):
    t = H.tests90(True)
    hits = H.search90(ct, CRIBS, alphas)
    n_set = sum(t.settings(m) for _, m in alphas)
    chance = sum(t.chance(m) for _, m in alphas)
    r = line("90 %s" % label, n_set, hits, chance)
    for h in sorted(hits, reverse=True)[:5]:
        pt = R.decrypt(ct, CRIBS, by_name[h[1]], h)
        sc, cnt = R.extra_score(pt, big, frozenset(R.positions(h[8])))
        print("      checks=%d %s %s %s fed %s lag %d word %d: %s english %s/%d" % (
            h[0], h[1], h[2], h[3], h[4], h[7], h[9], pt, "%.2f" % sc if sc is not None else "n/a", cnt))
    return n_set, r


def part59(ct, label, show=True):
    tried, hits, chance = H.search59(ct, CRIBS)
    n6 = len(hits)
    n7 = sum(1 for h in hits if h[0] >= 7)
    if show:
        print("  %-34s settings %14s  pass 6+: %d (chance %.2g)  pass 7+: %d  best %d" % (
            "59 %s" % label, "{:,}".format(tried), n6, chance, n7, max((h[0] for h in hits), default=0)))
        for h in sorted(hits, reverse=True)[:3]:
            print("      checks=%d %s src=%s lag=%d a=%+d b=%d p=%d: %s" % (h + (H.decrypt59(ct, CRIBS, h),)))
    return tried, (n6, n7, max((h[0] for h in hits), default=0))


def part88(ct, alphas, label):
    hits = H.search88(ct, CRIBS, alphas)
    n_streams = len(alphas) * 10 - (2 if any(m == "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for _, m in alphas) else 0)
    n_set = n_streams * H.prog_tests88()
    r = line("88 progressive %s" % label, n_set, hits, n_streams * H.prog_chance88())
    for h in sorted(hits, reverse=True)[:5]:
        print("      checks=%d %s %s %s [%s, offset +%d] %s" % (h[0], h[1], h[2], h[3], H.S88.label(h[4], h[5]), h[6], h[7]))
    return n_set, r


def part60(ct, label, show=True):
    hits, n, chance = H.slidefair_fixed(ct, CRIBS)
    if show:
        print("  %-34s settings %14s  pass (all 11 clue pairs): %d (chance %.2g)" % ("60C %s" % label, n, len(hits), chance))
        for h in hits:
            print("      %s" % (h,))
    return n, len(hits)


def part61(ct, label, show=True):
    hits, n, chance = H.search61(ct, CRIBS)
    n6, n7 = len(hits), sum(1 for h in hits if h[0] >= 7)
    if show:
        print("  %-34s settings %14s  pass 6+: %d (chance %.2g)  pass 7+: %d  best %d" % (
            "61 %s" % label, "{:,}".format(n), n6, chance, n7, max((h[0] for h in hits), default=0)))
        for h in sorted(hits, reverse=True)[:3]:
            print("      checks=%d %s p=%d %s" % h)
    return n, (n6, n7, max((h[0] for h in hits), default=0))


def part69(ct, alphas, label):
    joined, n2, n4 = H.search69(ct, CRIBS, alphas)
    n_set = n2 * n4                      # (row-2 signature, row-4 signature) pairs judged by the join
    chance = n2 * n4 / 26.0 / 26.0 ** 10     # pairs with the same column-0 letter, agreeing on 10 more letters
    pairs = H.name_join69(ct, CRIBS, alphas, joined) if joined else []
    print("  %-34s signature pairs %.3g  joined (9-10 checks): %d (chance %.2g); stream pairs behind them %d" % (
        "69B %s" % label, n_set, len(joined), chance, len(pairs)))
    for u, v, s in pairs[:6]:
        print("      rows 1-3 %s / rows 4-5 %s: column key letters %s" % (u, v, H.sig_letters(s)))
    return n_set, (len(joined), len(pairs))


def part57(ct, alphas, label):
    top = H.search57(ct, CRIBS, alphas, A57)
    print("  %-34s readings %14s  best key fragment %.3f  %s %s %s %s" % (
        "57 %s" % label, "{:,}".format(len(alphas) * 3 * 4 * 50), top[0][0], top[0][1], top[0][2], top[0][3], top[0][4]))
    return len(alphas) * 3 * 4 * 50, top


# ------------------------------------------------------------------ planted

def planted():
    eng = H.english_filler()
    cells = H.plant_cells(True)
    with Pool() as pool:
        res = dict(pool.map(H.run_plant_cell, [(i, N_PLANT, 118, eng, True) for i in range(len(cells))]))
    tot = {"hole": [0, 0, 0], "old": [0, 0, 0]}
    print("planted (idea 105's textbook plants through the fixed tests, %d messages per cell):" % N_PLANT)
    for i, (att, name, _, hole) in enumerate(cells):
        st = [r["status"] for r in res[i]]
        f, lim, miss = st.count("found"), st.count("limit"), st.count("HOLE")
        t = tot["hole" if hole else "old"]
        t[0], t[1], t[2] = t[0] + f, t[1] + lim, t[2] + miss
        print("  %-4s %-60s %s found %2d/%d  too few checks %2d  MISSED %d" % (
            att, name, "HOLE " if hole else "     ", f, len(st), lim, miss))
        for r in res[i]:
            if r["status"] == "HOLE":
                print("        missed: %s (%d checks)" % (r["params"], r["checks"]))
    st88 = H.stacked_map88()
    judge = [r for r in st88 if r[2] >= 7]
    print("  88 stacked-key map (every pair p<q<=13), attack 88 + idea 104's exact test: %d of %d judgeable found, "
          "%d with < 7 checks" % (sum(r[3] for r in judge), len(judge), len(st88) - len(judge)))
    # the audit must still see a mistake: the clue words one letter late, through the hole cells
    from kryptos import idea105_audit as A
    late = 0
    late_n = 0
    for i, (att, name, call, hole) in enumerate(cells):
        if hole:
            H.install(late88=att == "88")
            a = A.Audit(random.Random(7 + i), eng, offset=1, n_decoys=5)
            for _ in range(2 if SMOKE else 4):
                call(a)
            late += sum(r["status"] == "found" for r in a.records)
            late_n += len(a.records)
    H.install()
    print("  control: %d messages of the hole cells with the clue words one letter late: %d found (must be 0)" % (late_n, late))
    hole_ok = tot["hole"][2] == 0 and tot["old"][2] == 0 and late == 0 and all(r[3] for r in judge)
    return tot, len(judge), sum(r[3] for r in judge), late, hole_ok


def planted_reading(big):
    """End-to-end: a 90 and a 59 message at the new lags, found in a sample of alphabets and read back."""
    ok, out = 0, []
    alphas = dictionary_alphabets(mixed=True)
    named = [a for a in alphas[1:] if a[0] != "(A-Z)"]
    by_name = dict(alphas)
    for j, (lag, p) in enumerate(((30, 2), (32, 3), (33, 4))):
        rng = random.Random(1180 + j)
        ct, cribs, want, pt, m = R.plant(rng, named, "cipher", lag, 0, p)
        sample = rng.sample(alphas, 600 if SMOKE else 3000)
        if want[0] not in {n for n, _ in sample}:
            sample.append((want[0], m))
        t = H.tests90(True)
        hits = []
        for nm, mm in sample:
            hits += t.test_alphabet(nm, mm, ct, cribs)
        mine = [h for h in hits if h[1:10] == want]
        good = False
        if mine:
            dec = R.decrypt(ct, cribs, by_name[want[0]], mine[0])
            sc, cnt = R.extra_score(dec, big, frozenset(R.positions(0)))
            good = all(a == "." or a == b for a, b in zip(dec, pt)) and sc is not None and sc > ENGLISH
            out.append("90 lag %d word %d: found, %d of 97 letters read, 0 wrong=%s, English %.2f; %d other passes" % (
                lag, p, sum(c != "." for c in dec), good, sc or -99, len(hits) - len(mine)))
        else:
            out.append("90 lag %d word %d: NOT found" % (lag, p))
        ok += good
    for j, (lag, p, b) in enumerate(((40, 2, 1), (55, 3, 7))):
        rng = random.Random(5900 + j)
        from kryptos.round11 import english97
        pt = english97(rng)
        key = [rng.randrange(26) for _ in range(p)]
        A = H.ALPH59["KR"]
        ct = []
        for i, ch in enumerate(pt):
            u = A.index(ct[i - lag]) if i >= lag else rng.randrange(26)
            ct.append(A[(A.index(ch) + b * u + key[i % p]) % 26])
        ct = "".join(ct)
        cribs = {i: pt[i] for i in CRIBS}
        _, hits, _ = H.search59(ct, cribs)
        mine = [h for h in hits if h[1:] == ("ptKR/ctKR/uKR", "C", lag, 1, b, p)]
        if mine:
            dec = H.decrypt59(ct, cribs, mine[0])
            good = dec[lag:] == pt[lag:]
            out.append("59 cipher lag %d key %d b=%d: found with %d checks, letters %d-97 read back exactly=%s; %d other passes" % (
                lag, p, b, mine[0][0], lag + 1, good, len(hits) - 1))
        else:
            good = False
            out.append("59 cipher lag %d key %d: NOT found" % (lag, p))
        ok += good
    # 57: an English running key set under the plain A, scored among 3000 alphabets
    from kryptos import idea91_textbook as T
    mod57 = __import__("importlib").import_module("kryptos.idea105_audit").attack("57")
    alph57 = mod57.alphabets(limit=3000)
    text = mod57.english_text()
    for j, lay in enumerate(("M/M", "M/KR", "KR/M")):
        rng = random.Random(5700 + j)
        w, m = rng.choice(alph57)
        a0 = rng.randrange(len(text) - 97)
        pt = text[a0:a0 + 97]
        b0 = (a0 + 150 + rng.randrange(100)) % (len(text) - 97)
        key = text[b0:b0 + 97]
        plain, cipher = {"M/M": (m, m), "M/KR": (m, H.KR), "KR/M": (H.KR, m)}[lay]
        ct = T.tableau_encrypt(pt, plain, cipher, key, "A", False)
        top = H.search57(ct, {i: pt[i] for i in CRIBS}, alph57, A57)
        want = key[21:34] + "|" + key[63:74]
        good = top[0][4] == want
        out.append("57 %s key under A: best fragment %s (%.3f) %s; truth %s" % (lay, top[0][4], top[0][0], top[0][1:4], want))
        ok += good
    for o in out:
        print("  " + o)
    return ok, 8


if __name__ == "__main__":
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    a667 = dictionary_alphabets(mixed=True)
    a220 = dictionary_alphabets(mixed=False)
    mod57 = __import__("importlib").import_module("kryptos.idea105_audit").attack("57")
    a57 = mod57.alphabets(limit=3000 if SMOKE else None)
    by_name = dict(a667)
    with Experiment("close the idea-105 audit holes: 90 cipher 30-33, 59 short lags, 88 progressive over breaks, "
                    "60C same column, 61 clockwise, 69B letter join, 57 key under any letter", puzzle="k4",
                    notes="fixed copies of the test functions in kryptos/idea118_holes.py; only the settings the old "
                          "code missed; >=7 checks (59/61 also 6); controls 3 shuffled K4s on thirds (10 where no alphabet list)",
                    cribs_forced=True) as ex:
        t0 = time.time()
        total = 0
        print("K4:")
        n, k90 = part90(K4, a667, big, by_name, "K4")
        total += n
        n, k59 = part59(K4, "K4")
        total += n
        n, k88 = part88(K4, a220, "K4")
        total += n
        n, k60 = part60(K4, "K4")
        total += n
        n, k61 = part61(K4, "K4")
        total += n
        n, k69 = part69(K4, a220, "K4")
        total += n
        n, k57 = part57(K4, a57, "K4")
        total += n
        ex.count(total)
        print("K4 settings in all: {:,} ({:.0f} s)".format(total, time.time() - t0))

        print("controls:")
        c90, c88, c69, c57 = [], [], [], []
        for seed in SEEDS:
            c = shuffled_control(seed)
            c90.append(part90(c, a667[seed - 1::3], big, by_name, "shuffled %d (1/3)" % seed)[1])
            c88.append(part88(c, a220[seed - 1::3], "shuffled %d (1/3)" % seed)[1])
            c69.append(part69(c, a220[seed - 1::3], "shuffled %d (1/3)" % seed)[1])
            c57.append(part57(c, a57[seed - 1::3], "shuffled %d (1/3)" % seed)[1][0][0])
        c59 = [part59(shuffled_control(s), "", show=False)[1] for s in SEEDS10]
        c60 = [part60(shuffled_control(s), "", show=False)[1] for s in SEEDS10]
        c61 = [part61(shuffled_control(s), "", show=False)[1] for s in SEEDS10]
        print("  59 on %d shuffled K4s (pass 6+, 7+, best): %s" % (len(SEEDS10), c59))
        print("  60C on %d shuffled K4s (passes): %s" % (len(SEEDS10), c60))
        print("  61 on %d shuffled K4s (pass 6+, 7+, best): %s" % (len(SEEDS10), c61))

        tot, nj, fj, late, plant_ok = planted()
        rd, rn = planted_reading(big)
        print("planted, read back as English: %d/%d" % (rd, rn))
        print("planted hole cells: %d found, %d too few checks, %d missed; cells found before: %d found, %d too few, %d missed"
              % tuple(tot["hole"] + tot["old"]))

        k4_pass = k90[0] + k59[1] + k88[0] + k60 + k61[1] + k69[0]
        c_pass = sum(c[0] for c in c90) + sum(c[1] for c in c59) + sum(c[0] for c in c88) + sum(c60) + \
            sum(c[1] for c in c61) + sum(c[0] for c in c69)
        beats57 = k57[0][0] > max(c57) + 0.35
        print("K4 exact passes (7+; 60C all pairs; 69B joins): %d; controls together: %d. 57 best %.3f vs shuffled %s" % (
            k4_pass, c_pass, k57[0][0], ["%.3f" % x for x in c57]))
        print("VERDICT:", "K4 has passes - inspect" if k4_pass or beats57 else
              "no signal: 0 K4 passes in every hole; controls %d; planted %s" % (c_pass, "all found" if plant_ok and rd == rn else "INCOMPLETE"))
        if not plant_ok or rd != rn:
            print("WARNING: a planted answer was missed - the negative does not stand")
