"""Idea 121: ANY linear cipher-feedback rule up to 15 letters back, with free coefficients.

Scheidt says the English was masked with something simple that can be remembered. The simplest
masks are running sums and differences: add each letter to the cipher letter before it, or to
the one on its left and the one above it on a worksheet. Those are cipher-feedback rules with
several lags at once. Earlier rounds tried one lag at a time (59, 74, 90, 117) or one cipher
term (110 test B). Here the lags and their multipliers are left free:

    nC(C[i]) = s nP(P[i]) + a1 nF(C[i-1]) + ... + a15 nF(C[i-15]) + c          (mod 26)

nP, nC, nF number the plain, cipher and fed letters on the tableau alphabet M, on A-Z or on
KRYPTOS (27 ways); s = +1 or -1. All 97 cipher letters are known, so each of the 24 clue letters
gives one linear equation in a1..a15, c. 24 equations, 16 unknowns: 8 exact checks, solved
mod 13 and mod 2. Order 15 contains every lower order, so one solve covers running sums and
differences of any order, any binomial mask, left-plus-above on any worksheet up to 15 wide and
any mix of lags 1-15.

  A  cipher lags 1-15 + constant (8 checks); gauge: lags 1-19 (4 checks) to see chance behave
  B  sparse worksheet shapes with a lag over 15: {1,w}, {w-1,w,w+1}, {1,w,w+1}, {w,2w}, w <= 48,
     free coefficients, only shapes with 7+ checks (126 shapes, 7-21 checks)
  C  plain feedback too: cipher lags 1-R + plain lags 1-S, (S,R) = (1,7) (2,6) (3,5) (4,4)
     (5,1) (equations whose plain letters leave a clue block are dropped; 7-13 checks)
  D  cipher lags 1-R + plain lags 1-S + a repeating word of 3, 4 or 5 instead of the constant,
     R + S = 6 (7-15 checks)

Alphabets: A-Z, KRYPTOS and every dictionary keyword alphabet with its two transposition-mixed
forms (666,993). Test A runs on all of them. Tests B-D cost about 40 times more, so they run on
A-Z, KRYPTOS, the theme-word alphabets (all three forms) and every 15th dictionary alphabet.

Survivors are solved mod 26, decrypted over all 97 letters and scored on the big model.
Controls: 3 shuffled K4s, test A on a third of the alphabets each, B-D on the theme alphabets and
a third of the sample each. Planted: a double running sum, left-plus-above at width 7, lags 3, 8
and 13 with random multipliers, a mixed plain and cipher rule, left-plus-above at width 31, and
feedback plus a repeating word of 4, each on a random dictionary tableau among about 1,000
others; each must be the only survivor and read back with 0 wrong letters.

Not covered: order 16 and up with all lags (B covers only the listed sparse shapes), non-linear
feedback (a table of the fed letter, idea 117 for single lags), a word key longer than 5 on top
of feedback, tests B-D on the dictionary outside the 1-in-15 sample.

  python attacks/121_cipher_feedback_any_lags.py            (--prefilter for the clue card)
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea121_feedback import (POS, Plan, encrypt, init, merge, new_tally, resolve, scan,  # noqa: E402
                                      work)
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos import wordkeys  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1
TESTS = "ABCD"
SAMPLE = 15
PROCS = 8


def core_names():
    return {"KRYPTOS"} | set(wordkeys.theme_words())


def split(alphas):
    """(core alphabets, the rest) without A-Z and the KRYPTOS alphabet (those run in the fixed pass)."""
    core, rest, cn = [], [], core_names()
    for name, a in alphas:
        if a in (AZ, KRYPTOS_ALPHABET):
            continue
        (core if name.split("~")[0] in cn else rest).append((name, a))
    return core, rest


def items_for(core, rest, a_part, bcd_part):
    """Work items: core alphabets get every test; a_part gets A; the sample bcd_part gets every test."""
    bset = set(n for n, _ in bcd_part)
    out = [(n, a, TESTS) for n, a in core]
    out += [(n, a, TESTS if n in bset else "A") for n, a in a_part]
    aset = set(n for n, _ in a_part)
    extra = [x for x in bcd_part if x[0] not in aset]
    out += [(n, a, "BCD") for n, a in extra]
    return out


def search(ct, items, cribs=CRIBS):
    total = new_tally()
    plan = Plan(ct, cribs, TESTS)
    scan(plan, "(A-Z/KRYPTOS)", AZ, TESTS, total, fixed_only=True)
    for part in pmap(work, items, init, (ct, cribs, TESTS), chunk=400, procs=PROCS):
        merge(total, part)
    return total, plan


def show(label, tally):
    s, e = tally["settings"], tally["expected"]
    cnt = {t: 0 for t in TESTS}
    for h in tally["hits"]:
        cnt[h[0]] += 1
    print("%s: settings %s" % (label, "  ".join("%s %d" % (t, s.get(t, 0)) for t in TESTS)))
    print("   passes (chance predicts):  " + "   ".join("%s %d (%.5f)" % (t, cnt[t], e.get(t, 0.0)) for t in TESTS))
    g = tally["gauge_settings"]
    print("   gauge lags 1-19 (4 checks): mod 13 half passed %d (predicted %.0f), full pass %d (predicted %.1f); "
          "rank-deficient systems %d"
          % (tally["gauge_mod13"], g / 13.0 ** 4, tally["gauge_pass"], tally["gauge_expected"], tally["deficient"]))
    return cnt


def describe(h):
    test, sname, name, alpha, setting, c13, c2 = h
    return "test %s %s, alphabet %s, numbering P/C/fed = %s/%s/%s, sign %+d, checks %d mod 13, %d mod 2" % (
        test, sname, name, setting[0], setting[1], setting[2], setting[3], c13, c2)


def read(plan, hits, big):
    out = []
    for h in hits:
        r = resolve(plan, h, big)
        if r is None:
            continue
        sc, text, sol, nsol = r
        out.append((sc, text, describe(h), sol, nsol, h))
    out.sort(key=lambda x: -x[0])
    return out


def print_readings(rows, limit=15):
    for sc, text, desc, sol, nsol, _ in rows[:limit]:
        print("   english %.2f words %.2f  %s\n      coefficients %s (%s solutions)\n      %s"
              % (sc, word_coverage(text.replace("?", "")), desc, sol, nsol, text))


# ---------------------------------------------------------------- planted answers

def unit(rng):
    return rng.choice([1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25])


def plants(rng):
    nz = lambda: rng.randrange(1, 26)                                           # noqa: E731
    return [
        ("double running sum", {"a": {1: 2, 2: 25}}, ("M", "M", "M", 1), "A"),
        ("left plus above, width 7", {"a": {1: 1, 7: 1}, "c": rng.randrange(26)}, ("M", "AZ", "M", 1), "A"),
        ("lags 3, 8, 13 with random multipliers", {"a": {3: nz(), 8: nz(), 13: nz()}, "c": rng.randrange(26)},
         ("KR", "M", "AZ", -1), "A"),
        ("mixed plain and cipher rule", {"a": {1: nz(), 2: nz()}, "b": {1: unit(rng)}, "c": rng.randrange(26)},
         ("M", "M", "M", 1), "C"),
        ("left plus above, width 31", {"a": {1: 1, 31: 1}}, ("M", "M", "KR", 1), "B"),
        ("feedback plus a word of 4", {"a": {1: nz(), 3: nz()}, "b": {2: unit(rng)},
                                       "w": [rng.randrange(26) for _ in range(4)]}, ("AZ", "M", "M", -1), "D"),
    ]


def planted_case(rng, label, rule, setting, test, alphas, field, big):
    name, alpha = rng.choice(alphas)
    pt = english97(rng)
    ct = encrypt(pt, rule, alpha, setting, rng)
    cribs = {i: pt[i] for i in POS}
    items = [(n, a, TESTS) for n, a in field if n != name] + [(name, alpha, TESTS)]
    tally, plan = search(ct, items, cribs)
    mine = [h for h in tally["hits"] if h[0] == test and h[2] == name and h[4] == setting]
    others = set((h[2], h[4]) for h in tally["hits"]) - {(name, setting)}
    ok, note = False, "not found"
    if mine:
        rows = read(plan, mine, big)
        sc, text, desc, sol, nsol, _ = rows[0]
        known = sum(ch != "?" for ch in text)
        wrong = sum(ch != "?" and ch != p for ch, p in zip(text, pt))
        mx = max(list(rule.get("a", {})) + list(rule.get("b", {})))
        need = 97 - max(rule.get("a", {}))
        ok = wrong == 0 and known >= need and not others
        note = "%d of 97 letters read (%d before the deepest lag %d unreadable), %d wrong, english %.2f, %d shape(s) fired" % (
            known, 97 - known, mx, wrong, sc, len(mine))
    print("planted %s on %s (P/C/fed %s/%s/%s, sign %+d), test %s: found=%s (%s); other settings passing: %d"
          % (label, name, setting[0], setting[1], setting[2], setting[3], test, ok, note, len(others)))
    return ok


def prefilter_encrypt(pt, rng):
    """For the clue pre-filter: cipher feedback with three free lags on the KRYPTOS tableau."""
    rule = {"a": {1: rng.randrange(1, 26), 2: rng.randrange(26), 5: rng.randrange(1, 26)}, "c": rng.randrange(26)}
    return encrypt(pt, rule, KRYPTOS_ALPHABET, ("M", "M", "M", 1), rng)


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("linear cipher feedback with free lags on a keyword tableau", encrypt=prefilter_encrypt)
        sys.exit(0)
    t0 = time.time()
    alphas = dictionary_alphabets(mixed=True)
    core, rest = split(alphas)
    sample = rest[::SAMPLE]
    with Experiment("any linear cipher feedback up to 15 back with free coefficients (+ sparse worksheet lags, "
                    "plain feedback, word on top)", puzzle="k4",
                    notes="exact solve mod 13 and mod 2 at the 24 clue letters; A: order 15 + const (8 checks) on "
                          "%d alphabets x 27 numberings x 2 signs; B: 126 sparse shapes {1,w},{w-1,w,w+1},{1,w,w+1},"
                          "{w,2w} with a lag >15 (7+ checks); C: cipher+plain feedback R+S<=8 (7+); D: + word of "
                          "3-5, R+S=6; B-D on %d theme alphabets + 1 in %d of the dictionary (%d); 3 shuffled K4s; "
                          "6 planted" % (len(alphas), len(core), SAMPLE, len(sample)),
                    cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        print("alphabets: %d (theme %d, rest %d, B-D sample %d)" % (len(alphas), len(core), len(rest), len(sample)))
        plan0 = Plan(K4, CRIBS, TESTS)
        for t in TESTS:
            ch = sorted(set(s.checks for s in plan0.shapes[t]))
            print("test %s: %d shapes, checks %s" % (t, len(plan0.shapes[t]), ch))
        k4, plan = search(K4, items_for(core, rest, rest, sample))
        kc = show("K4", k4)
        total = sum(k4["settings"].values())
        k4_head = read(plan, k4["hits"], big)
        print("K4 survivors at 7+ checks: %d" % len(k4_head))
        print_readings(k4_head)
        for sc, text, desc, sol, nsol, _ in k4_head[:40]:
            ex.add(text.replace("?", "X"), english_big=round(sc, 3), setting=desc, coefficients=str(sol))
        k4_g = read(plan, k4["gauge_hits"][:200], big)
        print("K4 gauge passes read (first %d): best english %s" % (len(k4_g), "%.2f" % k4_g[0][0] if k4_g else "-"))
        print_readings(k4_g, 3)
        k4_best = k4_head[0][0] if k4_head else -99.0
        print("[%.0f s]" % (time.time() - t0))
        ctrl = []
        for j, seed in enumerate((1, 2, 3)):
            sct = shuffled_control(seed)
            st, splan = search(sct, items_for(core, rest, rest[j::3], sample[j::3]))
            sc_ = show("shuffled K4 seed %d (A on %d alphabets, B-D on %d)" % (seed, len(rest[j::3]) + len(core),
                                                                            len(sample[j::3]) + len(core)), st)
            total += sum(st["settings"].values())
            sh = read(splan, st["hits"], big)
            print_readings(sh, 5)
            ctrl.append((len(sh), sh[0][0] if sh else -99.0, st["gauge_pass"], st["gauge_expected"]))
            print("[%.0f s]" % (time.time() - t0))
        rng = random.Random(121)
        field = core + rest[::700]
        ok = 0
        cases = plants(rng)
        for label, rule, setting, test in cases:
            ok += planted_case(rng, label, rule, setting, test, rest, field, big)
        print("planted recovered: %d/%d (field %d alphabets each)" % (ok, len(cases), len(field) + 1))
        ex.count(total)
        reads = k4_best > ENGLISH and k4_best > max(c[1] for c in ctrl) + 0.3
        print("VERDICT:", ("K4 has a survivor that reads better than every control - inspect; " if reads
                           else "no signal; ")
              + "K4 %d settings pass with 7+ checks (%s; chance predicts %s), best reading %.2f; gauge %d (chance "
                "%.1f); shuffled K4s: %s pass, best readings %s, gauges %s (chance %s); planted %d/%d; %d settings "
                "tested in all [%.0f s]"
              % (len(k4_head), " ".join("%s %d" % (t, kc[t]) for t in TESTS),
                 " ".join("%s %.5f" % (t, k4["expected"].get(t, 0)) for t in TESTS), k4_best, k4["gauge_pass"],
                 k4["gauge_expected"], [c[0] for c in ctrl], ["%.2f" % c[1] for c in ctrl], [c[2] for c in ctrl],
                 ["%.1f" % c[3] for c in ctrl], ok, len(cases), total, time.time() - t0))
