"""Idea 110: ANY linear rule for the key, tested without naming the rule.

Scheidt: the method is simple, can be remembered, and can be run again years later. Rounds 9-11
tested named key rules one at a time (progressive keys, chain addition with two taps, formulas
from a list). This attack closes the whole class at once. If each key letter is a fixed linear
mix of the few key letters before it,

    K[i] = a1 K[i-1] + a2 K[i-2] + ... + a5 K[i-5] + c        (mod 26)

then the key letters the clues force (13 under EASTNORTHEAST, 11 under BERLINCLOCK) must obey
that one rule inside each block, whatever a1..a5 and c are. That is 8 + 6 equations in 6
unknowns, so 8 exact checks, solved mod 13 and mod 2. Nothing is guessed, and because the rule
only looks back inside a block, the test does not care where the blocks sit: a wrong gap or a
miscounted position cannot hide the rule.

One order-5 solve covers every lower order, and with it: progressive and polynomial keys up to
degree 4, chain addition with any taps up to 5 back and any multipliers, multiplying generators
K[i] = a K[i-1] + c, sums of those, and any order-4 rule with a drift term e*i (take differences:
the drift becomes the constant of an order-5 rule).

  A   order 5, free coefficients and constant                                   8 checks
  A2  order 5 plus a drift term e*i (this one needs the carved positions)       7 checks
  A6  order 6, only as a gauge that chance behaves as predicted                 5 checks
  B   text-fed: K[i] = a1 K[i-1] + a2 K[i-2] + u P[i-s] + v C[i-t] + c for s, t = 1..6, the
      plain and the cipher letter each numbered on the tableau alphabet, A-Z or KRYPTOS
      (324 settings per key stream, 7 to 15 checks)
  C   not linear: K[i] = g(K[i-d]), g(P[i-d]) or g(C[i-d]) for an ARBITRARY table g, d = 1..6.
      Equal inputs must give equal key letters; the forced repeats are the checks (7 required;
      5-6 kept as a gauge).

Key streams: A-Z, KRYPTOS and every dictionary keyword alphabet with its two transposition-mixed
forms, five layouts each (M/M, M/AZ, AZ/M, M/KR, KR/M), key read as C-P and as C+P.
Survivors are solved mod 26, the rule is run over all 97 places and the reading is scored on
the big English model. Controls: 3 shuffled K4s, each on A-Z, KRYPTOS and a different third of
the alphabets. Planted: a cubic key, a three-tap chain key with multipliers, a generator
a K + c, an order-4 rule with drift, a text-fed rule, an order-5 rule with drift and three
table rules, each on a random dictionary tableau; all but the drift-at-order-5 one are run a
second time with the second clue moved 2 places and must still be found.

Not covered: order 6 and up (under 7 checks), a constant that changes with position in any way
other than a drift e*i, text-fed rules with more than two key taps or lags over 6, alphabets
outside the dictionary set.

  python attacks/110_any_linear_key_rule.py            (--prefilter for the clue card)
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea110_linear import (GAUGE, MIN_CHECKS, NUMS, Plan, encrypt, init, lay_alphabets,  # noqa: E402
                                    linear_keyfn, merge, new_tally, poly_keyfn, resolve, table_keyfn, work)
from kryptos.round9 import UNITS, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1                      # big-model score per quadgram that real English clears
HEAD = ("A", "A2", "B", "C1", "C2")
GAUGES = ("A6", "C1g", "C2g")
MOVED = list(range(21, 34)) + list(range(65, 76))     # the second clue 2 places later


def clue_letters(ct, text, pos=POS):
    return [text[i] for i in pos], [ct[i] for i in pos]


def search(pl, cl, alphas, pos=POS):
    total = new_tally()
    for part in pmap(work, alphas, init, (pl, cl, pos), chunk=1000):
        merge(total, part)
    return total


def counts(tally):
    out = dict.fromkeys(HEAD + GAUGES, 0)
    for h in tally["hits"]:
        out[h[0]] += 1
    return out


def expected(tally, plan):
    e = plan.expected(tally["streams"])
    e["C1"], e["C1g"] = tally["C1_exp"], tally["C1g_exp"]
    return e


def n_tests(tally, plan):
    """Exact tests at the 7+ check level: A, A2, 324 x B, judged C1 and C2 settings."""
    c2 = sum(1 for x in plan.c2 if x[4] >= MIN_CHECKS)
    return tally["streams"] * (2 + 324 + c2) + tally["C1_judged"]


def show(label, tally, plan):
    c, e, s = counts(tally), expected(tally, plan), tally["streams"]
    print("%s: %d key streams, %d exact tests" % (label, s, n_tests(tally, plan)))
    print("   passes (chance predicts):  A %d (%.5f)   A2 %d (%.4f)   B %d (%.3f)   C1 %d (%.3f)   C2 %d (%.5f)"
          % (c["A"], e["A"], c["A2"], e["A2"], c["B"], e["B"], c["C1"], e["C1"], c["C2"], e["C2"]))
    print("   gauges:  order 6 at 5 checks %d (%.2f)   table of the key at 5-6 repeats %d (%.2f)   "
          "table of the text at 5-6 repeats %d (%.2f)"
          % (c["A6"], e["A6"], c["C1g"], e["C1g"], c["C2g"], e["C2g"]))
    print("   mod 2 halves passed (predicted):  A %d (%.0f)   A2 %d (%.0f)   order 6 %d (%.0f)   B %d"
          % (tally["A_mod2"], s / 256.0, tally["A2_mod2"], s / 128.0, tally["A6_mod2"], s / 32.0, tally["B_mod2"]))
    return c, e


def describe(r):
    p = r["params"]
    if r["test"] == "B":
        extra = "P[i-%d] numbered on %s, C[i-%d] numbered on %s" % (p[0], NUMS[p[1]], p[2], NUMS[p[3]])
    elif r["test"].startswith("C"):
        extra = r["rule"]
    else:
        extra = "order %d%s" % (p[0], " + drift" if p[1] else "")
    return "test %s, alphabet %s, layout %s, %s, %s, %d checks" % (r["test"], r["name"], r["lay"], r["form"],
                                                                    extra, r["checks"])


def new_letters(text, cribs):
    return "".join(ch for i, ch in enumerate(text) if ch != "?" and i not in cribs)


def read(hits, ct, cribs, plan, big):
    """Resolve hits and score the letters outside the clues. [(score, text, description, join, rule)]."""
    out = []
    for h in hits:
        r = resolve(h, ct, cribs, plan)
        if r is None:
            continue
        cands = r.get("readings") or [(r["text"], None, None, r.get("rule"))]
        best = None
        for text, join, total, rule in cands:
            new = new_letters(text, cribs)
            sc = big.score(new) if len(new) >= 12 else -99.0
            if best is None or sc > best[0]:
                best = (sc, text, describe(r), "%s/%s" % (join, total) if total else "-", rule)
        out.append(best)
    out.sort(key=lambda x: -x[0])
    return out


def print_readings(rows, limit=20):
    for sc, text, desc, join, rule in rows[:limit]:
        print("   english %.2f words %.2f  %s\n      block 2 reproduced from block 1: %s   rule %s\n      %s"
              % (sc, word_coverage(text.replace("?", "")), desc, join, rule, text))


# ---------------------------------------------------------------- planted answers

def plant(rng, kind, alphas):
    """An English text through a planted rule on a random dictionary tableau.
    Returns (label, ct, pt, tests that must fire, name, alphabet, layout, form)."""
    name, alpha = rng.choice(alphas)
    nz = lambda: rng.randrange(1, 26)                                           # noqa: E731
    seeds = [rng.randrange(26) for _ in range(6)]
    while True:
        pt = english97(rng)
        nump = numc = None
        if kind == "cubic":
            label, lay, form, tests = "cubic key", "M/M", "vig", ("A",)
            fn = poly_keyfn([rng.randrange(26), nz(), nz(), rng.choice(UNITS)])
        elif kind == "chain3":
            label, lay, form, tests = "three-tap chain key with multipliers", "M/AZ", "beau", ("A",)
            fn = linear_keyfn({"a": [nz(), 0, nz(), 0, rng.choice(UNITS)], "c": rng.randrange(26)}, seeds)
        elif kind == "generator":
            label, lay, form, tests = "generator a K + c", "AZ/M", "vig", ("A",)
            fn = linear_keyfn({"a": [rng.choice(UNITS[1:])], "c": nz()}, seeds)
        elif kind == "order4drift":
            label, lay, form, tests = "order 4 with a drift term", "KR/M", "beau", ("A",)
            fn = linear_keyfn({"a": [nz(), 0, 0, rng.choice(UNITS)], "c": rng.randrange(26), "e": nz()}, seeds)
        elif kind == "order5drift":
            label, lay, form, tests = "order 5 with a drift term", "M/KR", "vig", ("A2",)
            fn = linear_keyfn({"a": [nz(), 0, nz(), 0, rng.choice(UNITS)], "c": rng.randrange(26), "e": nz()}, seeds)
        elif kind == "textfed":
            label, lay, form, tests = "text-fed rule (two key taps, P 3 back on M, C 5 back on A-Z)", "M/M", "vig", ("B",)
            nump = {c: i for i, c in enumerate(alpha)}
            numc = {c: i for i, c in enumerate(AZ)}
            fn = linear_keyfn({"a": [nz(), nz()], "u": nz(), "v": nz(), "s": 3, "t": 5, "c": rng.randrange(26)},
                              seeds, nump, numc)
        elif kind == "table-key":
            label, lay, form, tests = "table of the last key letter", "M/M", "beau", ("C1",)
            fn = table_keyfn("key", 1, [rng.randrange(26) for _ in range(26)], seeds)
        elif kind == "table-plain":
            label, lay, form, tests = "table of the last plain letter", "M/AZ", "vig", ("C2",)
            fn = table_keyfn("plain", 1, {c: rng.randrange(26) for c in AZ}, seeds)
        else:
            label, lay, form, tests = "table of the last cipher letter", "KR/M", "vig", ("C2",)
            fn = table_keyfn("cipher", 1, {c: rng.randrange(26) for c in AZ}, seeds)
        pa, cb = lay_alphabets(lay, alpha)
        ct, _ = encrypt(pt, pa, cb, form, fn)
        if kind.startswith("table"):                      # a table rule needs 7 forced repeats to be judged
            if not all(judged(ct, pt, pos, kind, pa, cb, form) for pos in (POS, MOVED)):
                seeds = [rng.randrange(26) for _ in range(6)]
                continue
        return label, ct, pt, tests, name, alpha, lay, form


def judged(ct, pt, pos, kind, pa, cb, form):
    pl, cl = clue_letters(ct, pt, pos)
    plan = Plan(pl, cl, POS)
    if kind == "table-key":
        ia, ib = {c: i for i, c in enumerate(pa)}, {c: i for i, c in enumerate(cb)}
        k = [(ib[y] + ia[x]) % 26 if form == "beau" else (ib[y] - ia[x]) % 26 for x, y in zip(pl, cl)]
        inp = plan.lagged(k, 1)
        return len(inp) - len(set(inp)) >= MIN_CHECKS
    feed = "plain" if kind == "table-plain" else "cipher"
    return any(f == feed and d == 1 and c >= MIN_CHECKS for f, d, _, _, c in plan.c2)


def planted_case(rng, kind, alphas, sample, big, moved=True):
    """Returns (found and read back with the carved positions, found with the second clue moved)."""
    label, ct, pt, tests, name, alpha, lay, form = plant(rng, kind, alphas)
    field = sample + [(name, alpha)]
    cribs = {i: pt[i] for i in POS}
    pl, cl = clue_letters(ct, pt)
    tally = search(pl, cl, field)
    mine = [h for h in tally["hits"] if h[0] in tests and h[1:5] == (name, alpha, lay, form)]
    others = sum(1 for h in tally["hits"] if h[0] in HEAD and h[1] != name)
    ok1, note = False, "not found"
    if mine:
        sc, text, desc, join, rule = read(mine, ct, cribs, Plan(pl, cl, POS), big)[0]
        known = sum(ch != "?" for ch in text)
        wrong = sum(ch != "?" and ch != p for ch, p in zip(text, pt))
        ok1 = wrong == 0 and (known >= 60 or kind.startswith("table"))
        note = "%d of 97 letters read, %d wrong, english %.2f, block 2 reproduced %s" % (known, wrong, sc, join)
    ok2 = None
    if moved:
        pl2, cl2 = clue_letters(ct, pt, MOVED)
        t2 = search(pl2, cl2, field)
        ok2 = any(h[0] in tests and h[1:5] == (name, alpha, lay, form) for h in t2["hits"])
        others += sum(1 for h in t2["hits"] if h[0] in HEAD and h[1] != name)
    print("planted %s on %s (%s, %s): found=%s (%s); second clue moved 2 places: %s; passes on the %d other "
          "alphabets: %d" % (label, name, lay, form, ok1, note, "-" if ok2 is None else "found=%s" % ok2,
                             len(sample), others))
    return ok1, ok2


KINDS = (("cubic", True), ("chain3", True), ("generator", True), ("order4drift", True), ("textfed", True),
         ("order5drift", False), ("table-key", True), ("table-plain", True), ("table-cipher", True))


def prefilter_encrypt(pt, rng):
    """For the clue pre-filter: an order-3 linear key rule on the KRYPTOS tableau; key from rng only."""
    fn = linear_keyfn({"a": [rng.randrange(1, 26), rng.randrange(26), rng.randrange(1, 26)], "c": rng.randrange(26)},
                      [rng.randrange(26) for _ in range(3)])
    return encrypt(pt, KRYPTOS_ALPHABET, KRYPTOS_ALPHABET, "vig", fn)[0]


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("key from a linear recurrence on a keyword tableau", encrypt=prefilter_encrypt)
        sys.exit(0)
    alphas = dictionary_alphabets(mixed=True)
    with Experiment("any linear key rule: recurrences of order 5 with free coefficients, text-fed rules, key tables",
                    puzzle="k4",
                    notes="exact solve mod 13 and mod 2 on the 13+11 forced key letters, no rule named; order 5 + "
                          "constant (8 checks), order 5 + drift (7), K = a1K1 + a2K2 + uP[i-s] + vC[i-t] + c for "
                          "s,t 1-6 and 9 numberings (7-15), arbitrary tables of K/P/C 1-6 back (7+ forced repeats); "
                          "%d alphabets (A-Z, KRYPTOS, dictionary keyword + transposition-mixed) x 5 layouts x "
                          "Vig/Beau; 3 shuffled K4s on a third each; 9 planted rules" % len(alphas),
                    cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        pl, cl = clue_letters(K4, CRIBS)
        plan = Plan(pl, cl, POS)
        print("alphabets: %d; checks: A %d, A2 %d, order-6 gauge %d; B by longest lag 2..6: %s; text tables judged: %s"
              % (len(alphas), plan.neq[5] - 6, plan.neq[5] - 7, plan.neq[6] - 7,
                 " ".join("%d:%d" % (L, plan.neq[L] - 5) for L in range(2, 7)),
                 ", ".join("%s %d back = %d" % (f, d, c) for f, d, _, _, c in plan.c2)))
        k4 = search(pl, cl, alphas)
        kc, ke = show("K4", k4, plan)
        total = n_tests(k4, plan)
        k4_head = read([h for h in k4["hits"] if h[0] in HEAD], K4, CRIBS, plan, big)
        k4_gauge = read([h for h in k4["hits"] if h[0] in GAUGES], K4, CRIBS, plan, big)
        print("K4 survivors at %d+ checks: %d" % (MIN_CHECKS, len(k4_head)))
        print_readings(k4_head)
        for sc, text, desc, join, rule in k4_head[:40]:
            ex.add(text.replace("?", "X"), english_big=round(sc, 3), setting=desc, rule=str(rule))
        print("K4 gauge survivors (%d-%d checks): %d" % (GAUGE, MIN_CHECKS - 1, len(k4_gauge)))
        print_readings(k4_gauge, 8)
        k4_best = k4_head[0][0] if k4_head else -99.0
        ctrl = []
        for j, seed in enumerate((1, 2, 3)):
            sct = shuffled_control(seed)
            sub = alphas[:2] + alphas[2 + j::3]
            spl, scl = clue_letters(sct, CRIBS)
            splan = Plan(spl, scl, POS)
            st = search(spl, scl, sub)
            sc_, se = show("shuffled K4 seed %d (%d alphabets)" % (seed, len(sub)), st, splan)
            total += n_tests(st, splan)
            sh = read([h for h in st["hits"] if h[0] in HEAD], sct, CRIBS, splan, big)
            sg = read([h for h in st["hits"] if h[0] in GAUGES], sct, CRIBS, splan, big)
            print_readings(sh, 5)
            ctrl.append((len(sh), sh[0][0] if sh else -99.0, sum(sc_[g] for g in GAUGES),
                         sg[0][0] if sg else -99.0))
        rng = random.Random(110)
        sample = alphas[::40]
        ok = ok_moved = n_moved = 0
        for kind, moved in KINDS:
            a, b = planted_case(rng, kind, alphas, sample, big, moved)
            ok += a
            if b is not None:
                n_moved += 1
                ok_moved += b
        print("planted recovered: %d/%d; with the second clue moved 2 places: %d/%d"
              % (ok, len(KINDS), ok_moved, n_moved))
        ex.count(total)
        reads = k4_best > ENGLISH and k4_best > max(c[1] for c in ctrl) + 0.3
        print("VERDICT:", ("K4 has a survivor that reads better than every control - inspect; " if reads
                           else "no signal; ")
              + "K4 %d settings pass with %d+ checks (A %d, A2 %d, B %d, C1 %d, C2 %d; chance predicts %.3f in all), "
                "best reading english %.2f; gauges %d (chance %.2f), best gauge reading %.2f; shuffled K4s on a third "
                "of the alphabets each: %s pass, best readings %s, gauges %s (English needs %.1f; -99 = nothing to read)"
              % (len(k4_head), MIN_CHECKS, kc["A"], kc["A2"], kc["B"], kc["C1"], kc["C2"],
                 sum(ke[t] for t in HEAD), k4_best, len(k4_gauge), sum(ke[g] for g in GAUGES),
                 k4_gauge[0][0] if k4_gauge else -99.0, [c[0] for c in ctrl], ["%.2f" % c[1] for c in ctrl],
                 [c[2] for c in ctrl], ENGLISH))
