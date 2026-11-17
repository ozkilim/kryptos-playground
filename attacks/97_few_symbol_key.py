"""Idea 97: a key written with few symbols.

Scheidt: "I could have moved to a different math base". Sanborn: "delve into that particular
clock" (clock faces carry numerals). If K4's key is a list of numbers (digits in base 2-16,
clock hours 1-12, Roman numerals), then however irregular the list is, the key uses FEW
DIFFERENT VALUES. That can be tested with no rule for the key at all: on the right tableau the
24 key values forced by the clue letters would all sit inside a small window of the 26.

For random values the chance that all 24 fall in some window of 12 is about 2 in 10 million
per setting, and that they use 7 or fewer different values about 1 in 100 million.

The community showed that no alphabet makes all 24 values digits 0-9 (best 21) or keeps them
below 16, but for a window that starts at 0 and one way of reading the key. Here:

  alphabets  A-Z, KRYPTOS and every dictionary keyword alphabet with its two
             transposition-mixed forms (667,000)
  layouts    five per alphabet (M/M, M/A-Z, A-Z/M, M/KRYPTOS, KRYPTOS/M)
  views      C-P, C+P, P-C, -(C+P). A view and its negative give mirror-image values, so the
             window numbers are the same; they are computed once and count for both. Tests
             that name values (digits 0-9, below a base, Roman letters) are done for both signs.
  measured   (a) the smallest circular window holding all 24 values
             (b) the number of different values
             (c) the most clue letters inside any window of 5, 8, 10, 12, 16 values
             (d) the most covered by any 2, 3, 4, 7 values (idea 60 did 2/3/4 fixed rows on
                 A-Z and KRYPTOS only: 9/12/14, chance), and by the seven Roman numeral letters
                 I V X L C D M with the key letter read in A-Z, KRYPTOS or the tableau alphabet
             the same for each clue block alone (13 and 11 letters)

A hit is a window of 12 or less, 7 or fewer different values, or 24 Roman letters, that the
shuffled K4s do not also give. Otherwise K4's best numbers are compared with shuffled K4s on
the same alphabets. The 20 best settings are printed with their key values for a human look.

Planted: random non-periodic keys of digits 0-9, of base-12 digits, of clock hours 1-12 and of
Roman numeral letters, each on a dictionary tableau. Each must be flagged as a hit with its
exact key values; its rank is printed. (It is not always alone in first place: keyword
alphabets are close to shifted A-Z and to each other, so a neighbouring tableau often shows
almost the same key, and over 6.7 million key streams a window of 11-12 also turns up by chance.)

Scope: says nothing about keys that use most of the alphabet, or about alphabets outside the
dictionary set.

  python attacks/97_few_symbol_key.py
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets  # noqa: E402
from kryptos import idea97_fewsymbols as f  # noqa: E402

SEEDS = (1, 2) if SMOKE else tuple(range(1, 51))
HEAD = ["all win", "all d", "all cov5", "all cov8", "all cov10", "all cov12", "all cov16",
        "all top2", "all top3", "all top4", "all top7", "all digits", "all base", "all roman",
        "b1 win", "b1 d", "b1 cov5", "b1 cov8", "b1 top7", "b2 win", "b2 d", "b2 cov5", "b2 cov8", "b2 top7"]
LOW = {"win", "d", "base"}          # stats where smaller is the interesting direction


def better(name, a, b):
    """Is value a more extreme than b for this stat?"""
    return a < b if name.split()[1] in LOW else a > b


def show(label, s):
    print("%-12s" % label + "  ".join("%s=%d(x%d)" % (k.replace("all ", ""), s[k][0], s[k][1]) for k in HEAD[:14]))
    print("%-12s" % "" + "  ".join("%s=%d(x%d)" % (k, s[k][0], s[k][1]) for k in HEAD[14:]))


if __name__ == "__main__":
    t0 = time.time()
    alphas = dictionary_alphabets(mixed=True)
    n_set = (len(alphas) - 1) * 20 + 16
    with Experiment("key written with few symbols: smallest window, distinct values, Roman numerals",
                    puzzle="k4",
                    notes="%d alphabets (A-Z, KRYPTOS, dictionary keyword alphabets and their transposition-mixed forms) "
                          "x 5 layouts x 4 views (C-P, C+P and negatives); smallest circular window of the 24 key "
                          "values, distinct values, cover by windows of 5-16 and by any 2-7 values, Roman letters by "
                          "name; each clue block alone; %d shuffled controls" % (len(alphas), len(SEEDS)),
                    cribs_forced=True) as ex:
        print("alphabets %d, settings %d (key streams computed: %d)" % (len(alphas), n_set, n_set // 2))

        k4 = f.search(K4, CRIBS, alphas)
        ex.count(n_set)
        s4 = k4.summary()
        print("\nEach entry: best value (number of key streams that reach it). win = smallest window holding all, "
              "d = different values,\ncovW = most letters in a window of W, topN = most letters on N values, digits = "
              "most values 0-9, base = smallest base, roman = most Roman letters.")
        show("K4", s4)
        print("   (%.0f s)" % (time.time() - t0))

        ctrl = []
        for seed in SEEDS:
            c = f.search(shuffled_control(seed), CRIBS, alphas).summary()
            ctrl.append(c)
            if seed <= 5:
                show("shuffled %d" % seed, c)
        print("   (%.0f s)" % (time.time() - t0))

        print("\nK4 against the %d shuffled K4s, stat by stat (rank 1 = K4 more extreme than every control):" % len(SEEDS))
        alone = []
        for name in HEAD:
            vals = [c[name][0] for c in ctrl]
            beat = sum(better(name, v, s4[name][0]) for v in vals)
            tie = sum(v == s4[name][0] for v in vals)
            if beat == 0 and tie == 0:
                alone.append(name)
            print("   %-10s K4 %2d   controls %s   controls better %d, equal %d" % (
                name, s4[name][0], " ".join("%d:%d" % (v, vals.count(v)) for v in sorted(set(vals))), beat, tie))

        print("\nK4, 20 settings with the smallest window (key values at the 13 + 11 clue letters):")
        for _, rec in k4.top("win")[:20]:
            print("   " + f.line(rec))
        print("\nK4, 20 settings with the most letters on 7 values:")
        for _, rec in k4.top("top7")[:20]:
            print("   " + f.line(rec))
        print("\nK4, 5 settings with the most Roman numeral key letters:")
        for key, rec in k4.top("roman")[:5]:
            print("   %d of 24, key letter read in %s (sign %s): " % (-key[0], rec[9], rec[10]) + f.line(rec))
        for b in ("b1", "b2"):
            print("\nK4, clue block %s alone, 5 smallest windows:" % ("EASTNORTHEAST" if b == "b1" else "BERLINCLOCK"))
            for _, rec in k4.top(b)[:5]:
                print("   %-22s %-5s %-4s window %2d distinct %2d   %s" % (
                    rec[0][:22], rec[1], rec[2], rec[4], rec[6], f.fmt_key(rec[3])))

        # ---- planted answers: a key of few symbols on a dictionary tableau must come out first
        rng = random.Random(9700)
        pool = alphas[1:2000]
        plants = [("digits 0-9", list(range(10)), "M/M", "vig", "win"),
                  ("base 12 (0-11)", list(range(12)), "M/AZ", "beau", "win"),
                  ("clock hours 1-12", list(range(1, 13)), "KR/M", "vig", "win"),
                  ("Roman letters IVXLCDM (read in A-Z)", f.roman_values(AZ), "AZ/M", "vig", "top7")]
        ok = 0
        for label, values, lay, form, which in plants:
            name, m = rng.choice(pool)
            ct, pt, key = f.plant(rng, m, values, lay, form)
            t = f.search(ct, {i: pt[i] for i in POS}, alphas)
            truth = tuple(key[i] for i in POS)
            lst = [r for _, r in t.top(which)]
            rank = next((j for j, r in enumerate(lst) if r[:3] == (name, lay, form) and r[3] == truth), None)
            ahead = len({r[3] for r in lst[:rank]} - {truth}) if rank is not None else -1
            if which == "win":
                limit = len(values)
                found = rank is not None and lst[rank][4] <= limit
                extra = "key streams with a window of %d or less: %d, of 12 or less: %d" % (
                    limit, t.at_most("all", "win", limit), t.at_most("all", "win", 12))
            else:
                rl = [r for _, r in t.top("roman")]
                rr = next((j for j, r in enumerate(rl) if r[:3] == (name, lay, form) and r[3] == truth), None)
                found = rank is not None and lst[rank][6] <= 7 and rr is not None and t.highest("all", "roman")[0] == 24
                extra = "key streams with 7 or fewer values: %d; with 24 Roman letters by name: %d" % (
                    t.at_most("all", "d", 7), t.at_least("all", "roman", 24))
            ok += found
            print("\nplanted %s on %s %s %s -> flagged=%s; different keys ranked ahead of the true one: %d; %s" % (
                label, name, lay, form, found, ahead, extra))
            for r in lst[:4]:
                print("   " + f.line(r))
        print("\nplanted recovered: %d/%d" % (ok, len(plants)))

        # ---- verdict
        win, d, rom = s4["all win"][0], s4["all d"][0], s4["all roman"][0]
        hit = []
        if win <= 12 and all(c["all win"][0] > win for c in ctrl):
            hit.append("window %d" % win)
        if d <= 7 and all(c["all d"][0] > d for c in ctrl):
            hit.append("%d distinct values" % d)
        if rom == 24:
            hit.append("24 Roman letters")
        print("\nK4: smallest window %d, fewest distinct values %d, most Roman letters %d; shuffled K4s: window %s, "
              "distinct %s, Roman %s" % (win, d, rom, [c["all win"][0] for c in ctrl], [c["all d"][0] for c in ctrl],
                                         [c["all roman"][0] for c in ctrl]))
        print("stats where K4 is alone ahead of every control: %s" % (", ".join(alone) or "none"))
        print("VERDICT:", "INSPECT (%s): K4 stands out from the shuffled texts" % ", ".join(hit) if hit else
              "no hit (K4's smallest window %d is reached by %d of %d shuffled K4s, its %d distinct values by %d; no all-Roman "
              "key)" % (win, sum(c["all win"][0] <= win for c in ctrl), len(ctrl), d,
                        sum(c["all d"][0] <= d for c in ctrl)))
        if ok != len(plants):
            print("WARNING: a planted answer was missed - the negative does not stand")
        print("total %.0f s" % (time.time() - t0))
