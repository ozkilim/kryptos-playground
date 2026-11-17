"""Idea 94: each word is the key for the next word (word autokey) on every keyword tableau.

Scheidt: 'simple, can be remembered', and he 'masked the English language'. A key that never
repeats and needs no key text: after a primer word, every plaintext word is enciphered with the
word before it. Inside the clues the word before is known: EAST keys NORTH, NORTH keys EAST,
BERLIN keys CLOCK. That gives up to 14 letters whose key letter is known, with only one free
constant left, so 13 exact checks. The fixed-lag autokey tests of earlier rounds (lags 1-6, and
idea 74's repeating lag patterns) cannot see this, because the lag changes with every word length.

What is tested, exactly, on the clue letters (see kryptos/idea94_wordkey.py for the model):

  word splits   EAST|NORTH|EAST, EAST|NORTHEAST, EASTNORTH|EAST, EASTNORTHEAST; BERLIN|CLOCK, BERLINCLOCK
  key word      the previous word or the word two back, forwards or reversed, as plaintext or as
                its cipher letters; a longer word wraps round the key word, or runs on into its
                own letters (autokey restarted at each word)
  word in front for cipher feed and for run-on the unknown word in front of each clue matters:
                every length 1-12 is tried
  tableaux      A-Z, KRYPTOS and every dictionary keyword alphabet in its plain and two
                transposition-mixed forms (about 667,000), five layouts (M/M, M/AZ, AZ/M, M/KR,
                KR/M), Vigenere and Beaufort form (variant Beaufort is covered by the sign), the
                fed letter numbered on the plain-side or the cipher-side alphabet, added or subtracted
  pass          all pairs give the same constant, with 7 or more checks (8 or more pairs)
  count         for the eight full plain-feed tests (14 pairs) the largest number of pairs that
                agree is also recorded, K4 against shuffled K4s
  any tableau   the same pairs are checked against ANY tableau with distinct rows and columns
                (same plain and key letter must give the same cipher letter, and so on)
  hidden        one unknown alphabet on all three sides, X[C] = +-X[P] +- X[key] + const: linear
                equations mod 26, and a solution with the letters in DIFFERENT places is required

Every passing setting is decrypted from the first clue to the end under its best split into words
and read on the big English model.

K4 is run on every alphabet; each of five shuffled K4s on a different fifth (one full pass together).

Pre-filter (python attacks/94_word_autokey.py --prefilter): FLAG on the K5 clue, as expected for a
key that follows the message. Written reason for building it anyway: 13 exact checks, minutes of
computing, and no earlier test could see it.

Says nothing if the clue words are split in another way than listed, or if a transposition sits
before or after.

  python attacks/94_word_autokey.py
"""
import random
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers.substitution import AZ  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control, keyword_alphabet  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402
from kryptos.idea90_rowkey import extra_score  # noqa: E402
from kryptos.idea94_wordkey import (CLUE, CLUESET, CORE, HIDDEN_FORMS, MIN_CHECKS, PARTS, PRIMERS, TESTS,  # noqa: E402
                                    describe, encrypt, hidden_encrypt, hidden_search, label, latin_conflicts,
                                    plant, planted_words, read_hit, same_alphabet, search, search_cipher_count,
                                    settings_per_alphabet, state, triples, wanted)

ENGLISH = -5.1          # big-model score per quadgram that English reaches; noise sits near -6.5
SAMPLE = 600 if SMOKE else 9000
CIPHER_SAMPLE = 60 if SMOKE else 1000
SEEDS = (1, 2, 3, 4, 5)
# (mode, split of clue 1, split of clue 2, text, checks the planted answer must show)
PLANTS = ((("plain", "fwd", "wrap", 1), "E|N|E", "B|C", 0, 13),
          (("plain", "rev", "run", 1), "E|NE", "B|C", 1, 13),
          (("cipher", "fwd", "wrap", 1), "E|N|E", "B|C", 0, 23),
          (("cipher", "fwd", "wrap", 2), "E|NE", "B|C", 0, 13),
          (("plain", "fwd", "run", 1), "E|N|E", "B|C", 1, 13))


def prefilter_encrypt(pt, rng):
    """Word autokey (previous plaintext word, wrap) on a keyword tableau; the key comes from rng only."""
    m = keyword_alphabet(rng.choice(["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN", "LODESTONE"]))
    const = rng.randrange(26)
    primers = ["".join(rng.choice(AZ) for _ in range(6)) for _ in range(2)]
    cuts = {0, 21, 25, 30, 34, 63, 69, 74, len(pt)}
    p = 0
    while p < len(pt):
        p += rng.randint(2, 8)
        if p < len(pt) and not (21 < p < 34 or 63 < p < 74):
            cuts.add(p)
    cuts = sorted(cuts)
    words = [pt[a:b] for a, b in zip(cuts, cuts[1:])]
    return encrypt(words, m, "M/M", "vig", "M", 1, const, ("plain", "fwd", "wrap", 1), primers)


def read(hits, ct, cribs, by_name, big):
    """[(checks, quadgrams outside the clues, English score, text, hit)], best first."""
    out = []
    for h in hits[:60]:
        pt = read_hit(ct, cribs, by_name[h[1]], h, big)
        sc, cnt = extra_score(pt, big, CLUESET)
        out.append((h[0], cnt, sc, pt, h))
    return sorted(out, key=lambda r: (r[0], r[2] or -99), reverse=True)


def show(rows, limit=10):
    for checks, cnt, sc, pt, h in rows[:limit]:
        print("    " + describe(h))
        print("      %s   english %s over %d quadgrams outside the clues" % (pt, "%.2f" % sc if sc is not None else "n/a", cnt))


def tail(hist):
    return ", ".join("%d of 14: %d" % (c, hist[c]) for c in sorted(hist)) or "none at 6 or more"


def hidden_summary(res):
    """Counter of (feed, 14+ pairs?, status) and the list of tests that list solutions."""
    c, listed = Counter(), []
    for t, f, st, sols in res:
        mode, n1, n2 = TESTS[t]
        pairs = sum(len(PARTS[n]["pairs"]) for n in (n1, n2) if n is not None)
        c[mode[0], pairs >= 14, st] += 1
        if st in ("ok", "capped"):
            listed.append((pairs, t, f, sols))
    return c, sorted(listed, reverse=True)


def hidden_line(c):
    out = []
    for feed in ("plain", "cipher"):
        for big, name in ((True, "14+ pairs"), (False, "8-13 pairs")):
            tot = sum(v for (fd, b, _), v in c.items() if fd == feed and b == big)
            out.append("%s feed, %s: %d systems, %d impossible (%d on any tableau), %d with solutions listed, %d not decidable" % (
                feed, name, tot, c[feed, big, "none"] + c[feed, big, "tableau"], c[feed, big, "tableau"],
                c[feed, big, "ok"] + c[feed, big, "capped"], c[feed, big, "open"]))
    return out


def find_test(mode, p1, L1, p2, L2):
    for t, (md, n1, n2) in enumerate(TESTS):
        if md == mode and n1 is not None and n2 is not None and (p1, L1) in PARTS[n1]["labels"] \
                and (p2, L2) in PARTS[n2]["labels"]:
            return t
    return None


def planted_hidden(rng, mode, p1, p2, L, text=0):
    """Plant on a random hidden alphabet. Returns (found, status, note)."""
    words, pt = planted_words(text, p1, p2)
    alpha = "".join(rng.sample(AZ, 26))
    f = rng.randrange(len(HIDDEN_FORMS))
    fname, pcoef, sg = HIDDEN_FORMS[f]
    ct = hidden_encrypt(words, alpha, pcoef, sg, rng.randrange(26), mode, PRIMERS)
    cribs = {i: pt[i] for i in CLUE}
    t = find_test(mode, p1, L, p2, L)
    res = {(a, b): (st, sols) for a, b, st, sols in hidden_search(ct, cribs, tests=[t])}
    st, sols = res[t, f]
    if st in ("ok", "capped"):
        good = any(same_alphabet(s, alpha, AZ) for s, _ in sols)
        return good, st, "%s, %s: %d letters placed, true alphabet among the solutions: %s" % (fname, st, len(sols[0][0]), good)
    return st == "open", st, "%s: kept (%s; too few equations to pin the alphabet down)" % (fname, st)


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("word autokey (previous plaintext word keys the next) on a keyword tableau", encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "paper tableau and the word before: easy by hand")})
        sys.exit(0)
    alphas = dictionary_alphabets(mixed=True)
    if SMOKE:
        alphas = alphas[:3000]
    by_name = dict(alphas)
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    n_set = sum(settings_per_alphabet(m) for _, m in alphas)
    with Experiment("word autokey: each word keys the next (previous word or two back, plain or cipher, wrap or run-on)",
                    puzzle="k4",
                    notes="%d alphabets (A-Z, KRYPTOS, dictionary keyword + 2 transposition-mixed forms) x 5 layouts x "
                          "Vig/Beau x fed letter on plain/cipher side x sign; %d word-split tests; exact, >=%d checks; "
                          "5 shuffled controls on a fifth of the alphabets each; plus any-tableau and one-hidden-alphabet "
                          "tests" % (len(alphas), len(TESTS), MIN_CHECKS),
                    cribs_forced=True) as ex:
        t0 = time.time()
        S = state(K4, CRIBS)
        print("== any tableau with distinct rows and columns: the eight full plain-feed tests on K4")
        for mode, n1, n2 in CORE:
            tr = triples(PARTS[n1]["pairs"] + PARTS[n2]["pairs"], "plain", K4, S["pt"])
            bad = latin_conflicts(tr)
            print("   key word %s, %s, %s: %s" % (
                "forwards" if mode[1] == "fwd" else "reversed", "wrap" if mode[2] == "wrap" else "run-on",
                label(n1).split(" ")[0],
                "IMPOSSIBLE: " + "; ".join("plain %s under key %s gives %s, but plain %s under key %s gives %s" % (a + b)
                                           for a, b in bad) if bad else "no clash"))

        print("== keyword tableaux")
        hits, hist, tops = search(K4, CRIBS, alphas)
        k4 = read(hits, K4, CRIBS, by_name, big)
        ex.count(n_set)
        print("alphabets: %d; tests per view: %d; settings tested: %d; %.0f s" % (len(alphas), len(TESTS), n_set, time.time() - t0))
        print("K4: %d settings pass with >= %d checks; best checks %d" % (len(hits), MIN_CHECKS, max((h[0] for h in hits), default=0)))
        show(k4)
        print("K4, full plain-feed tests, pairs agreeing: %s" % tail(hist))
        for cnt, name, lay, form, fn, sg, t in tops[:8]:
            mode, n1, n2 = CORE[t]
            print("    %d of 14: %s %s %s fed on %s sign=%+d | key word %s, %s, %s" % (
                cnt, name, lay, form, fn, sg, mode[1], mode[2], label(n1).split(" ")[0]))
        ctrl_hits, ctrl_hist, ctrl_best = 0, Counter(), 0
        for seed in SEEDS:
            part, c = alphas[seed - 1::len(SEEDS)], shuffled_control(seed)
            h, hi, _ = search(c, CRIBS, part)
            rows = read(h, c, CRIBS, by_name, big)
            ctrl_hits += len(h)
            ctrl_best = max([ctrl_best] + [x[0] for x in h])
            ctrl_hist.update(hi)
            print("shuffled K4 seed %d on %d alphabets: %d settings pass; best checks %d; pairs agreeing: %s" % (
                seed, len(part), len(h), max((x[0] for x in h), default=0), tail(hi)))
            show(rows, 4)
        print("five shuffled fifths together: %d settings pass; pairs agreeing: %s" % (ctrl_hits, tail(ctrl_hist)))

        print("== cipher feed, previous word: most pairs agreeing out of 24, first %d alphabets" % CIPHER_SAMPLE)
        sample = alphas[:CIPHER_SAMPLE]
        ck4 = search_cipher_count(K4, CRIBS, sample)
        cctrl = [search_cipher_count(shuffled_control(seed), CRIBS, sample)[0] for seed in SEEDS]
        print("K4: %d of 24 (%s); shuffled K4s: %s" % (ck4[0], ck4[1], cctrl))

        print("== one hidden alphabet on all sides (%d tests x %d forms)" % (len(TESTS), len(HIDDEN_FORMS)))
        hk4, listed = hidden_summary(hidden_search(K4, CRIBS))
        ex.count(len(TESTS) * len(HIDDEN_FORMS))
        print("K4:")
        for line in hidden_line(hk4):
            print("    " + line)
        for pairs, t, f, sols in listed[:6]:
            mode, n1, n2 = TESTS[t]
            print("    listed: %d pairs, %s, %s, block 1: %s, block 2: %s, %d+ solutions, %d letters placed" % (
                pairs, HIDDEN_FORMS[f][0], mode, label(n1), label(n2), len(sols), len(sols[0][0])))
        hctrl = []
        for seed in SEEDS:
            c, li = hidden_summary(hidden_search(shuffled_control(seed), CRIBS))
            hctrl.append((c, li))
            print("shuffled K4 seed %d:" % seed)
            for line in hidden_line(c):
                print("    " + line)

        print("== planted answers")
        ok = 0
        named = [a for a in alphas if a[0] != "(A-Z)"]
        for j, (mode, p1, p2, text, need) in enumerate(PLANTS):
            rng = random.Random(9400 + j)
            ct, cribs, want, pt, m = plant(rng, named, mode, p1, p2, text)
            sample = rng.sample(alphas, min(SAMPLE, len(alphas)))
            if want[0] not in {n for n, _ in sample}:
                sample.append((want[0], m))
            h, _, _ = search(ct, cribs, sample, chunk=300)
            mine = [x for x in wanted(h, want, mode, p1, p2) if x[0] >= need]
            got = read_hit(ct, cribs, m, mine[0], big) if mine else ""
            right = sum(a == b for a, b in zip(got[34:], pt[34:]))
            sc = extra_score(got, big, CLUESET)[0] if mine else None
            good = bool(mine) and right >= 50
            ok += good
            print("planted %s %s %s %s -> found=%s with %s checks (settings passing on %d alphabets: %d); "
                  "letters 34-96 read back: %d of 63, english %s" % (
                      mode, p1, p2, want, good, mine[0][0] if mine else "-", len(sample), len(h), right,
                      "%.2f" % sc if sc is not None else "n/a"))
            if mine:
                print("      " + got)
        for j, (mode, p1, p2, L) in enumerate(((("cipher", "fwd", "wrap", 1), "E|N|E", "B|C", 3),
                                               (("plain", "fwd", "wrap", 1), "E|NE", "B|C", None))):
            good, st, note = planted_hidden(random.Random(9450 + j), mode, p1, p2, L)
            ok += good
            print("planted on a random hidden alphabet, %s %s %s -> found=%s; %s" % (mode, p1, p2, good, note))
        total = len(PLANTS) + 2
        print("planted recovered: %d/%d" % (ok, total))

        n4, b4 = len(hits), max((h[0] for h in hits), default=0)
        e4 = max((r[2] for r in k4 if r[2] is not None and r[1] >= 20), default=None)
        top4, topc = max(hist, default=0), max(ctrl_hist, default=0)
        english = e4 is not None and e4 > ENGLISH
        beats = (n4 > 0 and (b4 > max(ctrl_best, MIN_CHECKS) + 1 or n4 > 3 * ctrl_hits + 3)) or top4 > topc + 1
        h14 = sum(v for (fd, b, st), v in hk4.items() if b and st in ("ok", "capped"))
        print("VERDICT:", "K4 beats the controls and reads as English - inspect" if beats and english else
              "K4 beats the controls on checks but does not read as English - inspect" if beats else
              "no signal (K4: %d pass, best %d checks, most pairs agreeing %d of 14; five shuffled fifths together: %d pass, "
              "best %d checks, most pairs agreeing %d of 14; hidden alphabet with 14+ pairs: %d K4 systems list a solution)" % (
                  n4, b4, top4, ctrl_hits, ctrl_best, topc, h14))
        if ok != total:
            print("WARNING: a planted answer was missed - the negative does not stand")
        print("total time %.0f s" % (time.time() - t0))
