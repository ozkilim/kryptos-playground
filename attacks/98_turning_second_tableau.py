"""Idea 98: two tableaux, one layer a key word, the other turning steadily.

K2 ends LAYER TWO, Scheidt taught "shifting matrices" and calls K4 "more than one stage". Idea
84 closed two REPEATING keys on two different tableaux. Here one layer is a repeating key word
on alphabet A and the other is a tableau B that turns by a fixed step every letter:

    key layer    X -> A[ +-A^-1(X) + a_(i mod p) ]
    turn layer   X -> B[ +-B^-1(X) + s * g(i) + t ]        s = 1..25, t = 0..25

in both orders (key word first, or turn first). + is Vigenere (variant Beaufort is the same
with free key letters, s and t), - is Beaufort: 4 type pairs. g(i) is what the turn counts:
the whole text, or restarting at each carved row (K4 letters 1, 5, 36, 67), or at rows of 21 or
42. On one tableau (A = B) the two layers fold into one progressive key, which was closed
before, so A = B is skipped. With A different from B the turn hides the key word's period.

The test (kryptos/idea98_turning.py). For given B, type, s, t and row layout the turn layer is
fully known, so each clue letter gives the key layer's key value outright. A key word of length
p needs equal values wherever i mod p is equal. Checks = 24 clue letters minus the key slots
they touch; chance passes n checks about 26^-n of the time. Periods 1..23 all have 7+ checks
(p = 17, 18, 23 have exactly 7; p = 24 has 5 and is kept as a chance gauge only). All 3,900
(type of turn, layout, s, t) are tested at once with byte-string translates and big-integer
XORs. On the clue letters rows of 42 are the same test as rows of 21 (t moved by 21 s), so the
scan runs three layouts and every rows-of-21 survivor is read both ways.

  part 1   every ordered pair (A, B) of different alphabets from A-Z, KRYPTOS and the theme
           keyword alphabets
  part 2   every dictionary keyword alphabet D as (A-Z, D), (KRYPTOS, D), (D, A-Z), (D, KRYPTOS)
  nothing is cut: all s = 1..25 everywhere, and the 3 shuffled K4s get the same pairs as K4

Survivors: the key is forced where the clues touch it; all 97 letters are decrypted ('?' where
a long key is not reached) and scored on the big English model.

  python attacks/98_turning_second_tableau.py            (--prefilter for the clue card)
"""
import collections
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea98_turning import (LANES, MAXP, ROWS, Scanner, checks, decrypt, encrypt as tt_encrypt,  # noqa: E402
                                    key_text, key_values, periods, twin)
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

MIN_CHECKS = 7          # the headline bar (as in rounds 9-11)
ENGLISH = -5.1          # big-model score per quadgram a reading must beat (planted texts: about -4.2)
TNAME = {1: "Vigenere", -1: "Beaufort"}
CHK = {p: checks(p, POS) for p in range(1, MAXP + 1)}
PER_PAIR = 2 * 2 * LANES                      # (order, key type) x (turn type, layout, s, t)
_S = {}


def small_alphabets():
    """A-Z, KRYPTOS and the theme-word keyword alphabets (distinct)."""
    out, seen = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)], {AZ, KRYPTOS_ALPHABET}
    for w in wordkeys.theme_words():
        m = keyword_alphabet(w)
        if m not in seen:
            seen.add(m)
            out.append((w, m))
    return out


def part1_pairs(small):
    """(name A, A, name B, B): A carries the key word, B turns."""
    return [(an, a, bn, b) for an, a in small for bn, b in small if a != b]


def part2_pairs(dic, small):
    known = set(m for _, m in small)
    out = []
    for name, m in dic:
        if m in known:
            continue
        for xn, x in small[:2]:
            out.append((xn, x, name, m))
            out.append((name, m, xn, x))
    return out


def init(ct, cribs):
    _S["pl"] = [cribs[i] for i in POS]
    _S["cl"] = [ct[i] for i in POS]
    _S["scan"] = Scanner(POS)


def work(chunk):
    """Returns (pairs, [(checks, name A, A, name B, B, order, ek, eg, v, s, t, p)]); p = the
    shortest key length that fits (it has the most checks)."""
    scan, pl, cl, hits = _S["scan"].scan, _S["pl"], _S["cl"], []
    for an, a, bn, b in chunk:
        for order, ek, eg, v, s, t in scan(a, b, pl, cl):
            per = periods(key_values(pl, cl, POS, a, b, s, t, ek, eg, order, v), POS)
            p = max(per, key=lambda q: (CHK[q], -q))
            hits.append((CHK[p], an, a, bn, b, order, ek, eg, v, s, t, p))
    return len(chunk), hits


def search(ct, cribs, pairs):
    n, hits = 0, []
    for k, h in pmap(work, pairs, init, (ct, cribs), chunk=300):
        n += k
        hits.extend(h)
    return n, sorted(hits, key=lambda h: (-h[0], h[1], h[3], h[5:]))


def read_score(pt, big):
    """Big-model score per quadgram over the letters that are known; -99 if under 15 quadgrams."""
    q = [pt[i:i + 4] for i in range(len(pt) - 3) if "?" not in pt[i:i + 4]]
    return sum(big.logp.get(x, big.floor) for x in q) / len(q) if len(q) >= 15 else -99.0


def complete(hit, ct, cribs, big):
    """A survivor -> [(english, text, key word, layout name, s, t)], best first. Rows of 21 are
    also read as rows of 42 (the same on the clue letters)."""
    _, an, a, bn, b, order, ek, eg, v, s, t, p = hit
    slots = periods(key_values([cribs[i] for i in POS], [ct[i] for i in POS], POS, a, b, s, t, ek, eg, order, v),
                    POS)[p]
    out = []
    for vv, ss, tt in [(v, s, t)] + ([twin(v, s, t)] if twin(v, s, t) else []):
        pt = decrypt(ct, a, b, slots, ss, tt, ek, eg, order, vv)
        out.append((read_score(pt, big), pt, key_text(slots, a), ROWS[vv], ss, tt))
    return sorted(out, reverse=True)


def complete_all(hits, ct, cribs, big, limit=4000):
    out = []
    for h in hits[:limit]:
        for sc, pt, kw, rows, s, t in complete(h, ct, cribs, big):
            out.append((sc, pt, kw, rows, s, t, h))
    return sorted(out, key=lambda r: (-r[0], r[1]))


def describe(r):
    sc, pt, kw, rows, s, t, h = r
    first = "key word on %s (%s)" % (h[1], TNAME[h[6]])
    second = "turn on %s (%s) by %d per letter from %d, %s" % (h[3], TNAME[h[7]], s, t, rows)
    return "%s; key length %d, %d checks" % ((first + " then " + second) if h[5] == 1 else
                                              (second + " then " + first), h[11], h[0])


def by_checks(hits):
    c = collections.Counter(h[0] for h in hits)
    return " ".join("%d:%d" % (k, c[k]) for k in sorted(c)) or "none"


def headline(hits):
    return [h for h in hits if h[0] >= MIN_CHECKS]


def chance(npairs):
    """Survivors chance predicts if every check were an independent 1-in-26: (at 5-6 checks, at
    exactly 7, at 8+). A key that fits p fits its multiples too, so only the cheapest are counted
    once each: this is a rough guide, the shuffled K4s are the real yardstick."""
    lo = sum(26.0 ** -c for p, c in CHK.items() if c < MIN_CHECKS)
    at = sum(26.0 ** -c for p, c in CHK.items() if c == MIN_CHECKS)
    hi = sum(26.0 ** -c for p, c in CHK.items() if c > MIN_CHECKS)
    return npairs * PER_PAIR * lo, npairs * PER_PAIR * at, npairs * PER_PAIR * hi


# ---- planted messages -------------------------------------------------------------------------

def plant(rng, a, b, word, s, t, ek, eg, order, v):
    pt = english97(rng)
    ct = tt_encrypt(pt, a, b, [a.index(ch) for ch in word], s, t, ek, eg, order, v)
    return pt, ct, {i: pt[i] for i in POS}


def on_clues(v, s, t):
    """The scan's name for a setting: rows of 42 show up as rows of 21."""
    return (2, s, (t + 21 * s) % 26) if v == 3 else (v, s, t)


def planted_case(rng, big, label, an, a, bn, b, word, s, t, ek, eg, order, v, pairs):
    """Plant, search, read. Found = the true setting passes at the true key length, it is the only
    setting with 7+ checks, and the best reading is the planted text and scores as English."""
    pt, ct, cribs = plant(rng, a, b, word, s, t, ek, eg, order, v)
    n, hits = search(ct, cribs, pairs)
    hits = headline(hits)
    true = [h for h in hits if h[2] == a and h[4] == b and h[5:8] == (order, ek, eg)
            and h[8:11] == on_clues(v, s, t) and h[11] == len(word)]
    done = complete_all(hits, ct, cribs, big)
    ok = (len(true) == 1 and len(hits) == 1 and done[0][1] == pt and done[0][0] > ENGLISH
          and done[0][2] == word)
    print("planted %s: key word %s on %s (%s), turn on %s (%s) by %d from %d, %s, %s; %d settings searched -> "
          "true setting found=%s, survivors with %d+ checks %d, best reading english %.2f, is the planted text: %s, "
          "key word read back: %s -> %s"
          % (label, word, an, TNAME[ek], bn, TNAME[eg], s, t, ROWS[v],
             "key word first" if order == 1 else "turn first", n * PER_PAIR * (MAXP - 1), bool(true), MIN_CHECKS,
             len(hits), done[0][0] if done else -99, bool(done) and done[0][1] == pt,
             done[0][2] if done else "-", "ok" if ok else "MISSED"))
    return ok


def prefilter_encrypt(pt, rng):
    """For the clue pre-filter: key word layer on KRYPTOS then a turning A-Z tableau; key from rng only."""
    key = [rng.randrange(26) for _ in range(rng.randrange(5, 10))]
    return tt_encrypt(pt, KRYPTOS_ALPHABET, AZ, key, rng.randrange(1, 26), rng.randrange(26))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("key word on one tableau, steadily turning second tableau", encrypt=prefilter_encrypt)
        sys.exit(0)
    small = small_alphabets()
    dic = dictionary_alphabets()
    if SMOKE:
        small, dic = small[:12], dic[:1500]
    p1, p2 = part1_pairs(small), part2_pairs(dic, small)
    nper = sum(c >= MIN_CHECKS for c in CHK.values())
    with Experiment("key word on one tableau, steadily turning second tableau", puzzle="k4",
                    notes="exact periodic test on the clue letters with the turn layer (shift s*g(i)+t, s 1-25, "
                          "t 0-25) known; both layer orders; Vig/Beau per layer; turn counted over the whole text, "
                          "carved rows, rows of 21/42; key lengths 1-%d (7+ checks), 24 as gauge; %d ordered pairs "
                          "of A-Z/KRYPTOS/theme alphabets + %d dictionary alphabets against A-Z and KRYPTOS in "
                          "both roles; 3 shuffled K4s on the same pairs"
                          % (MAXP - 1, len(p1), len(p2) // 4), cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        print("alphabet pairs: part 1 %d (from %d alphabets), part 2 %d (%d dictionary alphabets x 4)"
              % (len(p1), len(small), len(p2), len(p2) // 4))
        print("per pair: %d settings (2 orders x 4 types x 3 row layouts x 25 steps x 26 starts), each tested at "
              "key lengths 1-%d; checks by key length: %s"
              % (PER_PAIR, MAXP, " ".join("%d:%d" % (p, CHK[p]) for p in sorted(CHK))))
        n, hits = search(K4, CRIBS, p1 + p2)
        ex.count(n * PER_PAIR * nper)
        lo, at, hi = chance(n)
        print("K4: %d pairs, %d settings x key lengths with %d+ checks" % (n, n * PER_PAIR * nper, MIN_CHECKS))
        print("K4 survivors by checks (checks:settings): %s   [chance predicts about %.0f at 5-6 checks, %.1f at "
              "exactly 7, %.2f at 8+]" % (by_checks(hits), lo, at, hi))
        k4_head = headline(hits)
        done = complete_all(k4_head, K4, CRIBS, big)
        gauge = complete_all([h for h in hits if h[0] < MIN_CHECKS], K4, CRIBS, big)
        for r in done[:40]:
            print("   english %.2f words %.2f  %s\n      key %s\n      %s"
                  % (r[0], word_coverage(r[1].replace("?", "")), describe(r), r[2], r[1]))
            ex.add(r[1].replace("?", "X"), english_big=round(r[0], 3), setting=describe(r), key=r[2])
        k4_best = done[0][0] if done else -99.0
        k4_gauge = gauge[0][0] if gauge else -99.0
        print("K4 best reading: %.2f among %d+ checks, %.2f among the 5-6 check gauge survivors (English needs %.1f)"
              % (k4_best, MIN_CHECKS, k4_gauge, ENGLISH))
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            sct = shuffled_control(seed)
            cp = p1 + p2                                    # the test is cheap: every control gets everything
            cn, chits = search(sct, CRIBS, cp)
            ch = headline(chits)
            cdone = complete_all(ch, sct, CRIBS, big)
            cg = complete_all([h for h in chits if h[0] < MIN_CHECKS], sct, CRIBS, big)
            clo, cat, chi = chance(cn)
            ctrl.append((len(ch), sum(h[0] > MIN_CHECKS for h in ch), cdone[0][0] if cdone else -99.0,
                         cg[0][0] if cg else -99.0, cn, len(chits) - len(ch)))
            print("shuffled K4 seed %d (%d pairs, the same as K4): survivors by checks %s   "
                  "[chance predicts about %.0f / %.1f / %.2f]; best reading %.2f at %d+ checks, %.2f in the gauge"
                  % (seed, cn, by_checks(chits), clo, cat, chi, ctrl[-1][2], MIN_CHECKS, ctrl[-1][3]))
        rng = random.Random(98)
        dn, dm = dic[len(dic) // 3]
        dn2, dm2 = dic[2 * len(dic) // 3]
        sample = [x for x in dic[::10 if SMOKE else 40] if x[0] not in (dn, dn2)]
        theme = small[2:]
        cases = [
            ("key word on KRYPTOS, then +3 turn on a dictionary tableau", "KRYPTOS", KRYPTOS_ALPHABET, dn, dm,
             "ABSCISSA", 3, 11, 1, 1, 1, 0, part2_pairs(sample + [(dn, dm)], small)),
            ("the reverse order: +3 turn on a dictionary tableau, then key word on KRYPTOS", "KRYPTOS",
             KRYPTOS_ALPHABET, dn, dm, "ILLUSION", 3, 20, 1, 1, 2, 0, part2_pairs(sample + [(dn, dm)], small)),
            ("Beaufort key word on a dictionary tableau, A-Z turning by 11, restart at carved rows", dn2, dm2,
             "(A-Z)", AZ, "LANTERN", 11, 5, -1, 1, 1, 1, part2_pairs(sample + [(dn2, dm2)], small)),
            ("theme tableaux, Beaufort turn by 25 in rows of 42 first, 11-letter key word second", theme[2][0],
             theme[2][1], theme[-1][0], theme[-1][1], "PALIMPSESTS"[:11], 25, 7, 1, -1, 2, 3, p1),
        ]
        ok = 0
        for c in cases:
            ok += planted_case(rng, big, *c)
        print("planted recovered: %d/%d" % (ok, len(cases)))
        # scale K4's count to a control's share of the pairs before comparing counts
        share = [c[4] / float(n) for c in ctrl]
        more = all(len(k4_head) * sh > c[0] + 3 * (c[0] ** 0.5) + 3 for sh, c in zip(share, ctrl))
        reads = k4_best > ENGLISH and k4_best > max(c[2] for c in ctrl) + 0.3
        print("VERDICT:", ("K4 beats every control - inspect; " if (more or reads) else "no signal; ") +
              "K4 %d settings pass with %d+ checks (%d of them with 8+; chance predicts about %.1f and %.2f), best "
              "reading english %.2f; shuffled K4s on %s of the pairs: %s pass with %d+ (%s with 8+), best readings "
              "%s (English needs %.1f; -99 = nothing to read). Gauge at 5-6 checks: K4 %d, shuffled %s"
              % (len(k4_head), MIN_CHECKS, sum(h[0] > MIN_CHECKS for h in k4_head), at, hi, k4_best,
                 ["%.2f" % s for s in share], [c[0] for c in ctrl], MIN_CHECKS, [c[1] for c in ctrl],
                 ["%.2f" % c[2] for c in ctrl], ENGLISH, len(hits) - len(k4_head), [c[5] for c in ctrl]))
