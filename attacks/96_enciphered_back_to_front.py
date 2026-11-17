"""Idea 96: the message enciphered back to front (an autokey that looks ahead).

Sanborn (2005) said he left "instructions in the earlier text that refer to later text". One
plain way for early letters to depend on later ones: encipher the message from its LAST letter
backwards with an autokey. Then the key letter for position i is a letter that FOLLOWS it,

    key[i] = word[i mod p] + sign * number(letter at i + d)

taken from the plaintext or from the ciphertext. With d = 42 (the K3 worksheet width, and the
distance between the two clues) BERLINCLOCK would be the key for EASTNORTHEAST. Every autokey
test so far (ideas 55, 59, 66, 74, 90) looked back; idea 54 looked 1-5 ahead on A-Z and
KRYPTOS only. This script is the mirror image, tested exactly on the clue letters:

  A  dictionary tableaux: A-Z, KRYPTOS and every dictionary keyword alphabet in its plain and
     two transposition-mixed forms (about 667,000), five layouts, Vigenere and Beaufort, fed
     letter numbered in M, A-Z or KRYPTOS, added or subtracted, a constant or a word of 2-4 on top.
       plain feed    d = 1..8 inside a clue (22 down to 8 pairs); the second clue keying the
                     first: d = 34..48 with the second clue moved s = -3..3 (8-11 pairs)
       cipher feed   d = 1..68 (24 pairs up to d = 23, 13 pairs for d = 34..63, 8 at d = 68)
  B  the mirror of idea 59 on A-Z / KRYPTOS: any multiplier 1..25 on the fed letter and a
     repeating word of 1-13 on top, same feeds and distances
  C  the mirror of idea 55: ONE hidden alphabet (both sides, or one side against A-Z / KRYPTOS),
     x[C] = +-x[P] +- x[fed] + c, d = 1..8, solved exactly; a solution must put different
     letters in different places

A setting passes with 7 or more independent checks (A, B: pairs - word length; C: 3 or more,
as in idea 55). Passing settings are decrypted as far as they force letters and read on the
big English model. Controls: 3 shuffled K4s per part (20 for C). Planted answers must be found.

Cannot decide: plain feed at d = 9..33 (5 or fewer checks, or no clue pairs at all), cipher
feed at d = 69 and beyond (under 8 pairs).

  python attacks/96_enciphered_back_to_front.py            (--prefilter for the clue card)
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402
from kryptos.idea96_ahead import (HIDDEN_MIN, MIN_CHECKS, TESTS, decrypt, encrypt, extra_score,  # noqa: E402
                                  hidden_plant, hidden_survivors, plant, positions, search,
                                  settings_per_alphabet, small_decrypt, small_plant, small_search)

# part A: (feed, d, shift of the second clue, word length, checks the planted answer must show)
PLANTS = (("plain", 3, 0, 1, 15), ("cipher", 11, 0, 1, 20), ("plain", 42, 0, 1, 9), ("plain", 40, -2, 2, 7),
          ("cipher", 50, 0, 3, 7))
SMALL_PLANTS = (("cipher", 11, 5), ("plain", 3, 6), ("plain", 42, 3), ("cipher", 30, 9))
HIDDEN_PLANTS = ((("?", "?"), "P", 1), (("?", "?"), "C", 3), (("?", "AZ"), "P", 3), (("KR", "?"), "C", 5),
                 (("AZ", "?"), "P", 2), (("?", "KR"), "C", 4))
SAMPLE = 600 if SMOKE else 9000
ENGLISH = -5.1          # big-model score per quadgram that English reaches; noise sits near -6.5


def prefilter_encrypt(pt, rng):
    """Plaintext look-ahead autokey, d = 3, KRYPTOS tableau; constant and primer from rng."""
    return encrypt(pt, KRYPTOS_ALPHABET, "M/M", "vig", "M", 1, "plain", 3, [rng.randrange(26)], rng)


def read(hits, ct, cribs, by_name, big):
    """[(checks, quadgrams outside the clues, score, text, hit)] for every passing setting."""
    out = []
    for h in hits:
        pt = decrypt(ct, cribs, by_name[h[1]], h)
        sc, cnt = extra_score(pt, big, frozenset(positions(h[8])))
        out.append((h[0], cnt, sc, pt, h))
    return sorted(out, key=lambda r: (r[0], r[2] or -99), reverse=True)


def show(rows, limit=12):
    for checks, cnt, sc, pt, h in rows[:limit]:
        print("    checks=%d %s %s %s feed=%s numbered in %s sign=%+d d=%d shift=%+d word=%d %s" % (
            checks, h[1], h[2], h[3], h[6], h[4], h[5], h[7], h[8], h[9], [v for _, v in h[10]]))
        print("      %s   english %s over %d quadgrams outside the clues" % (pt, "%.2f" % sc if sc is not None else "n/a", cnt))


def summary(rows):
    best = max((r[0] for r in rows), default=0)
    eng = max((r[2] for r in rows if r[2] is not None and r[1] >= 20), default=None)
    return len(rows), best, eng


def strong(surv):
    return [s for s in surv if s[3] >= HIDDEN_MIN]


def part_a(alphas, by_name, big, ex):
    print("== A: dictionary tableaux ==")
    n_set = sum(settings_per_alphabet(m) for _, m in alphas)
    t0 = time.time()
    k4 = read(search(K4, CRIBS, alphas), K4, CRIBS, by_name, big)
    ex.count(n_set)
    print("alphabets: %d; (feed, d, shift) tests: %d; settings tested: %d; %.0f s" % (
        len(alphas), len(TESTS), n_set, time.time() - t0))
    print("K4: %d settings pass with >= %d checks; best checks %d; best English (20+ quadgrams) %s" % (
        (summary(k4)[0], MIN_CHECKS) + summary(k4)[1:]))
    show(k4)
    ctrl = []
    for seed in (1, 2, 3):
        c = shuffled_control(seed)
        rows = read(search(c, CRIBS, alphas), c, CRIBS, by_name, big)
        ctrl.append(summary(rows))
        print("shuffled K4 seed %d on %d alphabets: %d settings pass; best checks %d; best English %s" % (
            (seed, len(alphas)) + ctrl[-1]))
        show(rows, 6)
    ok = 0
    named = [a for a in alphas if a[0] != "(A-Z)"]
    for j, (src, d, shift, p, need) in enumerate(PLANTS):
        rng = random.Random(9600 + j)
        ct, cribs, want, pt, m = plant(rng, named, src, d, shift, p)
        sample = rng.sample(alphas, min(SAMPLE, len(alphas)))
        if want[0] not in {n for n, _ in sample}:
            sample.append((want[0], m))
        rows = read(search(ct, cribs, sample, chunk=300), ct, cribs, by_name, big)
        mine = [r for r in rows if r[4][1:10] == want and r[0] >= need]
        good = bool(mine) and all(a == "." or a == b for a, b in zip(mine[0][3], pt))
        ok += good
        print("planted %s -> found=%s with %s checks (settings passing on %d alphabets: %d); forced text reads %s" % (
            want, good, mine[0][0] if mine else "-", len(sample), len(rows),
            "%.2f over %d quadgrams" % (mine[0][2], mine[0][1]) if mine and mine[0][2] is not None else "n/a"))
    print("A planted recovered: %d/%d" % (ok, len(PLANTS)))
    return k4, ctrl, ok


def part_b(big, ex):
    print("== B: A-Z / KRYPTOS, multiplier 1..25 on the fed letter, word of 1-13 on top ==")
    tried, hits, best = small_search(K4, CRIBS)
    ex.count(tried)
    print("K4: %d settings; %d pass with >= %d checks; most clue pairs agreeing on one constant (multiplier +-1): "
          "%d of %d (%s)" % (tried, len(hits), MIN_CHECKS, best[0], best[1], best[2]))
    for h in sorted(hits, reverse=True)[:8]:
        pt = small_decrypt(K4, CRIBS, h)
        print("    %s\n      %s  english %s" % (h[:9], pt, extra_score(pt, big, frozenset(positions(h[7])))))
    ctrl = []
    for seed in (1, 2, 3):
        _, h, b = small_search(shuffled_control(seed), CRIBS)
        ctrl.append((len(h), max((x[0] for x in h), default=0), "%d of %d" % b[:2]))
    print("shuffled K4s (passes, best checks, most pairs on one constant):", ctrl)
    ok = 0
    rng = random.Random(9650)
    for src, d, p in SMALL_PLANTS:
        ct, cribs, want, pt = small_plant(rng, src, d, p)
        _, h, _ = small_search(ct, cribs)
        mine = [x for x in h if x[1:9] == want]
        got = small_decrypt(ct, cribs, mine[0]) if mine else ""
        good = bool(mine) and all(a == "." or a == b for a, b in zip(got, pt))
        ok += good
        print("planted %s -> found=%s with %s checks (settings passing: %d), %d letters forced" % (
            want, good, mine[0][0] if mine else "-", len(h), len(got) - got.count(".")))
    print("B planted recovered: %d/%d" % (ok, len(SMALL_PLANTS)))
    return hits, best, ctrl, ok


def part_c(ex):
    print("== C: one hidden alphabet ==")
    tried, surv = hidden_survivors(K4, CRIBS)
    ex.count(tried)
    st = strong(surv)
    print("K4: %d models. Consistent with >= %d checks and distinct places: %d. Consistent but undecidable "
          "(< %d checks): %d. Contradicted: %d" % (tried, HIDDEN_MIN, len(st), HIDDEN_MIN, len(surv) - len(st),
                                                    tried - len(surv)))
    for s in st:
        print("   SURVIVOR %-40s equations %2d unknowns %2d checks %d alphabets %s %s" % s)
    print("   undecidable:", "; ".join(sorted(set(s[0].split(" a=")[0][6:] for s in surv if s[3] < HIDDEN_MIN))))
    ctrl = []
    for seed in range(1, 4 if SMOKE else 21):
        ctrl.append(len(strong(hidden_survivors(shuffled_control(seed), CRIBS)[1])))
    print("shuffled K4s: survivors with >= %d checks, per control:" % HIDDEN_MIN, ctrl)
    ok = 0
    rng = random.Random(9690)
    for mode, src, d in HIDDEN_PLANTS:
        ct, cribs, want, _ = hidden_plant(rng, mode, src, d)
        sv = hidden_survivors(ct, cribs)[1]
        mine = [s for s in strong(sv) if s[0] == want]
        ok += bool(mine)
        print("planted %-36s found=%s checks=%s alphabets=%s (strong survivors in all: %d)" % (
            want, bool(mine), mine[0][3] if mine else "-", mine[0][4] if mine else "-", len(strong(sv))))
    print("C planted recovered: %d/%d" % (ok, len(HIDDEN_PLANTS)))
    return st, ctrl, ok


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("look-ahead autokey (message enciphered back to front) on a keyword tableau",
                  encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "paper tableau; start at the last letter and work backwards")})
        sys.exit(0)
    alphas = dictionary_alphabets(mixed=True)
    if SMOKE:
        alphas = alphas[:3000]
    by_name = dict(alphas)
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    with Experiment("message enciphered back to front: autokey that looks ahead (plain d 1-8, 34-48; cipher d 1-68)",
                    puzzle="k4",
                    notes="A: %d alphabets (A-Z, KRYPTOS, dictionary keyword + 2 transposition-mixed forms) x 5 layouts x "
                          "Vig/Beau x feed numbering M/AZ/KR x sign x %d (feed, d, clue shift) tests x word 1-4; "
                          "B: A-Z/KRYPTOS, multiplier 1-25, word 1-13; C: one hidden alphabet, d 1-8; exact, >=%d checks; "
                          "3 shuffled controls per part" % (len(alphas), len(TESTS), MIN_CHECKS),
                    cribs_forced=True) as ex:
        k4, ctrl, ok_a = part_a(alphas, by_name, big, ex)
        hits_b, best_b, ctrl_b, ok_b = part_b(big, ex)
        st_c, ctrl_c, ok_c = part_c(ex)
        n4, b4, e4 = summary(k4)
        cn, cb = sum(c[0] for c in ctrl), max(c[1] for c in ctrl)
        english = e4 is not None and e4 > ENGLISH
        beats = n4 > 0 and (b4 > max(cb, MIN_CHECKS) + 1 or n4 > cn + 3)
        print("VERDICT A:", "K4 beats the controls and reads as English - inspect" if beats and english else
              "K4 beats the controls on checks but does not read as English - inspect" if beats else
              "no signal (K4: %d pass, best %d checks, best English %s; three shuffled K4s: %s pass, best %d, %s)" % (
                  n4, b4, e4, [c[0] for c in ctrl], cb, [c[2] for c in ctrl]))
        print("VERDICT B:", "FIT - inspect" if len(hits_b) > max(c[0] for c in ctrl_b) else
              "no signal (K4 %d pass, near miss %d of %d; shuffled %s)" % (len(hits_b), best_b[0], best_b[1], ctrl_b))
        print("VERDICT C:", "K4 has MORE strong survivors than controls - inspect" if len(st_c) > max(ctrl_c) else
              "no signal (K4 %d strong survivors; shuffled max %d)" % (len(st_c), max(ctrl_c)))
        total = len(PLANTS) + len(SMALL_PLANTS) + len(HIDDEN_PLANTS)
        print("planted recovered in all: %d/%d" % (ok_a + ok_b + ok_c, total))
        if ok_a + ok_b + ok_c != total:
            print("WARNING: a planted answer was missed - the negative does not stand")
