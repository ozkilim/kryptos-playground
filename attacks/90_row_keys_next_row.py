"""Idea 90: a worksheet row keys the next row (autokey 7, 8 or about 42 letters back).

Sanborn's K3 worksheet is 42 letters wide, and the two K4 clues start exactly 42 letters
apart. With the '?' in front, K4 is a 7 x 14 grid. If each row of the worksheet is keyed by
the row above it, the key letter for position i is the letter 7 or 42 places earlier, taken
from the plaintext or from the ciphertext, and the first clue is the key of the second:

    key[i] = word[i mod p] + sign * number(letter at i - L)

Earlier rounds tried lags 1-6 on keyword tableaux (plain feed) and gave lags 30-52 only a
quick look on A-Z / KRYPTOS. This script tests, exactly, on the clue letters:

  plain feed    lags 7 and 8 (10 and 8 clue pairs); the first clue keying the second: lags
                34..48 with the second clue moved by s = -3..3 letters, wherever 8 or more
                pairs remain (lag - s = 37..45; lag 42 in place has 11 pairs)
  cipher feed   lags 1..66 with the clues in place (24 pairs up to lag 21, 11 pairs for lags
                34..63), and lags 34..48 with the second clue moved by s = -3..3
  on top        nothing (one constant), or a repeating word of 2, 3 or 4 letters
  tableaux      A-Z, KRYPTOS and every dictionary keyword alphabet in its plain and two
                transposition-mixed forms (about 667,000), in five layouts (M/M, M/AZ, AZ/M,
                M/KR, KR/M), Vigenere and Beaufort form, fed letter numbered in M, A-Z or KRYPTOS,
                fed letter added or subtracted

A setting passes when the clue pairs agree with 7 or more independent checks
(checks = pairs - word length). Every passing setting is decrypted as far as it forces
letters and read on the big English model.

To keep the run near half an hour, K4 is tested on every alphabet, each of the three shuffled
K4s on a different third of them (so the three together make one full pass), and each planted
message on a sample of alphabets that includes its own.

Cannot decide: plain feed at lags 9-12 (5 or fewer checks) and 13-33 (no clue pairs).

  python attacks/90_row_keys_next_row.py
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402
from kryptos.idea90_rowkey import (MIN_CHECKS, TESTS, decrypt, extra_score, plant, positions,  # noqa: E402
                                   search, settings_per_alphabet)

# (feed, lag, shift of the second clue, word length, checks the planted answer must show)
PLANTS = (("plain", 42, 0, 1, 9), ("cipher", 7, 0, 1, 9), ("plain", 41, 2, 2, 7), ("cipher", 50, 0, 3, 7),
          ("plain", 7, 0, 3, 7))
SAMPLE = 600 if SMOKE else 9000
ENGLISH = -5.1          # big-model score per quadgram that English reaches; noise sits near -6.5


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
        print("    checks=%d %s %s %s feed=%s numbered in %s sign=%+d lag=%d shift=%+d word=%d %s" % (
            checks, h[1], h[2], h[3], h[6], h[4], h[5], h[7], h[8], h[9], [v for _, v in h[10]]))
        print("      %s   english %s over %d quadgrams outside the clues" % (pt, "%.2f" % sc if sc is not None else "n/a", cnt))


def summary(rows):
    best = max((r[0] for r in rows), default=0)
    eng = max((r[2] for r in rows if r[2] is not None and r[1] >= 20), default=None)
    return len(rows), best, eng


if __name__ == "__main__":
    alphas = dictionary_alphabets(mixed=True)
    if SMOKE:
        alphas = alphas[:3000]
    by_name = dict(alphas)
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    n_set = sum(settings_per_alphabet(m) for _, m in alphas)
    with Experiment("a worksheet row keys the next (autokey 7, 8, 34-48 back plain; 1-66 back cipher; word 1-4 on top)",
                    puzzle="k4",
                    notes="%d alphabets (A-Z, KRYPTOS, dictionary keyword + 2 transposition-mixed forms) x 5 layouts x "
                          "Vig/Beau x feed numbering M/AZ/KR x sign; %d (feed, lag, clue shift) tests; exact, >=%d checks; "
                          "controls on a third of the alphabets each" % (len(alphas), len(TESTS), MIN_CHECKS),
                    cribs_forced=True) as ex:
        t0 = time.time()
        k4 = read(search(K4, CRIBS, alphas), K4, CRIBS, by_name, big)
        ex.count(n_set)
        print("alphabets: %d; (feed, lag, shift) tests: %d; settings tested: %d; %.0f s" % (
            len(alphas), len(TESTS), n_set, time.time() - t0))
        print("K4: %d settings pass with >= %d checks; best checks %d; best English (20+ quadgrams) %s" % (
            (summary(k4)[0], MIN_CHECKS) + summary(k4)[1:]))
        show(k4)
        ctrl = []
        for seed in (1, 2, 3):
            part, c = alphas[seed - 1::3], shuffled_control(seed)
            rows = read(search(c, CRIBS, part), c, CRIBS, by_name, big)
            ctrl.append(summary(rows))
            print("shuffled K4 seed %d on %d alphabets: %d settings pass; best checks %d; best English %s" % (
                (seed, len(part)) + ctrl[-1]))
            show(rows, 6)
        ok = 0
        named = [a for a in alphas if a[0] != "(A-Z)"]
        for j, (src, lag, shift, p, need) in enumerate(PLANTS):
            rng = random.Random(9000 + j)
            ct, cribs, want, pt, m = plant(rng, named, src, lag, shift, p)
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
        print("planted recovered: %d/%d" % (ok, len(PLANTS)))
        n4, b4, e4 = summary(k4)
        cn, cb = sum(c[0] for c in ctrl), max(c[1] for c in ctrl)
        english = e4 is not None and e4 > ENGLISH
        beats = n4 > 0 and (b4 > max(cb, MIN_CHECKS) + 1 or n4 > 3 * cn + 3)
        print("VERDICT:", "K4 beats the controls and reads as English - inspect" if beats and english else
              "K4 beats the controls on checks but does not read as English - inspect" if beats else
              "no signal (K4: %d pass, best %d checks, best English %s; three shuffled thirds together: %d pass, best %d, %s)" % (
                  n4, b4, e4, cn, cb, [c[2] for c in ctrl]))
        if ok != len(PLANTS):
            print("WARNING: a planted answer was missed - the negative does not stand")
