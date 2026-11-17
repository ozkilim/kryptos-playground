"""Idea 100: plaintext autokey at a long lag (9 to 33 letters back, or ahead), decided by chains.

Bean measured repeated vertical pairs at width 21, both clue blocks start a row of 21, and the K3
worksheet rows are 42 wide. A row keyed by the row above is a plaintext autokey at a long lag:

    key[i] = sign * number(plaintext letter L places back, or L places ahead) + c
    Vigenere form:  cipher = plain + key      Beaufort form:  cipher = key - plain

Ideas 90 and 96 wrote that plain feed at lags 9-33 cannot be decided, because no (or few) clue
letters sit exactly one lag apart. That misses chains. With the tableau known, a known plaintext
letter and the cipher letter one lag further on give the next plaintext letter, and the other way
round. So every clue letter fixes its whole class of positions (i, i+L, i+2L, ...) and wherever a
class holds two clue letters we get one exact check:

    lag     9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 | 24 25 26 27 28 29 30 31 32 33
    checks 15 14 13 12 11 11  9  8  7  7  9 11 11  9  7 |  5  3  1  0  0  0  1  2  3  4
    forced 97 97 97 97 97 90 97 97 97 91 75 65 65 69 73 | 77 81 85 86 84 82 76 70 64 58  (of 97 letters)

What is run
  tableaux    A-Z, KRYPTOS and every dictionary keyword alphabet in its plain and two
              transposition-mixed forms (about 667,000), five layouts (M/M, M/AZ, AZ/M, M/KR, KR/M),
              Vigenere and Beaufort form, fed letter numbered in M, A-Z or KRYPTOS, added or subtracted,
              look-back and look-ahead
  lags 9-23   (7+ checks) every constant c = 0..25; a setting passes only if ALL its checks hold
  lags 24-33  a setting that passes the checks it has is decrypted as far as the clues force it and
              read on the big English model. First a cheap gate: of the two runs forced directly next
              to the clues (12 and 11 letters) one must look English and the other must not be
              hopeless; whatever passes is decrypted in full (58-86 letters) and scored.
              c: every value where a check exists (lags 24-26, 30-33: c is solved from the check).
              Lags 27, 28, 29 have no check: all 26 values of c on A-Z, KRYPTOS and the plain keyword
              alphabets (220,318), c = 0 only on the transposition-mixed alphabets (446,675).

Controls: three shuffled K4s, each on a different third of the alphabets (one full pass together).
Planted: six messages (lag 21 back, lag 13 ahead, lag 17 back, lag 24 ahead; lag 28 back with c = 0 and
lag 27 ahead with any c have no check and must be found by their English score alone).

Pre-filter (--prefilter): FLAG on the K5 clue, as for every key that follows the message. Written
reason to build it anyway: the test is exact, and the scope limit stated by ideas 90 and 96 is wrong.

Not covered: a repeating word on top of the autokey; hidden (non-dictionary) alphabets; lags 27-29
with c other than 0 on the transposition-mixed alphabets.

  python attacks/100_long_lag_autokey_chains.py            (--prefilter for the clue card)
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers.substitution import KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets  # noqa: E402
from kryptos.score import word_coverage  # noqa: E402
from kryptos.idea100_chains import (DIRS, FREE, HIGH, KEEP, LAGS, LOW, MIN_CHECKS, checks, encrypt, numberings,  # noqa: E402
                                    plant, search, settings_per_alphabet)

BIG = DATA_DIR / "english" / "quadgrams_big.txt"
# (direction, lag, c or None for random, must the alphabet be a plain keyword alphabet)
PLANTS = (("back", 21, None, False), ("ahead", 13, None, False), ("back", 17, None, False),
          ("ahead", 24, None, False), ("back", 28, 0, False), ("ahead", 27, None, True))
SAMPLE = 600 if SMOKE else 9000
ENGLISH = -5.1          # big-model score per quadgram that English reaches; noise sits near -6.5


def prefilter_encrypt(pt, rng):
    """Plaintext autokey 21 back on the KRYPTOS tableau; constant and primer from rng."""
    return encrypt(pt, KRYPTOS_ALPHABET, ("M/M", "vig", "M", 1, "back", 21, rng.randrange(26)), rng)


def allc_names(alphas):
    return {n for n, _ in alphas if "~" not in n}


def expected(alphas):
    """Chance passes expected per lag with 7+ checks: settings / 26^checks."""
    views = 0
    for _, m in alphas:
        plain, feeds = numberings(m)
        views += sum(len(cn) for _, cn in plain) * 2 * len(feeds) * 2 * len(DIRS)
    return {L: views * 26 / 26.0 ** checks(L) for L in HIGH}


def show(rows, limit=8):
    for sc, cnt, text, name, spec in rows[:limit]:
        print("    %s %s %s feed numbered in %s sign=%+d look-%s lag=%d c=%d (%d checks)" % ((name,) + spec + (checks(spec[5]),)))
        print("      %s   english %.2f over %d quadgrams outside the clues, word coverage %.2f" % (
            text, sc, cnt, word_coverage(text.replace(".", ""))))


def run(ct, cribs, alphas, label):
    t0 = time.time()
    hits, low, nlow = search(ct, cribs, alphas, allc_names(alphas), BIG)
    by_lag = {L: sum(1 for h in hits if h[4][5] == L) for L in HIGH}
    best_low = low[0][0] if low else None
    print("%s on %d alphabets (%.0f s): lags %d-%d: %d settings pass all checks %s; lags %d-%d: %d settings passed the "
          "English gate and were read in full, best %s, at or above %.1f: %d" % (
              label, len(alphas), time.time() - t0, HIGH[0], HIGH[-1], len(hits), {L: n for L, n in by_lag.items() if n},
              LOW[0], LOW[-1], nlow, "%.2f" % best_low if low else "none above %.1f" % KEEP, ENGLISH,
              sum(1 for r in low if r[0] >= ENGLISH)))
    return hits, low, nlow


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("long-lag plaintext autokey (a row keyed by the row above) on a keyword tableau",
                  encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "paper tableau; the key row is the plaintext row above")})
        sys.exit(0)
    alphas = dictionary_alphabets(mixed=True)
    if SMOKE:
        alphas = alphas[:3000]
    names = allc_names(alphas)
    n_set = sum(settings_per_alphabet(m, n in names) for n, m in alphas)
    with Experiment("long-lag plain autokey decided by chains (lags 9-33, look-back and look-ahead)",
                    puzzle="k4",
                    notes="%d alphabets (A-Z, KRYPTOS, dictionary keyword + 2 transposition-mixed forms) x 5 layouts x "
                          "Vig/Beau x feed numbering M/AZ/KR x sign x back/ahead x lag 9-33 x c; lags 9-23 exact (%d+ checks); "
                          "lags 24-33 read on the big English model; lags 27-29 all c on %d plain keyword alphabets, c=0 on "
                          "the mixed ones; controls on a third of the alphabets each" % (
                              len(alphas), MIN_CHECKS, len(names)), cribs_forced=True) as ex:
        print("lags %s; checks per lag: %s" % (list(LAGS), {L: checks(L) for L in LAGS}))
        print("settings tested: %d; lags without any check: %s" % (n_set, list(FREE)))
        exp = expected(alphas)
        print("chance passes expected per full pass at lags with %d+ checks: %s (sum %.2f)" % (
            MIN_CHECKS, {L: round(v, 3) for L, v in exp.items() if v >= 0.0005}, sum(exp.values())))
        hits4, low4, n4 = run(K4, CRIBS, alphas, "K4")
        ex.count(n_set)
        print("  K4 settings passing all checks:")
        show(hits4, 12)
        print("  K4 best readings at lags %d-%d:" % (LOW[0], LOW[-1]))
        show(low4, 6)
        ctrl = []
        for seed in (1, 2, 3):
            c = shuffled_control(seed)
            h, lo, n = run(c, CRIBS, alphas[seed - 1::3], "shuffled K4 seed %d" % seed)
            show(h, 4)
            show(lo, 2)
            ctrl.append((h, lo, n))
        ok = 0
        for j, (d, L, c, plain_only) in enumerate(PLANTS):
            rng = random.Random(10000 + j)
            pool = [a for a in alphas if a[0] != "(A-Z)" and not (plain_only and "~" in a[0])]
            ct, cribs, name, spec, pt, m = plant(rng, pool, d, L, c)
            sample = rng.sample(alphas, min(SAMPLE, len(alphas)))
            if name not in {n for n, _ in sample}:
                sample.append((name, m))
            hits, low, nlow = search(ct, cribs, sample, allc_names(sample), BIG, chunk=300)
            rows = hits if checks(L) >= MIN_CHECKS else low
            mine = [r for r in rows if r[3] == name and r[4] == spec]
            good = bool(mine) and all(a == "." or a == b for a, b in zip(mine[0][2], pt)) and mine[0][0] > ENGLISH
            if checks(L) < MIN_CHECKS:                       # must come out on top by its English score
                good = good and rows[0][3] == name and rows[0][4] == spec
            ok += good
            print("planted %s %s (%d checks) -> found=%s among %d alphabets (%d pass all checks, %d low-lag readings); "
                  "forced text reads %s" % (name, spec, checks(L), good, len(sample), len(hits), nlow,
                                            "%.2f over %d quadgrams" % mine[0][:2] if mine else "n/a"))
        print("planted recovered: %d/%d" % (ok, len(PLANTS)))
        ch = sum(len(c[0]) for c in ctrl)
        cb = max([c[1][0][0] for c in ctrl if c[1]] or [-99.0])
        b4 = low4[0][0] if low4 else -99.0
        eng_hits = [h for h in hits4 if h[0] > ENGLISH and h[1] >= 20]
        if eng_hits or (b4 > ENGLISH and b4 > cb + 0.3):
            print("VERDICT: K4 has a setting that passes and reads above the English line - inspect by hand")
        else:
            print("VERDICT: no signal (K4: %d pass all checks at lags %d-%d, none reads as English; best low-lag reading %.2f. "
                  "Three shuffled thirds together: %d pass, best low-lag reading %.2f. English needs %.1f)" % (
                      len(hits4), HIGH[0], HIGH[-1], b4, ch, cb, ENGLISH))
        if ok != len(PLANTS):
            print("WARNING: a planted answer was missed - the negative does not stand")
