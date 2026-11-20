"""Idea 142: plaintext autokey 9 to 14 letters back (or ahead) with a short repeating word on top.

Scheidt: the method is simple, can be remembered, and uses key word/s. A remembered word added to the
message itself, read a worksheet-like distance back, is such a method:

    key[i] = sign * number(plaintext letter L places back, or L places ahead) + word[i mod p]
    Vigenere form:  cipher = plain + key      Beaufort form:  cipher = key - plain

Idea 100 closed this for a constant (p = 1) at lags 9-33. Idea 90 added a word of 2-4, but only at lags
7, 8 and 34-48, where two clue letters sit exactly one lag apart. At lags 9-14 almost no clue letters do,
yet the chains of idea 100 still work: with the tableau known, a clue letter and the cipher letter one lag
on give the next plaintext letter once the word letter is known. Two clue letters in one class of places
(i, i+L, i+2L, ...) are joined by a chain of 1-5 steps, and each chain is one exact equation in the word
letters:

    lag     9  10  11  12  13  14
    chains 15  14  13  12  11  11        checks left after solving a word of p letters: chains - p (7 to 13)

The word is solved from the chains, not tried 26^p times (kryptos/idea142_wordchain.py: one-step chains
give a letter at once; two three-step chains with the same letters are matched by a hash join; the rest
are checked). The solver lists every word that fits all chains, so the test is exact.

What is run
  tableaux    A-Z, KRYPTOS and every dictionary keyword alphabet in its plain and two transposition-mixed
              forms (about 667,000), five layouts (M/M, M/AZ, AZ/M, M/KR, KR/M), Vigenere and Beaufort
              form, fed letter numbered in M, A-Z or KRYPTOS, added or subtracted, look-back and look-ahead
  lags        9, 10, 11, 12, 13, 14
  word        every word of 2, 3 and 4 letters (26^p, as numbers added to the key)
  A setting passes only if ALL its chains close. Each pass is decrypted as far as the clues force it
  (90-97 letters) and read on the big English model.

Controls: three shuffled K4s, each on a different third of the alphabets (one full pass together).
Planted: six messages (lag 14 back with a word of 3, lag 11 ahead with a word of 2, and four more), each
searched among 9,000 sampled alphabets; word and alphabet must come out exactly and the text must read.

Pre-filter (--prefilter): FLAG on the K5 clue, as for every key that follows the message. Written reason
to build it anyway: the test is exact and the gap (lags 9-14 with a word) was left by ideas 90 and 100.

Not covered: lags 15 and up with a word; words of 5 or more; hidden (non-dictionary) alphabets; cipher
feed (idea 90); a word that is itself read through a mixed alphabet is covered (the word is 26^p free
numbers), but a word that changes the fed letter's alphabet is not.

  python attacks/142_autokey_lag_9_14_with_word.py            (--prefilter for the clue card)
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
from kryptos.idea142_wordchain import (DIRS, LAGS, MIN_CHECKS, PERIODS, checks, encrypt, plant, search,  # noqa: E402
                                       settings_per_alphabet, views_per_alphabet, word_text)

BIG = DATA_DIR / "english" / "quadgrams_big.txt"
# (direction, lag, word length)
PLANTS = (("back", 14, 3), ("ahead", 11, 2), ("ahead", 13, 4), ("back", 9, 4), ("back", 12, 3), ("ahead", 10, 2))
SAMPLE = 600 if SMOKE else 9000
ENGLISH = -5.1          # big-model score per quadgram that English reaches; noise sits near -6.5


def prefilter_encrypt(pt, rng):
    """Plaintext autokey 14 back plus a word of 3 on the KRYPTOS tableau; word and primer from rng."""
    word = tuple(rng.randrange(26) for _ in range(3))
    return encrypt(pt, KRYPTOS_ALPHABET, ("M/M", "vig", "M", 1, "back", 14, word), rng)


def expected(alphas):
    """Chance passes expected per (lag, word length): settings / 26^chains. An upper estimate: in views where
    the chains tie down fewer than p word letters, more of them are pure checks."""
    views = sum(views_per_alphabet(m) for _, m in alphas) * len(DIRS)
    return {(L, p): views * 26.0 ** p / 26.0 ** checks(L) for L in LAGS for p in PERIODS}


def show(rows, limit=8):
    for sc, cnt, text, name, spec in rows[:limit]:
        lay, form, fn, sign, d, L, word = spec
        print("    %s %s %s feed numbered in %s sign=%+d look-%s lag=%d word=%s (%d chains - %d = %d checks)" % (
            name, lay, form, fn, sign, d, L, word_text(word), checks(L), len(word), checks(L) - len(word)))
        print("      %s   english %.2f over %d quadgrams outside the clues, word coverage %.2f" % (
            text, sc, cnt, word_coverage(text.replace(".", ""))))


def run(ct, cribs, alphas, label):
    t0 = time.time()
    hits = search(ct, cribs, alphas, BIG)
    cells = {}
    for h in hits:
        k = (h[3],) + h[4][:6]
        cells[k] = cells.get(k, 0) + 1
    print("%s on %d alphabets (%.0f s): %d settings pass all chains, in %d (alphabet, view, lag) cells; best reading %s; "
          "at or above %.1f: %d" % (label, len(alphas), time.time() - t0, len(hits), len(cells),
                                    "%.2f" % hits[0][0] if hits else "none", ENGLISH,
                                    sum(1 for h in hits if h[0] >= ENGLISH and h[1] >= 20)))
    return hits, cells


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("plaintext autokey at lag 9-14 with a short repeating word on top, on a keyword tableau",
                  encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "paper tableau; the key is the plaintext row above plus a remembered word")})
        sys.exit(0)
    alphas = dictionary_alphabets(mixed=True)
    if SMOKE:
        alphas = alphas[:3000]
    n_set = sum(settings_per_alphabet(m) for _, m in alphas)
    with Experiment("plain autokey lag 9-14 back/ahead with a repeating word of 2-4 on top (chains)",
                    puzzle="k4",
                    notes="%d alphabets (A-Z, KRYPTOS, dictionary keyword + 2 transposition-mixed forms) x 5 layouts x "
                          "Vig/Beau x feed numbering M/AZ/KR x sign x back/ahead x lag 9-14 x every word of 2-4 letters; "
                          "exact: all 11-15 chains must close (%d+ checks after the word); controls on a third of the "
                          "alphabets each; 6 planted" % (len(alphas), MIN_CHECKS), cribs_forced=True) as ex:
        print("lags %s; chains per lag: %s; word lengths %s" % (list(LAGS), {L: checks(L) for L in LAGS}, list(PERIODS)))
        assert all(checks(L) - p >= MIN_CHECKS for L in LAGS for p in PERIODS)
        print("settings tested: %d" % n_set)
        exp = expected(alphas)
        print("chance passes expected per full pass: %s (sum %.4f)" % (
            {k: round(v, 4) for k, v in exp.items() if v >= 0.0001}, sum(exp.values())))
        hits4, cells4 = run(K4, CRIBS, alphas, "K4")
        ex.count(n_set)
        print("  K4 settings passing all chains (best reading first):")
        show(hits4, 12)
        ctrl = []
        for seed in (1, 2, 3):
            c = shuffled_control(seed)
            h, cl = run(c, CRIBS, alphas[seed - 1::3], "shuffled K4 seed %d" % seed)
            show(h, 4)
            ctrl.append((h, cl))
        ok = 0
        for j, (d, L, p) in enumerate(PLANTS):
            rng = random.Random(14200 + j)
            pool = [a for a in alphas if a[0] != "(A-Z)"]
            ct, cribs, name, spec, pt, m = plant(rng, pool, d, L, p)
            sample = rng.sample(alphas, min(SAMPLE, len(alphas)))
            if name not in {n for n, _ in sample}:
                sample.append((name, m))
            hits = search(ct, cribs, sample, BIG, chunk=250)
            mine = [r for r in hits if r[3] == name and r[4] == spec]
            others = [r for r in hits if r[3] != name]
            good = (bool(mine) and all(a == "." or a == b for a, b in zip(mine[0][2], pt)) and mine[0][0] > ENGLISH
                    and hits[0][3] == name and hits[0][4] == spec and not others)
            ok += good
            print("planted %s %s %s feed %s sign=%+d look-%s lag=%d word=%s (%d checks) -> found=%s among %d alphabets "
                  "(%d settings pass, %d on other alphabets); forced text reads %s, %d of 97 letters" % (
                      (name,) + spec[:6] + (word_text(spec[6]), checks(L) - p, good, len(sample), len(hits), len(others),
                                            "%.2f over %d quadgrams" % mine[0][:2] if mine else "n/a",
                                            97 - mine[0][2].count(".") if mine else 0)))
        print("planted recovered: %d/%d" % (ok, len(PLANTS)))
        ch = sum(len(c[0]) for c in ctrl)
        cb = max([c[0][0][0] for c in ctrl if c[0]] or [-99.0])
        b4 = hits4[0][0] if hits4 else -99.0
        eng = [h for h in hits4 if h[0] > ENGLISH and h[1] >= 20]
        if eng and b4 > cb + 0.3:
            print("VERDICT: K4 has a setting that passes and reads above the English line - inspect by hand")
        else:
            print("VERDICT: no signal (K4: %d settings in %d cells pass all chains, best reading %s; three shuffled thirds "
                  "together: %d settings in %d cells, best reading %s; English needs %.1f)" % (
                      len(hits4), len(cells4), "%.2f" % b4 if hits4 else "none", ch, sum(len(c[1]) for c in ctrl),
                      "%.2f" % cb if ch else "none", ENGLISH))
        if ok != len(PLANTS):
            print("WARNING: a planted answer was missed - the negative does not stand")
