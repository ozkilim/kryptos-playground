"""Idea 102: the encoder loses the place in the key, once, inside a clue word.

Sanborn dropped a letter carving K2, misspelled the K1 key on his own worksheet (PALIMPCEST)
and calls his work rife with mistakes. In a hand Vigenere the commonest slip is losing the
place in the key: one key letter is skipped or used twice, and every later letter is one place
off. Idea 68 moved the whole second clue by 1-3 places (a slip BETWEEN the clues) and idea 81
dropped single clue letters (one wrong letter). Neither covers a slip that falls inside
EASTNORTHEAST or BERLINCLOCK, where it breaks every periodic test on that block.

For every key stream (A-Z, KRYPTOS, every dictionary keyword alphabet and its two
transposition-mixed forms; five layouts; Vigenere and Beaufort) take the 13 key values of
clue 1 and the 11 of clue 2 and test, for a slip before any letter of a block and in either
direction (skipped / used twice):

  A   one block alone with one slip: a repeating key of length L, and a sliding key (the
      differences repeat with length L), for every L that leaves 7 or more checks
  B   both blocks: one slip inside either block and ANY key offset between the blocks (any
      number of slips, or a restart, in the 29 letters between them), L = 2..12
  C   one slip in each block, any offset between them, L = 2..12 (the plan asked for 2..8)

The sliding key is tried in two readings: the slip is in the key word (a word letter skipped or
added twice: "slide-word") or in the running key itself ("slide-stream"). Every test is exact.
The expected number of chance passes (settings x 26^-checks x key streams) is printed next to
what was found. Near misses of test A with 5 or 6 checks are also counted, only so that K4 can
be compared with the shuffled controls where chance gives something.

Anything that passes is rebuilt and decrypted (key offset before clue 1 and after clue 2 free
by -2..2, best cut between the clues) and scored on the big English model.

  python attacks/102_lost_place_in_key.py            (--prefilter for the clue card)
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea102_slip as S  # noqa: E402
from kryptos.ciphers.substitution import KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, pmap, streams  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

MIN_CHECKS = 7
LOW = 5                      # near misses of test A, for the K4-versus-controls comparison only
ENGLISH = -5.1               # big-model score per quadgram that English reaches; noise sits near -6.5
_S = {}


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]
    S._tables(LOW)


def test_alphabet(name, m, pl, cl, min_a=LOW):
    hits = []
    for lay, form, k, _, _ in streams(m, pl, cl):
        for h in S.fast_hits(k, min_a):
            hits.append((h[1], name, lay, form, h))
    return hits


def work(chunk):
    hits = []
    for name, m in chunk:
        hits += test_alphabet(name, m, _S["p"], _S["c"])
    return hits


def search(ct, cribs, alphas):
    hits = []
    for h in pmap(work, alphas, init, (ct, cribs), chunk=1000):
        hits += h
    return sorted(hits, reverse=True)


def tally(hits):
    """Counts by test: A with 7+ checks, B, C, then near misses of A (5-6 checks), then best checks."""
    a = sum(1 for h in hits if h[4][0] == "A" and h[0] >= MIN_CHECKS)
    b = sum(1 for h in hits if h[4][0] == "B")
    c = sum(1 for h in hits if h[4][0] == "C")
    near = sum(1 for h in hits if h[4][0] == "A" and h[0] < MIN_CHECKS)
    return a, b, c, near, max((h[0] for h in hits), default=0)


def read(hits, ct, cribs, by_name, big, limit):
    """Decrypt the best `limit` hits: [(big-model score, word coverage, text, unknown key letters, hit)]."""
    out = []
    for ck, name, lay, form, h in hits[:limit]:
        text, unknown = S.decrypt(ct, cribs, by_name[name], lay, form, h, big.score)
        out.append((big.score(text), word_coverage(text), text, unknown, (ck, name, lay, form, h)))
    return sorted(out, reverse=True)


def show(rows, limit=6, tag="   "):
    for sc, cov, text, unknown, (ck, name, lay, form, h) in rows[:limit]:
        print("%s%s %s %s | %s" % (tag, name, lay, form, S.describe(h)))
        print("%s   score %.2f  words %.2f  unknown key letters %d  %s" % (tag, sc, cov, unknown, text))


def prefilter_encrypt(pt, rng):
    """Repeating key of 5-10 letters on the KRYPTOS tableau; one key letter skipped at a random place."""
    L = rng.randrange(5, 11)
    w = [rng.randrange(26) for _ in range(L)]
    at = rng.randrange(1, max(2, len(pt)))
    m = KRYPTOS_ALPHABET
    return "".join(m[(m.index(ch) + w[(i + (1 if i >= at else 0)) % L]) % 26] for i, ch in enumerate(pt))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("periodic key on a keyword tableau with one place lost in the key", encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "paper tableau; a hand slip, not a design")})
        sys.exit(0)
    alphas = dictionary_alphabets(mixed=True)
    if SMOKE:
        alphas = alphas[:3000]
    by_name = dict(alphas)
    index = {name: i for i, (name, _) in enumerate(alphas)}
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    n_streams = len(alphas) * 10 - 2
    exp7, exp5 = S.expected_chance(MIN_CHECKS), S.expected_chance(LOW)
    n_settings = sum(n for n, _ in exp7.values())
    with Experiment("one place lost in the key inside a clue word: repeating and sliding keys with a slip",
                    puzzle="k4",
                    notes="%d alphabets (plain and transposition-mixed) x 5 layouts x Vigenere/Beaufort; slip "
                          "before any clue letter, key letter skipped or used twice; A one block alone, B one "
                          "slip + any offset between the blocks (L 2-12), C one slip in each block (L 2-12); "
                          "repeating, slide-word, slide-stream; >=%d checks" % (len(alphas), MIN_CHECKS),
                    cribs_forced=True) as ex:
        print("alphabets: %d; key streams: %d; settings per stream: %d; settings: %d"
              % (len(alphas), n_streams, n_settings, n_streams * n_settings))
        for t in "ABC":
            n, e = exp7[t]
            print("test %s: %d settings per stream; chance expects %.3g passes per ciphertext"
                  % (t, n, e * n_streams))
        near_n = exp5["A"][0] - exp7["A"][0]
        near_e = (exp5["A"][1] - exp7["A"][1]) * n_streams
        print("test A near misses (%d-%d checks): %d more settings per stream; chance expects %.3g per "
              "ciphertext" % (LOW, MIN_CHECKS - 1, near_n, near_e))

        hits = search(K4, CRIBS, alphas)
        ex.count(n_streams * n_settings)
        k4 = tally(hits)
        print("K4: test A %d, test B %d, test C %d settings with >= %d checks; %d near misses of test A; "
              "best %d checks" % (k4[0], k4[1], k4[2], MIN_CHECKS, k4[3], k4[4]))
        k4_rows = read(hits, K4, CRIBS, by_name, big, 40)
        show(k4_rows)
        for sc, cov, text, unknown, (ck, name, lay, form, h) in k4_rows[:10]:
            ex.add(text, alphabet=name, layout=lay, form=form, setting=S.describe(h))
        k4_best = max((r[0] for r in k4_rows), default=-9.0)

        ctrl, ctrl_best, k4_third = [], [], []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            part = alphas[seed - 1::3]
            ct = shuffled_control(seed)
            h = search(ct, CRIBS, part)
            ctrl.append(tally(h))
            rows = read(h, ct, CRIBS, by_name, big, 40)
            ctrl_best.append(max((r[0] for r in rows), default=-9.0))
            show(rows, 2, "   shuffled %d: " % seed)
            k4_third.append(tally([x for x in hits if index[x[1]] % 3 == seed - 1]))
        print("shuffled K4s, a third of the alphabets each (A, B, C, near misses, best checks):", ctrl)
        print("K4 on the same thirds:", k4_third)
        print("best big-model score of a decrypted pass or near miss: K4 %.2f; shuffled %s (English is above %.1f)"
              % (k4_best, ", ".join("%.2f" % s for s in ctrl_best), ENGLISH))

        rng = random.Random(102)
        ok = 0
        for kind in ("skip27", "double-berlin", "both", "alone"):
            ct, cribs, pt, (name, lay, form), want = S.plant(rng, alphas, kind)
            part = alphas[index[name] % 6::6]
            h = search(ct, cribs, part)
            found = [x for x in h if x[1:] == (name, lay, form, want)]
            text, good = "", 0
            if found:
                text, _ = S.decrypt(ct, cribs, by_name[name], lay, form, want, big.score)
                good = sum(1 for p, q in zip(pt, text) if p == q)
            passed = bool(found) and (good >= 90 or kind == "alone")
            ok += passed
            print("planted %s: %s %s %s | %s -> found=%s; %d/97 letters read back, score %.2f; settings "
                  "passing %d" % (kind, name, lay, form, S.describe(want), bool(found), good,
                                  big.score(text) if text else -9.0, len(h)))
        print("planted recovered: %d/4" % ok)

        full = k4[0] + k4[1] + k4[2]
        cfull = sum(c[0] + c[1] + c[2] for c in ctrl)
        signal = full > 0 and cfull == 0 and k4_best > ENGLISH
        print("VERDICT:", "K4 passes, controls do not, and the text scores as English - inspect" if signal else
              "no signal (K4: %d passes with >= %d checks, %d near misses, best score %.2f; shuffled thirds: %s)"
              % (full, MIN_CHECKS, k4[3], k4_best, ctrl))
