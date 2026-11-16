"""Idea 66: K1/K2's machine with ANY dictionary keyword, against a battery of hand key rules.

K1 and K2 are a keyword tableau (KRYPTOS) plus a key rule (a repeating word). Round 9 tested
many key rules, but almost only on the A-Z and KRYPTOS tableaux. Scheidt says K4 runs "with the
correct key word/s", so the tableau keyword may simply be a different word. This runs a battery
of exact key-rule tests on EVERY dictionary keyword tableau (plain keyword alphabets and the two
transposition-mixed forms: ~667,000 alphabets), in five layouts (M/M, M/A-Z, A-Z/M, M/KRYPTOS,
KRYPTOS/M), Vigenere and Beaufort.

The battery (each is an exact test on the clue letters, 7 or more independent checks to count):
  repeating      key repeats with period p = 1..17                       (sanity; known dead)
  SLIDING        each key letter says how far to MOVE the strip from where it is, so the
                 key is the running sum of a repeating word: K_i - K_{i-1} repeats (p = 1..15).
                 New: a natural hand habit that destroys the period.
  progressive    key word shifted by a fixed step every cycle (p = 1..12)
  autokey        shift = +-(position of the plaintext or ciphertext letter L places back) + c,
                 position taken in M, lags 1..6
  word restart   key index goes back to 0 at each word (EAST|NORTHEAST, BERLIN|CLOCK)
  chain          K_i = K_{i-n} + K_{i-m}, taps up to 6
  TWO STACKED    two repeating key words added together (lengths p < q <= 13): LAYER TWO on any
                 keyword tableau. Rounds 3 and 8 did this on the A-Z and KRYPTOS tableaux only.
  growing key    the key word restarts after 1, 2, 3, ... letters

  python attacks/66_keyword_tableau_battery.py
"""
import os
import random
import sys
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
MIN_CHECKS = 7
B1, B2 = list(range(21, 34)), list(range(63, 74))
POS = B1 + B2
WORD_SLOT = [0, 1, 2, 3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4]
_S = {}


def mixes(word):
    m = keyword_alphabet(word)
    yield "", m
    u = []
    for ch in word:
        if ch not in u:
            u.append(ch)
    w = len(u)
    if w < 3:
        return
    cols = [m[c::w] for c in range(w)]
    yield "~cols", "".join(cols)
    yield "~keyed", "".join(cols[c] for c in sorted(range(w), key=lambda c: u[c]))


def alphabets():
    seen, out = {AZ}, [("(A-Z)", AZ)]
    vocab = ["KRYPTOS"] + wordkeys.theme_words() + wordkeys.common_words() + wordkeys.big_dictionary()
    for w in vocab:
        if 3 <= len(w) <= 22:
            for tag, m in mixes(w):
                if m not in seen:
                    seen.add(m)
                    out.append((w + tag, m))
        if SMOKE and len(out) >= 9000:
            break
    return out


def periodic(vals, poss, pmax):
    """Largest number of checks over periods 1..pmax with equal slots -> equal values, else 0."""
    best = (0, 0)
    n = len(vals)
    for p in range(1, pmax + 1):
        seen = {}
        ok = True
        for v, i in zip(vals, poss):
            r = i % p
            if r in seen:
                if seen[r] != v:
                    ok = False
                    break
            else:
                seen[r] = v
        if ok and n - len(seen) > best[0]:
            best = (n - len(seen), p)
    return best


def _tri_slots():
    out = []
    for i in POS:
        n = 0
        while (n + 1) * (n + 2) // 2 <= i:
            n += 1
        out.append(i - n * (n + 1) // 2)
    return out


TRI_SLOT = _tri_slots()


def _diffs(k, lag):
    """[(position, K[i+lag] - K[i])] for pairs inside one clue block."""
    out = [(POS[j], (k[j + lag] - k[j]) % 26) for j in range(13 - lag)]
    out += [(POS[j], (k[j + lag] - k[j]) % 26) for j in range(13, 24 - lag)]
    return out


def _residue_checks(d, q):
    seen = {}
    for i, v in d:
        if seen.setdefault(i % q, v) != v:
            return -1
    return len(d) - len(seen)


def _stacked_exact(k, p, q):
    from kryptos.round9 import solve_mod_p
    rows = []
    for i in POS:
        v = [0] * (p + q)
        v[i % p] = 1
        v[p + i % q] = 1
        rows.append(v)
    s13, s2 = solve_mod_p(rows, k, 13), solve_mod_p(rows, k, 2)
    if s13 is None or s2 is None:
        return -1
    return 24 - (p + q - len(s13[1]))


def battery(k, xp, xc):
    """k: 24 key values (clue order). xp/xc: positions of the clue plaintext/cipher letters in M
    (for autokey). Returns [(checks, rule)] with checks >= MIN_CHECKS."""
    out = []
    # repeating
    c, p = periodic(k, POS, 17)
    if c >= MIN_CHECKS:
        out.append((c, "repeating p=%d" % p))
    # sliding: differences repeat
    d = [(k[j] - k[j - 1]) % 26 for j in range(1, 13)] + [(k[j] - k[j - 1]) % 26 for j in range(14, 24)]
    dp = POS[1:13] + POS[14:24]
    c, p = periodic(d, dp, 15)
    if c >= MIN_CHECKS:
        out.append((c, "sliding p=%d" % p))
    # progressive: K[i+p] - K[i] is one constant for all pairs p apart; cross-block via step*cycles
    for p in range(1, 13):
        s = (k[p] - k[0]) % 26
        ok = True
        for j in range(13 - p):
            if (k[j + p] - k[j]) % 26 != s:
                ok = False
                break
        if not ok:
            continue
        for j in range(13, 24 - p):
            if (k[j + p] - k[j]) % 26 != s:
                ok = False
                break
        if not ok:
            continue
        # cross-block: positions 21+j and 63+m with same residue differ by step * (cycles apart)
        seen = {}
        for v, i in zip(k, POS):
            base = (v - s * (i // p)) % 26
            if seen.setdefault(i % p, base) != base:
                ok = False
                break
        if ok and 24 - len(seen) >= MIN_CHECKS:
            out.append((24 - len(seen), "progressive p=%d step=%d" % (p, s)))
    # autokey
    for name, x in (("plain", xp), ("cipher", xc)):
        for lag in range(1, 7):
            for b in (1, -1):
                c0 = (k[lag] - b * x[0]) % 26
                ok = True
                for j in range(lag, 13):
                    if (k[j] - b * x[j - lag]) % 26 != c0:
                        ok = False
                        break
                if not ok:
                    continue
                for j in range(13 + lag, 24):
                    if (k[j] - b * x[j - lag]) % 26 != c0:
                        ok = False
                        break
                if ok and 24 - 2 * lag - 1 >= MIN_CHECKS:
                    out.append((24 - 2 * lag - 1, "autokey %s lag=%d sign=%+d" % (name, lag, b)))
    # word restart
    seen, ok = {}, True
    for v, s in zip(k, WORD_SLOT):
        if seen.setdefault(s, v) != v:
            ok = False
            break
    if ok:
        out.append((24 - len(seen), "key restarts at each word"))
    # two stacked repeating keys (lengths p < q <= 13, q not a multiple of p): K = A[i mod p] + B[i mod q].
    # Then K[i+p] - K[i] depends only on i mod q, and K[i+q] - K[i] only on i mod p. Quick necessary
    # test here; hits are confirmed by a full linear solve.
    for p in range(2, 13):
        dp = _diffs(k, p)
        for q in range(p + 1, 14):
            if q % p == 0:
                continue
            c1 = _residue_checks(dp, q)
            if c1 < 0:
                continue
            c2 = _residue_checks(_diffs(k, q), p)
            if c2 < 0 or c1 + c2 < MIN_CHECKS + 1:
                continue
            ck = _stacked_exact(k, p, q)
            if ck >= MIN_CHECKS:
                out.append((ck, "two stacked keys p=%d q=%d" % (p, q)))
    # growing key: the key word restarts after 1, 2, 3, ... letters (K, KR, KRY, ...)
    seen, ok = {}, True
    for v, s in zip(k, TRI_SLOT):
        if seen.setdefault(s, v) != v:
            ok = False
            break
    if ok:
        out.append((24 - len(seen), "growing key (restart after 1,2,3,... letters)"))
    # chain addition
    for m in range(2, 7):
        for n in range(1, m):
            ok = True
            for j in list(range(m, 13)) + list(range(13 + m, 24)):
                if (k[j - n] + k[j - m] - k[j]) % 26:
                    ok = False
                    break
            if ok and 24 - 2 * m >= MIN_CHECKS:
                out.append((24 - 2 * m, "chain taps %d,%d" % (n, m)))
    return out


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]


def test_alphabet(name, m, pl, cl):
    iz = {c: i for i, c in enumerate(AZ)}
    ik = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    im = {c: i for i, c in enumerate(m)}
    xp, xc = [im[c] for c in pl], [im[c] for c in cl]
    hits = []
    for lay, ia, ib in (("M/M", im, im), ("M/AZ", im, iz), ("AZ/M", iz, im), ("M/KR", im, ik), ("KR/M", ik, im)):
        a, b = [ia[c] for c in pl], [ib[c] for c in cl]
        for form, k in (("vig", [(y - x) % 26 for x, y in zip(a, b)]), ("beau", [(y + x) % 26 for x, y in zip(a, b)])):
            for ck, rule in battery(k, xp, xc):
                hits.append((ck, name, lay, form, rule))
    return hits


def work(chunk):
    pl, cl = _S["p"], _S["c"]
    hits = []
    for name, m in chunk:
        hits += test_alphabet(name, m, pl, cl)
    return len(chunk), hits


def search(ct, cribs, alphas, procs=None):
    chunks = [alphas[i:i + 2000] for i in range(0, len(alphas), 2000)]
    hits = []
    with Pool(procs, initializer=init, initargs=(ct, cribs)) as pool:
        for _, h in pool.imap_unordered(work, chunks):
            hits += h
    return hits


def plant(rng, alphas, rule):
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    name, m = rng.choice(alphas)
    im = {c: i for i, c in enumerate(m)}
    p = rng.randrange(5, 10) if rule != "stacked" else rng.randrange(4, 7)
    word = [rng.randrange(26) for _ in range(p)]
    word2 = [rng.randrange(26) for _ in range(p + 3)]
    ct, k = [], 0
    for i, ch in enumerate(pt):
        if rule == "stacked":
            k = (word[i % p] + word2[i % (p + 3)]) % 26
        elif rule == "sliding":
            k = (k + word[i % p]) % 26
        else:   # autokey on the previous plaintext letter
            k = (im[pt[i - 1]] + 3) % 26 if i else 5
        ct.append(m[(im[ch] + k) % 26])
    return "".join(ct), {i: pt[i] for i in CRIBS}, name, ("sliding p=%d" % p if rule == "sliding" else
                                                     "two stacked keys p=%d q=%d" % (p, p + 3) if rule == "stacked" else "autokey plain lag=1 sign=+1")


if __name__ == "__main__":
    alphas = alphabets()
    n_tests = len(alphas) * 5 * 2
    with Experiment("every dictionary keyword tableau x battery of key rules (sliding, stacked, progressive, autokey, restart, chain)",
                    puzzle="k4", notes="%d alphabets (keyword + 2 transposition mixes) x 5 layouts x Vigenere/Beaufort; "
                    "exact tests, >=%d checks" % (len(alphas), MIN_CHECKS), cribs_forced=True) as ex:
        hits = search(K4, CRIBS, alphas)
        ex.count(n_tests)
        best = max((h[0] for h in hits), default=0)
        print("alphabets: %d; key streams tested: %d" % (len(alphas), n_tests))
        print("K4: %d (alphabet, layout, rule) settings pass with >= %d checks; best %d" % (len(hits), MIN_CHECKS, best))
        for h in sorted(hits, reverse=True)[:15]:
            print("   checks=%d %s %s %s %s" % h)
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3, 4):
            h = search(shuffled_control(seed), CRIBS, alphas)
            ctrl.append((len(h), max((x[0] for x in h), default=0)))
        print("shuffled K4s (settings passing, best checks):", ctrl)
        rng = random.Random(31)
        ok = 0
        for rule in ("sliding", "autokey", "stacked", "stacked"):
            ct, cribs, name, want = plant(rng, alphas, rule)
            h = search(ct, cribs, alphas)
            found = any(x[1] == name and x[2] == "M/M" and x[4] == want for x in h)
            ok += found
            print("planted %s on %s -> found=%s (settings %d, best checks %d)" % (want, name, found, len(h), max((x[0] for x in h), default=0)))
        print("planted recovered: %d/4" % ok)
        cb = max(c[1] for c in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if best > cb + 1 else
              "no signal (K4 best checks %d, %d settings; shuffled best %d, settings %s)" % (best, len(hits), cb, [c[0] for c in ctrl]))
