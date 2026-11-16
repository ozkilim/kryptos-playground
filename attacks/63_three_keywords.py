"""Idea 63: three remembered key words. Quagmire IV with two keyword alphabets and a key word.

Scheidt (2011, via Bean): K4's cipher is like what was "provided agents or pilots in case of
capture": "simple, can be remembered", run years later "with the correct key word/s". K1 and K2
already use one keyword alphabet (KRYPTOS) and one key word. The natural harder version of the
same machine uses THREE words: one mixes the plain alphabet, one mixes the cipher alphabet, one
is the repeating key (the ACA's Quagmire IV). With a key of 14-24 letters it is as flat as K4.

Earlier work covered one keyword alphabet at a time, or pairs from a ~90-word theme list. All
pairs of dictionary alphabets is 220,000^2 = 48 billion per key length, too many to try one by
one. But the test splits in two. For key length p, clue positions in the same key slot must
share a shift:

    x2[C_a] - x2[C_b] = x1[P_a] - x1[P_b]          (x1, x2 = positions in the two alphabets)

The left side depends only on the cipher alphabet, the right only on the plain alphabet. So we
compute each side once per alphabet and match them through a hash table: exact, and the whole
48 billion pairs take minutes. Beaufort form (signs flipped, = reversed cipher alphabet) too.

Alphabets: every dictionary word as a plain keyword alphabet and as the two usual
transposition-mixed alphabets (about 600,000 per side, 360 billion pairs per key length).

Key lengths 1-24 (5 to 23 independent checks each; 25 and 26 leave too few to list matches).
Every match is decrypted where the key is known and scored; we also ask whether the key letters
it implies can be a dictionary word.

  python attacks/63_three_keywords.py
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
from kryptos.score import quadgram_score  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
MAX_P = 24
_ALPHAS = None
_WORDS = None


def alphabets():
    global _ALPHAS
    if _ALPHAS is None:
        seen, out = {AZ, KRYPTOS_ALPHABET}, [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)]
        vocab = wordkeys.theme_words() + wordkeys.common_words() + wordkeys.big_dictionary()
        for w in vocab:
            if 3 <= len(w) <= 22:
                for tag, m in mixes(w):
                    if m not in seen:
                        seen.add(m)
                        out.append((w + tag, m))
                if SMOKE and len(out) >= 6000:
                    break
        _ALPHAS = out
    return _ALPHAS


def words_by_length():
    global _WORDS
    if _WORDS is None:
        _WORDS = {}
        for w in set(wordkeys.theme_words() + wordkeys.common_words() + wordkeys.big_dictionary()):
            if w.isalpha():
                _WORDS.setdefault(len(w), []).append(w)
    return _WORDS


def mixes(word):
    """The keyword alphabet, plus the two transposition-mixed alphabets from the same word
    (write the keyword alphabet in rows under the keyword, read the columns left to right, or
    in alphabetical order of the keyword's letters): the standard hand ways to mix an alphabet."""
    m = keyword_alphabet(word)
    yield "", m
    if os.environ.get("KRYPTOS_NOMIX"):
        return
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


def groups(pos, p):
    """Clue positions sharing a key slot, as lists of indexes into `pos` (only slots with 2+)."""
    g = {}
    for k, i in enumerate(pos):
        g.setdefault(i % p, []).append(k)
    return [v for v in g.values() if len(v) > 1]


def search(ct, cribs, alphas=None):
    """All (p, form, plain alphabet id, cipher alphabet id) consistent with the clues, p = 1..MAX_P."""
    alphas = alphas or alphabets()
    pos = sorted(cribs)
    xp = [bytes(m.index(cribs[i]) for i in pos) for _, m in alphas]
    xc = [bytes(m.index(ct[i]) for i in pos) for _, m in alphas]
    out = []
    for p in range(1, MAX_P + 1):
        gs = groups(pos, p)
        pairs = [(g[0], k) for g in gs for k in g[1:]]
        table = {}
        for a, v in enumerate(xp):
            table.setdefault(bytes((v[k] - v[r]) % 26 for r, k in pairs), []).append(a)
        for b, v in enumerate(xc):
            sig = bytes((v[k] - v[r]) % 26 for r, k in pairs)
            for a in table.get(sig, ()):
                out.append((p, "vig", a, b))
            neg = bytes((v[r] - v[k]) % 26 for r, k in pairs)
            for a in table.get(neg, ()):
                out.append((p, "beau", a, b))
    return out


def decrypt(ct, cribs, p, form, m1, m2):
    """Plaintext where the key slot is fixed by a clue ('.' elsewhere), and the shifts by slot."""
    shift = {}
    for i, pl in cribs.items():
        c, x = m2.index(ct[i]), m1.index(pl)
        shift[i % p] = (c - x) % 26 if form == "vig" else (c + x) % 26
    out = []
    for i, ch in enumerate(ct):
        s = shift.get(i % p)
        if s is None:
            out.append(".")
        else:
            c = m2.index(ch)
            out.append(m1[(c - s) % 26] if form == "vig" else m1[(s - c) % 26])
    return "".join(out), shift


def known_score(pt):
    """Mean quadgram score over the stretches of plaintext we could decrypt."""
    runs = [r for r in pt.split(".") if len(r) >= 4]
    n = sum(len(r) - 3 for r in runs)
    return sum(quadgram_score(r) * (len(r) - 3) for r in runs) / n if n else -9.0


def key_is_word(shift, p, m1, m2):
    """Could the implied key (letters named on A-Z with any offset, or on either alphabet) be a word?"""
    words = words_by_length().get(p, [])
    if not words:
        return None
    namings = [AZ[c:] + AZ[:c] for c in range(26)] + [m1, m2]
    for alpha in namings:
        pat = [alpha[shift[j]] if j in shift else None for j in range(p)]
        for w in words:
            if all(c is None or c == w[j] for j, c in enumerate(pat)):
                return w
    return None


def analyse(ct, cribs):
    alphas = alphabets()
    hits = search(ct, cribs, alphas)
    by_p = {}
    best = (-9.0, None)
    worded, short = [], []
    for p, form, a, b in hits:
        by_p[p] = by_p.get(p, 0) + 1
        if len(hits) > 40000 and p >= 24 and by_p[p] > 20000:
            continue
        pt, shift = decrypt(ct, cribs, p, form, alphas[a][1], alphas[b][1])
        sc = known_score(pt)
        if sc > best[0]:
            best = (sc, (p, form, alphas[a][0], alphas[b][0], pt))
        if p <= 23:
            short.append((p, form, alphas[a][0], alphas[b][0], round(sc, 2), pt))
        if p >= 5 and by_p[p] <= 3000:
            w = key_is_word(shift, p, alphas[a][1], alphas[b][1])
            if w:
                worded.append((p, form, alphas[a][0], alphas[b][0], w, round(sc, 2), pt))
    return {"n": len(hits), "by_p": by_p, "best": best, "worded": worded, "short": short}


def plant(rng):
    from kryptos import load
    from kryptos.data import letters
    alphas = alphabets()
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    (w1, m1), (w2, m2) = rng.choice(alphas[2:]), rng.choice(alphas[2:])
    key = rng.choice([w for L in range(9, 20) for w in words_by_length().get(L, [])[:400]])
    ct = "".join(m2[(m1.index(ch) + m2.index(key[i % len(key)])) % 26] for i, ch in enumerate(pt))
    return ct, {i: pt[i] for i in CRIBS}, (w1, w2, key), pt


def job(args):
    kind, ct, cribs = args
    return kind, analyse(ct, cribs)


if __name__ == "__main__":
    rng = random.Random(21)
    plants = [plant(rng) for _ in range(3)]
    jobs = [("K4", K4, CRIBS)] + [("shuffled %d" % s, shuffled_control(s), CRIBS) for s in (1, 2, 3)] + \
           [("planted %d" % k, pl[0], pl[1]) for k, pl in enumerate(plants)]
    n_alpha = len(alphabets())
    with Experiment("three key words: Quagmire IV with two dictionary alphabets (exact hash join)", puzzle="k4",
                    notes="%d keyword alphabets on each side x Vigenere/Beaufort x key length 1-%d; matches "
                          "decrypted and key tested as a dictionary word" % (n_alpha, MAX_P), cribs_forced=True) as ex:
        with Pool(min(7, os.cpu_count() or 2)) as pool:
            res = dict(pool.map(job, jobs))
        ex.count(n_alpha * n_alpha * 2 * MAX_P)
        k4 = res["K4"]
        print("alphabets per side: %d (%.1f billion pairs per key length and form)" % (n_alpha, n_alpha ** 2 / 1e9))
        print("K4: %d consistent (length, form, alphabet pair) settings; by key length: %s" % (k4["n"], dict(sorted(k4["by_p"].items()))))
        if k4["best"][1]:
            print("   best partial decrypt %.2f: %s" % (k4["best"][0], k4["best"][1]))
        print("   every setting with key length <= 23 (7+ checks):")
        for sh in sorted(k4["short"], key=lambda x: -x[4])[:25]:
            print("      p=%d %s %s / %s  score %.2f  %s" % sh)
        print("   settings whose key letters can be a dictionary word: %d" % len(k4["worded"]))
        for w in sorted(k4["worded"], key=lambda x: -x[5])[:8]:
            print("     ", w)
        ctrl_best = []
        for s in (1, 2, 3):
            r = res["shuffled %d" % s]
            ctrl_best.append(r["best"][0])
            print("shuffled %d: %d settings; by key length %s; best decrypt %.2f; word keys %d (best %s)" % (
                s, r["n"], dict(sorted(r["by_p"].items())), r["best"][0], len(r["worded"]),
                max((w[5] for w in r["worded"]), default=None)))
        ok = 0
        for k, pl in enumerate(plants):
            r = res["planted %d" % k]
            w1, w2, key = pl[2]
            found = any(x[2] == w1 and x[3] == w2 or x[4] == key for x in r["worded"]) or \
                (r["best"][1] and sum(a == b for a, b in zip(r["best"][1][4], pl[3])) >= 80)
            ok += bool(found)
            print("planted %s/%s key %s (length %d) -> found=%s; settings %d; best decrypt %.2f" % (
                w1, w2, key, len(key), bool(found), r["n"], r["best"][0]))
        print("planted recovered: %d/3" % ok)
        k4w = max((w[5] for w in k4["worded"]), default=-9)
        print("VERDICT:", "INSPECT: K4 decrypt beats controls" if k4["best"][0] > max(ctrl_best) + 0.4 or k4w > -4.6 else
              "no signal (K4 best decrypt %.2f; shuffled %s)" % (k4["best"][0], ["%.2f" % c for c in ctrl_best]))
