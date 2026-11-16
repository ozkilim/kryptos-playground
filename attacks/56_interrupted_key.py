"""Idea 56: the interrupted key. A short key that RESTARTS whenever a trigger letter turns up.

This is a classical hand cipher (the ACA's "Interrupted Key"): encipher with a key word, but jump
back to its first letter every time a chosen letter appears in the plaintext (or ciphertext),
or at each new word. The restarts break the period, so period tests see nothing, yet the
method is a small change to K1/K2's own system: a "change in the methodology" a sculptor could
do by hand. Earlier rounds tested restarts at sentence breaks and carved rows, not at letters
or words.

Inside the clues we know every letter, so we know exactly where the restarts fall. For each
rule we give every clue position a key-slot number and ask that equal slots need equal key
letters. Unknowns: the key length L (1-26) and where in the key each clue block starts (if no
restart has yet happened inside the block).

  triggers   restart AFTER or AT plaintext letter X, or ciphertext letter X (any X), or at each word
  ciphers    Vigenere / Beaufort / variant on A-Z and KRYPTOS (plain and cipher side independently)
  alphabets  plus the theme-word keyword alphabets on both sides (Quagmire III style)

"checks" = clue letters minus distinct key slots. Survivors need at least 5 checks.

  python attacks/56_interrupted_key.py
"""
import os
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import BLOCKS, WORDS, keyword_alphabet, shuffled_control  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
MIN_CHECKS = 5
WORD_STARTS = {w[0] for w in WORDS}


def alphabet_pairs():
    base = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
    for an, a in base.items():
        for bn, b in base.items():
            yield an + "/" + bn, a, b
    words = wordkeys.theme_words()
    for w in (words[:5] if SMOKE else words):
        m = keyword_alphabet(w)
        if m not in (AZ, KRYPTOS_ALPHABET):
            yield w + "/" + w, m, m


def triggers(ct, cribs):
    """Yield (name, set of clue positions where the key index is 0), one set per rule."""
    yield "word starts", set(WORD_STARTS)
    for x in AZ:
        for src, text in (("plain", cribs), ("cipher", {i: ct[i] for i in cribs})):
            hit = {i for i in cribs if text[i] == x}
            if not hit:
                continue   # no restart inside the clues: this is a plain repeating key (dead)
            yield "at %s %s" % (src, x), hit
            after = {i + 1 for i in hit if i + 1 in cribs}
            if after:
                yield "after %s %s" % (src, x), after


def block_fits(blk, zero, L, key):
    """Every consistent slot->key map for one clue block (one per unknown starting index).
    Positions before the block's first restart run on from an unknown index."""
    out = []
    starts = [0] if blk[0] in zero else range(L)
    for s0 in starts:
        m, j, ok = {}, s0, True
        for i in blk:
            if i in zero:
                j = 0
            s = j % L
            if m.setdefault(s, key[i]) != key[i]:
                ok = False
                break
            j += 1
        if ok:
            out.append(m)
    return out


def best_checks(zero, L, key):
    """Most checks over all consistent ways to place the two blocks, or -1."""
    f1 = block_fits(BLOCKS[0], zero, L, key)
    if not f1:
        return -1
    f2 = block_fits(BLOCKS[1], zero, L, key)
    best = -1
    for m1 in f1:
        for m2 in f2:
            if all(m1.get(s, k) == k for s, k in m2.items()):
                best = max(best, 24 - len(set(m1) | set(m2)))
    return best


def search(ct, cribs):
    tried, hits = 0, []
    trig = list(triggers(ct, cribs))
    for aname, a, b in alphabet_pairs():
        ia = {c: i for i, c in enumerate(a)}
        ib = {c: i for i, c in enumerate(b)}
        keys = {"vig": {i: (ib[ct[i]] - ia[cribs[i]]) % 26 for i in cribs},
                "beau": {i: (ib[ct[i]] + ia[cribs[i]]) % 26 for i in cribs}}
        for tname, zero in trig:
            for L in range(1, 27):
                for cname, key in keys.items():
                    tried += 1
                    ck = best_checks(zero, L, key)
                    if ck >= MIN_CHECKS:
                        hits.append((ck, aname, cname, tname, L))
    return tried, hits


def plant(rng):
    """Vigenere on KRYPTOS, key restarts after every plaintext T."""
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    key = "".join(rng.choice(AZ) for _ in range(rng.randrange(6, 11)))
    trig = rng.choice("ETAON")
    a = KRYPTOS_ALPHABET
    ct, j = [], 0
    for p in pt:
        ct.append(a[(a.index(p) + a.index(key[j % len(key)])) % 26])
        j = 0 if p == trig else j + 1
    return "".join(ct), {i: pt[i] for i in CRIBS}, ("KR/KR", "vig", "after plain " + trig, len(key))


if __name__ == "__main__":
    with Experiment("interrupted key (restart at a trigger letter or at each word)", puzzle="k4",
                    notes="key length 1-26, restart at/after plaintext or ciphertext letter X or word starts; "
                          "A-Z/KRYPTOS + theme keyword alphabets; exact slot consistency", cribs_forced=True) as ex:
        tried, hits = search(K4, CRIBS)
        ex.count(tried)
        print("K4: %d rules tested, %d survive with >= %d checks" % (tried, len(hits), MIN_CHECKS))
        for h in sorted(hits, reverse=True)[:12]:
            print("   checks=%d %s %s %s L=%d" % h)
        ctrl = []
        for seed in range(1, 4 if SMOKE else 11):
            _, h = search(shuffled_control(seed), CRIBS)
            ctrl.append((len(h), max((x[0] for x in h), default=0)))
        print("shuffled K4s (survivors, best checks):", ctrl)
        rng = random.Random(4)
        ok = 0
        for _ in range(5):
            ct, cribs, truth = plant(rng)
            _, h = search(ct, cribs)
            found = any(x[1:] == truth or (x[1:4] == truth[:3] and x[4] % truth[3] == 0) for x in h)
            ok += found
            print("planted %s -> found=%s (survivors %d, best checks %d)" % (
                truth, found, len(h), max((x[0] for x in h), default=0)))
        print("planted recovered: %d/5" % ok)
        best = max((x[0] for x in hits), default=0)
        cbest = max(c[1] for c in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if best > cbest else
              "no signal (K4 best checks %d, %d survivors; shuffled best %d, survivors %s)" % (
                  best, len(hits), cbest, [c[0] for c in ctrl]))
