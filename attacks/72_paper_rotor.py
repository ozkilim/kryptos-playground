"""Idea 72: a paper rotor with hidden wiring, turned by a key word.

A rotor is a scrambled wiring R between two ordinary alphabets that turns between letters:

    C = R[P + s] - s          (s = how far the rotor has turned)

This is not a shifted alphabet and not linear in a hidden alphabet, so none of the earlier
exact tests see it. Other people tested rotors that turn at a constant speed. Here the turn
comes from a key word, as a hand cipher would do it.

The test needs no guess about the wiring. Each clue letter gives one wire: input P + s goes to
output C + s. A real wiring never sends one input to two outputs or two inputs to one output.
24 wires on a 26-contact rotor collide about 8 times, so a wrong setting survives with chance
about 26^-8. Settings whose wires happen to collide fewer than 5 times (6 for exhaustive keys)
cannot be judged and are not counted; that is about 1 true setting in 20.

  turning rules   s = a*i in and b*i out (all 676 speed pairs)
                  s = key word letter (A-Z or KRYPTOS numbering), repeating; the same with the
                      running sum of the word (sliding), or with one extra step per letter
                  s = the previous cipher or plain letter; the running sum of the cipher text
                  every key of length 1..6 over all 26 letters (not just words)
  in/out          rotor turns the same way on both faces, or opposite ways
  alphabets       A-Z or KRYPTOS on each face

  python attacks/72_paper_rotor.py
"""
import itertools
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import B1, B2, POS, SMOKE, english97, pmap, vocabulary  # noqa: E402

ALPH = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
MIN_CHECKS = 5      # word and fixed rules; exhaustive keys need one more
KMAX = 3 if SMOKE else 6
_S = {}


def wires(pv, cv, s, sign):
    """Number of forced coincidences if the wires (P+s -> C+sign*s) form a real wiring, else -1."""
    f, g = {}, {}
    for x, y, t in zip(pv, cv, s):
        u, v = (x + t) % 26, (y + sign * t) % 26
        if f.setdefault(u, v) != v or g.setdefault(v, u) != u:
            return -1
    return len(pv) - len(f)


def views(ct, cribs):
    out = []
    for an, a in ALPH.items():
        for bn, b in ALPH.items():
            out.append(("pt%s/ct%s" % (an, bn), [a.index(cribs[i]) for i in POS], [b.index(ct[i]) for i in POS]))
    return out


def fixed_rules(ct, cribs):
    """Constant speeds and letter-fed turning. Returns (tests, hits)."""
    hits, n = [], 0
    for vn, pv, cv in views(ct, cribs):
        for a in range(26):
            for b in range(26):
                n += 1
                f, g, ok = {}, {}, True
                for x, y, i in zip(pv, cv, POS):
                    u, v = (x + a * i) % 26, (y + b * i) % 26
                    if f.setdefault(u, v) != v or g.setdefault(v, u) != u:
                        ok = False
                        break
                if ok and 24 - len(f) >= MIN_CHECKS:
                    hits.append((24 - len(f), vn, "speeds in %d out %d" % (a, b)))
        for nn, num in ALPH.items():
            cum, t = [], 0
            for ch in ct:
                cum.append(t)
                t += num.index(ch)
            feeds = {"previous cipher letter (%s)" % nn: [num.index(ct[i - 1]) for i in POS],
                     "running sum of cipher text (%s)" % nn: [cum[i] for i in POS]}
            for fn, s in feeds.items():
                for sign in (1, -1):
                    n += 1
                    ck = wires(pv, cv, s, sign)
                    if ck >= MIN_CHECKS:
                        hits.append((ck, vn, "%s, out %+d" % (fn, sign)))
            # previous plain letter: unknown for the first letter of each clue, so drop those two
            idx = [j for j, i in enumerate(POS) if i - 1 in cribs]
            s = [num.index(cribs[POS[j] - 1]) for j in idx]
            for sign in (1, -1):
                n += 1
                ck = wires([pv[j] for j in idx], [cv[j] for j in idx], s, sign)
                if ck >= MIN_CHECKS:
                    hits.append((ck, vn, "previous plain letter (%s), out %+d" % (nn, sign)))
    return n, hits


def init(ct, cribs):
    _S["v"] = views(ct, cribs)


def work_words(chunk):
    hits = []
    for w in chunk:
        p = len(w)
        for nn, num in ALPH.items():
            vals = [num.index(ch) for ch in w]
            plain = [vals[i % p] for i in POS]
            run, t, at = {}, 0, set(POS)
            for i in range(74):
                t += vals[i % p]
                if i in at:
                    run[i] = t
            schemes = (("word", plain), ("sliding word", [run[i] for i in POS]),
                       ("word + 1 per letter", [vals[i % p] + i for i in POS]))
            for sn, s in schemes:
                for vn, pv, cv in _S["v"]:
                    for sign in (1, -1):
                        ck = wires(pv, cv, s, sign)
                        if ck >= MIN_CHECKS:
                            hits.append((ck, vn, "%s %s (%s numbering), out %+d" % (sn, w, nn, sign)))
    return hits


def work_keys(chunk):
    """Every key of a given length; the first key letter is fixed at 0 (a constant only renames the wires)."""
    hits = []
    for p, head in chunk:
        slot = [i % p for i in POS]
        for tail in itertools.product(range(26), repeat=p - len(head)):
            key = head + tail
            s = [key[r] for r in slot]
            for vn, pv, cv in _S["v"]:
                for sign in (1, -1):
                    ck = wires(pv, cv, s, sign)
                    if ck >= MIN_CHECKS + 1:
                        hits.append((ck, vn, "key %s, out %+d" % ("".join(AZ[x] for x in key), sign)))
    return hits


def search(ct, cribs, words):
    n, hits = fixed_rules(ct, cribs)
    for h in pmap(work_words, words, init, (ct, cribs), chunk=3000):
        hits += h
    n += len(words) * 2 * 3 * 8
    jobs = [(1, (0,))]
    for p in range(2, KMAX + 1):
        jobs += [(p, (0, a)) for a in range(26)] if p < 5 else [(p, (0, a, b)) for a in range(26) for b in range(26)]
        n += 26 ** (p - 1) * 8
    for h in pmap(work_keys, jobs, init, (ct, cribs), chunk=4):
        hits += h
    return n + 8, hits


def encrypt(pt, wiring, s, sign=1):
    return "".join(AZ[(wiring[(AZ.index(ch) + t) % 26] - sign * t) % 26] for ch, t in zip(pt, s))


def plant(rng, words, kind):
    pt = english97(rng)
    wiring = list(range(26))
    rng.shuffle(wiring)
    if kind == "word":
        w = rng.choice([x for x in words if 5 <= len(x) <= 9])
        s = [AZ.index(w[i % len(w)]) for i in range(97)]
        want = "word %s (AZ numbering), out +1" % w
    else:
        key = [0] + [rng.randrange(26) for _ in range(2)]
        s = [key[i % 3] for i in range(97)]
        want = "key %s, out +1" % "".join(AZ[x] for x in key)
    return encrypt(pt, wiring, s), {i: pt[i] for i in CRIBS}, want


if __name__ == "__main__":
    words = sorted(set(w for w in vocabulary() if 2 <= len(w) <= 22))
    if SMOKE:
        words = words[:8000]
    with Experiment("paper rotor: hidden wiring between two alphabets, turned by a key word", puzzle="k4",
                    notes="wire-collision test (no wiring guessed); 676 constant speed pairs, letter-fed turning, "
                          "%d words x 3 schemes x 2 numberings, every key of length 1-%d; A-Z/KRYPTOS faces"
                          % (len(words), KMAX), cribs_forced=True) as ex:
        n, hits = search(K4, CRIBS, words)
        ex.count(n)
        best = max((h[0] for h in hits), default=0)
        print("rotor settings tested: %d" % n)
        print("K4: %d settings give a real wiring with >= %d forced coincidences; best %d" % (len(hits), MIN_CHECKS, best))
        for h in sorted(hits, reverse=True)[:15]:
            print("   checks=%d %s %s" % h)
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            h = search(shuffled_control(seed), CRIBS, words)[1]
            ctrl.append((len(h), max((x[0] for x in h), default=0)))
        print("shuffled K4s (settings passing, best checks):", ctrl)
        rng = random.Random(72)
        ok = 0
        for kind in ("word", "key", "word"):
            ct, cribs, want = plant(rng, words, kind)
            h = search(ct, cribs, words)[1]
            found = any(x[1] == "ptAZ/ctAZ" and x[2] == want for x in h)
            ok += found
            print("planted rotor, %s -> found=%s (settings passing %d)" % (want, found, len(h)))
        print("planted recovered: %d/3" % ok)
        cb = max(c[1] for c in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if hits and best > cb + 1 else
              "no signal (K4 %d settings, best %d; shuffled %s)" % (len(hits), best, ctrl))
