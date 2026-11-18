"""Idea 122: the sentence strips were enciphered one at a time, so the key's place at BERLINCLOCK is free.

Sanborn cut the plaintext into sentence strips and handled them out of order; the Cyrillic
Projector restarts its key at each block. If each sentence was enciphered on its own, or the
sentences were enciphered in a different order than they were carved, the key runs on inside each
clue, but its place at the second clue has nothing to do with the 42 letters between the clues.
Every joint test of rounds 9-11 assumed it does (idea 68 let the gap be off by 1-3 letters only;
idea 43 let a repeating key restart, on 18 alphabets).

Here the 13 and 11 forced key letters are two separate runs, and the second run's phase is free.
Also EAST | NORTHEAST | BERLINCLOCK as three runs with two free phases. On every keyword tableau
(A-Z, KRYPTOS, the dictionary keyword alphabets and both transposition-mixed forms; five layouts;
Vigenere and Beaufort), exact tests (see kryptos/idea122_strips.py):

  repeating key L 2..16 (3 runs: 2..9), strip moved by a word (sliding) L 2..16 (3 runs: 2..9),
  plain / cipher autokey lags 1-6 with a restarting word of L letters on top, progressive key with
  a free pass count (p 1..12), two stacked words p < q <= 9 with a free phase in each word.

The carved phase (g = 0) is left out: it was tested before. A setting counts with 7 or more exact
checks (8 for autokey over three runs, where the settings are many). Survivors are read with the
break between the runs tried at every letter 34..63 and scored on the big English model.

  python attacks/122_strips_enciphered_alone.py
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea104_holes import read_score  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets, english97  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402
from kryptos import idea122_strips as S  # noqa: E402

ENGLISH = -5.1          # big-model score per quadgram a reading must beat (planted texts: about -4.3)
DECOYS = 4000 if SMOKE else 20000


def encipher(pt, m, lay, form, keyval):
    """keyval(i) -> key value at text position i."""
    plain, cipher = S.faces(lay, m)
    ia = {c: i for i, c in enumerate(plain)}
    out = []
    for i, ch in enumerate(pt):
        k = keyval(i)
        out.append(cipher[(ia[ch] + k) % 26] if form == "vig" else cipher[(k - ia[ch]) % 26])
    return "".join(out)


def plant(kind, rng, alphas):
    """(ct, cribs, name, m, wanted hit minus checks, plaintext)."""
    name, m = rng.choice(alphas[2:])
    lay = rng.choice(("M/M", "M/AZ", "AZ/M", "M/KR", "KR/M"))
    form = rng.choice(("vig", "beau"))
    pt = english97(rng)
    if kind == "repeating 9, restart at a sentence start":
        w = [rng.randrange(26) for _ in range(9)]
        s = rng.choice([x for x in range(34, 63) if x % 9])
        ct = encipher(pt, m, lay, form, lambda i: w[(i if i < s else i - s) % 9])
        want = ("repeating" if False else "rep L=9", "2", ((-s) % 9,))
    elif kind == "sliding 6, sentences enciphered in swapped order":
        w = [rng.randrange(26) for _ in range(6)]
        s = rng.randrange(34, 63)
        t_of = [97 - s + i if i < s else i - s for i in range(97)]   # second sentence first
        acc, run = [], rng.randrange(26)
        for t in range(97):
            run = (run + w[t % 6]) % 26
            acc.append(run)
        ct = encipher(pt, m, lay, form, lambda i: acc[t_of[i]])
        want = ("slide L=6", "2", ((-97) % 6,))
    elif kind == "stacked 4 + 7, both restarted":
        a, b = [rng.randrange(26) for _ in range(4)], [rng.randrange(26) for _ in range(7)]
        s = rng.choice([x for x in range(34, 63) if x % 28])
        ct = encipher(pt, m, lay, form, lambda i: (a[(i if i < s else i - s) % 4] + b[(i if i < s else i - s) % 7]) % 26)
        want = ("two stacked keys p=4 q=7", "2", ((-s) % 4, (-s) % 7))
    else:   # "repeating 7, restart at NORTHEAST and between the clues"
        w = [rng.randrange(26) for _ in range(7)]
        s = rng.choice([x for x in range(34, 63) if x % 7])
        ct = encipher(pt, m, lay, form, lambda i: w[(i if i < 25 else i - 25 if i < s else i - s) % 7])
        want = ("rep L=7", "3", ((-25) % 7, (-s) % 7))
    return ct, {i: pt[i] for i in CRIBS}, name, m, (name, lay, form) + want, pt, s


def readings(hits, by_name, ct, cribs, big, limit=300):
    out = []
    for h in sorted(hits, reverse=True)[:limit]:
        sc, nq, brk, pt = S.best_reading(h, by_name[h[1]], ct, cribs, big, read_score)
        out.append((sc, nq, brk, pt, h))
    return sorted(out, reverse=True)


def describe(h):
    return "%d checks: %s %s %s, %s, %s runs, phases %s" % (h[0], h[1], h[2], h[3], h[4], h[5], h[6])


def tally(hits):
    main = [h for h in hits if S.is_main(h)]
    return main, len(hits) - len(main)


if __name__ == "__main__":
    t0 = time.time()
    alphas = dictionary_alphabets(mixed=True)
    by_name = dict(alphas)
    per_stream, chance1, gauge_n, gauge_c1, by = S.sizes()
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    print("alphabets: %d; settings per key stream: %d (+%d gauge settings at 5-%d checks)" % (len(alphas), per_stream, gauge_n, 7))
    print("   by family:", by)
    with Experiment("strips enciphered alone: free key phase at BERLINCLOCK (and at NORTHEAST)", puzzle="k4",
                    notes="%d alphabets x 5 layouts x Vig/Beau; %d free-phase settings per key stream; repeating, "
                          "sliding L<=16, autokey+word lags 1-6, progressive p<=12, stacked p<q<=9; 2 runs and "
                          "EAST|NORTHEAST|BERLINCLOCK 3 runs; >=7 checks (8 for 3-run autokey)" % (len(alphas), per_stream),
                    cribs_forced=True) as ex:
        n_streams, hits = S.search(K4, CRIBS, alphas)
        main, ng = tally(hits)
        tested = n_streams * per_stream
        ex.count(tested)
        print("K4: %d key streams, %d exact tests (%.0f s)" % (n_streams, tested, time.time() - t0))
        print("K4: %d pass (chance predicts %.2f); gauge passes %d (chance predicts %.1f)"
              % (len(main), chance1 * n_streams, ng, gauge_c1 * n_streams))
        for h in sorted(main, reverse=True)[:20]:
            print("   ", describe(h))
        best_read = None
        if main:
            rd = readings(main, by_name, K4, CRIBS, big)
            for sc, nq, brk, pt, h in rd[:10]:
                print("   read %.3f (%d quadgrams, break %d) cov %.2f %s | %s" % (sc, nq, brk, word_coverage(pt.replace("?", "")), pt, describe(h)))
                ex.add(pt.replace("?", "X"), english_big=round(sc, 3), setting=describe(h))
            best_read = rd[0][0]
        print("K4 best reading:", best_read)

        # controls: 3 shuffled K4s, each on A-Z, KRYPTOS and a third of the alphabets
        ctrl = []
        for c in range(3):
            t1 = time.time()
            sub = alphas[:2] + alphas[2 + c::3]
            sct = shuffled_control(c + 1)
            n_c, h = S.search(sct, CRIBS, sub)
            mc, gc = tally(h)
            best = None
            if mc:
                rd = readings(mc, by_name, sct, CRIBS, big)
                best = round(rd[0][0], 3)
            ctrl.append((len(mc), gc, best))
            print("shuffled K4 seed %d on %d alphabets (%d streams): %d pass (chance %.2f), gauge %d (chance %.1f), "
                  "best reading %s  [%.0f s]" % (c + 1, len(sub), n_c, len(mc), chance1 * n_c, gc, gauge_c1 * n_c,
                                                  best, time.time() - t1))

        # planted answers
        rng = random.Random(122)
        kinds = ("repeating 9, restart at a sentence start", "sliding 6, sentences enciphered in swapped order",
                 "stacked 4 + 7, both restarted", "repeating 7, restart at NORTHEAST and between the clues")
        ok = 0
        for kind in kinds:
            ct, cribs, name, m, want, pt, s = plant(kind, rng, alphas)
            sub = [(name, m)] + rng.sample(alphas, DECOYS)
            _, h = S.search(ct, cribs, sub, chunk=500)
            mh, _ = tally(h)
            found = [x for x in mh if x[1:] == want]
            rd = readings(found, dict(sub), ct, cribs, big) if found else []
            right = sum(a == b for a, b in zip(rd[0][3], pt)) if rd else 0
            good = bool(found) and rd[0][0] > ENGLISH
            ok += good
            print("planted [%s] break %d -> found=%s (%s); passes %d (%d on the planted alphabet); read %s, break %s, %d/97 right"
                  % (kind, s, bool(found), describe(found[0]) if found else want, len(mh), sum(x[1] == name for x in mh),
                     round(rd[0][0], 3) if rd else None, rd[0][2] if rd else None, right))
            if rd:
                print("      ", rd[0][3])
            others = [x for x in mh if x[1] != name]
            if others:
                print("       decoy passes, e.g.:", "; ".join(describe(x) for x in sorted(others, reverse=True)[:3]))
        print("planted recovered: %d/%d" % (ok, len(kinds)))
        assert ok == len(kinds), "planted answer not recovered"
        cm = max(c[0] for c in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if len(main) > cm + 2 and best_read and best_read > ENGLISH else
              "no signal (K4 %d passes, best reading %s; shuffled %s)" % (len(main), best_read, ctrl))
        print("total time %.0f s" % (time.time() - t0))
