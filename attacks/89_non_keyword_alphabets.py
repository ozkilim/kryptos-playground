"""Idea 89: alphabets that are not keyword alphabets.

Every exact test so far drew its mixed alphabets from A-Z, KRYPTOS or a dictionary word
(KRYPTOSABCDEFGH...). A hand cipher can mix its alphabet in other ways, and the simple ones
can be listed:

  text orders   take a sentence and write each letter down the first time it appears (a
                keyphrase alphabet). "The answers to the first three passages contain clues to
                the fourth", so the sentences are the sculpture's own: the K1, K2, K3 plaintexts
                (as carved and with the slips corrected), the K1-K4 ciphertext, the Morse text.
                Every starting letter, forwards and backwards, stopped after 1..26 different
                letters, the unused letters appended in A-Z or Z-A order.
  fixed orders  typewriter rows and columns, Morse-code orders (the entrance slabs), letter
                frequency orders (ETAOIN and the frequencies of the sculpture's own texts).

Anything that is A-Z, KRYPTOS or a dictionary keyword alphabet (plain or transposition-mixed)
is dropped, which leaves about 140,000 alphabets. Three tests on each:

  1 battery   kryptos.round11.battery on the key values the clues force: five layouts (M/M,
              M/A-Z, A-Z/M, M/KRYPTOS, KRYPTOS/M), Vigenere and Beaufort; repeating, sliding,
              progressive, autokey, two stacked keys, chain addition; 7+ exact checks
              (5-6 checks are counted as a gauge against the shuffled texts)
  2 key text  attack 57: the 13 + 11 key letters the clues force, scored as English
              (a sentence key), 560 views per alphabet
  3 join      attack 63's hash join for a repeating key of length 1-20 with TWO alphabets:
              a new one on one side and a dictionary alphabet (667,000, incl. KRYPTOS) on the
              other, both ways round, or new on both sides. Every fit is decrypted where the
              clues fix the key and scored on the big English model.

Overlap: idea 86 already showed that for ONE unknown alphabet (the five layouts) a repeating or
sliding key fits no alphabet at all at most lengths. New here: the other key rules, the sentence
key, and the two-alphabet join.

  python attacks/89_non_keyword_alphabets.py
"""
import os
import random
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import dictionary_alphabets  # noqa: E402
from kryptos import idea89_orders as o  # noqa: E402

ENGLISH = -5.1          # big-model score a real reading reaches (planted texts: about -4.2 to -4.9)
SEEDS = (1, 2, 3)


def named(alphas, m):
    return next(n for n, a in alphas if a == m)


def bcount(hits):
    hi, lo = o.split(hits)
    return len(hi), len(lo), max((h[0] for h in hits), default=0)


def match(a, b):
    return sum(x == y for x, y in zip(a, b))


if __name__ == "__main__":
    t0 = time.time()
    new, stats = o.new_alphabets()
    dic = [("KRYPTOS", KRYPTOS_ALPHABET)] + dictionary_alphabets(mixed=True)
    N, D = len(new), len(dic)
    n_bat, n_key = N * 10, N * 560
    n_join = (2 * N * D + N * N) * 2 * o.MAX_P
    with Experiment("non-keyword alphabets: text orders, QWERTY, Morse, frequency (battery, key text, join)",
                    puzzle="k4",
                    notes="%d alphabets (%d fixed orders, %d full text orders, %d phrase orders, %d reversed) not in the "
                          "dictionary set; battery 5 layouts x Vig/Beau >=7 checks; attack 57 key-text score; attack 63 "
                          "join vs %d dictionary alphabets both ways and new x new, key length 1-%d" % (
                              N, stats["fixed"], stats["full"], stats["phrase"], stats["reversed"], D, o.MAX_P),
                    cribs_forced=True) as ex:
        print("alphabets: %d new %s; dictionary side %d" % (N, stats, D))

        # ---- tests 1 and 2: battery and key text
        hits, top = o.search(K4, CRIBS, new)
        ex.count(n_bat + n_key)
        k4b = bcount(hits)
        print("\nTEST 1 battery. K4: %d settings with 7+ checks, %d with 5-6 (of %d key streams); best %d" % (
            k4b[0], k4b[1], n_bat, k4b[2]))
        for h in sorted(hits, reverse=True)[:10]:
            print("    checks=%d %s %s %s [%s]" % h)
        print("TEST 2 key text. K4 best forced key letters (big model, 18 quadgrams):")
        for t in top[:6]:
            print("    %.3f  %s  %s  %s  %s" % t)
        ctrl_b, ctrl_k = [], []
        for seed in SEEDS:
            h, tp = o.search(shuffled_control(seed), CRIBS, new)
            ctrl_b.append(bcount(h))
            ctrl_k.append(tp[0][0])
            print("shuffled K4 #%d: battery %d with 7+, %d with 5-6, best %d; best key text %.3f %s" % (
                (seed,) + ctrl_b[-1] + (tp[0][0], tp[0][4])))
        print("   (%.0f s so far)" % (time.time() - t0))

        # ---- planted messages for tests 1 and 2
        rng = random.Random(8900)
        ok, n_plants = 0, 0
        m_k2 = o.fill(o.first_seen("ITWASTOTALLYINVISIBLE"))
        m_k3 = o.fill(o.first_seen("SLOWLYDESPARATLYSLOWLY"), o.ZA)
        qwerty = dict(o.fixed_orders())["qwerty rows"]
        etaoin = dict(o.fixed_orders())["ETAOIN SHRDLU (linotype)"]
        morse = dict(o.fixed_orders())["morse by length, dot first"]
        for label, m, p in (("K2's opening sentence + A-Z", m_k2, 7), ("morse by length", morse, 9)):
            ct, pt = o.plant_sliding(rng, m, p)
            h, _ = o.search(ct, {i: pt[i] for i in CRIBS}, new, score=False)
            want = (named(new, m), "M/M", "vig", "sliding p=%d" % p)
            found = any(x[0] >= o.MIN_CHECKS and x[1:] == want for x in h)
            ok, n_plants = ok + found, n_plants + 1
            print("planted sliding key (period %d) on %s [%s] -> found=%s (settings with 7+: %d)" % (
                p, label, want[0], found, bcount(h)[0]))
        key_ok, key_n = 0, 0
        for label, m in (("K3's opening words + Z-A", m_k3), ("ETAOIN SHRDLU", etaoin),
                         ("K2's opening sentence + A-Z", m_k2), ("QWERTY rows", qwerty)):
            ct, pt, key = o.plant_running_key(rng, m)
            _, tp = o.search(ct, {i: pt[i] for i in CRIBS}, new)
            frag = key[21:34] + "|" + key[63:74]
            rank = next((i for i, t in enumerate(tp) if t[4] == frag), None)
            found = rank is not None and rank < 3
            key_ok, key_n = key_ok + found, key_n + 1
            print("planted sentence key on %s: true key %s -> best %.3f %s; rank of truth %s; found=%s" % (
                label, frag, tp[0][0], tp[0][4], rank, found))

        # ---- test 3: the join, K4 + controls + planted in parallel
        words = [w for w, _ in dic if "~" not in w and w.isalpha()]
        w1, w2 = rng.choice(dic[1:2000]), rng.choice(dic[1:2000])
        plants = []
        for label, a, b, key in (
                ("plain QWERTY rows / cipher %s" % w1[0], qwerty, w1[1], rng.choice([w for w in words if len(w) == 9])),
                ("plain %s / cipher Morse order" % w2[0], w2[1], morse, rng.choice([w for w in words if len(w) == 11])),
                ("plain K2 opening sentence / cipher QWERTY rows", m_k2, qwerty,
                 rng.choice([w for w in words if len(w) == 12]))):
            ct, pt = o.plant_three_words(rng, a, b, key)
            plants.append((label, key, ct, pt))
        jobs = [("K4", K4, CRIBS)] + [("shuffled %d" % s, shuffled_control(s), CRIBS) for s in SEEDS] + \
               [("planted %d" % j, pl[2], {i: pl[3][i] for i in CRIBS}) for j, pl in enumerate(plants)]
        with Pool(min(len(jobs), os.cpu_count() or 2)) as pool:
            res = dict(pool.map(o.join_job, jobs, chunksize=1))
        ex.count(n_join)
        k4 = res["K4"]
        checks = o.checks_by_length()
        print("\nTEST 3 join. %d new alphabets act as %d different plain and %d different cipher alphabets on the clue "
              "letters; %d dictionary alphabets; %.1f billion alphabet pairs per key length and form" % (
                  N, k4["classes"][0], k4["classes"][1], D, (2 * N * D + N * N) / 1e9))
        print("checks per key length:", checks)
        print("K4: %d fits; by key length %s" % (k4["n"], k4["by_p"]))
        print("   best readings (score over the letters the clues decide):")
        for r in k4["top"][:10]:
            print("     ", o.reading_line(r))
        if k4["best40"]:
            print("   best with 40+ quadgrams:", o.reading_line(k4["best40"]))
        print("   fits whose key letters can be a dictionary word: %d" % len(k4["worded"]))
        for r in sorted(k4["worded"], reverse=True)[:6]:
            print("      key %s: %s" % (r[8], o.reading_line(r)))
        ctrl_j = []
        for s in SEEDS:
            r = res["shuffled %d" % s]
            ctrl_j.append(r)
            print("shuffled %d: %d fits; by key length %s; best %.2f (%d quadgrams); best with 40+: %s; word keys %d" % (
                s, r["n"], r["by_p"], r["best"][0] if r["best"] else -9, r["best"][1] if r["best"] else 0,
                "%.2f" % r["best40"][0] if r["best40"] else "none", len(r["worded"])))
        for j, (label, key, ct, pt) in enumerate(plants):
            r = res["planted %d" % j]
            b = r["best"]
            found = bool(b) and match(b[7], pt) >= 80 and b[0] > ENGLISH
            ok, n_plants = ok + found, n_plants + 1
            print("planted three words (%s, key %s) -> found=%s; fits %d; best reading %.2f, %d of 97 letters right, "
                  "key word found: %s" % (label, key, found, r["n"], b[0] if b else -9, match(b[7], pt) if b else 0,
                                          any(x[8] == key for x in r["worded"])))
        print("planted recovered: %d/%d (sliding key and three words); sentence keys ranked in the top 3: %d/%d" % (
            ok, n_plants, key_ok, key_n))

        # ---- verdict
        def sc(r, k):
            return r[k][0] if r[k] else -9.0

        flags = []
        if k4b[0] > max(c[0] for c in ctrl_b) and k4b[2] > max(c[2] for c in ctrl_b) + 1:
            flags.append("battery")
        if top[0][0] > max(ctrl_k) + 0.35:
            flags.append("key text")
        if sc(k4, "best40") > ENGLISH or sc(k4, "best") > max(sc(c, "best") for c in ctrl_j) + 0.4:
            flags.append("join")
        print("\nK4 vs shuffled: battery (7+, 5-6, best) %s vs %s; key text %.3f vs %s; join best %.2f vs %s, "
              "best with 40+ quadgrams %.2f vs %s" % (
                  k4b, ctrl_b, top[0][0], ["%.3f" % c for c in ctrl_k], sc(k4, "best"),
                  ["%.2f" % sc(c, "best") for c in ctrl_j], sc(k4, "best40"), ["%.2f" % sc(c, "best40") for c in ctrl_j]))
        print("VERDICT:", "INSPECT (%s): K4 stands out from the shuffled texts" % ", ".join(flags) if flags else
              "no signal (K4 looks like the shuffled texts in all three tests)")
        if ok != n_plants:
            print("WARNING: a planted answer was missed - the negative does not stand")
        print("total %.0f s" % (time.time() - t0))
