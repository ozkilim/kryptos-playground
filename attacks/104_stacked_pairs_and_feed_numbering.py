"""Idea 104: close the two holes the idea-91 audit found in the key-rule battery.

Idea 91 gave 678 textbook-enciphered messages to the round 9-11 tests. Attack 66 missed 115 that
had enough checks, for two reasons. Neither says anything about K4; they say K4 was never tested
there. This attack runs K4 through both.

Hole (a): two stacked key words. The key is two repeating words of lengths p and q added
together. Attack 66 and kryptos.round11.battery first add two partial counts and drop the pair
when the sum is under 8. That drops 20 of the 41 pairs p < q <= 13 that really have 7 or more
exact checks: (3,11) (3,13) (4,11) (4,13) (5,9) (5,11) (5,12) (5,13) (6,9) (6,10) (6,11) (6,13)
(7,8) (7,9) (7,10) (7,11) (8,9) (8,10) (8,12) (9,12). Here every pair is tested exactly, with no
pre-filter (the loop test of kryptos/idea104_holes.py, equal to attack 66's mod-13 / mod-2 solve):

  base      all 41 pairs on the 24 clue letters, plus 41 pairs with a longer second word (14-45
            letters) that also have 7+ checks and were never in anyone's list
  gap       the pairs the old filter dropped when the gap between the clues is off by 1-3 (68)
  mod       the 20 dropped pairs with the arithmetic mod 27..31 (70)
  mult      the 20 dropped pairs behind a fixed multiplier 3..23 (71B)
  drop      the dropped pairs with one clue letter left out, each of the 24 in turn (81)
  breaks    the dropped pairs when word breaks use up key letters (88: 6 ways to split the clue
            words x 0-25 extra breaks between the clues)

Hole (b): the number of the fed letter. Attack 66 tested autokey only with the fed letter
numbered on the keyword alphabet M. Here it is numbered on A-Z and on KRYPTOS: that is Quagmire I
autokey as the ACA defines it (key letter found on the straight cipher strip), its mirror (found
on the plain strip), and rows picked by the A-Z labels as carved on Kryptos. Lags 1-6, plain and
cipher feed, both signs. Also a progressive key that is moved on in A-Z, KRYPTOS or M order while
it is looked up on a different cipher strip (26 index offsets, word length 1-12).

Everything runs on every dictionary keyword tableau (plain keyword alphabets and both
transposition-mixed forms), five layouts, Vigenere and Beaufort form, and needs 7 or more exact
checks. Survivors are decrypted as far as the clue letters fix the key and the letters outside
the clues are scored on the big English model.

  python attacks/104_stacked_pairs_and_feed_numbering.py            (--prefilter for the clue card)
"""
import collections
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos import idea104_holes as H  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1          # big-model score per quadgram a reading must beat (planted texts: about -4.3)
PART_OF = {"st": None, "ak": "autokey", "pg": "progressive"}


def part_of(hit):
    v = hit[5]
    if hit[6][0] != "st":
        return PART_OF[hit[6][0]]
    for word, part in (("base", "base"), ("gap", "gap"), ("clue", "gap"), ("mod", "mod"), ("multiplier", "mult"),
                       ("drop", "drop"), ("breaks", "breaks")):
        if v.startswith(word):
            return part
    raise ValueError(v)


def describe(hit):
    return "%d checks: %s %s %s, %s [%s]" % (hit[0], hit[1], hit[2], hit[3], hit[4], hit[5])


def report(tag, n_alpha, hits, sz):
    """Prints the table by part; returns {part: (7 checks, 8+ checks)}."""
    c = collections.Counter((part_of(h), min(h[0], 8)) for h in hits)
    print("%s: %d alphabets" % (tag, n_alpha))
    out = {}
    for part in H.PARTS:
        tests, chance = sz[part]
        out[part] = (c[part, 7], c[part, 8])
        print("   %-11s %15d exact tests; pass with 7 checks: %d, with 8+: %d   [chance predicts %.3f in all]"
              % (part, tests * n_alpha, c[part, 7], c[part, 8], chance * n_alpha))
    return out


def readings(hits, by_name, ct, cribs, big, limit=400):
    out = []
    for h in sorted(hits, reverse=True)[:limit]:
        pt = H.read(h, by_name[h[1]], ct, cribs)
        sc, nq = H.read_score(pt, big)
        out.append((sc, nq, pt, h))
    return sorted(out, key=lambda r: (-r[0], -r[3][0]))


def prefilter_encrypt(pt, rng):
    """For the clue pre-filter: two stacked key words of lengths (7, 9) on the KRYPTOS tableau; key from rng only."""
    a, b = [rng.randrange(26) for _ in range(7)], [rng.randrange(26) for _ in range(9)]
    kr = KRYPTOS_ALPHABET
    return "".join(kr[(kr.index(ch) + a[i % 7] + b[i % 9]) % 26] for i, ch in enumerate(pt))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("two stacked keys at the dropped length pairs / autokey numbered off the tableau", encrypt=prefilter_encrypt)
        sys.exit(0)
    dic = dictionary_alphabets(mixed=True)
    if SMOKE:
        dic = dic[:3000]
    by_name = dict(dic)
    sz = H.sizes()
    per_alpha = sum(v[0] for v in sz.values())
    with Experiment("two stacked keys at the length pairs the old pre-filter dropped; autokey and progressive key "
                    "numbered on A-Z / KRYPTOS", puzzle="k4",
                    notes="exact loop tests on the clue letters, 7+ checks, no pre-filter: stacked pairs p<q<=13 (all 41) "
                          "and 41 longer pairs; the dropped pairs under gap slack 1-3, mod 27-31, multipliers 3-23, one "
                          "clue letter left out, word breaks counted; autokey lags 1-6 fed letter numbered on A-Z or "
                          "KRYPTOS; progressive key moved on in another alphabet's order; %d keyword alphabets incl. "
                          "transposition-mixed, 5 layouts, Vigenere/Beaufort; 3 shuffled K4s on a third each" % len(dic),
                    cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        print("two stacked keys on the 24 clue letters: true number of exact checks per length pair (p, q):")
        rows = H.stacked_fn("base", 26, False)[3]
        print("   tested before (21):", " ".join("(%d,%d):%d" % (p, q, ck) for _, p, q, ck, old in rows if old))
        print("   dropped by the old pre-filter (20):", " ".join("(%d,%d):%d" % (p, q, ck) for _, p, q, ck, old in rows
                                                                 if not old and q <= H.QMAX_OLD))
        print("   longer second word, never listed (%d):" % sum(q > H.QMAX_OLD for _, p, q, ck, old in rows),
              " ".join("(%d,%d):%d" % (p, q, ck) for _, p, q, ck, old in rows if q > H.QMAX_OLD))
        for part in ("gap", "drop", "breaks", "mult"):
            lst = H.stacked_fn(part)[3]
            print("   %-6s %5d (position set, pair) tests the old filter dropped, over %d position sets; checks %d-%d"
                  % (part, len(lst), len({r[0] for r in lst}), min(r[3] for r in lst), max(r[3] for r in lst)))
        print("   mod    %5d pairs for each of N = 27..31 (the same 20)" % len(H.stacked_fn("mod", 27)[3]))

        t0 = time.time()
        hits = H.search(K4, CRIBS, dic)
        ex.count(per_alpha * len(dic))
        print("K4: %d exact tests (%d per alphabet), %.0f s" % (per_alpha * len(dic), per_alpha, time.time() - t0))
        k4c = report("K4", len(dic), hits, sz)
        done = readings(hits, by_name, K4, CRIBS, big)
        for r in done[:40]:
            print("   english %.2f over %d new quadgrams, words %.2f; %s\n      %s"
                  % (r[0], r[1], word_coverage(r[2].replace("?", "")), describe(r[3]), r[2]))
            ex.add(r[2].replace("?", "X"), english_big=round(r[0], 3), setting=describe(r[3]))
        k4_best = max((r[0] for r in done), default=-99.0)
        k4_unread = sum(r[0] == -99.0 for r in done)
        print("K4: %d survivors with %d+ checks; best reading %.2f (English needs %.1f); %d cannot be read "
              "(fewer than %d new quadgrams)" % (len(hits), H.MIN_CHECKS, k4_best, ENGLISH, k4_unread, H.MIN_NEW))

        ctrl = []
        for seed in (1, 2, 3):
            sct = shuffled_control(seed)
            part = dic[:2] + dic[2:][seed - 1::3]
            ch = H.search(sct, CRIBS, part)
            report("shuffled K4 seed %d" % seed, len(part), ch, sz)
            cd = readings(ch, by_name, sct, CRIBS, big)
            for r in cd[:5]:
                print("   english %.2f over %d new quadgrams; %s" % (r[0], r[1], describe(r[3])))
            ctrl.append((len(ch), sum(h[0] >= 8 for h in ch), max((r[0] for r in cd), default=-99.0), len(part)))

        # planted answers 1: the idea-91 audit (textbook encryptors, no shared code) pointed at this test
        smap = H.audit_stacked_map()
        judged = [r for r in smap if r[2] >= H.MIN_CHECKS]
        print("idea-91 map of two stacked keys, this idea's test alone: %d of %d length pairs with %d+ checks found "
              "(2 textbook messages each, %d of %d messages; idea 91 had 21 of 41 with attack 66); the %d pairs with "
              "fewer checks: %d messages listed; loop test accepts the true key with the right count at %d of %d pairs"
              % (sum(r[3] == 2 for r in judged), len(judged), H.MIN_CHECKS, sum(r[3] for r in judged), 2 * len(judged),
                 len(smap) - len(judged), sum(r[3] for r in smap if r[2] < H.MIN_CHECKS),
                 sum(r[4] == r[2] for r in smap), len(smap)))
        map_ok = sum(r[3] == 2 for r in judged) == len(judged) == 41
        recs = H.audit_cells(2 if SMOKE else 6)
        tab = collections.OrderedDict()
        for r in recs:
            kind = r["model"].split(" [")[0]
            row = tab.setdefault(kind, [0, 0, 0])
            row[0] += 1
            row[1] += r["status"] == "found"
            row[2] += r["status"] == "HOLE"
        print("idea-91 cells for attack 66 (73 models), judged by attack 66 plus this idea's tests:")
        for kind, row in tab.items():
            print("   %-58s planted %3d found %3d missed %d" % (kind, row[0], row[1], row[2]))
        a_found, a_all = sum(r["status"] == "found" for r in recs), len(recs)
        print("   all: %d of %d found (idea 91 had 323 of 438 with attack 66 alone)" % (a_found, a_all))

        # planted answers 2: inside a sample of the dictionary, with the reading
        rng = random.Random(104)
        sample = dic[::5 if SMOKE else 40]
        ok = 0
        for kind in H.PLANTS:
            ct, cribs, name, m, want, pt = H.plant(kind, rng, dic)
            alphas = sample if (name, m) in sample else sample + [(name, m)]
            h = H.search(ct, cribs, alphas)
            mine = [x for x in h if x[1] == name and x[2:6] == want]
            rd = readings(h, by_name, ct, cribs, big)
            slack = 1 if kind == "drop" else 0           # the wrongly given clue letter itself
            bad = [r for r in rd if sum(a != b and a != "?" for a, b in zip(r[2], pt)) > slack]
            best_bad = max([r[0] for r in bad] or [-99.0])
            good = no_reading = False
            if mine:
                text = H.read(mine[0], m, ct, cribs)
                sc, nq = H.read_score(text, big)
                right = sum(a == b for a, b in zip(text, pt))
                wrong = sum(a != b and a != "?" for a, b in zip(text, pt))
                no_reading = nq < H.MIN_NEW          # the clue letters fix too little of the key to read
                good = wrong <= slack and (no_reading or (sc > ENGLISH and sc > best_bad))
            ok += good
            print("planted %-22s %s %s %s [%s] on %s -> %s; %d settings pass in %d alphabets (%d read wrongly)%s"
                  % (kind, want[0], want[1], want[2], want[3], name,
                     ("FOUND" + (" (exact test only, too little to read)" if no_reading else "")) if good else "MISSED",
                     len(h), len(alphas), len(bad),
                     "" if not mine else "; %d checks, %d of 97 letters read (%d wrong), english %.2f over %d new quadgrams, "
                     "best wrong reading %.2f" % (mine[0][0], right, wrong, sc, nq, best_bad)))
        print("planted recovered: %d/%d in the dictionary sample; idea-91 stacked map %s; idea-91 cells %d/%d"
              % (ok, len(H.PLANTS), "41/41" if map_ok else "NOT 41/41", a_found, a_all))

        share = [c[3] / float(len(dic)) for c in ctrl]
        more = all(len(hits) * sh > c[0] + 3 * (c[0] ** 0.5) + 3 for sh, c in zip(share, ctrl))
        reads = k4_best > ENGLISH and k4_best > max(c[2] for c in ctrl) + 0.3
        print("VERDICT:", ("K4 beats every control - inspect; " if (more or reads) else "no signal; ") +
              "K4 %d tests pass with %d+ checks (%d with 8+), best reading english %.2f; shuffled K4s on %s of the "
              "alphabets: %s pass with %d+ (%s with 8+), best readings %s (English needs %.1f; -99 = nothing to read)"
              % (len(hits), H.MIN_CHECKS, sum(h[0] >= 8 for h in hits), k4_best, ["%.2f" % s for s in share],
                 [c[0] for c in ctrl], H.MIN_CHECKS, [c[1] for c in ctrl], ["%.2f" % c[2] for c in ctrl], ENGLISH))
