"""Idea 106: each K4 letter counts WORDS through the solved K1-K3 text (a prisoner letter code).

Scheidt compared K4 to the ciphers given to agents and pilots in case of capture: simple, not
mathematical, kept in the head. The letter codes taught to air crews hid a message in an ordinary
text; the reader found it by counting words. Sanborn: the first three answers hold clues to the
fourth, and the solver needs "just to be able to read". Idea 85 counted LETTERS through the
sculpture's text and found nothing (and found that a 26-letter window can hardly hold English).
This idea counts words.

The solver holds a text that is on the sculpture, cut into words. Each K4 letter is a number
(its place in A-Z or in the KRYPTOS alphabet). The number picks a word; one letter of that word
(first, second, third, fourth or last) is the plaintext.

  W (walk)    move on that many words from the last word used
  B (window)  word number = start + a*i + value                     (i = place in K4)
  C (pairs)   one K4 letter gives the word number, its neighbour the letter number in the word

  texts      K1, K2, K3 plaintexts, alone and joined in order, and the Morse text; spelling as
             carved or corrected; X (and K3's closing Q) as words or dropped; K2 ending ID BY ROWS
             or X LAYER TWO. 56 word lists.
  counting   A-Z or KRYPTOS numbering, counted forwards or backwards, extra advance a = -30..30
             words per letter. Numbering from 0 or 1 and reading the text backwards are inside
             this sweep (a = 0 or +-1 is the plain rule). Every start word; ring and line.

Every setting of W and B fixes all 97 letters, so the test is exact: count the clue letters that
come out right. A hit is 24 of 24 (or 22-23 with a readable rest). Rule C in its plain form halves
the message, so no clue position applies to it; it is tested (a) with overlapping pairs, which keep
97 places, (b) as a count of how many clue letters can be reached at all, and (c) by looking for
the clue words in the halved readings.

Controls: 20 shuffled K4s through the same search. Planted: messages written so that the rule can
encode them (words drawn so that every next letter is reachable), found at 24/24 and read back.

  python attacks/106_word_counts_through_k1_k3.py            (--prefilter for the clue card)
"""
import random
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import fingerprint as FP  # noqa: E402
from kryptos import wordkeys  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE  # noqa: E402
from kryptos.score import Quadgrams, ioc, word_coverage  # noqa: E402
from kryptos import idea106_words as M  # noqa: E402

MAIN = "K1-K3 (as carved, X kept, ID BY ROWS)"
ENGLISH = -5.1          # big-model score per quadgram that English reaches; noise sits near -6.5

PLANTS = [  # rule, text, pick, numbering, sign, advance, ring
    ("W", MAIN, "1", "AZ", 1, 1, True),                                         # the plain A=1..Z=26 walk, first letters
    ("W", "K1-K3 (corrected, X dropped, LAYER TWO)", "last", "KR", 1, 0, True),  # walk on last letters
    ("B", MAIN, "1", "AZ", 1, 7, True),                                         # window that moves 7 words a letter
    ("B", "K1-K3 (corrected, X kept, LAYER TWO)", "3", "KR", -1, 1, False),     # window on a line, third letters
    ("W", "K3 (as carved, X kept, ID BY ROWS)", "1", "AZ", 1, -12, False),      # walk on a line (drifts slowly)
]
C_PLANT = (MAIN, 1, "AZ", 1, 3, ("KR", 1, True, False))     # overlapping pairs, letter number wraps round the word


def vocab():
    return [w for w in wordkeys.common_words()[:4000] if 2 <= len(w) <= 9]


def plant(rng, spec, T, words):
    """Write a message the rule can encode, encode it; (ct, clue letters, message, start)."""
    rule, tname, pick, an, sgn, a, ring = spec
    text = M.line(T[tname], pick)
    L = len(text)
    for _ in range(400):
        s = rng.randrange(L)
        pt = M.compose(rng, text, rule, a, s, words, sgn, ring, tries=3)
        if not pt:
            continue
        ct = M.encode(pt, text, rule, M.ALPHAS[an], a, s, rng, sgn, ring)
        if ct and (ring or "?" not in M.read(ct, text, rule, an, sgn, a, s, False)):
            return ct, {i: pt[i] for i in CRIBS}, pt, s
    raise RuntimeError("could not plant %r" % (spec,))


def check_plant(spec, ct, cribs, pt, s, TL, serial=False):
    """(best clue count, settings at 24, planted setting found at 24/24 and read back)."""
    rule, tname, pick, an, sgn, a, ring = spec
    r = M.search(ct, cribs, TL, serial=serial)
    ti = M.canon(TL)[[n for n, _ in TL].index(tname), pick]      # the first list with the same line of letters
    text = M.line(TL[ti][1], pick)
    hit = (24, rule, ti, pick, an, sgn, a, s) in r["tops"]
    m = r["best"][rule, "ring" if ring else "line"][0]
    return m, sum(t[0] == 24 for t in r["tops"]), m == 24 and hit and M.read(ct, text, rule, an, sgn, a, s, ring) == pt


def plant_c(rng, T, vocabulary):
    tname, e, an, sgn, a, mode = C_PLANT
    words = T[tname]
    for t in range(1, 201):
        s = rng.randrange(len(words))
        pt = M.compose_c(rng, words, a, s, mode, vocabulary, M.ALPHAS[an], sgn, tries=2)
        ct = pt and M.encode_c(pt, words, e, M.ALPHAS[an], a, s, mode, rng, sgn)
        if ct:
            return ct, {i: pt[i] for i in CRIBS}, pt, s, t
    raise RuntimeError("could not plant rule C")


def check_plant_c(ct, cribs, pt, s, TL, serial=False):
    tname, e, an, sgn, a, mode = C_PLANT
    r = M.search_c(ct, cribs, TL, serial=serial)
    ti = [n for n, _ in TL].index(tname)
    back = M.c_read(ct, TL[ti][1], e, an, sgn, a, s, mode)
    hit = (24, ti, e, an, sgn, a, s, mode) in r["tops"]
    return r["top"], sum(t[0] == 24 for t in r["tops"]), hit and back[:-1] == pt[:-1]


def summary(res):
    b = res["best"]
    return "W ring %d line %d plain %d; B ring %d line %d plain %d" % (
        b["W", "ring"][0], b["W", "line"][0], b["W", "plain"][0], b["B", "ring"][0], b["B", "line"][0], b["B", "plain"][0])


def tails(res, rules="BW"):
    return ", ".join(">=%d: %d" % (k, M.tail(res, k, rules)) for k in (9, 10, 11, 12, 13))


def prefilter_encrypt(pt, rng):
    """Rule B, first letters of K1-K3, start and advance from rng, nearest word. A letter that no
    word in the window starts with cannot be encoded; it is written as itself (marked in the card)."""
    text = M.line(dict(M.word_texts(full=False))[MAIN], "1")
    s, a = rng.randrange(len(text)), rng.randrange(0, 31)
    out = []
    for i, p in enumerate(pt):
        c = [d for d in range(26) if text[(s + a * i + d) % len(text)] == p]
        out.append(M.AZ[c[0]] if c else p)
    return "".join(out)


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("word count through K1-K3 (window rule, first letters)", encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "count words with a finger; nothing to compute")})
        sys.exit(0)
    TL = M.word_texts()
    T = dict(TL)
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    with Experiment("K4 letters count words through K1-K3 (walk, window, pairs)", puzzle="k4",
                    notes="%d word lists (K1, K2, K3, joins, Morse; carved/corrected, X kept/dropped, both K2 endings) x "
                          "letter 1-4 or last of the word x A-Z/KRYPTOS numbering x count forwards/backwards x advance "
                          "-%d..%d x every start, ring and line; rules W (walk), B (window), C (pairs, overlapping); "
                          "20 shuffled controls" % (len(TL), M.A_MAX, M.A_MAX), cribs_forced=True) as ex:
        print("word lists: %d (%d words in all; longest %d words); distinct lines of letters for rules W and B: %d"
              % (len(TL), sum(len(w) for _, w in TL), max(len(w) for _, w in TL),
                 sum(ti == k[0] for k, ti in M.canon(TL).items())))
        tot = {an: sum(al.index(c) + 1 for c in K4) for an, al in M.ALPHAS.items()}
        print("K4 as counts from 1: %d words in all (A-Z), %d (KRYPTOS): a plain walk on a line needs a text that long, "
              "so the plain walk only works on a ring" % (tot["AZ"], tot["KR"]))

        print("how many of the 24 clue letters each text can produce at all (letter 1 / 2 / 3 / 4 / last of a word):")
        shown = set()
        for name, words in TL:
            if name.split(" (")[0] in shown:
                continue
            shown.add(name.split(" (")[0])
            pr = M.producible(words)
            print("   %-46s %3d words   %s" % (name, len(words), " / ".join("%d" % pr[p] for p in M.PICKS)))
        allp = [M.producible(w) for _, w in TL]
        print("   over all %d lists: %s" % (len(TL), " / ".join("%d-%d" % (min(p[k] for p in allp), max(p[k] for p in allp))
                                                                 for k in M.PICKS)))
        for pick in ("1", "last"):
            c = Counter(M.line(T[MAIN], pick))
            print("   %s letters of %s: %s; missing %s" % ("first" if pick == "1" else "last", MAIN,
                  " ".join("%s%d" % kv for kv in c.most_common()), "".join(x for x in M.AZ if x not in c) or "none"))

        # ---- rules W and B
        res = M.search(K4, CRIBS, TL)
        ex.count(res["n"])
        print("rules W and B: %d settings; mean clue letters per setting: W %.2f, B %.2f of 24"
              % (res["n"], M.mean(res["hist"]["W"]), M.mean(res["hist"]["B"])))
        print("K4 best clue letters:", summary(res))
        for k, b in sorted(res["best"].items()):
            ti, pick, an, sgn, a, s = b[1]
            print("   rule %s %-5s %d/24  [%s, letter %s, %s, count %+d, a=%d, start %d]"
                  % (k[0], k[1], b[0], TL[ti][0], pick, an, sgn, a, s))
        print("K4 settings with W: %s | B: %s" % (tails(res, "W"), tails(res, "B")))
        full = []
        for c, rule, ti, pick, an, sgn, a, s in res["tops"]:
            pt = M.read(K4, M.line(TL[ti][1], pick), rule, an, sgn, a, s)
            full.append((c, big.score(pt.replace("?", "X")), pt, rule, TL[ti][0], pick, an, sgn, a, s))
        print("best full readings (clue letters, big-model English score, word coverage):")
        for c, q, pt, rule, name, pick, an, sgn, a, s in sorted(full, reverse=True)[:6]:
            ex.add(pt.replace("?", "X"), rule=rule, text=name, letter=pick, numbering=an, sign=sgn, advance=a, start=s)
            print("   %d/24  %.2f  %.2f  %s  [rule %s, %s, letter %s, %s, %+d, a=%d, s=%d]"
                  % (c, q, word_coverage(pt.replace("?", "X")), pt, rule, name, pick, an, sgn, a, s))
        best_eng = max(full, key=lambda x: x[1]) if full else None
        if best_eng:
            print("   most English-looking of the %d kept (>=%d clue letters): %.2f (%d/24) %s"
                  % (len(full), M.KEEP, best_eng[1], best_eng[0], best_eng[2]))
            print("   [on the big model English is about %.1f or better, noise about -6.5]" % ENGLISH)

        ctrl = []
        for seed in ((1, 2) if SMOKE else range(1, 21)):
            r = M.search(shuffled_control(seed), CRIBS, TL)
            ctrl.append(r)
            print("shuffled K4 #%d: %s | all %s" % (seed, summary(r), tails(r)))
        ctop = [r["top"] for r in ctrl]
        print("shuffled K4s best (W and B):", ctop, " K4:", res["top"])
        for key in sorted(res["best"]):
            cs = [r["best"][key][0] for r in ctrl]
            print("   rule %s %-5s K4 %d, shuffled %d-%d (%d of %d at or above K4)"
                  % (key[0], key[1], res["best"][key][0], min(cs), max(cs), sum(c >= res["best"][key][0] for c in cs), len(cs)))

        # ---- rule C
        rc = M.search_c(K4, CRIBS, TL)
        ex.count(rc["n"] + rc["nhalf"])
        print("rule C, overlapping pairs: %d settings; mean %.2f of 24; best with strict letter numbers %d/24, with "
              "letter numbers wrapping round the word %d/24" % (rc["n"], M.mean(rc["hist"]), rc["best"][False][0],
                                                                 rc["best"][True][0]))
        for wrap in (False, True):
            ti, e, an, sgn, a, s, mode = rc["best"][wrap][1]
            pt = M.c_read(K4, TL[ti][1], e, an, sgn, a, s, mode)
            print("   %s: %s  [%s, neighbour %+d, word count %s %+d, a=%d, start %d, letter number %s from %d%s]  "
                  "english %.2f" % ("wrap" if wrap else "strict", pt, TL[ti][0], e, an, sgn, a, s, mode[0], mode[1],
                                    ", from the end" if mode[3] else "", big.score(pt.replace("?", "X"))))
            ex.add(pt.replace("?", "X"), rule="C", text=TL[ti][0], wrap=wrap, start=s, advance=a)
        can_s = [v for (ti, w), v in rc["can"].items() if not w]
        can_w = [v for (ti, w), v in rc["can"].items() if w]
        mi = [n for n, _ in TL].index(MAIN)
        print("   clue letters that can be reached at all (some word, best letter numbering): strict %d-%d of 24 over the "
              "lists (%s: %d); wrapping %d-%d (%d)" % (min(can_s), max(can_s), MAIN, rc["can"][mi, False],
                                                       min(can_w), max(can_w), rc["can"][mi, True]))
        print("   halved message (pairs that do not overlap): %d readings of 48 letters; clue words seen: %s"
              % (rc["nhalf"], ", ".join("%s %d" % (w, rc["half"][w]) for w in M.HALF_WORDS)))
        cc = []
        for seed in ((1, 2) if SMOKE else range(1, 21)):
            r = M.search_c(shuffled_control(seed), CRIBS, TL)
            cc.append(r)
            print("shuffled K4 #%d rule C: strict %d wrap %d; reachable strict %d-%d wrap %d-%d; halved %s"
                  % (seed, r["best"][False][0], r["best"][True][0],
                     min(v for (t, w), v in r["can"].items() if not w), max(v for (t, w), v in r["can"].items() if not w),
                     min(v for (t, w), v in r["can"].items() if w), max(v for (t, w), v in r["can"].items() if w),
                     ", ".join("%s %d" % (w, r["half"][w]) for w in M.HALF_WORDS)))
        cctop = [r["top"] for r in cc]
        print("shuffled K4s best (rule C): strict %s wrap %s   K4: strict %d wrap %d"
              % ([r["best"][False][0] for r in cc], [r["best"][True][0] for r in cc], rc["best"][False][0], rc["best"][True][0]))

        # ---- planted answers
        rng = random.Random(106)
        words, ok, total = vocab(), 0, len(PLANTS) + 1
        for spec in PLANTS:
            ct, cribs, pt, s = plant(rng, spec, T, words)
            m, n24, good = check_plant(spec, ct, cribs, pt, s, TL)
            ok += good
            print("planted rule %s on %s, letter %s, %s %+d, a=%d, %s, start %d: best %d/24, %d setting%s at 24, planted "
                  "setting found and read back: %s   (cipher IC %.4f)\n      message: %s"
                  % (spec[0], spec[1], spec[2], spec[3], spec[4], spec[5], "ring" if spec[6] else "line", s, m, n24,
                     "" if n24 == 1 else "s", "yes" if good else "NO", ioc(ct), pt))
        eng = FP.english_windows()
        ct, cribs, pt, s, draws = plant_c(rng, T, words)
        m, n24, good = check_plant_c(ct, cribs, pt, s, TL)
        ok += good
        print("planted rule C (overlapping pairs, wrapping letter number, draw %d): best %d/24, %d setting%s at 24, "
              "found and read back: %s\n      message: %s"
              % (draws, m, n24, "" if n24 == 1 else "s", "yes" if good else "NO", pt))
        print("planted recovered: %d/%d" % (ok, total))

        # ---- can the method carry ordinary English?
        trials = 20 if SMOKE else 200
        msgs = [eng[o:o + M.N] for o in (rng.randrange(len(eng) - M.N) for _ in range(trials))]
        print("can ordinary English (not from the sculpture) be encoded? %d messages of 97 letters on %s:" % (trials, MAIN))
        for pick in M.PICKS:
            text = M.line(T[MAIN], pick)
            nb = max(sum(bool(M.starts_b(p, text, a)) for p in msgs) for a in range(0, M.A_MAX + 1))
            rw = {a: sorted(M.reach(p, text, a) for p in msgs) for a in (0, 1, 5, 13, 30)}
            fullw = max(sum(x == M.N for x in r) for r in rw.values())
            print("   letter %-4s window: %d of %d (best advance); walk: %d of %d; a walk dies after %d letters (median, a=1), "
                  "longest %d" % (pick, nb, trials, fullw, trials, rw[1][trials // 2], max(r[-1] for r in rw.values())))
        rcs = sorted(max(M.reach_c(p, T[MAIN], C_PLANT[4], s, C_PLANT[5]) for s in range(0, len(T[MAIN]), 8)) for p in msgs)
        print("   pairs (overlapping, wrapping letter number, a=%d): %d of %d; dies after %d letters (median), longest %d"
              % (C_PLANT[4], sum(x == M.N for x in rcs), trials, rcs[trials // 2], rcs[-1]))
        print("index of coincidence: K4 %.4f; the planted cipher texts above show what the method gives" % ioc(K4))

        top = max(res["top"], rc["top"])
        beat = res["top"] > max(ctop) + 2 or rc["top"] > max(cctop) + 2
        reads = best_eng is not None and best_eng[1] > ENGLISH
        print("VERDICT:", "FULL HIT - read it" if top == 24 else
              ("K4 beats controls - inspect" if beat and reads else
               "no signal (K4 best %d/24 by W/B, %d/24 by C; shuffled %d-%d and %d-%d; 24 needed; planted %d/%d)"
               % (res["top"], rc["top"], min(ctop), max(ctop), min(cctop), max(cctop), ok, total)))
