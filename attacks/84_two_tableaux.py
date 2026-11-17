"""Idea 84: two layers on two different tableaux (the layers do not add up).

K2 ends LAYER TWO and Scheidt calls K4 "more than one stage". Every stacked-key test so far put
both layers on the SAME tableau, where two repeating keys simply add into one key stream. If the
first layer is on one alphabet and the second on another, nothing adds:

    Y = A[ +-A^-1(P) + a_(i mod p) ]      layer one: repeating key a (length p) on alphabet A
    C = B[ +-B^-1(Y) + b_(i mod q) ]      layer two: repeating key b (length q) on alphabet B

+ is Vigenere (variant Beaufort is Vigenere with the key negated, and the key letters are free
here, so it is covered), - is Beaufort: 4 type pairs.

Given A and B the 24 clue letters decide a setting exactly (kryptos/idea84_twotab.py). Each clue
letter ties one letter of a to one letter of b. Guess one key letter (26 values), follow the
ties, and every tie that closes a loop is a check; a wrong guess dies at the first check.
"Checks" = clue letters minus key letters, counted per connected piece: chance passes a setting
with n checks about 26^-n of the time. No key is guessed and no word list is needed for keys.

  part 1   every ordered pair of different alphabets from A-Z, KRYPTOS and the theme-word
           keyword alphabets
  part 2   every dictionary keyword alphabet D as (D, A-Z), (A-Z, D), (D, KRYPTOS), (KRYPTOS, D)
  keys     every (p, q) up to 26 x 26 whose test has 7 or more checks: all p + q <= 17, plus
           long first or second keys the clues only partly touch (lengths 19-22 with a short
           partner). Settings with 5 or 6 checks are also counted, only to see that chance
           behaves as predicted (K4 against shuffled K4s).
  skipped  A = B (the keys add; closed in earlier rounds)

Survivors: every key that fits is used to decrypt all 97 letters ('?' where the clues do not
reach the key) and the reading is scored on the big English model.

  python attacks/84_two_tableaux.py
"""
import collections
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea84_twotab import (compile_scan, decrypt, encrypt as tt_encrypt, key_text, plans,  # noqa: E402
                                   solve, tables)
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

MIN_CHECKS = 7          # the headline bar (as in rounds 9-11)
WATCH = 5               # settings with 5-6 checks are kept too, as a chance gauge only
ENGLISH = -5.1          # big-model score per quadgram a reading must beat (planted texts: about -4.2)
TYPES = ((1, 1), (1, -1), (-1, 1), (-1, -1))
TNAME = {1: "Vigenere", -1: "Beaufort"}
PLANS = plans(POS, WATCH)
_S = {}


def small_alphabets():
    """A-Z, KRYPTOS and the theme-word keyword alphabets (distinct)."""
    out, seen = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)], {AZ, KRYPTOS_ALPHABET}
    for w in wordkeys.theme_words():
        m = keyword_alphabet(w)
        if m not in seen:
            seen.add(m)
            out.append((w, m))
    return out


def part1_pairs(small):
    return [(an, a, bn, b) for an, a in small for bn, b in small if a != b]


def part2_pairs(dic, small):
    known = set(m for _, m in small)
    out = []
    for name, m in dic:
        if m in known:
            continue
        for xn, x in small[:2]:
            out.append((name, m, xn, x))
            out.append((xn, x, name, m))
    return out


def init(ct, cribs):
    _S["pl"] = [cribs[i] for i in POS]
    _S["cl"] = [ct[i] for i in POS]
    _S["scan"] = compile_scan(PLANS, len(POS))


def work(chunk):
    """Returns (settings tested, [(checks, name A, A, name B, B, e1, e2, p, q, keys that fit)])."""
    scan, pl, cl, hits = _S["scan"], _S["pl"], _S["cl"], []
    for an, a, bn, b in chunk:
        for e1, e2 in TYPES:
            F, G = tables(a, b, e1, e2, pl, cl)
            for k, n in scan(F, G):
                p = PLANS[k]
                hits.append((p["checks"], an, a, bn, b, e1, e2, p["p"], p["q"], n))
    return len(chunk) * len(TYPES) * len(PLANS), hits


def search(ct, cribs, pairs):
    n, hits = 0, []
    for k, h in pmap(work, pairs, init, (ct, cribs), chunk=600):
        n += k
        hits.extend(h)
    return n, hits


def read_score(pt, big):
    """Big-model score per quadgram over the letters that are known; -99 if under 15 quadgrams."""
    q = [pt[i:i + 4] for i in range(len(pt) - 3) if "?" not in pt[i:i + 4]]
    return sum(big.logp.get(x, big.floor) for x in q) / len(q) if len(q) >= 15 else -99.0


def complete(hit, ct, cribs, big):
    """Every key that fits a surviving setting -> [(english, text, key a, key b)], best first."""
    _, an, a, bn, b, e1, e2, p, q, _ = hit
    plan = next(x for x in PLANS if x["p"] == p and x["q"] == q)
    F, G = tables(a, b, e1, e2, [cribs[i] for i in POS], [ct[i] for i in POS])
    out = []
    for sa, sb in solve(plan, F, G):
        pt = decrypt(ct, a, b, sa, sb, p, q, e1, e2)
        out.append((read_score(pt, big), pt, key_text(sa, p, a), key_text(sb, q, b)))
    return sorted(out, reverse=True)


def complete_all(hits, ct, cribs, big, limit=5000):
    out = []
    for h in sorted(hits, key=lambda h: (-h[0], h[1], h[3], h[5:]))[:limit]:
        for sc, pt, ka, kb in complete(h, ct, cribs, big)[:3]:
            out.append((sc, pt, ka, kb, h))
    return sorted(out, key=lambda r: (-r[0], r[1]))


def describe(h):
    return "%s (%s) then %s (%s), p=%d q=%d, %d checks, %d keys fit" % (
        h[1], TNAME[h[5]], h[3], TNAME[h[6]], h[7], h[8], h[0], h[9])


def by_checks(hits):
    c = collections.Counter(h[0] for h in hits)
    return " ".join("%d:%d" % (k, c[k]) for k in sorted(c)) or "none"


def headline(hits):
    return [h for h in hits if h[0] >= MIN_CHECKS]


def chance(npairs):
    """Settings chance is expected to pass, if every check were an independent 1-in-26."""
    lo = sum(26.0 ** -p["checks"] for p in PLANS if p["checks"] < MIN_CHECKS)
    hi = sum(26.0 ** -p["checks"] for p in PLANS if p["checks"] >= MIN_CHECKS)
    return npairs * len(TYPES) * lo, npairs * len(TYPES) * hi


# ---- planted messages -------------------------------------------------------------------------

def word_key(word, alpha):
    return [alpha.index(ch) for ch in word]


def plant(rng, an, a, bn, b, e1, e2, w1, w2):
    pt = english97(rng)
    ct = tt_encrypt(pt, a, b, word_key(w1, a), word_key(w2, b), e1, e2)
    return pt, ct, {i: pt[i] for i in POS}


def agrees(got, pt):
    return len(got) == len(pt) and all(g in ("?", p) for g, p in zip(got, pt)) and got.count("?") < len(pt) / 2


def planted_case(rng, big, label, an, a, bn, b, e1, e2, w1, w2, pairs):
    """Plant, search the given alphabet pairs, read the survivors. Found = the true setting passes,
    the best reading is the planted text and scores as English, and no survivor (7+ checks) reads
    anything else."""
    pt, ct, cribs = plant(rng, an, a, bn, b, e1, e2, w1, w2)
    n, hits = search(ct, cribs, pairs)
    hits = headline(hits)
    true = [h for h in hits if (h[2], h[4], h[5], h[6], h[7], h[8]) == (a, b, e1, e2, len(w1), len(w2))]
    done = complete_all(hits, ct, cribs, big)
    right = [r for r in done if agrees(r[1], pt)]
    other = set((r[4][1], r[4][3]) for r in done if not agrees(r[1], pt))
    ok = bool(true) and bool(done) and done[0][1] == pt and done[0][0] > ENGLISH and not other
    print("planted %s: %s key %s (%s) then %s key %s (%s); %d settings searched -> true setting found=%s; "
          "survivors %d (same message at a multiple of the key lengths: %d; reading something else: %d); "
          "best reading english %.2f, is the planted text: %s -> %s"
          % (label, an, w1, TNAME[e1], bn, w2, TNAME[e2], n, bool(true), len(hits), len(hits) - 1 if true else 0,
             len(other), done[0][0] if done else -99, bool(done) and done[0][1] == pt, "ok" if ok else "MISSED"))
    return ok


def encrypt(pt, rng):
    """For the clue pre-filter: KRYPTOS tableau then A-Z tableau, two random keys from rng only."""
    a = [rng.randrange(26) for _ in range(rng.randrange(4, 9))]
    b = [rng.randrange(26) for _ in range(rng.randrange(4, 9))]
    return tt_encrypt(pt, KRYPTOS_ALPHABET, AZ, a, b)


if __name__ == "__main__":
    small = small_alphabets()
    dic = dictionary_alphabets()
    if SMOKE:
        small, dic = small[:12], dic[:1500]
    p1, p2 = part1_pairs(small), part2_pairs(dic, small)
    nhead = sum(p["checks"] >= MIN_CHECKS for p in PLANS)
    with Experiment("two repeating-key layers on two different tableaux", puzzle="k4",
                    notes="exact propagation on the clue letters; %d ordered pairs of A-Z/KRYPTOS/theme alphabets "
                          "+ %d dictionary alphabets against A-Z and KRYPTOS, both orders; Vig/Beau per layer; "
                          "%d (p,q) plans with >=%d checks (all p+q<=17) and %d watch plans with %d-%d checks; "
                          "3 shuffled K4s (part 2 on a third each)"
                          % (len(p1), len(p2) // 4, nhead, MIN_CHECKS, len(PLANS) - nhead, WATCH, MIN_CHECKS - 1),
                    cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        print("alphabet pairs: part 1 %d (from %d alphabets), part 2 %d (%d dictionary alphabets x 4)"
              % (len(p1), len(small), len(p2), len(p2) // 4))
        print("(p,q) plans: %d with %d+ checks, %d more with %d-%d checks (chance gauge)"
              % (nhead, MIN_CHECKS, len(PLANS) - nhead, WATCH, MIN_CHECKS - 1))
        n, hits = search(K4, CRIBS, p1 + p2)
        ex.count(n)
        lo, hi = chance(len(p1) + len(p2))
        print("settings tested on K4: %d (of them %d at %d+ checks)" % (n, (len(p1) + len(p2)) * 4 * nhead, MIN_CHECKS))
        print("K4 survivors by checks (checks:settings): %s   [chance predicts %.1f at %d-%d checks, %.3f at %d+]"
              % (by_checks(hits), lo, WATCH, MIN_CHECKS - 1, hi, MIN_CHECKS))
        done = complete_all(hits, K4, CRIBS, big)
        for sc, pt, ka, kb, h in done[:12]:
            print("   english %.2f words %.2f  %s\n      keys %s | %s\n      %s"
                  % (sc, word_coverage(pt.replace("?", "")), describe(h), ka, kb, pt))
            ex.add(pt.replace("?", "X"), english_big=round(sc, 3), setting=describe(h), key_a=ka, key_b=kb)
        k4_head = headline(hits)
        k4_best = max((r[0] for r in done if r[4][0] >= MIN_CHECKS), default=-99.0)
        k4_any = done[0][0] if done else -99.0
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            sct = shuffled_control(seed)
            cp = p1 + [x for j, x in enumerate(p2) if (j // 4) % 3 == seed % 3]
            cn, chits = search(sct, CRIBS, cp)
            cdone = complete_all(chits, sct, CRIBS, big)
            clo, chi = chance(len(cp))
            ctrl.append((len(headline(chits)), len(chits), cdone[0][0] if cdone else -99.0))
            print("shuffled K4 seed %d (%d settings, part 1 in full and a third of part 2): survivors by checks %s   "
                  "[chance predicts %.1f / %.3f]; best reading english %.2f"
                  % (seed, cn, by_checks(chits), clo, chi, ctrl[-1][2]))
        rng = random.Random(84)
        names = dict(small)
        theme = [x for x in small[2:]]
        sample = dic[::10 if SMOKE else 40]
        ok = tot = 0
        cases = [("KRYPTOS then A-Z", "KRYPTOS", KRYPTOS_ALPHABET, "(A-Z)", AZ, 1, 1, "SHADOW", "LANTERN", p1),
                 ("theme then theme, long keys", theme[2][0], theme[2][1], theme[-1][0], theme[-1][1], 1, -1,
                  "ABSCISSA", "LODESTONE", p1)]
        dn, dm = dic[len(dic) // 3]
        dn2, dm2 = dic[2 * len(dic) // 3]
        cases += [("dictionary tableau then KRYPTOS", dn, dm, "KRYPTOS", KRYPTOS_ALPHABET, 1, -1, "BERLIN", "ILLUSION",
                   part2_pairs(sample + [(dn, dm)], small)),
                  ("A-Z then dictionary tableau", "(A-Z)", AZ, dn2, dm2, -1, 1, "COMPASS", "TUNNEL",
                   part2_pairs(sample + [(dn2, dm2)], small))]
        for c in cases:
            ok += planted_case(rng, big, *c)
            tot += 1
        print("planted recovered: %d/%d" % (ok, tot))
        beats = (len(k4_head) > max(c[0] for c in ctrl) and k4_best > ENGLISH) or \
                (k4_any > ENGLISH and k4_any > max(c[2] for c in ctrl) + 0.3)
        print("VERDICT:", ("K4 beats every control - inspect; " if beats else "no signal; ") +
              "K4 %d settings pass with %d+ checks (%d with %d+), best reading english %.2f; shuffled K4s %s pass "
              "with %d+ (%s with %d+), best readings %s (English needs %.1f; -99 = nothing to read)"
              % (len(k4_head), MIN_CHECKS, len(hits), WATCH, k4_any, [c[0] for c in ctrl], MIN_CHECKS,
                 [c[1] for c in ctrl], WATCH, ["%.2f" % c[2] for c in ctrl], ENGLISH))
