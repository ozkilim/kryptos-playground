"""Idea 144: a key word on one tableau, and a second tableau turned by a short list of steps.

Idea 98 closed a key word on alphabet A stacked with a second tableau B that turns by ONE fixed
step every letter. A strip moved by hand need not move evenly: step 3, then 1, then 3, then 1
is just as easy ("shifting matrices", as Scheidt taught). Here the second layer turns by a
repeating list of k steps:

    key layer    X -> A[ +-A^-1(X) + a_(i mod p) ]
    turn layer   X -> B[ +-B^-1(X) + T(i) ]        T(0) = t,  T(i+1) = T(i) + s[i mod k]

in both orders (key word first, or turn first). + is Vigenere (variant Beaufort is the same with
free key letters, steps and t), - is Beaufort: 4 type pairs. k = 2: 676 step lists; k = 3:
17,576. Lists with all steps equal are idea 98 again: they are scanned (as a cross-check that
this code finds what idea 98 found) but not counted.

The test (kryptos/idea144_steps.py). For given B, type, step list and t the turn layer is fully
known, so each clue letter gives the key layer's key value outright. A key word of length p
needs equal values wherever i mod p is equal. Checks = 24 clue letters minus the key slots they
touch; chance passes n checks about 26^-n of the time. Key lengths 1..23 all have 7+ checks
(17, 18, 23 have exactly 7; 24 has 5 and is kept as a chance gauge only). Exact, nothing guessed.

  k = 2    every ordered pair (A, B) of different alphabets from A-Z, KRYPTOS and the theme
           keyword alphabets, and every dictionary keyword alphabet D as (A-Z, D), (KRYPTOS, D),
           (D, A-Z), (D, KRYPTOS): the 888,238 pairs of idea 98
  k = 3    the theme pairs only (7,310)
  shuffled K4s: every theme pair, and a different third of the dictionary alphabets each

Survivors with 7+ checks: the key is forced where the clues touch it. It is matched against the
English word list (data/web2.txt plus the repo's theme and common words), and all 97 letters are
decrypted ('?' where a long key is not reached) and scored on the big English model.

  python attacks/144_step_pattern_second_tableau.py            (--prefilter for the clue card)
"""
import collections
import random
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR, WORDS  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea144_steps import (MAXP, Scanner, checks, decrypt, encrypt as st_encrypt, key_text,  # noqa: E402
                                   key_values, periods)
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

MIN_CHECKS = 7          # the headline bar (as in rounds 9-11 and idea 98)
ENGLISH = -5.1          # big-model score per quadgram a reading must beat (planted texts: about -4.3)
TNAME = {1: "Vigenere", -1: "Beaufort"}
CHK = {p: checks(p, POS) for p in range(1, MAXP + 1)}
_S = {}


def per_pair(k):
    """Settings per alphabet pair: 2 orders x 2 key types x 2 turn types x step lists x 26 starts.
    The 26 lists with all steps equal (idea 98) are left out."""
    return 8 * (26 ** k - 26) * 26


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
    """(name A, A, name B, B): A carries the key word, B turns."""
    return [(an, a, bn, b) for an, a in small for bn, b in small if a != b]


def part2_pairs(dic, small):
    known = set(m for _, m in small)
    out = []
    for name, m in dic:
        if m in known:
            continue
        for xn, x in small[:2]:
            out.append((xn, x, name, m))
            out.append((name, m, xn, x))
    return out


def init(ct, cribs, k):
    _S["pl"] = [cribs[i] for i in POS]
    _S["cl"] = [ct[i] for i in POS]
    _S["scan"] = Scanner(POS, k)


def work(chunk):
    """Returns (pairs, [(checks, name A, A, name B, B, order, ek, eg, steps, t, p)]); p = the
    shortest key length that fits (it has the most checks)."""
    scan, pl, cl, hits = _S["scan"].scan, _S["pl"], _S["cl"], []
    for an, a, bn, b in chunk:
        for order, ek, eg, steps, t in scan(a, b, pl, cl):
            per = periods(key_values(pl, cl, POS, a, b, steps, t, ek, eg, order), POS)
            p = max(per, key=lambda q: (CHK[q], -q))
            hits.append((CHK[p], an, a, bn, b, order, ek, eg, steps, t, p))
    return len(chunk), hits


def search(ct, cribs, pairs, k):
    """-> (pairs done, hits with a real step pattern, hits with one constant step = idea 98)."""
    n, hits = 0, []
    for c, h in pmap(work, pairs, init, (ct, cribs, k), chunk=200 if k == 2 else 8):
        n += c
        hits.extend(h)
    hits.sort(key=lambda h: (-h[0], h[1], h[3], h[5:]))
    return n, [h for h in hits if len(set(h[8])) > 1], [h for h in hits if len(set(h[8])) == 1]


def read_score(pt, big):
    """Big-model score per quadgram over the letters that are known; -99 if under 15 quadgrams."""
    q = [pt[i:i + 4] for i in range(len(pt) - 3) if "?" not in pt[i:i + 4]]
    return sum(big.logp.get(x, big.floor) for x in q) / len(q) if len(q) >= 15 else -99.0


def load_words():
    """{length: set of words}, length 3+: data/web2.txt plus the repo's theme and common words."""
    out = collections.defaultdict(set)
    with open(WORDS) as f:
        for line in f:
            w = "".join(ch for ch in line.upper() if "A" <= ch <= "Z")
            if len(w) >= 3:
                out[len(w)].add(w)
    for w in ["KRYPTOS"] + wordkeys.theme_words() + wordkeys.common_words():
        if len(w) >= 3:
            out[len(w)].add(w)
    return out


def word_matches(slots, a, words):
    """Dictionary words the forced key spells, read as A[k] and as A[-k] (the other sign habit).
    Unreached slots match any letter."""
    out = []
    for sign in (1, -1):
        pat = "".join("." if k is None else a[(sign * k) % 26] for k in slots)
        if len(pat) < 3:
            continue
        if "." not in pat:
            if pat in words.get(len(pat), ()):
                out.append(pat)
        else:
            rx = re.compile(pat + "$")
            out.extend(sorted(w for w in words.get(len(pat), ()) if rx.match(w)))
    return out


def complete(hit, ct, cribs, big, words):
    """A survivor -> [(english, text, key as letters, key length, checks, words)] at the shortest
    key length that fits (the one with the most checks), as in idea 98."""
    _, an, a, bn, b, order, ek, eg, steps, t, p = hit
    slots = periods(key_values([cribs[i] for i in POS], [ct[i] for i in POS], POS, a, b, steps, t, ek, eg, order),
                    POS)[p]
    pt = decrypt(ct, a, b, slots, steps, t, ek, eg, order)
    return [(read_score(pt, big), pt, key_text(slots, a), p, CHK[p], word_matches(slots, a, words))]


def complete_all(hits, ct, cribs, big, words, limit=4000):
    out = []
    for h in hits[:limit]:
        for sc, pt, kw, q, c, ws in complete(h, ct, cribs, big, words):
            out.append((sc, pt, kw, q, c, ws, h))
    return sorted(out, key=lambda r: (-r[0], r[1]))


def describe(r):
    sc, pt, kw, q, c, ws, h = r
    first = "key word on %s (%s)" % (h[1], TNAME[h[6]])
    second = "turn on %s (%s) by steps %s from %d" % (h[3], TNAME[h[7]], ",".join(map(str, h[8])), h[9])
    return "%s; key length %d, %d checks" % ((first + " then " + second) if h[5] == 1 else
                                              (second + " then " + first), q, c)


def by_checks(hits):
    c = collections.Counter(h[0] for h in hits)
    return " ".join("%d:%d" % (k, c[k]) for k in sorted(c)) or "none"


def headline(hits):
    return [h for h in hits if h[0] >= MIN_CHECKS]


def chance(npairs, k):
    """Survivors chance predicts if every check were an independent 1-in-26: (at 5-6 checks, at
    exactly 7, at 8+). A rough guide; the shuffled K4s are the real yardstick."""
    n = npairs * per_pair(k)
    return (n * sum(26.0 ** -c for c in CHK.values() if c < MIN_CHECKS),
            n * sum(26.0 ** -c for c in CHK.values() if c == MIN_CHECKS),
            n * sum(26.0 ** -c for c in CHK.values() if c > MIN_CHECKS))


def run_text(label, ct, pairs, k, big, words, ex=None):
    """Search one text at one k; print; -> dict of the numbers the verdict needs."""
    n, hits, const = search(ct, CRIBS, pairs, k)
    lo, at, hi = chance(n, k)
    head = headline(hits)
    done = complete_all(head, ct, CRIBS, big, words)
    gauge = [h for h in hits if h[0] < MIN_CHECKS]
    gdone = complete_all(gauge, ct, CRIBS, big, words, limit=1500)
    worded = [r for r in done if r[5]]
    print("%s, k = %d: %d pairs, %d settings (x key lengths 1-23). Survivors by checks (checks:settings): %s   "
          "[chance predicts about %.0f at 5-6 checks, %.1f at exactly 7, %.2f at 8+]"
          % (label, k, n, n * per_pair(k), by_checks(hits), lo, at, hi))
    print("   %d pass with %d+ checks (%d with 8+); %d of them spell a dictionary key word; best reading %.2f; "
          "gauge best reading %.2f (English needs %.1f); constant-step settings (idea 98, not counted): %s"
          % (len(head), MIN_CHECKS, sum(h[0] > MIN_CHECKS for h in head), len(worded),
             done[0][0] if done else -99.0, gdone[0][0] if gdone else -99.0, ENGLISH, by_checks(const)))
    for r in done[:12 if ex is not None else 3]:
        print("      english %.2f words %.2f  %s\n         key %s  dictionary words: %s\n         %s"
              % (r[0], word_coverage(r[1].replace("?", "")), describe(r), r[2], ",".join(r[5][:5]) or "none", r[1]))
        if ex is not None:
            ex.add(r[1].replace("?", "X"), english_big=round(r[0], 3), setting=describe(r), key=r[2])
    for h in headline(const)[:5]:
        print("      constant step (idea 98's): %s on %s/%s, step %d from %d, key length %d, %d checks"
              % ("key first" if h[5] == 1 else "turn first", h[1], h[3], h[8][0], h[9], h[10], h[0]))
    return dict(n=n, head=len(head), eight=sum(h[0] > MIN_CHECKS for h in head), worded=len(worded),
                best=done[0][0] if done else -99.0, gauge=len(gauge), gbest=gdone[0][0] if gdone else -99.0,
                at=at, hi=hi, lo=lo, const=len(headline(const)),
                english=[r for r in done if r[0] > ENGLISH], word_rows=worded)


# ---- planted messages -------------------------------------------------------------------------

def plant(rng, a, b, word, steps, t, ek, eg, order):
    pt = english97(rng)
    ct = st_encrypt(pt, a, b, [a.index(ch) for ch in word], steps, t, ek, eg, order)
    return pt, ct, {i: pt[i] for i in POS}


def planted_case(rng, big, words, label, an, a, bn, b, word, steps, t, ek, eg, order, pairs):
    """Plant, search, read. Found = the true setting passes at the true key length, its key is
    read back as the planted dictionary word, and the best reading of all survivors is the
    planted text and scores as English."""
    k = len(steps)
    pt, ct, cribs = plant(rng, a, b, word, steps, t, ek, eg, order)
    pairs = sorted(set(pairs))
    n, hits, _ = search(ct, cribs, pairs, k)
    hits = headline(hits)
    true = [h for h in hits if h[2] == a and h[4] == b and h[5:8] == (order, ek, eg)
            and h[8] == tuple(steps) and h[9] == t and h[10] == len(word)]
    done = complete_all(hits, ct, cribs, big, words)
    worded = [r for r in done if r[5]]
    ok = (len(true) == 1 and bool(done) and done[0][1] == pt and done[0][0] > ENGLISH and done[0][2] == word
          and word in done[0][5])
    for r in worded:
        if r[1] != pt:
            print("   (another survivor spells a word: %s, key %s, words %s, english %.2f)"
                  % (describe(r), r[2], ",".join(r[5][:5]), r[0]))
    print("planted %s: key word %s on %s (%s), turn on %s (%s) by steps %s from %d, %s; %d settings searched -> "
          "true setting found=%s, survivors with %d+ checks %d, with a dictionary key word %d, best reading "
          "english %.2f, is the planted text: %s, key word read back: %s -> %s"
          % (label, word, an, TNAME[ek], bn, TNAME[eg], ",".join(map(str, steps)), t,
             "key word first" if order == 1 else "turn first", n * per_pair(k) * (MAXP - 1), bool(true), MIN_CHECKS,
             len(hits), len(worded), done[0][0] if done else -99, bool(done) and done[0][1] == pt,
             done[0][2] if done else "-", "ok" if ok else "MISSED"))
    return ok


def prefilter_encrypt(pt, rng):
    """For the clue pre-filter: key word layer on KRYPTOS, then an A-Z tableau turned by a list of
    2 or 3 steps; key from rng only."""
    key = [rng.randrange(26) for _ in range(rng.randrange(5, 10))]
    steps = [rng.randrange(26) for _ in range(rng.choice((2, 3)))]
    return st_encrypt(pt, KRYPTOS_ALPHABET, AZ, key, steps, rng.randrange(26))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("key word on one tableau, second tableau turned by a repeating step list",
                  encrypt=prefilter_encrypt)
        sys.exit(0)
    small = small_alphabets()
    dic = dictionary_alphabets()
    if SMOKE:
        small, dic = small[:6], dic[:240]
    p1, p2 = part1_pairs(small), part2_pairs(dic, small)
    nper = sum(c >= MIN_CHECKS for c in CHK.values())
    seeds = (1, 2) if SMOKE else (1, 2, 3)
    with Experiment("144 key word on one tableau, second tableau turned by a repeating list of 2-3 steps",
                    puzzle="k4",
                    notes="exact periodic test on the clue letters with the turn layer known (T(i+1) = T(i) + "
                          "s[i mod k], start t 0-25); k=2 (650 non-constant step lists) on %d ordered pairs of "
                          "A-Z/KRYPTOS/theme alphabets + %d dictionary alphabets against A-Z and KRYPTOS in both "
                          "roles; k=3 (17,550 lists) on the theme pairs; both layer orders; Vig/Beau per layer; key "
                          "lengths 1-%d (7+ checks), 24 as gauge; survivors joined with the word list and read; "
                          "3 shuffled K4s on the theme pairs + a third of the dictionary alphabets each"
                          % (len(p1), len(p2) // 4, MAXP - 1), cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        words = load_words()
        print("alphabet pairs: theme part %d (from %d alphabets), dictionary part %d (%d dictionary alphabets x 4); "
              "word list %d words" % (len(p1), len(small), len(p2), len(p2) // 4, sum(map(len, words.values()))))
        print("per pair: k=2 %d settings, k=3 %d settings (2 orders x 4 types x step lists x 26 starts), each tested "
              "at key lengths 1-%d; checks by key length: %s"
              % (per_pair(2), per_pair(3), MAXP, " ".join("%d:%d" % (p, CHK[p]) for p in sorted(CHK))))
        k4 = {2: run_text("K4", K4, p1 + p2, 2, big, words, ex), 3: run_text("K4", K4, p1, 3, big, words, ex)}
        ex.count((k4[2]["n"] * per_pair(2) + k4[3]["n"] * per_pair(3)) * nper)
        ctrl = []
        for seed in seeds:
            sct = shuffled_control(seed)
            third = [pr for j in range(0, len(p2), 4) if (j // 4) % len(seeds) == seed - 1 for pr in p2[j:j + 4]]
            ctrl.append({2: run_text("shuffled K4 seed %d" % seed, sct, p1 + third, 2, big, words),
                         3: run_text("shuffled K4 seed %d" % seed, sct, p1, 3, big, words)})
        rng = random.Random(144)
        dn, dm = dic[len(dic) // 3]
        dn2, dm2 = dic[2 * len(dic) // 3]
        sample = [x for x in dic[::20 if SMOKE else 150] if x[0] not in (dn, dn2)]
        theme = small[2:]
        (t1n, t1), (t2n, t2) = theme[1], theme[-1]
        sub = p1[::1 if SMOKE else 15]
        cases = [
            ("k=2, key word on KRYPTOS, then a dictionary tableau turned 3,11,3,11,...", "KRYPTOS", KRYPTOS_ALPHABET,
             dn, dm, "ABSCISSA", (3, 11), 7, 1, 1, 1, part2_pairs(sample + [(dn, dm)], small)),
            ("k=2, the reverse order: Beaufort A-Z turned 25,4,..., then Beaufort key word on a dictionary tableau",
             dn2, dm2, "(A-Z)", AZ, "LANTERN", (25, 4), 20, -1, -1, 2, part2_pairs(sample + [(dn2, dm2)], small)),
            ("k=3, theme tableaux, key word first, turn 5,0,19", t1n, t1, t2n, t2, "ILLUSION", (5, 0, 19), 11, 1, 1,
             1, sub + [(t1n, t1, t2n, t2)]),
            ("k=3, theme tableaux, Beaufort turn 7,7,12 first, 11-letter key word second", t2n, t2, "KRYPTOS",
             KRYPTOS_ALPHABET, "UNDERGROUND", (7, 7, 12), 3, 1, -1, 2, sub + [(t2n, t2, "KRYPTOS", KRYPTOS_ALPHABET)]),
        ]
        ok = 0
        for c in cases:
            ok += planted_case(rng, big, words, *c)
        print("planted recovered: %d/%d" % (ok, len(cases)))
        reads = [r for k in (2, 3) for r in k4[k]["english"]]
        cbest = max(c[k]["best"] for c in ctrl for k in (2, 3))
        kbest = max(k4[k]["best"] for k in (2, 3))
        signal = bool(reads) and kbest > cbest + 0.3
        for k in (2, 3):
            print("SUMMARY k=%d: K4 %d pass with %d+ checks (%d with 8+; chance %.1f at exactly 7 and %.2f at 8+), "
                  "%d spell a dictionary key word, best reading %.2f, gauge (5 checks) %d (chance %.0f). Shuffled "
                  "K4s on %s of the pairs: %s pass (%s with 8+), dictionary key words %s, best readings %s, gauge %s"
                  % (k, k4[k]["head"], MIN_CHECKS, k4[k]["eight"], k4[k]["at"], k4[k]["hi"], k4[k]["worded"],
                     k4[k]["best"], k4[k]["gauge"], k4[k]["lo"],
                     ["%.2f" % (c[k]["n"] / float(k4[k]["n"])) for c in ctrl], [c[k]["head"] for c in ctrl],
                     [c[k]["eight"] for c in ctrl], [c[k]["worded"] for c in ctrl],
                     ["%.2f" % c[k]["best"] for c in ctrl], [c[k]["gauge"] for c in ctrl]))
        print("VERDICT:", ("K4 has a reading above the English bar that beats every control - inspect; " if signal
                           else "no signal; ") +
              "K4 best reading %.2f, shuffled best %.2f (English needs %.1f; -99 = nothing to read); K4 survivors "
              "whose key is a dictionary word: %d; planted %d/%d"
              % (kbest, cbest, ENGLISH, k4[2]["worded"] + k4[3]["worded"], ok, len(cases)))
