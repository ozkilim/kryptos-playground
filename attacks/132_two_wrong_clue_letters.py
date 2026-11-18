"""Idea 132: two wrong clue letters, for the exact tests that still keep enough checks.

Sanborn calls his work "rife with mistakes on purpose", and K1-K3 hold at least five errors
(IQLUSION, UNDERGRUUND, DESPARATLY, PALIMPCEST, the dropped S). Idea 81 left out one of the 24
clue letters at a time and found nothing. If TWO of the 24 letters are wrong, every exact test
so far, idea 81 included, fails on the true method. Here two letters are left out:

  one from EASTNORTHEAST and one from BERLINCLOCK          13 x 11 = 143 pairs, bar 7 checks
  both from one block                                      78 + 55 = 133 pairs, bar 9 checks

Tests, each on the 22 letters kept (kryptos/idea132_droptwo.py):

  battery   the key-rule battery with idea 104's two hole fixes: repeating p <= 17, sliding p <= 15,
            progressive p <= 12 (key moved on along the cipher strip, and along A-Z / KRYPTOS / M
            with 26 index offsets), autokey lag 1-6 (plain and cipher feed, fed letter numbered on M,
            A-Z or KRYPTOS, both signs), chain addition (taps <= 6), two stacked repeating keys
            (exact loop test, p < q <= 26). Vigenere and Beaufort, 5 layouts.
  pairs     attack 71 part A: C = A[i mod p] * P + B[i mod q], p, q = 1..17, A-Z/KRYPTOS views.
  rotor     attack 72: a hidden rotor wiring turned by a dictionary word (3 schemes, 2 numberings,
            4 face pairs, 2 directions). Hits kept from 5 forced coincidences; bar 7 / 9 headline.

Alphabets. Core run: A-Z, KRYPTOS, the theme words and the common words (19,622 keyword alphabets),
all rules, bar 7 (one per block). Wide run: the other 647,371 alphabets of the full 666,993 list
(big dictionary and transposition-mixed forms), at bar 8 for one-per-block pairs, without the
progressive hole form (it costs 3x the rest; its chance is tiny but the time is not). The expected
chance count is printed beside every count.

Survivors are read with the two dropped clue letters re-read by the rule (the "corrections"),
scored on the big quadgram model and word coverage.

Controls: 3 shuffled K4s with the same 276 drop pairs: the core run in full each, the wide run on
a different third of the wide list each, pairs and rotor in full.

Planted: sliding key 7 and progressive key 5 on dictionary tableaux, each with two clue letters
changed (one per block; both in BERLINCLOCK), plus two stacked keys, progressive moved on in A-Z
order, autokey with the fed letter numbered on A-Z, a multiplier+adder pair and a rotor, each with
one wrong letter per block. The changed positions must be named exactly.

  python attacks/132_two_wrong_clue_letters.py
"""
import collections
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos import idea132_droptwo as T  # noqa: E402
from kryptos.ciphers.substitution import AZ  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea104_holes import read_score  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, vocabulary  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1
ALL = ("battery", "hole", "stacked")
WIDE = ("battery", "akhole", "stacked")
WIDE_BAR = 8
SAMPLE = 300 if SMOKE else 3000
PMAX = 6 if SMOKE else 17


def log(msg):
    print(msg, flush=True)


def lists():
    core_words = set(["KRYPTOS"] + wordkeys.theme_words() + wordkeys.common_words())
    core = [a for a in dictionary_alphabets(mixed=False) if a[0] == "(A-Z)" or a[0] in core_words]
    seen = {m for _, m in core}
    wide = [a for a in dictionary_alphabets(mixed=True) if a[1] not in seen]
    if SMOKE:
        core, wide = core[:600], wide[:900]
    return core, wide


def nstreams(alphas):
    return sum(8 if m == AZ else 10 for _, m in alphas)


def expect(alphas, bar_cross, parts):
    return nstreams(alphas) * sum(v[1] for v in T.chance(bar_cross, parts=parts).values())


def ntests(alphas, bar_cross, parts):
    return nstreams(alphas) * sum(v[0] for v in T.chance(bar_cross, parts=parts).values())


def summary(hits):
    return dict(collections.Counter((T.kind(h[5]), h[0]) for h in hits))


def readings(hits, by_name, ct, cribs, big, limit=300):
    out = []
    for h in sorted(hits, reverse=True)[:limit]:
        text = T.read(h, by_name[h[1]], ct, cribs)
        sc, nq = read_score(text, big)
        w1, w2, ch = T.corrections(text, cribs, h[5])
        out.append((sc, nq, text, h, w1, w2, ch))
    out.sort(key=lambda r: -r[0])
    return out


def show(rows, n=10):
    for sc, nq, text, h, w1, w2, ch in rows[:n]:
        log("   %.2f over %d new quadgrams, words %.2f; checks %d %s %s %s %s; dropped %s (minimal %s) %s/%s %s\n      %s"
            % (sc, nq, word_coverage(text.replace("?", "")), h[0], h[1], h[2], h[3], h[4],
               [POS[j] for j in h[5]], [POS[j] for j in h[6]], w1, w2, " ".join(ch), text))


# ------------------------------------------------------------------ planted answers

def wrong_two(rng, pt, where, avoid=()):
    """The 24 clue letters of pt with two changed: (cribs, D as clue indexes). `avoid`: clue indexes
    that no check of the planted rule touches (an error there cannot be seen by any test)."""
    b1 = [j for j in range(13) if j not in avoid]
    b2 = [j for j in range(13, 24) if j not in avoid]
    if where == "cross":
        D = (rng.choice(b1), rng.choice(b2))
    else:
        D = tuple(sorted(rng.sample(b2, 2)))
    cribs = {i: pt[i] for i in CRIBS}
    for j in D:
        cribs[POS[j]] = rng.choice([c for c in AZ if c != pt[POS[j]]])
    return cribs, D


def plant_key(rng, alphas, rule, where):
    """Message on a dictionary keyword tableau (M/M, Vigenere) with key rule `rule`; two clue letters
    then given wrongly. Returns (ct, cribs, pt, (name, alphabet), want)."""
    pt = english97(rng)
    name, m = rng.choice([a for a in alphas if a[1] != AZ])
    n = len(pt)
    if rule == "sliding":
        p = 7
        w = [rng.randrange(26) for _ in range(p)]
        key, t = [], 0
        for i in range(n):
            t = (t + w[i % p]) % 26
            key.append(t)
        prefix = "sliding p=7"
    elif rule == "progressive":
        p, s = 5, rng.randrange(1, 26)
        base = [rng.randrange(26) for _ in range(p)]
        key = [(base[i % p] + s * (i // p)) % 26 for i in range(n)]
        prefix = "progressive p=5 step=%d" % s
    elif rule == "stacked":
        p, q = 4, 7
        a, b = [rng.randrange(26) for _ in range(p)], [rng.randrange(26) for _ in range(q)]
        key = [(a[i % p] + b[i % q]) % 26 for i in range(n)]
        prefix = "two stacked keys p=4 q=7"
    elif rule == "progressive AZ order":
        p, s, c = 6, rng.randrange(1, 26), rng.randrange(26)
        base = [rng.randrange(26) for _ in range(p)]
        key = [(m.index(AZ[(base[i % p] + s * (i // p)) % 26]) - c) % 26 for i in range(n)]
        prefix = "progressive p=6 step=%d moved on in AZ order, offset %d" % (s, c)
    elif rule == "autokey AZ":
        L, c0 = 3, rng.randrange(26)
        key, ct = [], []
        for i in range(n):
            k = rng.randrange(26) if i < L else (AZ.index(ct[i - L]) + c0) % 26
            key.append(k)
            ct.append(m[(m.index(pt[i]) + k) % 26])
        prefix = "autokey cipher lag=3 sign=+1 fed on AZ"
    if rule != "autokey AZ":
        ct = "".join(m[(m.index(ch) + k) % 26] for ch, k in zip(pt, key))
    else:
        ct = "".join(ct)
    # cipher autokey lag 3: the key at 21-23 and 63-65 comes from letters outside the clues, so no
    # check uses those clue letters and an error there is invisible to any test
    avoid = (0, 1, 2, 13, 14, 15) if rule == "autokey AZ" else ()
    cribs, D = wrong_two(rng, pt, where, avoid)
    return ct, cribs, pt, (name, m), (name, "M/M", "vig", prefix, D)


def plant_pair(rng, where):
    pt = english97(rng)
    p, q = rng.randrange(3, 6), rng.randrange(3, 6)
    units = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    a, b = [rng.choice(units) for _ in range(p)], [rng.randrange(26) for _ in range(q)]
    ct = "".join(AZ[(a[i % p] * AZ.index(ch) + b[i % q]) % 26] for i, ch in enumerate(pt))
    cribs, D = wrong_two(rng, pt, where)
    return ct, cribs, ("ptAZ/ctAZ", "multiplier word %d + adder word %d" % (p, q), D)


def plant_rotor(rng, words, where):
    pt = english97(rng)
    wiring = list(range(26))
    rng.shuffle(wiring)
    w = rng.choice([x for x in words if 5 <= len(x) <= 9])
    ct = "".join(AZ[(wiring[(AZ.index(ch) + AZ.index(w[i % len(w)])) % 26] - AZ.index(w[i % len(w)])) % 26]
                 for i, ch in enumerate(pt))
    while True:
        cribs, D = wrong_two(rng, pt, where)
        # each changed letter must clash with the true wiring as the other 22 letters fix it (a
        # wrong letter that happens to fit an unused wire cannot be seen by any test)
        f, g = {}, {}
        for j, i in enumerate(POS):
            if j not in D:
                t = AZ.index(w[i % len(w)])
                u, v = (AZ.index(cribs[i]) + t) % 26, (AZ.index(ct[i]) + t) % 26
                f[u], g[v] = v, u
        if all(f.get((AZ.index(cribs[POS[j]]) + AZ.index(w[POS[j] % len(w)])) % 26, None) not in (
                None, (AZ.index(ct[POS[j]]) + AZ.index(w[POS[j] % len(w)])) % 26)
               or g.get((AZ.index(ct[POS[j]]) + AZ.index(w[POS[j] % len(w)])) % 26, None) not in (
                None, (AZ.index(cribs[POS[j]]) + AZ.index(w[POS[j] % len(w)])) % 26) for j in D):
            break
    return ct, cribs, ("ptAZ/ctAZ", "word %s (AZ numbering), out +1" % w, D)


def run_plants(core, words):
    ok, total = 0, 0
    rng = random.Random(132)
    for rule, where in (("sliding", "cross"), ("sliding", "B2"), ("progressive", "cross"), ("progressive", "B2"),
                        ("stacked", "cross"), ("progressive AZ order", "cross"), ("autokey AZ", "cross")):
        ct, cribs, pt, (name, m), want = plant_key(rng, core, rule, where)
        sample = rng.sample(core, min(SAMPLE, len(core)))
        if name not in {n for n, _ in sample}:
            sample.append((name, m))
        hits = T.search(ct, cribs, sample, parts=ALL, chunk=50)
        good = [h for h in hits if h[1:5] == want[:3] + (want[3],) and h[5] == want[4] and h[6] == want[4]]
        others = [h for h in hits if h not in good]
        found = bool(good)
        txt = ""
        if found:
            text = T.read(good[0], m, ct, cribs)
            right = sum(a == b for a, b in zip(text, pt))
            w1, w2, ch = T.corrections(text, cribs, good[0][5])
            fixed = all(text[POS[j]] == pt[POS[j]] for j in want[4])
            found = found and fixed
            txt = "read back %d/97, corrections %s (true letters restored: %s), %s/%s" % (right, " ".join(ch), fixed, w1, w2)
        total += 1
        ok += found
        log("planted %s, wrong letters at %s (%s): found=%s; %s; other passing settings %d (%s)"
            % (rule, [POS[j] for j in want[4]], where, found, txt, len(others),
               sorted(set((h[1], h[4], tuple(POS[j] for j in h[5])) for h in others))[:4]))
    for where in ("cross", "B2"):
        ct, cribs, want = plant_pair(rng, where)
        n, h = T.pairs_search_par(ct, cribs, PMAX)
        found = any(x[1:3] == want[:2] and x[3] == want[2] for x in h)
        ok += found
        total += 1
        log("planted pairs %s at %s: found=%s (fits %d of %d)" % (want[1], [POS[j] for j in want[2]], found, len(h), n))
    for where in ("cross", "B2"):
        ct, cribs, want = plant_rotor(rng, words, where)
        h = T.rotor_search(ct, cribs, words)
        found = any(x[1:3] == want[:2] and x[3] == want[2] for x in h)
        ok += found
        total += 1
        log("planted rotor %s at %s: found=%s (settings passing %d)" % (want[1], [POS[j] for j in want[2]], found, len(h)))
    return ok, total


# ------------------------------------------------------------------ main

def one_ct(label, ct, core, wide, words, by_name, big, share=None):
    """Full search for one ciphertext. share: (start, step) slice of the wide list for controls."""
    res = {}
    t0 = time.time()
    hc = T.search(ct, CRIBS, core, 7, parts=ALL)
    ec = expect(core, 7, ALL)
    log("%s core: %d alphabets, %d exact tests; passes %d (chance %.3f); by (pair kind, checks) %s; %.0f s"
        % (label, len(core), ntests(core, 7, ALL), len(hc), ec, summary(hc), time.time() - t0))
    wl = wide if share is None else wide[share[0]::share[1]]
    t0 = time.time()
    hw = T.search(ct, CRIBS, wl, WIDE_BAR, parts=WIDE)
    ew = expect(wl, WIDE_BAR, WIDE)
    log("%s wide: %d alphabets, %d exact tests; passes %d at bar %d (chance %.3f); by (pair kind, checks) %s; %.0f s"
        % (label, len(wl), ntests(wl, WIDE_BAR, WIDE), len(hw), WIDE_BAR, ew, summary(hw), time.time() - t0))
    hits = hc + hw
    rows = readings(hits, by_name, ct, CRIBS, big)
    show(rows)
    t0 = time.time()
    npair, hp = T.pairs_search_par(ct, CRIBS, PMAX)
    log("%s pairs: %d systems; fits %d; %s" % (label, npair, len(hp), sorted(hp, reverse=True)[:5]))
    hr = T.rotor_search(ct, CRIBS, words)
    r_head = [h for h in hr if len(h[3]) == 2 and h[0] >= T.bar(h[3])]
    log("%s rotor: %d words; real wirings with >= 5 coincidences %d (by coincidences %s), at the bar (7 / 9) %d; "
        "fits needing < 2 drops %d; %.0f s" % (label, len(words), len(hr), dict(collections.Counter(h[0] for h in hr)),
                                              len(r_head), sum(len(h[3]) < 2 for h in hr), time.time() - t0))
    for h in sorted(hr, reverse=True)[:5]:
        log("      rotor %d %s %s dropped %s" % (h[0], h[1], h[2], [POS[j] for j in h[3]]))
    res.update(core=len(hc), core_chance=ec, wide=len(hw), wide_chance=ew, wide_n=len(wl), pairs=len(hp),
               rotor5=len(hr), rotor_bar=len(r_head), rotor_best=max((h[0] for h in hr), default=0),
               best_read=max((r[0] for r in rows), default=-99.0), rows=rows, hits=hits, npair=npair)
    return res


if __name__ == "__main__":
    t_all = time.time()
    core, wide = lists()
    words = sorted(set(w for w in vocabulary() if 2 <= len(w) <= 22))
    if SMOKE:
        words = words[:4000]
    by_name = dict(core + wide)
    with Experiment("two wrong clue letters (one per block, or both in one block at 9+ checks): battery with idea-104 "
                    "holes, 71A pairs and 72 rotor on 22 of the 24 clue letters", puzzle="k4",
                    notes="276 drop pairs (143 one per block at 7+ checks, 133 in one block at 9+); core %d alphabets "
                          "all rules incl. progressive hole; wide %d alphabets at 8+ (one per block) without the "
                          "progressive hole; 71A p,q<=%d; rotor %d words; 3 shuffled K4s" % (
                              len(core), len(wide), PMAX, len(words)), cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        for bc in (7, 8):
            log("chance per key stream at bar %d (one per block) / 9 (one block): %s" % (
                bc, {k: "%d tests, %.3g" % v for k, v in T.chance(bc, parts=ALL).items()}))
        log("expected chance passes: core at bar 7 %.3f, core at bar 8 %.3f; wide (all %d) at bar 7 %.3f, at bar 8 %.3f"
            % (expect(core, 7, ALL), expect(core, 8, ALL), len(wide), expect(wide, 7, WIDE), expect(wide, 8, WIDE)))

        ok, nplants = run_plants(core, words)
        log("planted recovered: %d/%d (%.0f s)" % (ok, nplants, time.time() - t_all))

        k4 = one_ct("K4", K4, core, wide, words, by_name, big)
        tested = ntests(core, 7, ALL) + ntests(wide, WIDE_BAR, WIDE) + k4["npair"] + len(words) * 48 * 276
        ex.count(tested)
        for r in k4["rows"][:20]:
            ex.add(r[2].replace("?", "X"), english_big=round(r[0], 3), setting="%s %s %s %s drop %s" % (
                r[3][1], r[3][2], r[3][3], r[3][4], [POS[j] for j in r[3][5]]))

        ctrl = []
        for seed in (1, 2, 3):
            c = one_ct("shuffled %d" % seed, shuffled_control(seed), core, wide, words, by_name, big, (seed - 1, 3))
            ctrl.append(c)

        log("SUMMARY")
        log("K4: core passes %d (chance %.3f), wide passes %d (chance %.3f), pairs %d, rotor >=5 %d at bar %d best %d, "
            "best reading %.2f" % (k4["core"], k4["core_chance"], k4["wide"], k4["wide_chance"], k4["pairs"], k4["rotor5"],
                                   k4["rotor_bar"], k4["rotor_best"], k4["best_read"]))
        for s, c in zip((1, 2, 3), ctrl):
            log("shuffled %d: core passes %d (chance %.3f), wide passes %d on %d (chance %.3f), pairs %d, rotor >=5 %d at "
                "bar %d best %d, best reading %.2f" % (s, c["core"], c["core_chance"], c["wide"], c["wide_n"],
                                                       c["wide_chance"], c["pairs"], c["rotor5"], c["rotor_bar"],
                                                       c["rotor_best"], c["best_read"]))
        beats = k4["best_read"] > ENGLISH and all(k4["best_read"] > c["best_read"] + 0.3 for c in ctrl)
        log("planted %d/%d; tested %d" % (ok, nplants, tested))
        log("VERDICT: %s" % ("K4 beats every control and reads as English - inspect" if beats else "no signal"))
        log("total %.0f s" % (time.time() - t_all))
