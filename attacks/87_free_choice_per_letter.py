"""Idea 87: free choice per letter between two or three cipher systems, with a repeating key.

Scheidt 'masked the English language'; Sanborn (1990) spoke of 'two separate systems'; in 2019 he
said the solver needs 'just to be able to read'. Suppose the encoder had one key word and, at each
letter, was free to use either of two (or three) systems - say Vigenere or Beaufort on the same
tableau - picking whichever kept the letter counts flat. The reader would try both at each letter
and keep the one that reads. Idea 60 tested switching between fixed rows, and rule-based
switching; the community tested a fixed form per key letter. A free choice at every letter with a
repeating key word has not been tested.

The test. For a clue letter (p, c) each allowed system forces one key value, so the clue gives a
SET of 1-3 key values (a 26-bit mask). A repeating key of length L fits only if, in every residue
class mod L, the sets of the clue letters in that class share a value. A sliding key (running sum
of a repeating word w, k_i = k_(i-1) + w_(i mod L)) is solved exactly by a small depth-first search
over the clue letters.

A set test is weaker than an exact one, so its strength is measured on the same scale:
expected chance solutions = 26^free * prod(|S_i|/26), strength = -log26 of that (kryptos/
idea87_freeform.py). With one system per letter this is the usual 'clue letters minus key
letters'. Headline bar: strength 7 (the rounds 9-11 bar). 5-7 is a chance gauge; below 5 the
setting is not decided and is only counted (repeating) or skipped (sliding, below 3).

Choice sets, for every alphabet M (A-Z, KRYPTOS and every dictionary keyword alphabet):
  form choice    in each of the five layouts of idea 66 (M/M, M/AZ, AZ/M, M/KR, KR/M; for A-Z:
                 AZ/AZ, AZ/KR, KR/AZ, KR/KR), key = a number: {Vig, Beau}, {Vig, variant},
                 {Beau, variant}, {all three}. Repeating L = 1-17 and sliding L = 1-17.
  tableau choice key = a letter, read on each tableau's own alphabet (K1/K2 style): {M tableau,
                 A-Z tableau} and {M tableau, KRYPTOS tableau}, one form (Vig, Beau or variant
                 on both), plus {Vig, Beau} x both tableaux (4 systems). Repeating L = 1-17.

Survivors with strength >= 5 are decoded on all 97 letters: the key gives 1-3 candidate letters at
every place, and a beam search on the big quadgram model picks the reading (plus word coverage).
Controls: 3 shuffled K4s, each on A-Z and a different third of the dictionary alphabets. Planted: English with 7- and 11-letter keys and a coin
flip per letter (and a tableau-choice and a sliding plant), found and read back.

Pre-filter (python attacks/87_free_choice_per_letter.py --prefilter): see the card in 87.md.

  python attacks/87_free_choice_per_letter.py
"""
import collections
import itertools
import math
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos import idea87_freeform as F  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

LENGTHS = list(range(1, 18))
MIN = 7.0               # headline bar, in exact-check equivalents
WATCH = 5.0             # chance gauge
SLIDE_FLOOR = 3.0       # sliding settings weaker than this are not searched
ENGLISH = -5.1          # big-model score per quadgram English reaches (planted ~ -4.5, noise ~ -6.5)
FORM_SETS = (("vig", "beau"), ("vig", "var"), ("beau", "var"), ("vig", "beau", "var"))
IDX = F.IDX
REP = F.rep_groups(POS, LENGTHS)
REP_FREE = {L: len(REP[L]) for L in LENGTHS}
SLIDE = F.slide_groups(POS, LENGTHS)
BANDS = ((7.0, "7+"), (5.0, "5-7"), (3.0, "3-5"), (-1e9, "<3"))
_S = {}


def layouts(m):
    if m == AZ:
        return (("AZ/AZ", AZ, AZ), ("AZ/KR", AZ, KRYPTOS_ALPHABET), ("KR/AZ", KRYPTOS_ALPHABET, AZ),
                ("KR/KR", KRYPTOS_ALPHABET, KRYPTOS_ALPHABET))
    return (("M/M", m, m), ("M/AZ", m, AZ), ("AZ/M", AZ, m), ("M/KR", m, KRYPTOS_ALPHABET),
            ("KR/M", KRYPTOS_ALPHABET, m))


def settings(m):
    """[(label, systems, slide)] for alphabet m."""
    out = []
    for lay, a, b in layouts(m):
        for fs in FORM_SETS:
            out.append(("%s %s" % (lay, "/".join(fs)), [F.system(a, b, f) for f in fs], True))
    if m != AZ:
        for xn, x in (("AZ", AZ), ("KR", KRYPTOS_ALPHABET)):
            if x == m:
                continue
            for f in F.FORMS:
                out.append(("tableau M|%s %s" % (xn, f), [F.system(m, m, f, m), F.system(x, x, f, x)], False))
            out.append(("tableau M|%s vig/beau" % xn, [F.system(m, m, f, m) for f in ("vig", "beau")] +
                        [F.system(x, x, f, x) for f in ("vig", "beau")], False))
    return out


def band(s):
    return next(n for t, n in BANDS if s >= t)


def init(ct, cribs):
    _S["pl"] = [IDX[cribs[i]] for i in POS]
    _S["cl"] = [IDX[ct[i]] for i in POS]


def test_alphabet(name, m, pl, cl):
    """Returns (settings, passes by (kind, band), predicted by (kind, band), hits with strength >= WATCH)."""
    n, got, pred, hits = 0, collections.Counter(), collections.Counter(), []
    for label, systems, slide in settings(m):
        ms = F.masks(systems, pl, cl)
        ls = F.logsum(ms)
        for L in LENGTHS:
            n += 1
            s = ls - REP_FREE[L]
            b = band(s)
            pred["rep", b] += min(1.0, 26.0 ** -s)
            if F.rep_test(ms, REP[L]) is not None:
                got["rep", b] += 1
                if s >= WATCH:
                    hits.append((round(s, 2), "rep", name, m, label, L))
        if not slide:
            continue
        dms = None
        for L in LENGTHS:
            groups, touched, link = SLIDE[L]
            s = ls - touched - link
            if s < SLIDE_FLOOR:
                continue
            n += 1
            b = band(s)
            pred["slide", b] += min(1.0, 26.0 ** -s)
            if dms is None:
                dms = F.diff_masks(ms, POS)
            if F.slide_filter(dms, groups) and F.slide_solve(ms, POS, L, limit=1):
                got["slide", b] += 1
                if s >= WATCH:
                    hits.append((round(s, 2), "slide", name, m, label, L))
    return n, got, pred, hits


def work(chunk):
    pl, cl = _S["pl"], _S["cl"]
    n, got, pred, hits = 0, collections.Counter(), collections.Counter(), []
    for name, m in chunk:
        a, b, c, d = test_alphabet(name, m, pl, cl)
        n += a
        got.update(b)
        pred.update(c)
        hits.extend(d)
    return n, got, pred, hits


def search(ct, cribs, alphas):
    n, got, pred, hits = 0, collections.Counter(), collections.Counter(), []
    for a, b, c, d in pmap(work, alphas, init, (ct, cribs), chunk=400):
        n += a
        got.update(b)
        pred.update(c)
        hits.extend(d)
    return n, got, pred, hits


# ---- reading survivors -------------------------------------------------------------------------

def systems_for(m, label):
    return next(sy for lab, sy, _ in settings(m) if lab == label)


def _masks_for(hit, ct, cribs):
    _, kind, _, m, label, L = hit
    sy = systems_for(m, label)
    return sy, F.masks(sy, [IDX[cribs[i]] for i in POS], [IDX[ct[i]] for i in POS])


def read_hit(hit, ct, cribs, big, width=300, limit=24):
    """Best reading over the keys that fit: (score, text, key). Repeating key: every key if there are
    at most `limit`, else two rounds of class-by-class improvement from the first."""
    _, kind, _, m, label, L = hit
    sy, ms = _masks_for(hit, ct, cribs)
    fixed = {i: cribs[i] for i in POS}

    def run(labels):
        return F.beam(F.candidates(ct, sy, labels, fixed), big.logp, big.floor, width)

    best = (-99.0, "", "")
    if kind == "rep":
        inter = F.rep_test(ms, REP[L])
        res = [POS[g[0]] % L for g in REP[L]]
        opts = [F.bits(x) for x in inter]
        total = 1
        for o in opts:
            total *= len(o)

        def go(choice):
            key = dict(zip(res, choice))
            sc, txt = run([key.get(i % L) for i in range(len(ct))])
            return sc, txt, "".join(AZ[key[r]] for r in range(L))

        if total <= limit:
            for combo in itertools.product(*opts):
                r = go(combo)
                if r[0] > best[0]:
                    best = r
        else:
            cur = [o[0] for o in opts]
            best = go(cur)
            for _ in range(2):
                for c, o in enumerate(opts):
                    for v in o:
                        if v == cur[c]:
                            continue
                        trial = list(cur)
                        trial[c] = v
                        r = go(trial)
                        if r[0] > best[0]:
                            best, cur = r, trial
    else:
        for w, ks in F.slide_solve(ms, POS, L, limit=limit):
            sc, txt = run(F.slide_key(w, ks[0], POS[0], len(ct)))
            if sc > best[0]:
                best = (sc, txt, "w=" + "".join(AZ[x] if x >= 0 else "?" for x in w) + " k21=" + AZ[ks[0]])
    return best


def read_all(hits, ct, cribs, big, limit=400):
    out = []
    for h in sorted(hits, key=lambda h: -h[0])[:limit]:
        sc, txt, key = read_hit(h, ct, cribs, big)
        out.append((sc, txt, key, h))
    return sorted(out, key=lambda r: -r[0])


def describe(h):
    return "%s %s, alphabet %s, %s L=%d, strength %.2f" % (h[1], "key", h[2], h[4], h[5], h[0])


def fmt(cnt, kind):
    return " ".join("%s:%s" % (b, ("%.3g" % cnt[kind, b]) if isinstance(cnt[kind, b], float) else cnt[kind, b])
                    for _, b in BANDS)


# ---- planted messages --------------------------------------------------------------------------

def plant(rng, m, label, kind, word):
    sy = systems_for(m, label)
    pt = english97(rng)
    if label.startswith("tableau"):
        lab = [IDX[ch] for ch in word]                 # key letters
    else:
        lab = [m.index(ch) if "M" in label.split()[0] else AZ.index(ch) for ch in word]
    L = len(lab)
    if kind == "rep":
        key_at = lambda i: lab[i % L]                  # noqa: E731
    else:
        run, t = [], rng.randrange(26)
        for i in range(97):
            t = (t + lab[i % L]) % 26
            run.append(t)
        key_at = run.__getitem__
    ct = F.encrypt(pt, sy, key_at, rng)
    return pt, ct, {i: pt[i] for i in POS}


def agreement(a, b):
    return sum(x == y for x, y in zip(a, b)) / len(b)


def planted_case(rng, big, alphas, name, m, label, kind, word):
    """Found = the true setting passes the bar and its reading is English with 85%+ letters right, and no
    survivor that does not carry the planted text (under 50% letters right) reads as English.
    Supersets of the true systems (e.g. all three forms, or both tableaux) carry it too and pass."""
    pt, ct, cribs = plant(rng, m, label, kind, word)
    n, got, pred, hits = search(ct, cribs, alphas)
    head = [h for h in hits if h[0] >= MIN]
    true = [h for h in head if h[3] == m and h[4] == label and h[1] == kind and h[5] == len(word)]
    done = read_all(head, ct, cribs, big)
    tr = read_hit(true[0], ct, cribs, big) if true else (-99.0, "", "")
    ag = agreement(tr[1], pt) if true else 0.0
    false = [r for r in done if agreement(r[1], pt) < 0.5]
    ok = bool(true) and ag >= 0.85 and tr[0] > ENGLISH and not any(r[0] > ENGLISH for r in false)
    print("planted %s %s %s key %s: %d settings -> true setting passes %s (strength %s); %d over the bar "
          "(%d carry the planted text, %d do not, best of those %.2f); true reading %.2f english, %.0f%% letters "
          "right, words %.2f -> %s\n    %s\n    %s"
          % (kind, name, label, word, n, bool(true), true[0][0] if true else "-", len(head), len(done) - len(false),
             len(false), false[0][0] if false else -99, tr[0], 100 * ag, word_coverage(tr[1]) if true else 0,
             "ok" if ok else "MISSED", pt, tr[1]))
    return ok


def prefilter_encrypt(pt, rng):
    """KRYPTOS tableau, repeating key of 4-9 letters, coin flip Vigenere/Beaufort per letter, all from rng."""
    sy = [F.system(KRYPTOS_ALPHABET, KRYPTOS_ALPHABET, f) for f in ("vig", "beau")]
    key = [rng.randrange(26) for _ in range(rng.randrange(4, 10))]
    return F.encrypt(pt, sy, lambda i: key[i % len(key)], rng)


PLANTS = (("KRYPTOS", "M/M vig/beau", "rep", "LANTERN"),
          ("dict1", "M/AZ vig/beau", "rep", "UNDERGROUND"),
          ("dict2", "tableau M|AZ vig", "rep", "COMPASS"),
          ("(A-Z)", "AZ/AZ vig/beau", "slide", "BERLIN"))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("free choice per letter: Vigenere or Beaufort on one tableau, repeating key",
                  encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "paper tableau; at each letter use either row rule")})
        sys.exit(0)
    alphas = dictionary_alphabets()
    if SMOKE:
        alphas = alphas[:1500]
    with Experiment("free choice per letter between Vig/Beau/variant or two tableaux, repeating or sliding key",
                    puzzle="k4", cribs_forced=True,
                    notes="label sets per clue letter, classes must intersect; %d alphabets x 5 layouts x 4 form "
                          "sets + tableau sets (M|AZ, M|KR); repeating L 1-17, sliding L 1-17 (strength>=3); "
                          "bar = strength 7; 3 shuffled K4s; beam read on big model" % len(alphas)) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        n, got, pred, hits = search(K4, CRIBS, alphas)
        ex.count(n)
        print("alphabets %d; settings tested on K4: %d" % (len(alphas), n))
        for kind in ("rep", "slide"):
            print("  K4 %s passes by strength band: %s\n     chance predicts:            %s"
                  % (kind, fmt(got, kind), fmt(pred, kind)))
        done = read_all(hits, K4, CRIBS, big)
        for sc, txt, key, h in done[:12]:
            print("   english %.2f words %.2f  %s key %s\n      %s" % (sc, word_coverage(txt), describe(h), key, txt))
            ex.add(txt, english_big=round(sc, 3), setting=describe(h), key=key)
        k4_head = [h for h in hits if h[0] >= MIN]
        k4_best = done[0][0] if done else -99.0
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            sct = shuffled_control(seed)
            calphas = alphas[:1] + [x for j, x in enumerate(alphas[1:]) if j % 3 == seed % 3]
            cn, cgot, cpred, chits = search(sct, CRIBS, calphas)
            cdone = read_all(chits, sct, CRIBS, big)
            ctrl.append((sum(1 for h in chits if h[0] >= MIN), len(chits), cdone[0][0] if cdone else -99.0))
            print("shuffled K4 seed %d (%d settings, a third of the alphabets): rep %s | slide %s; %d at 7+, %d at 5+, best reading %.2f"
                  % (seed, cn, fmt(cgot, "rep"), fmt(cgot, "slide"), ctrl[-1][0], ctrl[-1][1], ctrl[-1][2]))
        rng = random.Random(87)
        sample = alphas[::10 if SMOKE else 40]
        by = {"KRYPTOS": KRYPTOS_ALPHABET, "(A-Z)": AZ,
              "dict1": alphas[len(alphas) // 3][1], "dict2": alphas[2 * len(alphas) // 3][1]}
        ok = 0
        for nm, label, kind, word in PLANTS:
            m = by[nm]
            ok += planted_case(rng, big, sample + [(nm, m)], nm, m, label, kind, word)
        print("planted recovered: %d/%d" % (ok, len(PLANTS)))
        beats = len(k4_head) > max(c[0] for c in ctrl) and k4_best > ENGLISH
        print("VERDICT:", ("K4 beats every control - inspect; " if beats else "no signal; ") +
              "K4 %d settings at strength 7+ (%d at 5+), best reading %.2f; shuffled K4s %s at 7+, %s at 5+, best %s"
              % (len(k4_head), len(hits), k4_best, [c[0] for c in ctrl], [c[1] for c in ctrl],
                 ["%.2f" % c[2] for c in ctrl]))
