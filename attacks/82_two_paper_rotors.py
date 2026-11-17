"""Idea 82: two paper rotors in series, both wirings hidden.

Idea 72 closed ONE rotor with a hidden wiring. Two rotors is the smallest machine it cannot see:

    Y = R1[P + s] - s        the fast rotor, turned s (a constant speed, a key word, a short key)
    C = R2[Y + t] - t        the slow rotor, turned t (constant inside each clue, or stepping rarely)

No wiring is guessed. Each clue letter ties one contact of R1 to one contact of R2:

    R1[P + s] - R2back[C + t] = s - t      (mod 26)

so the 24 clue letters draw a graph between the two rotors (kryptos/idea82_tworotor.py). A wrong
setting dies when a closed loop does not add up, or when two contacts of one rotor are forced onto
the same letter. A setting that survives is scored by its number of closed loops ("forced
coincidences that came out right").

Two forms are tested:

  H  two different hidden wirings. 52 unknown contacts against 24 clue letters: a true setting
     makes few loops (most make 0-2), so most of this space CANNOT be judged. The script counts
     exactly how much can (the "decidable" share) and reports K4 against shuffled K4s by loops.
  B  one strip used there and back: the second rotor is the first read backwards, at its own
     position. 26 unknowns against 24 letters: almost every true setting can be judged.

  fast turn s     constant speed 0-25; previous cipher letter; running sum of the cipher text;
                  dictionary word (plain, sliding = running sum, or word + 1 per letter; A-Z or
                  KRYPTOS numbering); every key of length 1-5 (H) / 1-4 (B) over all 26 letters
  slow turn t     constant inside each clue block, second block d = 0-25 further on (this is the
                  "are the two blocks' wirings a shift of each other" question);
                  one step per pass of the key; for the small families also: at most one step
                  inside each block (every odometer with period >= 13), a step every 2-12
                  letters, or a second constant speed
                  form B also needs the slow strip's start position: all 26 for the small
                  families; for keys it is folded into the key (exact when both rotors turn
                  the same way); for words either start 0-25 with d = 0, or start 0 with any d
  faces           A-Z or KRYPTOS numbering on the plain and on the cipher side
  small families  (and keys up to length 4 in H, 3 in B) also both turning directions per
                  rotor, and (H) the slow rotor first

A loop can be as plain as the same plain letter meeting the same cipher letter twice at the same
rotor positions. With a short key such loops are shared by every key of that length, so on a
planted short-key message thousands of keys pass together: the test then proves the key length
and the block structure, not the exact key.

  python attacks/82_two_paper_rotors.py
"""
import collections
import itertools
import random
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.idea82_tworotor import (back_decrypt, back_pieces, back_wirings,  # noqa: E402
                                     encrypt as rotor_encrypt, loops, loops_back)
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, english97, pmap, vocabulary  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ALPH = (("AZ", AZ), ("KR", KRYPTOS_ALPHABET))
BLK = [0] * 13 + [1] * 11
ALL_SIGNS = ((1, 1), (1, -1), (-1, 1), (-1, -1))
PLUS = ((1, 1),)
KMAX = {"H": 3 if SMOKE else 5, "B": 2 if SMOKE else 4}
KFULL = {"H": 3 if SMOKE else 4, "B": 2 if SMOKE else 3}     # up to here: all directions (and both orders in H)
# Form H: loops needed before a surviving setting counts as a hit. Fixed from the smoke run and
# a first full run: each extra loop cuts the survivors of a shuffled K4 about 40-170 times, and
# no shuffled K4 got past 3, so 5 loops leave well under 0.05 chance hits in the whole search.
# Form B: a survivor fixes most of the strip, so every survivor with 2+ loops is completed: the
# pieces of wiring must fit on one strip (many survivors die here), then all 97 letters are
# decrypted with every strip that fits and the English score decides.
MIN = {("H", "small"): 5, ("H", "keys"): 5, ("H", "words"): 5,
       ("B", "small"): 2, ("B", "keys"): 2, ("B", "words"): 2}
ENGLISH = -5.1      # big-model score per quadgram a reading must beat; planted texts read back at -3.9 to -4.9
FN = {"H": loops, "B": loops_back}
_S = {}


def sweep(mode, fasts, slows, signs, orders, views, minrec, hist, hits):
    """Every fast rule x slow rule x face numbering x direction. Returns the number of settings."""
    fn = FN[mode]
    for vn, pv, cv in views:
        for order in orders:
            first, second = (fasts, slows) if order == 0 else (slows, fasts)
            ua = [(n, s, [(p + a) % 26 for p, a in zip(pv, s)]) for n, s in first]
            for e2 in sorted(set(x[1] for x in signs)):
                vb = [(n, t, [(c + e2 * b) % 26 for c, b in zip(cv, t)]) for n, t in second]
                for e1 in sorted(set(x[0] for x in signs if x[1] == e2)):
                    for an, s, us in ua:
                        es = s if e1 == 1 else [-a for a in s]
                        for bn, t, vs in vb:
                            r = fn(us, vs, [a - b for a, b in zip(es, t)])
                            if r >= 0:
                                hist[r] += 1
                                if r >= minrec:
                                    fast, slow = (an, bn) if order == 0 else (bn, an)
                                    hits.append((r, mode, vn, "fast first" if order == 0 else "slow first",
                                                 "%+d%+d" % (e1, e2), fast, slow))
    return len(views) * len(orders) * len(signs) * len(fasts) * len(slows)


def views(ct, cribs):
    return [("pt%s/ct%s" % (an, bn), [a.index(cribs[i]) for i in POS], [b.index(ct[i]) for i in POS])
            for an, a in ALPH for bn, b in ALPH]


def block_slows(mode):
    """Slow rotor constant inside each clue block. H: only the difference d matters (a common
    turn just renames the contacts). B: the start position matters too."""
    if mode == "H":
        return [("slow: block 2 is %d on" % d, [d * b for b in BLK]) for d in range(26)]
    return [("slow: start %d, block 2 is %d on" % (t0, d), [t0 + d * b for b in BLK])
            for t0 in range(26) for d in range(26)]


def word_slows(mode):
    if mode == "H":
        return block_slows("H")
    return ([("slow: start %d, block 2 is 0 on" % t0, [t0] * 24) for t0 in range(26)] +
            [("slow: start 0, block 2 is %d on" % d, [d * b for b in BLK]) for d in range(1, 26)])


def per_pass(p):
    return ("slow: one step per pass of the key", [i // p for i in POS])


def small_slows(mode):
    out = []
    if mode == "H":
        for j1 in range(13):                 # step after the j1-th letter of block 1 (0 = none)
            for j2 in range(11):
                for d in range(26):
                    t = [1 if j1 and j >= j1 else 0 for j in range(13)] + \
                        [d + (1 if j2 and j >= j2 else 0) for j in range(11)]
                    out.append(("slow: block 2 is %d on, steps inside blocks at %d/%d" % (d, j1, j2), t))
        starts = (0,)
    else:
        out += block_slows("B")
        starts = range(26)
    for t0 in starts:
        for L in range(2, 13):
            for off in range(L):
                out.append(("slow: start %d, steps every %d letters (offset %d)" % (t0, L, off),
                            [t0 + (i + off) // L for i in POS]))
        for b in range(1, 26):
            out.append(("slow: start %d, speed %d" % (t0, b), [t0 + b * i for i in POS]))
    return out


def small_fasts(ct):
    out = [("speed %d" % a, [a * i % 26 for i in POS]) for a in range(26)]
    for nn, num in ALPH:
        cum, t = [], 0
        for ch in ct:
            cum.append(t % 26)
            t += num.index(ch)
        out.append(("previous cipher letter (%s)" % nn, [num.index(ct[i - 1]) for i in POS]))
        out.append(("running sum of cipher text (%s)" % nn, [cum[i] for i in POS]))
    return out


def word_fasts(w):
    p, out = len(w), []
    for nn, num in ALPH:
        vals = [num.index(ch) for ch in w]
        run, t = [], 0
        for i in range(74):
            t = (t + vals[i % p]) % 26
            run.append(t)
        out.append(("word %s (%s)" % (w, nn), [vals[i % p] for i in POS]))
        out.append(("sliding word %s (%s)" % (w, nn), [run[i] for i in POS]))
        out.append(("word + 1 per letter %s (%s)" % (w, nn), [(vals[i % p] + i) % 26 for i in POS]))
    return out


def init(ct, cribs):
    _S["ct"] = ct
    _S["v"] = views(ct, cribs)
    _S["slow"] = {(m, k): f(m) for m in "HB" for k, f in (("small", small_slows), ("word", word_slows))}


def work_small(chunk):
    out = []
    for mode, idx in chunk:
        hist, hits = collections.Counter(), []
        fasts = small_fasts(_S["ct"])[idx:idx + 1]
        n = sweep(mode, fasts, _S["slow"][mode, "small"], ALL_SIGNS, (0, 1) if mode == "H" else (0,), _S["v"],
                  MIN[mode, "small"], hist, hits)
        out.append((mode, "small", n, hist, hits))
    return out


def work_words(chunk):
    out = []
    for mode in "HB":
        hist, hits, n = collections.Counter(), [], 0
        fasts = [f for w in chunk for f in word_fasts(w)]
        n += sweep(mode, fasts, _S["slow"][mode, "word"], PLUS, (0,), _S["v"], MIN[mode, "words"], hist, hits)
        for w in chunk:
            n += sweep(mode, word_fasts(w), [per_pass(len(w))], PLUS, (0,), _S["v"], MIN[mode, "words"], hist, hits)
        out.append((mode, "words", n, hist, hits))
    return out


def work_keys(chunk):
    """Every key of a given length. H: first letter 0 (a constant only renames the contacts).
    B: all 26^p keys, slow strip starting at 0 (the same thing as every start position)."""
    out = []
    for mode, p, head in chunk:
        hist, hits = collections.Counter(), []
        slot = [i % p for i in POS]
        fasts = []
        for tail in itertools.product(range(26), repeat=p - len(head)):
            key = head + tail
            fasts.append(("key " + "".join(AZ[x] for x in key), [key[r] for r in slot]))
        full = p <= KFULL[mode]
        slows = (block_slows("H") if mode == "H" else [("slow: start 0, block 2 is %d on" % d, [d * b for b in BLK])
                                                       for d in range(26)]) + [per_pass(p)]
        n = sweep(mode, fasts, slows, ALL_SIGNS if full else PLUS, (0, 1) if full and mode == "H" else (0,),
                  _S["v"], MIN[mode, "keys"], hist, hits)
        out.append((mode, "keys", n, hist, hits))
    return out


def key_jobs(only=None, third=None, maxp=None):
    jobs = []
    for mode in "HB":
        for p in range(1, KMAX[mode] + 1):
            free = p - 1 if mode == "H" else p           # letters that are really searched
            fix = (0,) if mode == "H" else ()
            nhead = max(0, min(free, free - 2))          # leave two letters to the worker
            for h in itertools.product(range(26), repeat=nhead):
                jobs.append((mode, p, fix + h))
    jobs = [j for j in jobs if (only is None or j[0] in only) and (maxp is None or j[1] <= maxp)]
    if third is not None:                                # controls: a third of the long keys
        short = [j for j in jobs if j[1] <= KFULL[j[0]]]
        jobs = short + [j for j in jobs if j[1] > KFULL[j[0]]][third::3]
    return jobs


def search(ct, cribs, words, parts=("small", "keys", "words"), modes="HB", third=None, maxp=None):
    """Returns (settings tested, {(mode, family): Counter(loops -> surviving settings)}, hits)."""
    n, hist, hits = 0, collections.defaultdict(collections.Counter), []

    def take(results):
        nonlocal n
        for chunk in results:
            for mode, fam, k, h, hh in chunk:
                if mode in modes:
                    n += k
                    hist[mode, fam].update(h)
                    hits.extend(hh)
    if "small" in parts:
        take(pmap(work_small, [(m, i) for m in modes for i in range(30)], init, (ct, cribs), chunk=1))
    if "keys" in parts:
        take(pmap(work_keys, key_jobs(modes, third, maxp), init, (ct, cribs), chunk=8))
    if "words" in parts:
        take(pmap(work_words, words, init, (ct, cribs), chunk=400))
    return n, hist, hits


# ---- form B survivors: build the strip and read the whole message ----------------------------------

def full_streams(hit, ct):
    """The turns of both rotors at all 97 places for a hit, as a list of (s, t) (more than one
    when the slow rotor moves at an unknown place between the clues). None if not rebuilt."""
    fast, slow = hit[5], hit[6]
    num = dict(ALPH)
    m = re.match(r"(word|sliding word|word \+ 1 per letter) (\w+) \((\w\w)\)$", fast)
    if m:
        vals = [num[m.group(3)].index(ch) for ch in m.group(2)]
        p = len(vals)
        if m.group(1) == "word":
            s = [vals[i % p] for i in range(97)]
        elif m.group(1) == "sliding word":
            s, t = [], 0
            for i in range(97):
                t = (t + vals[i % p]) % 26
                s.append(t)
        else:
            s = [(vals[i % p] + i) % 26 for i in range(97)]
    elif fast.startswith("key "):
        vals = [AZ.index(ch) for ch in fast[4:]]
        p = len(vals)
        s = [vals[i % p] for i in range(97)]
    elif fast.startswith("speed "):
        a = int(fast[6:])
        s = [a * i % 26 for i in range(97)]
    elif fast.startswith("previous cipher letter"):
        a = num[fast[-3:-1]]
        s = [a.index(ct[i - 1]) for i in range(97)]
    elif fast.startswith("running sum"):
        a = num[fast[-3:-1]]
        s, t = [], 0
        for ch in ct:
            s.append(t % 26)
            t += a.index(ch)
    else:
        return None
    m = re.match(r"slow: start (\d+), block 2 is (\d+) on$", slow)
    if m:
        t0, d = int(m.group(1)), int(m.group(2))
        if d == 0:
            return [(s, [t0] * 97)]
        return [(s, [t0] * j + [t0 + d] * (97 - j)) for j in range(34, 64)]     # one jump, place unknown
    if slow == "slow: one step per pass of the key":
        return [(s, [i // p for i in range(97)])]
    m = re.match(r"slow: start (\d+), steps every (\d+) letters \(offset (\d+)\)$", slow)
    if m:
        t0, L, off = (int(x) for x in m.groups())
        return [(s, [t0 + (i + off) // L for i in range(97)])]
    m = re.match(r"slow: start (\d+), speed (\d+)$", slow)
    if m:
        t0, b = int(m.group(1)), int(m.group(2))
        return [(s, [t0 + b * i for i in range(97)])]
    return None


def read_score(pt, big):
    """Big-model score per quadgram over the stretches that are known; -99 if under 15 quadgrams."""
    q = [pt[i:i + 4] for i in range(len(pt) - 3) if "?" not in pt[i:i + 4]]
    return sum(big.logp.get(x, big.floor) for x in q) / len(q) if len(q) >= 15 else -99.0


def complete(hit, ct, cribs, big):
    """Build the strip for a form B survivor and read the message: (best English score, text with
    ? where the strip is unknown, number of strips that fit). 0 strips = the setting is dead."""
    num = dict(ALPH)
    a, b = num[hit[2][2:4]], num[hit[2][7:9]]
    e1, e2 = int(hit[4][:2]), int(hit[4][2:])
    cv = [b.index(ch) for ch in ct]
    best, n = (-99.0, ""), 0
    for s, t in full_streams(hit, ct) or []:
        us = [(a.index(cribs[i]) + s[i]) % 26 for i in POS]
        vs = [(cv[i] + e2 * t[i]) % 26 for i in POS]
        r = back_pieces(us, vs, [e1 * s[i] - t[i] for i in POS])
        if r is None:
            continue
        for w in back_wirings(r[1]):
            n += 1
            pt = "".join("?" if x is None else a[x] for x in back_decrypt(w, cv, s, t, e1, e2))
            best = max(best, (read_score(pt, big), pt))
    return best[0], best[1], n


def complete_all(hits, ct, cribs, big, limit=200000):
    """Complete the form B survivors (most loops first). Returns [(score, text, hit)] for those
    with at least one strip that fits, best first."""
    out = []
    for h in sorted((h for h in hits if h[1] == "B"), reverse=True)[:limit]:
        sc, pt, n = complete(h, ct, cribs, big)
        if n:
            out.append((sc, pt, h))
    return sorted(out, reverse=True)


def same_text(got, pt, hit):
    """True if every letter that was read is right and at least half the message was read. When
    the slow rotor moves between the clues the place is not part of the setting (the reading
    tries every place), so the 29 letters between the clues are not held against it."""
    free = range(34, 63) if re.search(r"block 2 is [1-9]", hit[6]) else ()
    return (len(got) == len(pt) and all(g in ("?", p) or i in free for i, (g, p) in enumerate(zip(got, pt)))
            and got.count("?") < len(pt) / 2)


# ---- planted messages -------------------------------------------------------------------------

def wirings(rng, mode):
    r1 = list(range(26))
    rng.shuffle(r1)
    if mode == "B":
        r2 = [0] * 26
        for i, x in enumerate(r1):
            r2[x] = i
    else:
        r2 = list(range(26))
        rng.shuffle(r2)
    return r1, r2


def draw(rng, words, mode, kind):
    """One random true setting of the given kind: (fast name, slow name, s, t) over all 97 places."""
    d = rng.randrange(26)
    blk = [0] * 34 + [d] * 63                    # the slow rotor moves somewhere between the clues
    slow = "slow: block 2 is %d on" % d if mode == "H" else "slow: start 0, block 2 is %d on" % d
    if kind == "word":
        w = rng.choice([x for x in words if 5 <= len(x) <= 9])
        return "word %s (AZ)" % w, slow, [AZ.index(w[i % len(w)]) for i in range(97)], blk
    if kind == "key":
        p = 3
        key = [0 if mode == "H" else rng.randrange(26)] + [rng.randrange(26) for _ in range(p - 1)]
        if SMOKE and mode == "B":
            key = key[:2]
        return "key " + "".join(AZ[x] for x in key), slow, [key[i % len(key)] for i in range(97)], blk
    a = rng.randrange(1, 26)                     # constant speed, slow rotor steps every L letters
    L, off = rng.randrange(5, 13), 0
    return ("speed %d" % a, "slow: start 0, steps every %d letters (offset %d)" % (L, off),
            [a * i % 26 for i in range(97)], [(i + off) // L for i in range(97)])


def plant(rng, words, mode, kind, need=None):
    """A planted message whose true setting makes at least `need` loops (default: the hit
    threshold). Returns (ct, cribs, wanted hit, loops, draws used, plaintext)."""
    fam = {"word": "words", "key": "keys", "speed": "small"}[kind]
    need = MIN[mode, fam] if need is None else need
    for tries in range(1, 100000):
        fast, slow, s, t = draw(rng, words, mode, kind)
        pt = english97(rng)
        r1, r2 = wirings(rng, mode)
        cv = rotor_encrypt([AZ.index(ch) for ch in pt], r1, r2, s, t)
        ct = "".join(AZ[x] for x in cv)
        r = FN[mode]([(AZ.index(pt[i]) + s[i]) % 26 for i in POS], [(cv[i] + t[i]) % 26 for i in POS],
                     [s[i] - t[i] for i in POS])
        assert r >= 0, "a true setting must always pass"
        if r >= need:
            return ct, {i: pt[i] for i in POS}, (mode, "ptAZ/ctAZ", "fast first", "+1+1", fast, slow), r, tries, pt
    raise RuntimeError("no decidable planted setting")


def decidable(rng, words, mode, kind, n):
    """Share of random true settings of this kind that reach the hit threshold."""
    fam = {"word": "words", "key": "keys", "speed": "small"}[kind]
    ok = 0
    for _ in range(n):
        ok += plant(rng, words, mode, kind, need=0)[3] >= MIN[mode, fam]
    return ok / n


def encrypt(pt, rng):
    """For the clue pre-filter: a two-rotor message with a key drawn from rng only."""
    r1, r2 = wirings(rng, "H")
    key = [rng.randrange(26) for _ in range(rng.randrange(5, 10))]
    d = rng.randrange(26)
    n = len(pt)
    cv = rotor_encrypt([AZ.index(ch) for ch in pt], r1, r2, [key[i % len(key)] for i in range(n)],
                       [0 if i < n // 2 else d for i in range(n)])
    return "".join(AZ[x] for x in cv)


def table(hist):
    out = []
    for key in sorted(hist):
        h = hist[key]
        out.append("%s/%s: %s" % (key[0], key[1], " ".join("%d:%d" % (k, h[k]) for k in sorted(h)) or "none"))
    return out


def best(hits, mode):
    return max((h[0] for h in hits if h[1] == mode), default=0)


if __name__ == "__main__":
    words = sorted(set(w for w in vocabulary() if 2 <= len(w) <= 22))
    if SMOKE:
        words = words[:3000]
    with Experiment("two paper rotors in series, hidden wirings (and one strip there and back)", puzzle="k4",
                    notes="loop test on the contact graph, no wiring guessed; fast = 26 speeds, cipher feeds, "
                          "%d words x 6, keys to length %d (H) / %d (B); slow = constant per clue block "
                          "(d 0-25), one step per key pass, rare steps; A-Z/KRYPTOS faces"
                          % (len(words), KMAX["H"], KMAX["B"]), cribs_forced=True) as ex:
        n, hist, hits = search(K4, CRIBS, words)
        ex.count(n)
        print("two-rotor settings tested on K4: %d" % n)
        print("K4, surviving settings by number of loops (loops:settings):")
        for line in table(hist):
            print("   " + line)
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        hh = [h for h in hits if h[1] == "H"]
        print("form H, K4 hits (%d or more loops): %d" % (MIN["H", "words"], len(hh)))
        for h in sorted(hh, reverse=True)[:20]:
            print("   loops=%d form %s %s, %s, directions %s, %s, %s" % h)
        done = complete_all(hits, K4, CRIBS, big)
        nb = sum(h[1] == "B" for h in hits)
        print("form B, K4 survivors with %d or more loops: %d; their wiring pieces fit on one strip: %d"
              % (MIN["B", "words"], nb, len(done)))
        for sc, pt, h in done[:8]:
            print("   english %.2f words %.2f loops=%d %s, %s, %s, %s, %s\n      %s"
                  % (sc, word_coverage(pt), h[0], h[2], h[4], h[5], h[6], h[3], pt))
            ex.add(pt, form="B", english_big=round(sc, 3), setting=" | ".join(h[2:]))
        kb = done[0][0] if done else -99.0
        ctrl, cbs = [], []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            # each shuffled K4 gets the small families and the shorter keys in full, and a different
            # third of the words and of the longest keys
            sct = shuffled_control(seed)
            cn, ch, chits = search(sct, CRIBS, words[seed % 3::3], third=seed % 3)
            cdone = complete_all(chits, sct, CRIBS, big)
            ctrl.append(chits)
            cbs.append(cdone[0][0] if cdone else -99.0)
            print("shuffled K4 seed %d (%d settings): form H hits %d; form B survivors %d, fit on one strip %d, "
                  "best english %.2f" % (seed, cn, sum(h[1] == "H" for h in chits),
                                         sum(h[1] == "B" for h in chits), len(cdone), cbs[-1]))
            for line in table(ch):
                print("   " + line)
        rng = random.Random(82)
        print("share of true settings that reach the threshold (random draws):")
        for mode in "HB":
            for kind in ("speed", "key", "word"):
                print("   form %s, %s: %.1f%%" % (mode, kind, 100 * decidable(rng, words, mode, kind, 300 if SMOKE else 3000)))
        ok = tot = 0
        sample = words[::40]
        for mode in "HB":
            for kind in ("word", "key", "speed"):
                ct, cribs, want, r, tries, pt = plant(rng, words, mode, kind)
                part = {"word": "words", "key": "keys", "speed": "small"}[kind]
                ws = sorted(set(sample + [want[4].split()[1]])) if kind == "word" else []
                h = search(ct, cribs, ws, parts=(part,), modes=mode, maxp=KFULL[mode])[2]
                found = any(x[1:] == want for x in h)
                note = ""
                if mode == "B":                  # the message itself must come back, and score as English
                    pdone = complete_all(h, ct, cribs, big)
                    right = bool(pdone) and same_text(pdone[0][1], pt, pdone[0][2])
                    found = found and right and pdone[0][0] > ENGLISH
                    note = "; %d fit on one strip; best reading english %.2f, is the planted text: %s (%d of 97 letters read)" % (
                        len(pdone), pdone[0][0] if pdone else -99, right, 97 - pdone[0][1].count("?") if pdone else 0)
                ok += found
                tot += 1
                print("planted form %s: %s, %s (loops %d, draw %d) -> found=%s; settings over threshold %d%s"
                      % (mode, want[4], want[5], r, tries, found, len(h), note))
        print("planted recovered: %d/%d" % (ok, tot))
        hk, hc = best(hits, "H"), max(best(c, "H") for c in ctrl)
        beats = (hk > hc + 1) or (kb > ENGLISH and kb > max(cbs) + 0.3)
        print("VERDICT:", ("K4 beats every control - inspect; " if beats else "no signal; ") +
              "form H: K4 %d hits (best loops %d), shuffled %s; form B: K4 %d survivors, %d fit on one strip, "
              "best english %.2f; shuffled best english %s (-99 = none fit; English needs %.1f)"
              % (len(hh), hk, [sum(h[1] == "H" for h in c) for c in ctrl], nb, len(done), kb,
                 ["%.2f" % x for x in cbs], ENGLISH))
