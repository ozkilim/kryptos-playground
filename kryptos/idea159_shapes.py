"""Idea 159: letter shapes. Three fixed shape codings of the 26 capitals, the statistics of part A
(are the clue pairs closer in shape than chance, and than alphabet closeness explains), and the
two-systems-by-place model of part B (shape change at pattern places, an ordinary repeating key elsewhere).

The codings are written out once, here, in their common textbook form, and are not tuned:

  SEG16   the 16-segment display (top and bottom bars are two segments each)
  DOT57   the 5x7 dot matrix of character LCDs
  STROKE  a stroke list for sans-serif block capitals (stencil letters): each letter is a set of named strokes

Distance = number of segments / dots / strokes present in one letter and not the other.
"One stroke" is fixed per coding before any test: SEG16 <= 2 segments (one full bar), DOT57 <= 5 dots (one
row of dots), STROKE <= 1 stroke.
"""
import bisect
import random
from itertools import combinations

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import DATA_DIR
from .score import Quadgrams

# ------------------------------------------------------------------ the three codings

_SEG = {
    "A": "A1 A2 B C E F G1 G2", "B": "A1 A2 B C D1 D2 I L G2", "C": "A1 A2 D1 D2 E F",
    "D": "A1 A2 B C D1 D2 I L", "E": "A1 A2 D1 D2 E F G1", "F": "A1 A2 E F G1",
    "G": "A1 A2 C D1 D2 E F G2", "H": "B C E F G1 G2", "I": "A1 A2 D1 D2 I L", "J": "B C D1 D2 E",
    "K": "E F G1 J M", "L": "D1 D2 E F", "M": "B C E F H J", "N": "B C E F H M",
    "O": "A1 A2 B C D1 D2 E F", "P": "A1 A2 B E F G1 G2", "Q": "A1 A2 B C D1 D2 E F M",
    "R": "A1 A2 B E F G1 G2 M", "S": "A1 A2 F G1 G2 C D1 D2", "T": "A1 A2 I L", "U": "B C D1 D2 E F",
    "V": "E F K J", "W": "B C E F K M", "X": "H J K M", "Y": "H J L", "Z": "A1 A2 J K D1 D2",
}
SEG16 = {ch: frozenset(s.split()) for ch, s in _SEG.items()}

_DOT = {
    "A": ".###. #...# #...# #...# ##### #...# #...#", "B": "####. #...# #...# ####. #...# #...# ####.",
    "C": ".###. #...# #.... #.... #.... #...# .###.", "D": "###.. #..#. #...# #...# #...# #..#. ###..",
    "E": "##### #.... #.... ####. #.... #.... #####", "F": "##### #.... #.... ####. #.... #.... #....",
    "G": ".###. #...# #.... #.### #...# #...# .####", "H": "#...# #...# #...# ##### #...# #...# #...#",
    "I": ".###. ..#.. ..#.. ..#.. ..#.. ..#.. .###.", "J": "..### ...#. ...#. ...#. ...#. #..#. .##..",
    "K": "#...# #..#. #.#.. ##... #.#.. #..#. #...#", "L": "#.... #.... #.... #.... #.... #.... #####",
    "M": "#...# ##.## #.#.# #.#.# #...# #...# #...#", "N": "#...# #...# ##..# #.#.# #..## #...# #...#",
    "O": ".###. #...# #...# #...# #...# #...# .###.", "P": "####. #...# #...# ####. #.... #.... #....",
    "Q": ".###. #...# #...# #...# #.#.# #..#. .##.#", "R": "####. #...# #...# ####. #.#.. #..#. #...#",
    "S": ".#### #.... #.... .###. ....# ....# ####.", "T": "##### ..#.. ..#.. ..#.. ..#.. ..#.. ..#..",
    "U": "#...# #...# #...# #...# #...# #...# .###.", "V": "#...# #...# #...# #...# #...# .#.#. ..#..",
    "W": "#...# #...# #...# #.#.# #.#.# #.#.# .#.#.", "X": "#...# #...# .#.#. ..#.. .#.#. #...# #...#",
    "Y": "#...# #...# #...# .#.#. ..#.. ..#.. ..#..", "Z": "##### ....# ...#. ..#.. .#... #.... #####",
}
DOT57 = {ch: frozenset(i for i, x in enumerate(s.replace(" ", "")) if x == "#") for ch, s in _DOT.items()}

# strokes: LV RV CV full verticals (left, right, centre); TB MB BB bars (top, middle, bottom);
# UB LB upper / lower bowl on a stem; DB the big bowl of D; RING the closed round; ARC the open round of C;
# SPUR the bar of G; TAIL of Q; LEG the lower-right diagonal of R and K; ARM the upper-right diagonal of K;
# AL AR the two sides of A; VL VR the two sides of V; M1 M2 the inner V of M; W1-W4 the four strokes of W;
# DN the falling diagonal (N, X), UP the rising diagonal (X, Z); YL YR YS the arms and stem of Y;
# HOOK of J; CUP the bottom curve of U; SS the S curve.
_STR = {
    "A": "AL AR MB", "B": "LV UB LB", "C": "ARC", "D": "LV DB", "E": "LV TB MB BB", "F": "LV TB MB",
    "G": "ARC SPUR", "H": "LV RV MB", "I": "CV", "J": "RV HOOK", "K": "LV ARM LEG", "L": "LV BB",
    "M": "LV RV M1 M2", "N": "LV RV DN", "O": "RING", "P": "LV UB", "Q": "RING TAIL", "R": "LV UB LEG",
    "S": "SS", "T": "CV TB", "U": "LV RV CUP", "V": "VL VR", "W": "W1 W2 W3 W4", "X": "DN UP",
    "Y": "YL YR YS", "Z": "TB UP BB",
}
STROKE = {ch: frozenset(s.split()) for ch, s in _STR.items()}

CODINGS = {"SEG16": (SEG16, 2), "DOT57": (DOT57, 5), "STROKE": (STROKE, 1)}
NAMES = list(CODINGS)


def dist_table(name):
    code = CODINGS[name][0]
    return {a + b: len(code[a] ^ code[b]) for a in AZ for b in AZ}


DIST = {n: dist_table(n) for n in NAMES}
THR = {n: CODINGS[n][1] for n in NAMES}
NEAR = {n: {a: "".join(b for b in AZ if DIST[n][a + b] <= THR[n]) for a in AZ} for n in NAMES}


def near(name, a, b):
    return DIST[name][a + b] <= THR[name]


def near_pairs(name):
    """The unordered pairs of different letters within one stroke."""
    return [a + b for a, b in combinations(AZ, 2) if near(name, a, b)]


def alpha_dist(a, b):
    d = (AZ.index(a) - AZ.index(b)) % 26
    return min(d, 26 - d)


# ------------------------------------------------------------------ part A: the statistic

STATS = [(n, k) for n in NAMES for k in ("near", "mean")]   # six statistics, 'near' high = odd, 'mean' low = odd


def stats(pairs):
    """pairs: [(plain, cipher)]. Six numbers in the order of STATS; all turned so that HIGH is odd."""
    out = []
    for n in NAMES:
        d = DIST[n]
        ds = [d[p + c] for p, c in pairs]
        out.append(sum(x <= THR[n] for x in ds))
        out.append(-sum(ds) / len(ds))
    return out


def _bin(d):
    return 0 if d == 0 else 1 if d <= 2 else 2 if d <= 5 else 3


def profile(pairs):
    h = [0, 0, 0, 0]
    for p, c in pairs:
        h[_bin(alpha_dist(p, c))] += 1
    return tuple(h)


def null_permute(pairs, rng, n):
    """Control (i): the same plain and cipher letters, paired at random."""
    pl, cl = [p for p, _ in pairs], [c for _, c in pairs]
    for _ in range(n):
        rng.shuffle(cl)
        yield list(zip(pl, cl))


def null_sign(pairs, rng, n):
    """Control (ii-a): same plain letter, same alphabet distance, the direction (+ or -) at random."""
    base = [(p, AZ.index(p), alpha_dist(p, c)) for p, c in pairs]
    for _ in range(n):
        yield [(p, AZ[(i + (d if rng.random() < 0.5 else -d)) % 26]) for p, i, d in base]


def null_any_letter(pairs, rng, n):
    """Control (ii-b): any letter of the alphabet, moved by the same alphabet distance in a random direction."""
    ds = [alpha_dist(p, c) for p, c in pairs]
    for _ in range(n):
        out = []
        for d in ds:
            i = rng.randrange(26)
            out.append((AZ[i], AZ[(i + (d if rng.random() < 0.5 else -d)) % 26]))
        yield out


def null_matched(pairs, rng, n, thin=40, burn=4000):
    """Control (ii-c): the same plain and cipher letters, paired at random among the pairings that have the
    same alphabet-distance profile as the real one (how many pairs at distance 0, 1-2, 3-5, 6-13).
    A Markov chain over pairings: swap two or cycle three cipher letters, keep the move if the profile holds."""
    pl, cl = [p for p, _ in pairs], [c for _, c in pairs]
    m = len(pl)
    b = [_bin(alpha_dist(p, c)) for p, c in zip(pl, cl)]
    steps = 0
    made = 0
    while made < n:
        if rng.random() < 0.5:
            i, j = rng.sample(range(m), 2)
            ni, nj = _bin(alpha_dist(pl[i], cl[j])), _bin(alpha_dist(pl[j], cl[i]))
            if sorted((ni, nj)) == sorted((b[i], b[j])):
                cl[i], cl[j] = cl[j], cl[i]
                b[i], b[j] = ni, nj
        else:
            i, j, k = rng.sample(range(m), 3)
            ni, nj, nk = (_bin(alpha_dist(pl[i], cl[j])), _bin(alpha_dist(pl[j], cl[k])),
                          _bin(alpha_dist(pl[k], cl[i])))
            if sorted((ni, nj, nk)) == sorted((b[i], b[j], b[k])):
                cl[i], cl[j], cl[k] = cl[j], cl[k], cl[i]
                b[i], b[j], b[k] = ni, nj, nk
        steps += 1
        if steps > burn and steps % thin == 0:
            made += 1
            yield list(zip(pl, cl))


def p_values(obs, sample):
    """obs: six numbers (high = odd); sample: list of six-number lists from a null.
    Returns (p per statistic, corrected p for the smallest of the six, null means)."""
    n = len(sample)
    cols = [sorted(row[j] for row in sample) for j in range(len(obs))]

    def tail(j, x):          # share of the null at or above x
        return (n - bisect.bisect_left(cols[j], x - 1e-12)) / n

    ps = [(1 + round(tail(j, obs[j]) * n)) / (1 + n) for j in range(len(obs))]
    floor = min(tail(j, obs[j]) for j in range(len(obs)))
    hits = sum(1 for row in sample if min(tail(j, row[j]) for j in range(len(obs))) <= floor + 1e-12)
    return ps, (1 + hits) / (1 + n), [sum(c) / n for c in cols]


# ------------------------------------------------------------------ part B1: do the near places form a pattern?

def pattern_stat(flags, places, periods=range(2, 32)):
    """flags[i] true if clue place places[i] is shape-near. For each period: the number of near places that sit
    in a residue class holding at least two clue places, all of them near. Returns (best, {period: count})."""
    per = {}
    for p in periods:
        cls = {}
        for f, i in zip(flags, places):
            cls.setdefault(i % p, []).append(f)
        per[p] = sum(len(v) for v in cls.values() if len(v) >= 2 and all(v))
    return max(per.values()), per


def perfect_periods(flags, places, periods=range(2, 14)):
    """Periods at which every residue class is all near or all not near (and at least one is all near)."""
    out = []
    for p in periods:
        cls = {}
        for f, i in zip(flags, places):
            cls.setdefault(i % p, []).append(f)
        if all(all(v) or not any(v) for v in cls.values()) and any(all(v) for v in cls.values()):
            out.append(p)
    return out


# ------------------------------------------------------------------ part B2: mask + repeating key, exact clue test

LAYOUTS = [("AZ/AZ", AZ, AZ), ("KR/KR", KRYPTOS_ALPHABET, KRYPTOS_ALPHABET),
           ("AZ/KR", AZ, KRYPTOS_ALPHABET), ("KR/AZ", KRYPTOS_ALPHABET, AZ)]   # plain strip / cipher strip
SIGNS = [("vig", 1), ("beau", -1)]
PERIODS = range(2, 14)      # mask period
KEYLENS = range(1, 13)      # key length at the unmasked places
MODES = ("abs", "skip")     # key letter by position in the text / by count of unmasked letters


def key_index(n, p, classes, L, mode):
    """Key index for every position (None at masked places)."""
    out, c = [], 0
    for i in range(n):
        if i % p in classes:
            out.append(None)
        else:
            out.append((i if mode == "abs" else c) % L)
            c += 1
    return out


def masks(ct, cribs, coding):
    """(period, classes) for every non-empty set of residue classes whose clue places are all shape-near
    (classes without a clue place cannot be judged and are left out)."""
    for p in PERIODS:
        cls = {}
        for i, ch in cribs.items():
            cls.setdefault(i % p, []).append(near(coding, ch, ct[i]))
        pure = sorted(r for r, v in cls.items() if all(v))
        for k in range(1, len(pure) + 1):
            for sub in combinations(pure, k):
                yield p, frozenset(sub)


def clue_test(ct, cribs, coding, min_checks=2):
    """Every setting whose key letters at the unmasked clue places agree. Returns (tested, judged, survivors);
    survivor = (checks, coding, period, classes, L, mode, layout, sign, {key index: value})."""
    n = len(ct)
    tested = judged = 0
    out = []
    kv = {}
    for lname, pa, ca in LAYOUTS:
        for sname, s in SIGNS:
            kv[lname, sname] = {i: (ca.index(ct[i]) - s * pa.index(ch)) % 26 for i, ch in cribs.items()}
    for p, classes in masks(ct, cribs, coding):
        open_places = [i for i in sorted(cribs) if i % p not in classes]
        for L in KEYLENS:
            for mode in MODES:
                if mode == "skip" and L == 1:
                    continue        # same as abs
                ki = key_index(n, p, classes, L, mode)
                checks = len(open_places) - len({ki[i] for i in open_places})
                for (lname, sname), k in kv.items():
                    tested += 1
                    if checks < min_checks:
                        continue
                    judged += 1
                    key, ok = {}, True
                    for i in open_places:
                        if key.setdefault(ki[i], k[i]) != k[i]:
                            ok = False
                            break
                    if ok:
                        out.append((checks, coding, p, tuple(sorted(classes)), L, mode, lname, sname, key))
    return tested, judged, out


_BIG = None


def big():
    global _BIG
    if _BIG is None:
        _BIG = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    return _BIG


def viterbi(cands, model=None):
    """cands: one string of allowed letters per position. Best text by the sum of quadgram log-probabilities.
    Returns (mean log10 per quadgram, text)."""
    model = model or big()
    get, fl = model.logp.get, model.floor
    states = {"": (0.0, "")}
    for opts in cands:
        new = {}
        for ctx, (sc, txt) in states.items():
            for ch in opts:
                q = ctx + ch
                s2 = sc + (get(q, fl) if len(q) == 4 else 0.0)
                key = q[-3:]
                if key not in new or s2 > new[key][0]:
                    new[key] = (s2, txt + ch)
        states = new
    sc, txt = max(states.values())
    return sc / max(1, len(cands) - 3), txt


def complete(ct, cribs, surv, model=None):
    """Read the whole text for one surviving setting: unmasked places by the key (unknown key letters by
    hill climbing), masked places by choice among the shape neighbours. Returns (score, text, unknown keys)."""
    _, coding, p, classes, L, mode, lname, sname, key = surv
    pa, ca = next((a, b) for nm, a, b in LAYOUTS if nm == lname)
    s = dict(SIGNS)[sname]
    ki = key_index(len(ct), p, set(classes), L, mode)
    key = dict(key)
    unknown = sorted({k for k in ki if k is not None} - set(key))

    def cands():
        out = []
        for i, ch in enumerate(ct):
            if i in cribs:
                out.append(cribs[i])
            elif ki[i] is None:
                out.append(NEAR[coding][ch])
            elif ki[i] in key:
                out.append(pa[(s * (ca.index(ch) - key[ki[i]])) % 26])
            else:
                out.append(AZ)
        return out

    if len(unknown) > 4:        # too little is fixed for a hill climb to mean anything: leave those free
        sc, txt = viterbi(cands(), model)
        return sc, txt, len(unknown)
    for u in unknown:
        key[u] = 0
    best = viterbi(cands(), model)
    for _ in range(2 if unknown else 0):
        for u in unknown:
            keep = key[u]
            for v in range(26):
                key[u] = v
                t = viterbi(cands(), model)
                if t[0] > best[0]:
                    best, keep = t, v
            key[u] = keep
    return best[0], best[1], len(unknown)


def encrypt(pt, rng, coding="STROKE", p=3, classes=None, L=None, mode=None, layout=None, sign=None, change=0.8):
    """Two systems by place: at masked places the letter gains or loses at most one stroke, elsewhere a
    repeating key. Everything not given is drawn from rng. Returns (ct, setting)."""
    classes = classes if classes is not None else {rng.randrange(p)}
    L = L or rng.randrange(4, 9)
    mode = mode or rng.choice(MODES)
    lname, pa, ca = layout or rng.choice(LAYOUTS)
    sname, s = sign or rng.choice(SIGNS)
    key = [rng.randrange(26) for _ in range(L)]
    ki = key_index(len(pt), p, set(classes), L, mode)
    out = []
    for i, ch in enumerate(pt):
        if ki[i] is None:
            nb = [x for x in NEAR[coding][ch] if x != ch]
            out.append(rng.choice(nb) if nb and rng.random() < change else ch)
        else:
            out.append(ca[(s * pa.index(ch) + key[ki[i]]) % 26])
    return "".join(out), (coding, p, tuple(sorted(classes)), L, mode, lname, sname)


def attack(ct, cribs, model=None, min_checks=2, strong=5):
    """Clue test over the three codings, then every survivor read. Returns a dict."""
    tested = judged = 0
    reads = []
    for coding in NAMES:
        t, j, sv = clue_test(ct, cribs, coding, min_checks)
        tested += t
        judged += j
        for s in sv:
            sc, txt, unk = complete(ct, cribs, s, model)
            reads.append((sc, txt, s[:8], unk))
    reads.sort(key=lambda r: -r[0])
    return {"tested": tested, "judged": judged, "survivors": len(reads),
            "strong": [r for r in reads if r[2][0] >= strong], "reads": reads}


def shuffle_pairs(ct, cribs, seed):
    """Second control: the 24 clue pairs keep their letters but change places among the 24 clue places;
    the other 73 cipher letters are shuffled. Returns (ct, cribs)."""
    rng = random.Random(seed)
    places = sorted(cribs)
    pairs = [(cribs[i], ct[i]) for i in places]
    rng.shuffle(pairs)
    rest = [ct[i] for i in range(len(ct)) if i not in cribs]
    rng.shuffle(rest)
    out, it = list(ct), iter(rest)
    new = {}
    for i in range(len(ct)):
        if i not in cribs:
            out[i] = next(it)
    for i, (p, c) in zip(places, pairs):
        out[i] = c
        new[i] = p
    return "".join(out), new


# ------------------------------------------------------------------ part B3: ANY mask among the near clue places

def free_mask_test(ct, cribs, coding, min_checks=4, blocks=None):
    """No pattern assumed: any non-empty set of shape-near clue places may be the masked ones; the other clue
    places must fit one repeating key (length 1-12). 'abs' numbers the key by text position; 'skip' numbers it
    by unmasked letters, so the offset g between the two clue blocks is free (the mask in the gap is unknown).
    Returns (tested, judged, survivors); survivor = (checks, coding, masked places, L, mode, g, layout, sign, key)."""
    places = sorted(cribs)
    if blocks is None:
        blocks, run = [], [places[0]]
        for i in places[1:]:
            if i == run[-1] + 1:
                run.append(i)
            else:
                blocks.append(run)
                run = [i]
        blocks.append(run)
    nearp = [i for i in places if near(coding, cribs[i], ct[i])]
    kv = {}
    for lname, pa, ca in LAYOUTS:
        for sname, s in SIGNS:
            kv[lname, sname] = {i: (ca.index(ct[i]) - s * pa.index(ch)) % 26 for i, ch in cribs.items()}
    tested = judged = 0
    out = []
    for k in range(1, len(nearp) + 1):
        for sub in combinations(nearp, k):
            m = set(sub)
            ranks, opened = {}, []
            for b, run in enumerate(blocks):
                c = 0
                for i in run:
                    if i not in m:
                        ranks[i] = (b, c)
                        opened.append(i)
                        c += 1
            for L in KEYLENS:
                plans = [("abs", 0, {i: i % L for i in opened})]
                if len(blocks) == 2 and L > 1:
                    plans += [("skip", g, {i: (ranks[i][1] + g * ranks[i][0]) % L for i in opened})
                              for g in range(L)]
                for mode, g, idx in plans:
                    checks = len(opened) - len(set(idx.values()))
                    for (lname, sname), kk in kv.items():
                        tested += 1
                        if checks < min_checks:
                            continue
                        judged += 1
                        key, ok = {}, True
                        for i in opened:
                            if key.setdefault(idx[i], kk[i]) != kk[i]:
                                ok = False
                                break
                        if ok:
                            out.append((checks, coding, tuple(sub), L, mode, g, lname, sname, key))
    return tested, judged, out


def free_read(ct, cribs, surv, model=None):
    """A reading for an 'abs' free-mask survivor: each non-clue place is either under the key or masked, so it
    may be the key's letter or a shape neighbour of the cipher letter; the quadgram model chooses."""
    _, coding, _, L, mode, _, lname, sname, key = surv
    if mode != "abs":
        return None
    pa, ca = next((a, b) for nm, a, b in LAYOUTS if nm == lname)
    s = dict(SIGNS)[sname]
    cands = []
    for i, ch in enumerate(ct):
        if i in cribs:
            cands.append(cribs[i])
        elif i % L in key:
            x = pa[(s * (ca.index(ch) - key[i % L])) % 26]
            cands.append(x + NEAR[coding][ch].replace(x, ""))
        else:
            cands.append(AZ)
    return viterbi(cands, model)


def free_attack(ct, cribs, model=None, min_checks=4):
    tested = judged = 0
    surv, reads = [], []
    for coding in NAMES:
        t, j, sv = free_mask_test(ct, cribs, coding, min_checks)
        tested += t
        judged += j
        for s in sv:
            surv.append(s[:8])
            r = free_read(ct, cribs, s, model)
            if r:
                reads.append((r[0], r[1], s[:8]))
    reads.sort(key=lambda r: -r[0])
    return {"tested": tested, "judged": judged, "survivors": surv, "reads": reads}
