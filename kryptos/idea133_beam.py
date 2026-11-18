"""Idea 133: a small-shift key on the first part of K4 only, on a hidden plain alphabet against A-Z.

Model (idea 112's layout "ptX/AZ"): a hidden plain alphabet X (each letter L has a place x(L)),
cipher letters read on A-Z. For letters 1..E of K4 (the first regime), C_i = AZ[x(P_i) + k_i]
with every key value k_i inside a window of w values (w = 5: digits 0-4; w = 6: 0-5). Shifting
the alphabet shifts the key, so the window is [0, w-1] without loss of generality.

So plain letter P_i must sit at one of the w places AZ(C_i) - k, k = 0..w-1. Each letter L thus
carries a set of allowed places (a bitmask "domain"): the intersection of the windows of every
cipher letter it stands under. A reading is possible exactly when the 26 letters can be given
distinct places inside their domains (a bipartite matching). EASTNORTHEAST (positions 21-33)
fixes the first domains; at w = 5 they allow 4,288 arrangements of E A S T N O R H (idea 112),
at w = 6 36,960. The beam never enumerates them: it keeps the domains and the matching, which
is the same set of alphabets, "lazily", and narrows them as letters are chosen.

Two searches:
  beam(...)      key free in the window (any digits). Beam search on the big quadgram model,
                 growing the text leftwards from position 20 to 0, then rightwards from 34.
                 Records the best mean quadgram score of text[0:E] for every regime end E.
  periodic(...)  key repeating with period p (2..13) inside the window. Then the 13 clue key
                 values fix the whole key, every position has a known place, and the reading is
                 a simple substitution on the places that EASTNORTHEAST leaves empty; this is
                 solved by hill climbing. Exact up to the hill climb.
"""
import math
import random

from .data import DATA_DIR

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
N = 26
FULL = (1 << N) - 1
B1 = list(range(21, 34))          # EASTNORTHEAST, 0-indexed
LEFT = list(range(20, -1, -1))    # grown leftwards from the clue
RIGHT0 = 34
B2_START = 63                     # BERLINCLOCK: the first regime must end before it

_QG = None


def qgrams(path=None):
    """Big quadgram model as a flat list of 26**4 log10 probabilities (floor for unseen)."""
    global _QG
    if _QG is not None and path is None:
        return _QG
    path = path or DATA_DIR / "english" / "quadgrams_big.txt"
    counts = {}
    with open(path) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            q, c = line.split()
            counts[q] = int(c)
    tot = float(sum(counts.values()))
    floor = math.log10(0.01 / tot)
    t = [floor] * (N ** 4)
    for q, c in counts.items():
        if len(q) == 4 and q.isalpha():
            t[_idx(q)] = math.log10(c / tot)
    _QG = t
    return t


def _idx(s):
    v = 0
    for ch in s:
        v = v * N + (ord(ch) - 65)
    return v


def mean_score(text, qg=None):
    qg = qg or qgrams()
    if len(text) < 4:
        return -99.0
    return sum(qg[_idx(text[i:i + 4])] for i in range(len(text) - 3)) / (len(text) - 3)


def windows(w):
    """win[c] = places a plain letter may have under cipher letter c (k = 0..w-1)."""
    return [sum(1 << ((c - k) % N) for k in range(w)) for c in range(N)]


def block_domains(ct, plain, pos, w):
    """Letter domains after the clue letters at pos; None if a letter's domain is empty."""
    win = windows(w)
    dom = [FULL] * N
    for i in pos:
        L = ord(plain[i - pos[0]]) - 65
        dom[L] &= win[ord(ct[i]) - 65]
        if not dom[L]:
            return None
    return dom


def _augment(L, dom, match, owner):
    """Try to give letter L a place (Kuhn augment). match: letter->place, owner: place->letter.
    Mutates match/owner on success."""
    seen = 0
    stack_path = []

    def go(u):
        nonlocal seen
        m = dom[u] & ~seen
        while m:
            low = m & -m
            v = low.bit_length() - 1
            seen |= low
            o = owner[v]
            if o < 0 or go(o):
                owner[v] = u
                match[u] = v
                return True
            m &= m - 1
        return False

    return go(L)


def initial_match(dom):
    """A matching of the restricted letters, or None if none exists."""
    match, owner = [-1] * N, [-1] * N
    for L in range(N):
        if dom[L] != FULL and not _augment(L, dom, match, owner):
            return None
    return match, owner


def min_window_b1(ct, plain, pos=B1, wmax=8):
    """Smallest w for which the clue block alone admits an alphabet (ptX/AZ)."""
    for w in range(1, wmax + 1):
        d = block_domains(ct, plain, pos, w)
        if d is not None and initial_match(d) is not None:
            return w
    return None


def beam(ct, plain_block, w, width=2000, qg=None, end_max=B2_START, min_right=15):
    """Beam search for the free-key model. Returns {E: (score, text)} for regime ends E
    (1-indexed: the regime covers letters 1..E, i.e. positions 0..E-1) with E-34 >= min_right,
    plus the count of states expanded."""
    qg = qg or qgrams()
    win = windows(w)
    dom0 = block_domains(ct, plain_block, B1, w)
    if dom0 is None:
        return {}, 0
    m0 = initial_match(dom0)
    if m0 is None:
        return {}, 0
    cv = [ord(ch) - 65 for ch in ct]
    blk = [ord(ch) - 65 for ch in plain_block]
    # state: (score, dom tuple, match list, owner list, left letters (list, leftmost first), right letters)
    states = [(0.0, tuple(dom0), m0[0], m0[1], [], [])]
    expanded = 0
    best = {}
    N3, N2 = N ** 3, N ** 2
    order = [("L", i) for i in LEFT] + [("R", j) for j in range(RIGHT0, end_max)]
    for side, i in order:
        c = cv[i]
        wm = win[c]
        cands = []
        for si, st in enumerate(states):
            sc, dom, match, owner, lt, rt = st
            if side == "L":
                nxt = (lt + blk)[:3]
                tail = nxt[0] * N2 + nxt[1] * N + nxt[2]
            else:
                prv = (blk + rt)[-3:]
                head = (prv[0] * N2 + prv[1] * N + prv[2]) * N
            for L in range(N):
                if dom[L] & wm:
                    q = qg[L * N3 + tail] if side == "L" else qg[head + L]
                    cands.append((sc + q, si, L))
        expanded += len(cands)
        cands.sort(reverse=True)
        new, seen = [], set()
        for sc, si, L in cands:
            st = states[si]
            dom, match, owner, lt, rt = st[1], st[2], st[3], st[4], st[5]
            nd = dom[L] & wm
            if side == "L":
                fr = (L,) + tuple((lt + blk)[:2])
            else:
                fr = tuple((blk + rt)[-2:]) + (L,)
            if nd == dom[L]:
                key = (dom, fr)
                if key in seen:
                    continue
                d2, m2, o2 = dom, match, owner
            else:
                d2 = list(dom)
                d2[L] = nd
                d2 = tuple(d2)
                key = (d2, fr)
                if key in seen:
                    continue
                if match[L] >= 0 and nd >> match[L] & 1:
                    m2, o2 = match, owner
                else:
                    m2, o2 = list(match), list(owner)
                    if m2[L] >= 0:
                        o2[m2[L]] = -1
                        m2[L] = -1
                    if not _augment(L, d2, m2, o2):
                        continue
            seen.add(key)
            if side == "L":
                new.append((sc, d2, m2, o2, [L] + lt, rt))
            else:
                new.append((sc, d2, m2, o2, lt, rt + [L]))
            if len(new) >= width:
                break
        states = new
        if not states:
            break
        if side == "R":
            E = i + 1
            if E - RIGHT0 >= min_right:
                top = states[0]
                nq = E - 3
                text = "".join(chr(65 + x) for x in top[4] + blk + top[5])
                best[E] = (top[0] / nq, text, top[1])
    return best, expanded


def check_reading(ct, text, w):
    """Is text (positions 0..len-1) a possible reading of ct under the model? (exact)"""
    win = windows(w)
    dom = [FULL] * N
    for i, ch in enumerate(text):
        L = ord(ch) - 65
        dom[L] &= win[ord(ct[i]) - 65]
        if not dom[L]:
            return False
    return initial_match(dom) is not None


# ---------------------------------------------------------------- periodic key (exact)

def arrangements(ct, plain_block, w):
    """All places of the clue-block letters (dicts letter->place) at window w."""
    win = windows(w)
    dom = {}
    for i, p in zip(B1, plain_block):
        m = win[ord(ct[i]) - 65]
        dom[p] = dom.get(p, FULL) & m
    letters = sorted(dom, key=lambda l: bin(dom[l]).count("1"))
    out = []

    def rec(k, asg, used):
        if k == len(letters):
            out.append(dict(asg))
            return
        l = letters[k]
        m = dom[l] & ~used
        while m:
            low = m & -m
            asg[l] = low.bit_length() - 1
            rec(k + 1, asg, used | low)
            m &= m - 1
        asg.pop(l, None)

    if all(dom.values()):
        rec(0, {}, 0)
    return out


def periodic_keys(ct, plain_block, w, p):
    """[(arrangement, key list of length p indexed by position mod p)] for a period-p key."""
    out = []
    for a in arrangements(ct, plain_block, w):
        key = {}
        ok = True
        for i, ch in zip(B1, plain_block):
            k = (ord(ct[i]) - 65 - a[ch]) % N
            if key.setdefault(i % p, k) != k:
                ok = False
                break
        if ok and len(key) == p:
            out.append((a, [key[r] for r in range(p)]))
    return out


def solve_periodic(ct, plain_block, arr, key, E, qg=None, rng=None, restarts=4, iters=3000):
    """Hill-climb the empty places for a fixed arrangement and period key over positions 0..E-1.

    Returns (mean score, text, place->letter string)."""
    qg = qg or qgrams()
    rng = rng or random.Random(0)
    p = len(key)
    fixed = {v: ch for ch, v in arr.items()}
    places = [(ord(ct[i]) - 65 - key[i % p]) % N for i in range(E)]
    free_letters = [ch for ch in AZ if ch not in arr]
    free_places = [v for v in range(N) if v not in fixed]
    blk = {i: plain_block[i - 21] for i in B1}

    # text as ints; free positions grouped by place; quadgrams touched by each place
    txt = [0] * E
    slot = {}                      # place -> positions it decides
    for i in range(E):
        if i in blk:
            txt[i] = ord(blk[i]) - 65
        elif places[i] in fixed:
            txt[i] = ord(fixed[places[i]]) - 65
        else:
            slot.setdefault(places[i], []).append(i)
    used = [v for v in free_places if v in slot]
    nq = E - 3
    touch = {}
    for v in used:
        s = set()
        for i in slot[v]:
            s.update(j for j in range(i - 3, i + 1) if 0 <= j < nq)
        touch[v] = s
    N3, N2 = N ** 3, N ** 2

    def q(j):
        return qg[txt[j] * N3 + txt[j + 1] * N2 + txt[j + 2] * N + txt[j + 3]]

    def setp(v, L):
        for i in slot[v]:
            txt[i] = L

    best = None
    if len(used) < 1:
        total = sum(q(j) for j in range(nq))
        return (total / nq, "".join(chr(65 + x) for x in txt), "".join(fixed.get(v, ".") for v in range(N)))
    for _ in range(restarts):
        perm = [ord(ch) - 65 for ch in free_letters]
        rng.shuffle(perm)
        assign = dict(zip(free_places, perm))
        for v in used:
            setp(v, assign[v])
        cur = sum(q(j) for j in range(nq))
        stale = 0
        for _ in range(iters):
            a = rng.choice(used)
            b = rng.choice(free_places)
            if a == b:
                continue
            js = touch[a] | touch.get(b, set())
            old = sum(q(j) for j in js)
            assign[a], assign[b] = assign[b], assign[a]
            setp(a, assign[a])
            if b in slot:
                setp(b, assign[b])
            new = sum(q(j) for j in js)
            if new >= old:
                if new > old:
                    stale = 0
                cur += new - old
            else:
                assign[a], assign[b] = assign[b], assign[a]
                setp(a, assign[a])
                if b in slot:
                    setp(b, assign[b])
                stale += 1
                if stale > 800:
                    break
        if best is None or cur > best[0]:
            alph = "".join(fixed[v] if v in fixed else chr(65 + assign[v]) for v in range(N))
            best = (cur, "".join(chr(65 + x) for x in txt), alph)
    return (best[0] / nq, best[1], best[2])


# ---------------------------------------------------------------- planted text

def plant(text, E, w, rng, second_key_word="ABSCISSA"):
    """Encrypt text: letters 1..E with digits 0..w-1 on a random plain alphabet against A-Z,
    the rest (including BERLINCLOCK) with a Vigenere word on A-Z (a different system)."""
    X = list(AZ)
    rng.shuffle(X)
    X = "".join(X)
    out = []
    for i, ch in enumerate(text):
        if i < E:
            k = rng.randrange(w)
            out.append(AZ[(X.index(ch) + k) % N])
        else:
            k = ord(second_key_word[i % len(second_key_word)]) - 65
            out.append(AZ[(ord(ch) - 65 + k) % N])
    return "".join(out), X


def agreement(a, b, positions):
    return sum(a[i] == b[i] for i in positions if i < len(a) and i < len(b))


# ---------------------------------------------------------------- pool workers (spawn-safe)

def periodic_job(args):
    """Solve every period-p arrangement of one text at window w, ends Es. Returns the top few."""
    label, ct, w, p, Es, seed, keep = args
    rng = random.Random(seed)
    qg = qgrams()
    pk = periodic_keys(ct, "EASTNORTHEAST", w, p)
    top = []
    for a, k in pk:
        for E in Es:
            s, txt, alph = solve_periodic(ct, "EASTNORTHEAST", a, k, E, qg=qg, rng=rng, restarts=2, iters=2500)
            top.append((s, E, txt, k, alph))
    top.sort(reverse=True)
    # polish the best screened settings with a stronger climb (same budget for every text)
    seen, pol = set(), []
    for s0, E, txt, k, alph in top:
        if len(pol) >= 12:
            break
        a = {ch: alph.index(ch) for ch in set("EASTNORTHEAST")}
        tag = (tuple(sorted(a.items())), E)
        if tag in seen:
            continue
        seen.add(tag)
        s, txt2, alph2 = solve_periodic(ct, "EASTNORTHEAST", a, k, E, qg=qg, rng=rng, restarts=16, iters=6000)
        pol.append(max((s, E, txt2, k, alph2), (s0, E, txt, k, alph)))
    pol.sort(reverse=True)
    return label, w, p, len(pk), pol[:keep]


def beam_job(args):
    label, ct, w, width = args
    res, n = beam(ct, "EASTNORTHEAST", w, width=width)
    return label, w, {E: (s, t) for E, (s, t, _) in res.items()}, n
