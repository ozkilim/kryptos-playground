"""Idea 102: the encoder loses the place in the key once, inside a clue word.

One key letter is skipped (d = +1) or used twice (d = -1) just before letter s of a clue block
(s = 1..12 in EASTNORTHEAST, 1..10 in BERLINCLOCK); every later letter is one key place off.
Letter j of a block then sits at key place t(j) = j + (d if j >= s else 0).

Three key rules, all with an unknown key word w of length L:

  repeating      key value of a letter = w[t mod L]
  slide-word     the key value grows by one word letter per text letter (differences repeat);
                 the slip is in the word: the difference into letter j is w[t(j) mod L]
  slide-stream   the same running key K(t) = K(t-1) + w[t mod L], but the slip is in the running
                 stream: a skipped place gives a difference w[s] + w[s+1], a doubled place gives 0

Three tests on the 24 key values k the clue letters force:

  A   one block alone, one slip, every L that leaves min_checks or more coincidences
  B   both blocks, one slip in either block, the other block unslipped but at ANY key offset x
      (any number of slips, or a restart, in the 29 letters between the clues), L = 2..12
  C   one slip in each block, any offset x, L = 2..12

`slow_hits` is the plain loop over every setting with the exact solver `evaluate`. `fast_hits`
returns exactly the same set (a test compares them) but looks at a setting only when its first
forced equality already holds: block by block for L <= 9, on the joined system for L = 10..12.

A hit is (test, checks, rule, L, s1, d1, s2, d2, x). s = 0 means no slip in that block, s = -1
means the block is not used (test A); x = -1 in test A.
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET

RULES = ("repeating", "slide-word", "slide-stream")
NB = (13, 11)                 # letters in each clue block
OFF = (0, 13)                 # where each block starts in the 24 key values
START = (21, 63)              # where each block starts in the text
ZERO = 47                     # index of the constant 0 in the value vector
MIN_CHECKS = 7
L_B = range(2, 13)            # test B key lengths
L_C = range(2, 13)            # test C key lengths (the plan asked for 2..8)
L_BLOCK = 9                   # up to here the fast search filters block by block
_KIDX = list(range(24))
_DIDX = list(range(24, 36)) + list(range(37, 47)) + [ZERO]


def values(k):
    """k[0..23], then the 23 differences k[j+1]-k[j] (index 24+j), then a constant 0."""
    return list(k) + [(k[j + 1] - k[j]) % 26 for j in range(23)] + [0]


def slips(b):
    """Every slip inside block b: (s, d)."""
    return [(s, d) for s in range(1, NB[b]) for d in (1, -1)]


def block_system(rule, b, L, s, d, x=0):
    """The equations one block gives: (terms, zeros, sums).

    terms: (residue, value index): that value equals w[residue]
    zeros: value indexes that must be 0
    sums:  (r1, r2, value index): that value equals w[r1] + w[r2]
    Residues are key places counted from the block's first letter, plus x, mod L."""
    n, off = NB[b], OFF[b]
    t = [j + (d if s > 0 and j >= s else 0) for j in range(n)]
    terms, zeros, sums = [], [], []
    if rule == "repeating":
        terms = [((t[j] + x) % L, off + j) for j in range(n)]
    elif rule == "slide-word":
        terms = [((t[j + 1] + x) % L, 24 + off + j) for j in range(n - 1)]
    else:
        for j in range(n - 1):
            step = t[j + 1] - t[j]
            if step == 1:
                terms.append(((t[j + 1] + x) % L, 24 + off + j))
            elif step == 2:
                sums.append(((t[j] + 1 + x) % L, (t[j] + 2 + x) % L, 24 + off + j))
            else:
                zeros.append(24 + off + j)
    return terms, zeros, sums


def system(rule, L, c1, c2, x):
    """Equations of a setting. c1 / c2 = (s, d) per block, (0, 0) no slip, (-1, 0) block unused."""
    terms, zeros, sums = [], [], []
    for b, (s, d) in enumerate((c1, c2)):
        if s < 0:
            continue
        t, z, u = block_system(rule, b, L, s, d, x if b else 0)
        terms += t
        zeros += z
        sums += u
    return terms, zeros, sums


def evaluate(V, terms, zeros, sums):
    """Exact test. Returns (independent coincidences, {residue: w}) or None if inconsistent."""
    w, checks = {}, 0
    for r, vi in terms:
        v = V[vi]
        u = w.get(r)
        if u is None:
            w[r] = v
        elif u != v:
            return None
        else:
            checks += 1
    for vi in zeros:
        if V[vi]:
            return None
        checks += 1
    pending = list(sums)
    moved = True
    while pending and moved:
        moved, rest = False, []
        for r1, r2, vi in pending:
            a, b = w.get(r1), w.get(r2)
            if a is not None and b is not None:
                if (a + b - V[vi]) % 26:
                    return None
                checks += 1
            elif a is not None:
                w[r2] = (V[vi] - a) % 26
            elif b is not None:
                w[r1] = (V[vi] - b) % 26
            else:
                rest.append((r1, r2, vi))
                continue
            moved = True
        pending = rest
    if len(pending) == 2 and set(pending[0][:2]) == set(pending[1][:2]):
        if V[pending[0][2]] != V[pending[1][2]]:
            return None
        checks += 1
    return checks, w


_BLANK = [0] * 48


def structural_checks(sysm):
    return evaluate(_BLANK, *sysm)[0]


def _configs(rule, b, L):
    """Distinct slipped settings of one block (identical equation systems are merged)."""
    seen = {str(block_system(rule, b, L, 0, 0))}
    out = []
    for s, d in slips(b):
        sig = str(block_system(rule, b, L, s, d))
        if sig not in seen:
            seen.add(sig)
            out.append((s, d))
    return out


def settings(min_a=MIN_CHECKS):
    """Every setting tested: (test, checks, rule, L, c1, c2, x)."""
    for rule in RULES:
        for b in (0, 1):
            for L in range(2, NB[b]):
                for c in _configs(rule, b, L):
                    c1, c2 = (c, (-1, 0)) if b == 0 else ((-1, 0), c)
                    ck = structural_checks(system(rule, L, c1, c2, 0))
                    if ck >= min_a:
                        yield "A", ck, rule, L, c1, c2, -1
        for L in L_B:
            for b in (0, 1):
                for c in _configs(rule, b, L):
                    c1, c2 = (c, (0, 0)) if b == 0 else ((0, 0), c)
                    for x in range(L):
                        ck = structural_checks(system(rule, L, c1, c2, x))
                        if ck >= MIN_CHECKS:
                            yield "B", ck, rule, L, c1, c2, x
        for L in L_C:
            for c1 in _configs(rule, 0, L):
                for c2 in _configs(rule, 1, L):
                    for x in range(L):
                        ck = structural_checks(system(rule, L, c1, c2, x))
                        if ck >= MIN_CHECKS:
                            yield "C", ck, rule, L, c1, c2, x


_SETTINGS = {}


def all_settings(min_a=MIN_CHECKS):
    if min_a not in _SETTINGS:
        _SETTINGS[min_a] = list(settings(min_a))
    return _SETTINGS[min_a]


def hit(test, ck, rule, L, c1, c2, x):
    return (test, ck, rule, L, c1[0], c1[1], c2[0], c2[1], x)


def slow_hits(k, min_a=MIN_CHECKS):
    """The plain loop: every setting through the exact solver."""
    V = values(k)
    out = set()
    for test, ck, rule, L, c1, c2, x in all_settings(min_a):
        if evaluate(V, *system(rule, L, c1, c2, x)) is not None:
            out.add(hit(test, ck, rule, L, c1, c2, x))
    return out


def expected_chance(min_a=MIN_CHECKS):
    """{test: (settings, expected passes per key stream if the key values were random)}."""
    out = {}
    for test, ck, rule, L, c1, c2, x in all_settings(min_a):
        n, e = out.get(test, (0, 0.0))
        out[test] = (n + 1, e + 26.0 ** -ck)
    return out


# ------------------------------------------------------------------ the fast version

def _pairs(terms, zeros):
    first, out = {}, []
    for r, vi in terms:
        f = first.setdefault(r, vi)
        if f != vi:
            out.append((f, vi))
    return out + [(vi, ZERO) for vi in zeros]


_T = {}


def _tables(min_a):
    t = _T.get(min_a)
    if t is not None:
        return t
    cfgs, bfirst, always, jfirst, joint = [], {}, {}, {}, []
    for ri, rule in enumerate(RULES):
        for L in range(2, L_BLOCK + 1):
            for b in (0, 1):
                for s, d in [(0, 0)] + _configs(rule, b, L):
                    sysm = block_system(rule, b, L, s, d)
                    ck = structural_checks(sysm)
                    cid = len(cfgs)
                    a_ok = s > 0 and ck >= min_a and L < NB[b]
                    cfgs.append((ri, L, b, s, d, ck, sysm, bool(sysm[2]), a_ok))
                    pairs = _pairs(sysm[0], sysm[1])
                    if pairs:
                        bfirst.setdefault(pairs[0], []).append((tuple(pairs[1:]), cid))
                    else:
                        always.setdefault((ri, L), ([], []))[b].append(cid)
        for L in range(L_BLOCK + 1, max(L_B) + 1):
            both = [(c1, c2) for c1 in _configs(rule, 0, L) for c2 in _configs(rule, 1, L)] if L in L_C else []
            one = [(c, (0, 0)) for c in _configs(rule, 0, L)] + [((0, 0), c) for c in _configs(rule, 1, L)]
            for test, cc in (("B", one), ("C", both)):
                for c1, c2 in cc:
                    for x in range(L):
                        sysm = system(rule, L, c1, c2, x)
                        ck = structural_checks(sysm)
                        if ck < MIN_CHECKS:
                            continue
                        pairs = _pairs(sysm[0], sysm[1])
                        jid = len(joint)
                        joint.append((hit(test, ck, rule, L, c1, c2, x), sysm))
                        jfirst.setdefault(pairs[0], []).append((tuple(pairs[1:]), jid))
    static = [key for key, (p1, p2) in always.items() if p1 and p2]
    t = _T[min_a] = (cfgs, bfirst, always, jfirst, joint, static)
    return t


def _equal_pairs(V, idx):
    seen = {}
    for i in idx:
        v = V[i]
        g = seen.get(v)
        if g is None:
            seen[v] = [i]
        else:
            for h in g:
                yield h, i
            g.append(i)


def fast_hits(k, min_a=MIN_CHECKS):
    """Same result as slow_hits."""
    cfgs, bfirst, always, jfirst, joint, static = _tables(min_a)
    V = values(k)
    out = set()
    dyn = {}
    for idx in (_KIDX, _DIDX):
        for pair in _equal_pairs(V, idx):
            for rest, cid in bfirst.get(pair, ()):
                for a, b in rest:
                    if V[a] != V[b]:
                        break
                else:
                    ri, L, b, s, d, ck, sysm, has_sum, a_ok = cfgs[cid]
                    if has_sum and evaluate(V, *sysm) is None:
                        continue
                    if a_ok:
                        c = (s, d)
                        out.add(hit("A", ck, RULES[ri], L, c if b == 0 else (-1, 0), c if b else (-1, 0), -1))
                    dyn.setdefault((ri, L), ([], []))[b].append(cid)
            for rest, jid in jfirst.get(pair, ()):
                for a, b in rest:
                    if V[a] != V[b]:
                        break
                else:
                    h, sysm = joint[jid]
                    if evaluate(V, *sysm) is not None:
                        out.add(h)
    keys = set(dyn)
    keys.update(static)
    for key in keys:
        d1, d2 = dyn.get(key, ((), ()))
        a1, a2 = always.get(key, ((), ()))
        p1, p2 = list(d1) + list(a1), list(d2) + list(a2)
        if not p1 or not p2:
            continue
        ri, L = key
        rule = RULES[ri]
        for i1 in p1:
            c1 = cfgs[i1][3:5]
            for i2 in p2:
                c2 = cfgs[i2][3:5]
                both = c1[0] > 0 and c2[0] > 0
                if both:
                    if L not in L_C:
                        continue
                elif c1[0] == 0 and c2[0] == 0:
                    continue
                for x in range(L):
                    sysm = system(rule, L, c1, c2, x)
                    r = evaluate(V, *sysm)
                    if r is not None and r[0] >= MIN_CHECKS:
                        out.add(hit("C" if both else "B", r[0], rule, L, c1, c2, x))
    return out


# ------------------------------------------------------------------ rebuilding the key and reading

def _alphabets(lay, m):
    a, b = lay.split("/")
    pick = {"M": m, "AZ": AZ, "KR": KRYPTOS_ALPHABET}
    return pick[a], pick[b]


def key_values(ct, cribs, m, lay, form):
    a, b = _alphabets(lay, m)
    pos = sorted(cribs)
    sign = -1 if form == "vig" else 1
    return [(b.index(ct[i]) + sign * a.index(cribs[i])) % 26 for i in pos]


def decrypt(ct, cribs, m, lay, form, h, score, slack=2):
    """Rebuild the key from a hit and decrypt all 97 letters.

    Before the first clue and after the second the key offset may be off by -slack..slack (the
    best-scoring choice is kept). Between the clues the key runs on from clue 1 up to a cut and
    backwards from clue 2 after it (best-scoring cut). Returns (text, unknown key letters)."""
    test, ck, rule, L, s1, d1, s2, d2, x = h
    k = key_values(ct, cribs, m, lay, form)
    V = values(k)
    c1, c2 = (s1, d1), (s2, d2)
    res = evaluate(V, *system(rule, L, c1, c2, max(x, 0)))
    if res is None:
        return None, L
    wd = res[1]
    w = [wd.get(r, 0) for r in range(L)]
    unknown = L - len(wd)
    pre = [0]
    for v in w:
        pre.append(pre[-1] + v)

    def S(T):                                   # sum of w over key places 0..T (any integer T)
        return (T // L) * pre[L] + pre[T % L + 1]

    a, b = _alphabets(lay, m)
    ib = {c: i for i, c in enumerate(b)}

    def region(lo, hi, shift, anchor, t_anchor):
        """Letters lo..hi-1 at key place i + shift; anchor = a clue letter next to the region."""
        kv_a = k[sorted(cribs).index(anchor)]
        out = []
        for i in range(lo, hi):
            T = i + shift
            if rule == "repeating":
                kv = w[T % L]
            elif rule == "slide-stream":
                kv = kv_a + S(T) - S(t_anchor)
            elif i > anchor:                    # slide-word, walking forwards from the anchor
                kv = kv_a + S(T) - S(anchor + shift)
            else:                               # slide-word, walking backwards from the anchor
                kv = kv_a - w[t_anchor % L] - (S(anchor - 1 + shift) - S(T))
            y = ib[ct[i]]
            out.append(a[(y - kv) % 26] if form == "vig" else a[(kv - y) % 26])
        return "".join(out)

    def best(options):
        return max(options, key=score)

    if test == "A":
        b0, n, d = (21, 13, d1) if s1 > 0 else (63, 11, d2)
        head = best([region(0, b0, -b0 + o, b0, 0) for o in range(-slack, slack + 1)])
        tail = best([region(b0 + n, 97, -b0 + d + o, b0 + n - 1, n - 1 + d) for o in range(-slack, slack + 1)])
        text = head + "".join(cribs[i] for i in range(b0, b0 + n)) + tail
        return text, unknown
    head = best([region(0, 21, -21 + o, 21, 0) for o in range(-slack, slack + 1)])
    fwd = region(34, 63, -21 + d1, 33, 12 + d1)
    bwd = region(34, 63, -63 + x, 63, x)
    gap = best([fwd[:c] + bwd[c:] for c in range(30)])
    tail = best([region(74, 97, -63 + x + d2 + o, 73, 10 + x + d2) for o in range(-slack, slack + 1)])
    return head + "EASTNORTHEAST" + gap + "BERLINCLOCK" + tail, unknown


# ------------------------------------------------------------------ planted answers

LAYS = (("M/M", "vig"), ("M/AZ", "beau"), ("KR/M", "vig"), ("M/M", "beau"), ("AZ/M", "vig"))

PLANTS = {
    # name: (rule, L, slips as (text index, d), test that must find it)
    "skip27": ("repeating", 7, ((27, 1),), "B"),
    "double-berlin": ("slide-word", 5, ((68, -1),), "B"),
    "both": ("slide-stream", 6, ((25, -1), (47, 1), (70, 1)), "C"),
    "alone": ("repeating", 4, ((24, 1), (30, 1), (66, -1)), "A"),
}


def plant(rng, alphas, kind):
    """An English text with the clues in place, enciphered with a key that slips.

    Returns (ciphertext, cribs, plaintext, (alphabet name, layout, form), hit the search must report)."""
    from .round11 import english97
    rule, L, sl, test = PLANTS[kind]
    pt = english97(rng)
    pt = pt[:21] + "EASTNORTHEAST" + pt[34:63] + "BERLINCLOCK" + pt[74:]
    name, m = rng.choice(alphas)
    lay, form = rng.choice(LAYS)
    a, b = _alphabets(lay, m)
    w = rng.sample(range(1, 26), L)
    T = [i + sum(d for at, d in sl if at <= i) for i in range(97)]
    lo, hi = min(T), max(T)
    stream, acc = {}, rng.randrange(26)
    for u in range(lo - 1, hi + 1):
        acc = (acc + w[u % L]) % 26
        stream[u] = acc
    ct, kv = [], rng.randrange(26)
    for i, ch in enumerate(pt):
        if rule == "repeating":
            kv = w[T[i] % L]
        elif rule == "slide-word":
            kv = (kv + w[T[i] % L]) % 26
        else:
            kv = stream[T[i]]
        xx = a.index(ch)
        ct.append(b[(xx + kv) % 26] if form == "vig" else b[(kv - xx) % 26])
    ct = "".join(ct)
    cribs = {i: pt[i] for i in list(range(21, 34)) + list(range(63, 74))}
    c = [(0, 0), (0, 0)]
    for at, d in sl:
        for bi in (0, 1):
            if START[bi] < at < START[bi] + NB[bi]:
                c[bi] = (at - START[bi], d)
    if test == "A":
        bi = 1 if kind == "alone" else 0
        blk = [(-1, 0), (-1, 0)]
        blk[bi] = c[bi]
        ck = structural_checks(system(rule, L, blk[0], blk[1], 0))
        want = hit("A", ck, rule, L, blk[0], blk[1], -1)
    else:
        x = (T[63] - T[21]) % L
        ck = structural_checks(system(rule, L, c[0], c[1], x))
        want = hit(test, ck, rule, L, c[0], c[1], x)
    return ct, cribs, pt, (name, lay, form), want


def describe(h):
    test, ck, rule, L, s1, d1, s2, d2, x = h

    def one(s, d, b):
        if s < 0:
            return "not used"
        if s == 0:
            return "no slip"
        return "key letter %s before text letter %d" % ("skipped" if d > 0 else "used twice", START[b] + s)
    return "test %s checks=%d %s L=%d clue 1: %s; clue 2: %s%s" % (
        test, ck, rule, L, one(s1, d1, 0), one(s2, d2, 1), "" if x < 0 else "; offset %d" % x)
