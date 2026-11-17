"""Idea 90: autokey that looks one worksheet row back (7, 8 or about 42 letters).

Model (every letter i):

    key[i] = word[i mod p] + sign * number(fed letter at i - L)        (mod 26)
    Vigenere form:  cipher = plain + key      Beaufort form:  cipher = key - plain

The fed letter is the plaintext or the ciphertext L places back. Plain and cipher letters are
numbered in a keyword alphabet M, A-Z or KRYPTOS (five layouts); the fed letter is numbered in
M, A-Z or KRYPTOS. p = 1 is a plain constant, p = 2..4 a short repeating word on top.

The test is exact on the clue letters: the value key[i] - sign * number(fed) must be the same
for all clue pairs whose position i falls in the same class mod p.
checks = pairs - classes; a setting passes with 7 or more checks.

  plain feed    both letters must be clue letters: lags 7 and 8 inside a clue, and the first
                clue keying the second (lag 34..48 with the second clue moved s = -3..3, kept
                where 8+ pairs remain, i.e. lag - s = 37..45)
  cipher feed   only the keyed letter must be a clue letter: lags 1..66 with the clues in place,
                lags 34..48 again with the second clue moved s = -3..3
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round11 import B1, B2, pmap

MIN_CHECKS = 7
SHIFTS = (0, -3, -2, -1, 1, 2, 3)
PERIODS = (1, 2, 3, 4)
NCLUE = len(B1) + len(B2)
IZ = {c: i for i, c in enumerate(AZ)}
IK = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
FEEDS = ("M", "AZ", "KR")
_S = {}


def positions(s):
    """True positions of the 24 clue letters when the second clue sits s places later."""
    return B1 + [i + s for i in B2]


def _order(pairs):
    """Longest run of consecutive keyed positions first (the quick test reads its pairs 0, 3 and 4)."""
    runs, cur = [], [pairs[0]]
    for pr in pairs[1:]:
        if pr[0] == cur[-1][0] + 1:
            cur.append(pr)
        else:
            runs.append(cur)
            cur = [pr]
    runs.append(cur)
    runs.sort(key=len, reverse=True)
    assert len(runs[0]) >= 5
    return [pr for r in runs for pr in r]


def build_tests():
    """Every (feed, lag, shift) test: dict with pairs (clue index j, position i, source index a).

    Source index a points into the feed array: 0..23 = clue plaintext letters, 24.. = ciphertext."""
    tests = []
    for s in SHIFTS:
        pos = positions(s)
        where = {i: j for j, i in enumerate(pos)}
        plain_lags = [L for L in range(34, 49)] + ([7, 8] if s == 0 else [])
        cipher_lags = range(1, 67) if s == 0 else range(34, 49)
        for src, lags in (("plain", plain_lags), ("cipher", cipher_lags)):
            for L in lags:
                if src == "plain":
                    pairs = [(j, i, where[i - L]) for j, i in enumerate(pos) if i - L in where]
                else:
                    pairs = [(j, i, NCLUE + i - L) for j, i in enumerate(pos) if i - L >= 0]
                if len(pairs) - 1 < MIN_CHECKS:
                    continue
                pairs = _order(pairs)
                periods = [p for p in PERIODS if len(pairs) - len({i % p for _, i, _ in pairs}) >= MIN_CHECKS]
                tests.append({"src": src, "lag": L, "shift": s, "pairs": pairs, "periods": periods,
                              "quick": (pairs[0][0], pairs[3][0], pairs[4][0], pairs[0][2], pairs[3][2], pairs[4][2])})
    return tests


TESTS = build_tests()
SETTINGS_PER_VIEW = sum(len(t["periods"]) for t in TESTS)      # per (layout, form, feed numbering, sign)
QK = [t["quick"][:3] for t in TESTS]          # clue indices of pairs 0, 3, 4
QX = [t["quick"][3:] for t in TESTS]
SIDX = [SHIFTS.index(t["shift"]) for t in TESTS]


def layouts(m):
    im = {c: i for i, c in enumerate(m)}
    if m == AZ:
        return im, (("AZ/AZ", IZ, IZ), ("AZ/KR", IZ, IK), ("KR/AZ", IK, IZ), ("KR/KR", IK, IK))
    return im, (("M/M", im, im), ("M/AZ", im, IZ), ("AZ/M", IZ, im), ("M/KR", im, IK), ("KR/M", IK, im))


def settings_per_alphabet(m):
    return (4 if m == AZ else 5) * 2 * (2 if m == AZ else 3) * 2 * SETTINGS_PER_VIEW


def _full(t, k, x, sg, periods):
    """Exact test once the quick test passed. Returns [(checks, period, word values by class)]."""
    alive = [(p, {}) for p in periods]
    for j, i, a in t["pairs"]:
        v = (k[j] - sg * x[a]) % 26
        alive = [(p, seen) for p, seen in alive if seen.setdefault(i % p, v) == v]
        if not alive:
            return []
    out = []
    for p, seen in alive:
        if not any(p % q == 0 for _, q, _ in out):          # a word of 1 implies 2, 3, 4; a word of 2 implies 4
            out.append((len(t["pairs"]) - len(seen), p, tuple(sorted(seen.items()))))
    return out


P124 = [[p for p in t["periods"] if p != 3] for t in TESTS]
P3 = [[p for p in t["periods"] if p == 3] for t in TESTS]


def test_alphabet(name, m, ct, cribs):
    """All passing settings for one alphabet. cribs: {standard position: plaintext letter}."""
    im, lays = layouts(m)
    pl = [cribs[i] for i in B1 + B2]
    feeds = (("M", im), ("AZ", IZ), ("KR", IK)) if m != AZ else (("AZ", IZ), ("KR", IK))
    xs = []
    for fn, ix in feeds:
        x = [ix[c] for c in pl] + [ix[c] for c in ct]
        q = (set(), set(), set(), set())                    # (pairs 4 apart, sign +), (4, -), (3, +), (3, -)
        for n, (a0, a3, a4) in enumerate(QX):
            q[0].add(n * 26 + (x[a4] - x[a0]) % 26)
            q[1].add(n * 26 + (x[a0] - x[a4]) % 26)
            q[2].add(n * 26 + (x[a3] - x[a0]) % 26)
            q[3].add(n * 26 + (x[a0] - x[a3]) % 26)
        xs.append((fn, x, q))
    cls = [[ct[i] for i in positions(s)] for s in SHIFTS]
    hits = []
    for lay, ia, ib in lays:
        a = [ia[c] for c in pl]
        bs = [[ib[c] for c in cl] for cl in cls]
        for form, ks in (("vig", [[(y - u) % 26 for u, y in zip(a, b)] for b in bs]),
                         ("beau", [[(y + u) % 26 for u, y in zip(a, b)] for b in bs])):
            # quick test: the pairs 4 apart (word of 1, 2 or 4) or 3 apart (word of 3) must agree
            c4 = [n * 26 + (ks[si][j4] - ks[si][j0]) % 26 for n, (si, (j0, j3, j4)) in enumerate(zip(SIDX, QK))]
            c3 = [n * 26 + (ks[si][j3] - ks[si][j0]) % 26 for n, (si, (j0, j3, j4)) in enumerate(zip(SIDX, QK))]
            for fn, x, q in xs:
                for qs, cs, sg, per in ((q[0], c4, 1, P124), (q[1], c4, -1, P124), (q[2], c3, 1, P3), (q[3], c3, -1, P3)):
                    for c in qs.intersection(cs):
                        n = c // 26
                        if per[n]:
                            t = TESTS[n]
                            for checks, p, word in _full(t, ks[SIDX[n]], x, sg, per[n]):
                                hits.append((checks, name, lay, form, fn, sg, t["src"], t["lag"], t["shift"], p, word))
    return hits


def init(ct, cribs):
    _S["ct"], _S["cribs"] = ct, cribs


def work(chunk):
    hits = []
    for name, m in chunk:
        hits += test_alphabet(name, m, _S["ct"], _S["cribs"])
    return hits


def search(ct, cribs, alphas, chunk=1500, procs=None):
    hits = []
    for h in pmap(work, alphas, init, (ct, cribs), chunk=chunk, procs=procs):
        hits += h
    return hits


# ---------------------------------------------------------------- encrypt / decrypt

def _nums(m, lay, fn):
    im = {c: i for i, c in enumerate(m)}
    side = {"M": (m, im), "AZ": (AZ, IZ), "KR": (KRYPTOS_ALPHABET, IK)}
    a, b = lay.split("/")
    return side[a], side[b], side[fn]


def encrypt(pt, m, lay, form, fn, sg, src, lag, word, rng):
    """Encrypt with the model. The first `lag` letters have nothing to look back at: they use a random primer."""
    (_, ia), (ab, _), (_, ix) = _nums(m, lay, fn)
    ct = []
    for i, ch in enumerate(pt):
        if i < lag:
            f = rng.randrange(26)
        else:
            f = ix[pt[i - lag]] if src == "plain" else ix[ct[i - lag]]
        k = (word[i % len(word)] + sg * f) % 26
        ct.append(ab[(ia[ch] + k) % 26 if form == "vig" else (k - ia[ch]) % 26])
    return "".join(ct)


def decrypt(ct, cribs, m, hit):
    """Every plaintext letter a passing setting forces ('.' where nothing is known)."""
    _, _, lay, form, fn, sg, src, lag, s, p, word = hit
    (aa, ia), (_, ib), (ax, ix) = _nums(m, lay, fn)
    w = dict(word)
    pt = ["."] * len(ct)
    for i, std in zip(positions(s), B1 + B2):
        if 0 <= i < len(ct):
            pt[i] = cribs[std]
    changed = True
    while changed:
        changed = False
        for i in range(lag, len(ct)):
            if i % p not in w:
                continue
            if src == "cipher":
                f = ix[ct[i - lag]]
            elif pt[i - lag] != ".":
                f = ix[pt[i - lag]]
            else:
                f = None
            if f is not None and pt[i] == ".":
                k = (w[i % p] + sg * f) % 26
                pt[i] = aa[(ib[ct[i]] - k) % 26 if form == "vig" else (k - ib[ct[i]]) % 26]
                changed = True
            elif f is None and pt[i] != ".":            # plain feed, backwards: the keyed letter gives its source
                k = (ib[ct[i]] - ia[pt[i]]) % 26 if form == "vig" else (ib[ct[i]] + ia[pt[i]]) % 26
                pt[i - lag] = ax[(sg * (k - w[i % p])) % 26]
                changed = True
    return "".join(pt)


def extra_score(pt, big, clue):
    """English per quadgram over forced letters outside the clues. Returns (score or None, quadgrams)."""
    tot, cnt = 0.0, 0
    get, fl = big.logp.get, big.floor
    for i in range(len(pt) - 3):
        q = pt[i:i + 4]
        if "." in q or (i in clue and i + 3 in clue):
            continue
        tot += get(q, fl)
        cnt += 1
    return (tot / cnt if cnt else None), cnt


def plant(rng, alphas, src, lag, shift=0, p=1, pt=None):
    """A planted message: (ct, cribs at the standard positions, wanted hit fields)."""
    from .round11 import english97
    pt = pt or english97(rng)
    name, m = rng.choice(alphas)
    lay = rng.choice(["M/M", "M/AZ", "AZ/M", "M/KR", "KR/M"])
    form, fn, sg = rng.choice(["vig", "beau"]), rng.choice(FEEDS), rng.choice([1, -1])
    word = rng.sample(range(26), p)
    ct = encrypt(pt, m, lay, form, fn, sg, src, lag, word, rng)
    pos = positions(shift)
    cribs = {std: pt[i] for i, std in zip(pos, B1 + B2)}
    return ct, cribs, (name, lay, form, fn, sg, src, lag, shift, p), pt, m
