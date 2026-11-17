"""Idea 96: the message enciphered back to front (an autokey that looks AHEAD).

If the message is enciphered from its last letter backwards, an autokey takes its key letter
from a letter that comes LATER in the text:

    key[i] = word[i mod p] + b * number(fed letter at i + d)        (mod 26)
    Vigenere form:  cipher = plain + key      Beaufort form:  cipher = key - plain

The fed letter is the plaintext or the ciphertext d places further on. Every earlier autokey
test in this repository (ideas 55, 59, 66, 74, 90) looks back; this module is their mirror.

Three exact tests on the clue letters, each needing 7 or more independent checks:

  dictionary   (test_alphabet) plain and cipher letters numbered in a keyword alphabet M, A-Z or
               KRYPTOS (five layouts), fed letter numbered in M, A-Z or KRYPTOS, b = +-1, word of 1-4
  small        (small_search) A-Z / KRYPTOS on each side, any multiplier b = 1..25, word of 1-13
  hidden       (hidden_survivors) one unknown alphabet: x[C] = a*x[P] + b*x[U] + c is linear in the
               26 unknown positions; a solution must put different letters in different places

  plain feed    both letters must be clue letters: d = 1..8 inside a clue, and the second clue
                keying the first (d = 34..48 with the second clue moved s = -3..3, kept where 8+
                pairs remain, i.e. d - s = 37..45)
  cipher feed   only the keyed letter must be a clue letter: d = 1..68 (24 pairs up to d = 23,
                13 pairs for d = 34..63, 8 at d = 68)
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round9 import BLOCKS, solutions_mod26, solve_mod_p
from .round11 import B1, B2, pmap

N = 97
MIN_CHECKS = 7
SHIFTS = (0, -3, -2, -1, 1, 2, 3)
PERIODS = (1, 2, 3, 4)
NCLUE = len(B1) + len(B2)
IZ = {c: i for i, c in enumerate(AZ)}
IK = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
FEEDS = ("M", "AZ", "KR")
PLAIN_IN = range(1, 9)
PLAIN_ACROSS = range(34, 49)
CIPHER = range(1, 75)
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
    """Every (feed, d, shift) test: dict with pairs (clue index j, position i, source index a).

    Source index a points into the feed array: 0..23 = clue plaintext letters, 24.. = ciphertext."""
    tests = []
    for s in SHIFTS:
        pos = positions(s)
        where = {i: j for j, i in enumerate(pos)}
        plain = list(PLAIN_ACROSS) + (list(PLAIN_IN) if s == 0 else [])
        cipher = CIPHER if s == 0 else ()            # a moved second clue changes nothing for d >= 34
        for src, ds in (("plain", plain), ("cipher", cipher)):
            for d in ds:
                if src == "plain":
                    pairs = [(j, i, where[i + d]) for j, i in enumerate(pos) if i + d in where]
                else:
                    pairs = [(j, i, NCLUE + i + d) for j, i in enumerate(pos) if i + d < N]
                if len(pairs) - 1 < MIN_CHECKS:
                    continue
                pairs = _order(pairs)
                periods = [p for p in PERIODS if len(pairs) - len({i % p for _, i, _ in pairs}) >= MIN_CHECKS]
                tests.append({"src": src, "d": d, "shift": s, "pairs": pairs, "periods": periods,
                              "quick": (pairs[0][0], pairs[3][0], pairs[4][0], pairs[0][2], pairs[3][2], pairs[4][2])})
    return tests


TESTS = build_tests()
SETTINGS_PER_VIEW = sum(len(t["periods"]) for t in TESTS)      # per (layout, form, feed numbering, sign)
QK = [t["quick"][:3] for t in TESTS]
QX = [t["quick"][3:] for t in TESTS]
SIDX = [SHIFTS.index(t["shift"]) for t in TESTS]
P124 = [[p for p in t["periods"] if p != 3] for t in TESTS]
P3 = [[p for p in t["periods"] if p == 3] for t in TESTS]


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


def test_alphabet(name, m, ct, cribs):
    """All passing settings for one alphabet. cribs: {standard position: plaintext letter}.

    A hit is (checks, name, layout, form, feed numbering, sign, feed, d, shift, word length, word)."""
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
                                hits.append((checks, name, lay, form, fn, sg, t["src"], t["d"], t["shift"], p, word))
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


def encrypt(pt, m, lay, form, fn, b, src, d, word, rng):
    """Encrypt from the last letter backwards. The last d letters have nothing after them: random primer."""
    (_, ia), (ab, _), (_, ix) = _nums(m, lay, fn)
    n = len(pt)
    ct = [None] * n
    for i in range(n - 1, -1, -1):
        if i + d >= n:
            f = rng.randrange(26)
        else:
            f = ix[pt[i + d]] if src == "plain" else ix[ct[i + d]]
        k = (word[i % len(word)] + b * f) % 26
        ct[i] = ab[(ia[pt[i]] + k) % 26 if form == "vig" else (k - ia[pt[i]]) % 26]
    return "".join(ct)


def decrypt(ct, cribs, m, hit, b=None):
    """Every plaintext letter a passing setting forces ('.' where nothing is known)."""
    _, _, lay, form, fn, sg, src, d, s, p, word = hit
    b = sg if b is None else b
    (aa, ia), (_, ib), (ax, ix) = _nums(m, lay, fn)
    w = dict(word)
    binv = pow(b, -1, 26) if b % 2 and b % 13 else None
    pt = ["."] * len(ct)
    for i, std in zip(positions(s), B1 + B2):
        if 0 <= i < len(ct):
            pt[i] = cribs[std]
    changed = True
    while changed:
        changed = False
        for i in range(len(ct) - d - 1, -1, -1):
            if i % p not in w:
                continue
            if src == "cipher":
                f = ix[ct[i + d]]
            elif pt[i + d] != ".":
                f = ix[pt[i + d]]
            else:
                f = None
            if f is not None and pt[i] == ".":
                k = (w[i % p] + b * f) % 26
                pt[i] = aa[(ib[ct[i]] - k) % 26 if form == "vig" else (k - ib[ct[i]]) % 26]
                changed = True
            elif f is None and pt[i] != "." and binv is not None:    # plain feed: the keyed letter gives its source
                k = (ib[ct[i]] - ia[pt[i]]) % 26 if form == "vig" else (ib[ct[i]] + ia[pt[i]]) % 26
                pt[i + d] = ax[(binv * (k - w[i % p])) % 26]
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


def plant(rng, alphas, src, d, shift=0, p=1, pt=None):
    """A planted message: (ct, cribs at the standard positions, wanted hit fields, plaintext, alphabet)."""
    from .round11 import english97
    pt = pt or english97(rng)
    name, m = rng.choice(alphas)
    lay = rng.choice(["M/M", "M/AZ", "AZ/M", "M/KR", "KR/M"])
    form, fn, sg = rng.choice(["vig", "beau"]), rng.choice(FEEDS), rng.choice([1, -1])
    word = rng.sample(range(26), p)
    ct = encrypt(pt, m, lay, form, fn, sg, src, d, word, rng)
    pos = positions(shift)
    cribs = {std: pt[i] for i, std in zip(pos, B1 + B2)}
    return ct, cribs, (name, lay, form, fn, sg, src, d, shift, p), pt, m


# ---------------------------------------------------------------- small: A-Z / KRYPTOS, any multiplier, word 1-13

SMALL_PMAX = 13
SIDES = (("AZ", IZ), ("KR", IK))


def small_search(ct, cribs):
    """Mirror of idea 59 on A-Z / KRYPTOS: idx(C) = a*idx(P) + b*idx(fed) + word[i mod p], b = 1..25, p = 1..13.

    Returns (settings tested, hits, best): hits are (checks, layout, form, feed numbering, b, feed, d, shift,
    word length, word) with the smallest word length that fits; best = (matched, pairs, description) is the
    largest number of clue pairs agreeing on ONE constant with b = +-1 (the near-miss count)."""
    pl = [cribs[i] for i in B1 + B2]
    cls = [[ct[i] for i in positions(s)] for s in SHIFTS]
    hits, tried, best = [], 0, (0, 0, "")
    for an, ia in SIDES:
        for bn, ib in SIDES:
            for form, a in (("vig", 1), ("beau", -1)):
                bases = [[(ib[c] - a * ia[q]) % 26 for q, c in zip(pl, cl)] for cl in cls]
                for fn, ix in SIDES:
                    x = [ix[c] for c in pl] + [ix[c] for c in ct]
                    for t in TESTS:
                        base = bases[SHIFTS.index(t["shift"])]
                        tri = [(base[j], x[s], i) for j, i, s in t["pairs"]]
                        np_ = len(tri)
                        pmax = min(SMALL_PMAX, np_ - MIN_CHECKS)
                        for b in range(1, 26):
                            rem = [((k - b * u) % 26, i) for k, u, i in tri]
                            tried += pmax
                            if b in (1, 25):
                                cnt = {}
                                for v, _ in rem:
                                    cnt[v] = cnt.get(v, 0) + 1
                                top = max(cnt.values())
                                if (top, -np_) > (best[0], -best[1]):
                                    best = (top, np_, "pt%s/ct%s %s feed %s on %s b=%+d d=%d shift=%+d" % (
                                        an, bn, form, t["src"], fn, 1 if b == 1 else -1, t["d"], t["shift"]))
                            found = []
                            for p in range(1, pmax + 1):
                                if any(p % q == 0 for q in found):
                                    continue
                                seen = {}
                                for v, i in rem:
                                    if seen.setdefault(i % p, v) != v:
                                        break
                                else:
                                    if np_ - len(seen) >= MIN_CHECKS:
                                        found.append(p)
                                        hits.append((np_ - len(seen), an + "/" + bn, form, fn, b, t["src"], t["d"],
                                                     t["shift"], p, tuple(sorted(seen.items()))))
    return tried, hits, best


def small_decrypt(ct, cribs, hit):
    checks, lay, form, fn, b, src, d, s, p, word = hit
    return decrypt(ct, cribs, AZ, (checks, "", lay, form, fn, 1, src, d, s, p, word), b=b)


def small_plant(rng, src, d, p, b=None, pt=None):
    from .round11 import english97
    pt = pt or english97(rng)
    lay = rng.choice(["AZ/AZ", "AZ/KR", "KR/AZ", "KR/KR"])
    form, fn = rng.choice(["vig", "beau"]), rng.choice(["AZ", "KR"])
    b = b or rng.choice([3, 5, 7, 11, 17, 25])
    word = rng.sample(range(26), p)
    ct = encrypt(pt, AZ, lay, form, fn, b, src, d, word, rng)
    return ct, {i: pt[i] for i in B1 + B2}, (lay, form, fn, b, src, d, 0, p), pt


# ---------------------------------------------------------------- hidden alphabet (mirror of idea 55)

KNOWN = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
MODES = [("?", "?"), ("?", "AZ"), ("?", "KR"), ("AZ", "?"), ("KR", "?")]
HIDDEN_D = {"P": range(1, 9), "C": range(1, 9)}
HIDDEN_MIN = 3


def _term(side, letter):
    return ("var", letter) if side == "?" else ("num", KNOWN[side].index(letter))


def hidden_system(ct, cribs, mode, src, d, a, b):
    """x[C_i] = a*x[P_i] + b*x[U_(i+d)] + c0 over the clue letters. Returns (rows, rhs, variable names).

    Plain feed: U is on the plain side and must be a clue letter. Cipher feed: U is on the cipher side and
    is known everywhere, so every clue letter with i + d inside the text gives an equation."""
    ps, cs = mode
    names, rows, rhs = {"c0": 0}, [], []
    for blk in BLOCKS:
        for i in blk:
            j = i + d
            if src == "P":
                if j not in cribs:
                    continue
                u = _term(ps, cribs[j])
            else:
                if j >= len(ct):
                    continue
                u = _term(cs, ct[j])
            row, c = {0: -1}, 0
            for coef, (kind, v) in ((1, _term(cs, ct[i])), (-a, _term(ps, cribs[i])), (-b, u)):
                if kind == "num":
                    c -= coef * v
                else:
                    col = names.setdefault("x" + v, len(names))
                    row[col] = row.get(col, 0) + coef
            rows.append(row)
            rhs.append(c % 26)
    n = len(names)
    return [[r.get(j, 0) % 26 for j in range(n)] for r in rows], rhs, names


def hidden_survivors(ct, cribs, limit=60000):
    """(models tried, survivors). A survivor is (name, equations, unknowns, checks, alphabets | 'many', example).

    A model survives if the clue equations are consistent mod 26 and, when the solutions can be listed, at
    least one puts different letters in different places. checks = equations - rank (mod 13)."""
    out, tried = [], 0
    for mode in MODES:
        for src in "PC":
            for d in HIDDEN_D[src]:
                for a in (1, -1):
                    for b in (1, -1):
                        tried += 1
                        rows, rhs, names = hidden_system(ct, cribs, mode, src, d, a, b)
                        if not rows:
                            continue
                        sols = solutions_mod26(rows, rhs, limit)
                        if sols is None:
                            continue
                        s13 = solve_mod_p(rows, rhs, 13)
                        checks = len(rows) - (len(names) - len(s13[1]))
                        name = "ahead %s/%s src=%s d=%d a=%+d b=%+d" % (mode[0], mode[1], src, d, a, b)
                        if sols == "many":
                            out.append((name, len(rows), len(names), checks, "many", None))
                            continue
                        xs = [j for nm, j in names.items() if nm != "c0"]
                        good = [v for v in sols if len({v[j] for j in xs}) == len(xs)]
                        if good:
                            ex = {nm[1:]: good[0][j] for nm, j in names.items() if nm != "c0"}
                            out.append((name, len(rows), len(names), checks, len(good), ex))
    return tried, out


def hidden_plant(rng, mode, src, d, a=1, b=1, pt=None):
    """Plant on a random hidden alphabet (one side, or both sides sharing it)."""
    from .round11 import english97
    pt = pt or english97(rng)
    alpha = "".join(rng.sample(AZ, 26))
    pa = alpha if mode[0] == "?" else KNOWN[mode[0]]
    ca = alpha if mode[1] == "?" else KNOWN[mode[1]]
    ip, ic = {c: i for i, c in enumerate(pa)}, {c: i for i, c in enumerate(ca)}
    c0, n = rng.randrange(26), len(pt)
    ct = [None] * n
    for i in range(n - 1, -1, -1):
        if i + d >= n:
            u = rng.randrange(26)
        else:
            u = ip[pt[i + d]] if src == "P" else ic[ct[i + d]]
        ct[i] = ca[(a * ip[pt[i]] + b * u + c0) % 26]
    return "".join(ct), {i: pt[i] for i in B1 + B2}, "ahead %s/%s src=%s d=%d a=%+d b=%+d" % (mode[0], mode[1], src, d, a, b), pt
