"""Idea 117: tests that need no alphabet. Which fed-key models clash on every possible tableau?

A tableau with distinct rows and distinct columns is a Latin square T: cipher = T[key][plain]. In any
such square, two letters enciphered with

    the same key letter and the same plain letter   give the same cipher letter,
    the same key letter and the same cipher letter  come from the same plain letter,
    the same plain letter and the same cipher letter were made with the same key letter.

So two clue triples (plain, key, cipher) that agree in two places and differ in the third are a CLASH,
and a clash rules the model out on every tableau at once: keyword, mixed, hidden, random, with any
constant added to the key (a fixed relabelling of the rows keeps the square Latin).

The test applies wherever the key letter at a clue position is itself a known letter of some text:
plaintext autokey (the key letter is a clue plaintext letter), ciphertext autokey (the key letter is a
ciphertext letter, known everywhere), lag patterns, and running keys from known texts.

Part B narrows the square to one hidden alphabet X on all three sides: X[C] = a*X[P] + b*X[K] + E
(a, b = +-1), linear in the 26 unknown places, solved mod 26 with distinct places required.
Part C reads the key letter on A-Z (or KRYPTOS) as a number k: X[C] = a*X[P] + b*k + E.
"""
import random

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .idea93_hidden import solve_injective
from .idea94_wordkey import forced_equal, same_alphabet
from .round11 import B1, B2

N = 97
SHIFTS = (0, -1, 1, -2, 2, -3, 3)
PT1, PT2 = "EASTNORTHEAST", "BERLINCLOCK"
IZ = {c: i for i, c in enumerate(AZ)}
IK = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
# (name, a, b): X[C] = a*X[P] + b*X[K] + E. Same four forms as idea 94.
FORMS = (("C = P + K", 1, 1), ("C = P - K", 1, -1), ("C = K - P", -1, 1), ("C = -P - K", -1, -1))
PLAIN_LAGS = tuple(range(1, 61))
CIPHER_LAGS = tuple(range(1, 69))
CHAIN_LAGS = tuple(range(15, 27))


def clue_positions(shift=0):
    return B1 + [p + shift for p in B2]


def clue_plain(shift=0):
    pos = clue_positions(shift)
    return pos, {p: ch for p, ch in zip(pos, PT1 + PT2)}


# ---------------------------------------------------------------- models as index specs

def fixed_models(shift=0):
    """[(family, name, spec)]: spec = [(position, source position, 'P' or 'C')]: the key letter at the
    clue position is the plain/cipher letter at the source position. Only specs with 2+ known triples."""
    pos, pt = clue_plain(shift)
    out = []
    for L in PLAIN_LAGS:
        for d, dn in ((-1, "back"), (1, "ahead")):
            spec = [(i, i + d * L, "P") for i in pos if i + d * L in pt]
            if len(spec) >= 2:
                out.append(("plain autokey", "plain %s %d" % (dn, L), spec))
    for L in CIPHER_LAGS:
        for d, dn in ((-1, "back"), (1, "ahead")):
            spec = [(i, i + d * L, "C") for i in pos if 0 <= i + d * L < N]
            out.append(("cipher autokey", "cipher %s %d" % (dn, L), spec))
    return out


def triples(spec, ct, pt):
    """(plain, key, cipher, position, source) for every known clue letter of a model."""
    return [(pt[i], pt[s] if side == "P" else ct[s], ct[i], i, s) for i, s, side in spec]


def clashes(tr):
    """Index pairs of triples that no Latin square allows: two of (plain, key, cipher) equal, the third not."""
    out = []
    for x in range(len(tr)):
        a = tr[x]
        for y in range(x + 1, len(tr)):
            b = tr[y]
            if (a[0] == b[0]) + (a[1] == b[1]) + (a[2] == b[2]) == 2:
                out.append((x, y))
    return out


def letters_touched(tr, x):
    return {tr[x][3]} | ({tr[x][4]} if tr[x][4] is not None else set())


def one_letter_saves(tr, cl):
    """True if all clashes go away when one position's letter is taken as wrong (dropping every triple that
    uses it as target or as source). A clash that one bad letter explains is a fragile kill."""
    if not cl:
        return True
    common = letters_touched(tr, cl[0][0]) | letters_touched(tr, cl[0][1])
    for x, y in cl[1:]:
        common &= letters_touched(tr, x) | letters_touched(tr, y)
        if not common:
            return False
    return bool(common)


def testable_pairs(tr):
    """Pairs that share at least one of (plain, key, cipher): the only pairs that could clash."""
    return sum(1 for x in range(len(tr)) for y in range(x + 1, len(tr))
               if tr[x][0] == tr[y][0] or tr[x][1] == tr[y][1] or tr[x][2] == tr[y][2])


def part_a(ct, shift=0):
    """{name: (family, n_triples, n_clashes, fragile, testable)} for every fixed model."""
    pos, pt = clue_plain(shift)
    out = {}
    for fam, name, spec in fixed_models(shift):
        tr = triples(spec, ct, pt)
        cl = clashes(tr)
        out[name] = (fam, len(tr), len(cl), bool(cl) and one_letter_saves(tr, cl), testable_pairs(tr))
    return out


# ---------------------------------------------------------------- idea 74 lag patterns (CSP count)

PATTERN_LMAX = {"cipher": 20, "plain": 8}


def pattern_tables(ct, feed, p, shift=0):
    """dom[r]: lags allowed in class r (no clash inside the class); comp[r][a][s]: bitmask of lags b for class s
    compatible with lag a in class r. Lags 1..lmax, bit L."""
    pos, pt = clue_plain(shift)
    lmax = PATTERN_LMAX[feed]
    cls = [[i for i in pos if i % p == r] for r in range(p)]
    tri = {}
    for r in range(p):
        for L in range(1, lmax + 1):
            t = []
            for i in cls[r]:
                s = i - L
                if feed == "plain":
                    if s in pt:
                        t.append((pt[i], pt[s], ct[i], i, s))
                elif s >= 0:
                    t.append((pt[i], ct[s], ct[i], i, s))
            tri[r, L] = t
    dom = [0] * p
    for r in range(p):
        for L in range(1, lmax + 1):
            if not clashes(tri[r, L]):
                dom[r] |= 1 << L
    comp = {}
    for r in range(p):
        for a in range(1, lmax + 1):
            if not dom[r] >> a & 1:
                continue
            for s in range(r + 1, p):
                m = 0
                for b in range(1, lmax + 1):
                    if dom[s] >> b & 1 and not clashes(tri[r, a] + tri[s, b]):
                        m |= 1 << b
                comp[r, a, s] = m
    return dom, comp, lmax


def count_patterns(dom, comp, p, lmax):
    """Number of lag patterns (one lag per class) with no clash anywhere."""
    def rec(r, masks):
        if r == p - 1:
            return bin(masks[r]).count("1")
        tot = 0
        m = masks[r]
        a = 1
        while a <= lmax:
            if m >> a & 1:
                new = list(masks)
                ok = True
                for s in range(r + 1, p):
                    new[s] &= comp[r, a, s]
                    if not new[s]:
                        ok = False
                        break
                if ok:
                    tot += rec(r + 1, new)
            a += 1
        return tot
    return rec(0, list(dom))


def sample_patterns(dom, comp, p, lmax, n, rng):
    """Fraction of n random lag patterns (uniform over all lmax^p) that have no clash."""
    good = 0
    for _ in range(n):
        lag = [rng.randint(1, lmax) for _ in range(p)]
        if all(dom[r] >> lag[r] & 1 for r in range(p)) and all(
                comp[r, lag[r], s] >> lag[s] & 1 for r in range(p) for s in range(r + 1, p)):
            good += 1
    return good / n


def pattern_survivors(ct, feed, p, shift=0, sample=None, rng=None):
    dom, comp, lmax = pattern_tables(ct, feed, p, shift)
    total = lmax ** p
    if sample:
        return total, sample_patterns(dom, comp, p, lmax, sample, rng) * total, True
    return total, count_patterns(dom, comp, p, lmax), False


# ---------------------------------------------------------------- running keys: bitmask scan over offsets

def pair_rules(ct, shift=0):
    """[(da, db, must_equal)]: for clue indices a < b (offsets from position 21), the key letters must be equal
    (plain and cipher both equal) or must differ (exactly one of plain, cipher equal)."""
    pos, pt = clue_plain(shift)
    out = []
    for x in range(len(pos)):
        for y in range(x + 1, len(pos)):
            i, j = pos[x], pos[y]
            pe, ce = pt[i] == pt[j], ct[i] == ct[j]
            if pe and ce:
                out.append((i - 21, j - 21, True))
            elif pe or ce:
                out.append((i - 21, j - 21, False))
    return out, pos[-1] - 21


def running_survivors(stream, rules, span):
    """Bitmask over u: the key letter at clue position 21 is stream[u] (stream[u + i - 21] at position i).
    A bit is set when no clash occurs. Only u with the whole clue span inside the stream count."""
    n = len(stream) - span
    if n <= 0:
        return 0, 0
    full = (1 << n) - 1
    pm = {}
    for k, ch in enumerate(stream):
        pm[ch] = pm.get(ch, 0) | (1 << k)
    eq = {}
    alive = full
    for da, db, must in rules:
        d = db - da
        e = eq.get(d)
        if e is None:
            e = 0
            for m in pm.values():
                e |= m & (m >> d)
            eq[d] = e
        sh = e >> da
        alive &= sh if must else ~sh
        if not alive:
            break
    return alive & full, n


def bits(m):
    out, k = [], 0
    while m:
        if m & 1:
            out.append(k)
        m >>= 1
        k += 1
    return out


def running_triples(stream, u, ct, shift=0):
    pos, pt = clue_plain(shift)
    return [(pt[i], stream[u + i - 21], ct[i], i, None) for i in pos]


# ---------------------------------------------------------------- Part B / Part C linear systems

def rows_hidden(tr, a, b):
    """X[C] - a*X[P] - b*X[K] - E = 0 for each triple (columns 0-25 letters, 26 = E)."""
    rows = []
    for p, k, c, *_ in tr:
        r = [0] * 27
        r[IZ[c]] += 1
        r[IZ[p]] -= a
        r[IZ[k]] -= b
        r[26] -= 1
        rows.append([v % 26 for v in r])
    return rows, [0] * len(rows)


def rows_numeric(tr, a, b, kidx):
    """X[C] - a*X[P] - E = b*k (k = key letter on A-Z or KRYPTOS)."""
    rows, rhs = [], []
    for p, k, c, *_ in tr:
        r = [0] * 27
        r[IZ[c]] += 1
        r[IZ[p]] -= a
        r[26] -= 1
        rows.append([v % 26 for v in r])
        rhs.append((b * kidx[k]) % 26)
    return rows, rhs


def chain_rows(ct, L, a, b, shift=0, direction="back"):
    """Two-step chains of plain autokey at lag L through an unknown middle letter (idea 100), one hidden
    alphabet, form X[C] = a X[P] + b X[K] + E with K = plaintext L back (or ahead).
      back:  j in block 1, i = j + L unknown, i + L in block 2:
             X[C_{i+L}] - a X[P_{i+L}] - ab X[C_i] + a X[P_j] + (ab - 1) E = 0
      ahead: X[C_i] - ab X[C_j] + b X[P_j] - b X[P_{i+L}] + (ab - 1) E = 0"""
    pos, pt = clue_plain(shift)
    rows = []
    for j in pos[:13]:
        i, h = j + L, j + 2 * L
        if h not in pt or i in pt:
            continue
        r = [0] * 27
        if direction == "back":
            r[IZ[ct[h]]] += 1
            r[IZ[pt[h]]] -= a
            r[IZ[ct[i]]] -= a * b
            r[IZ[pt[j]]] += a
        else:
            r[IZ[ct[i]]] += 1
            r[IZ[ct[j]]] -= a * b
            r[IZ[pt[j]]] += b
            r[IZ[pt[h]]] -= b
        r[26] += a * b - 1
        rows.append([v % 26 for v in r])
    return rows, [0] * len(rows)


def decide(rows, rhs, tr=None, max_points=31000):
    """'tableau' (Latin clash), 'none' (no solution with distinct places), 'ok'/'capped' (solutions listed),
    'open' (too many to list and no forced collision). Returns (status, solutions)."""
    if tr is not None and clashes(tr):
        return "tableau", []
    if not rows:
        return "open", []
    sols, status = solve_injective(rows, rhs, max_points=max_points, max_sols=64)
    if status == "many":
        if not any(rhs) and forced_equal(rows):
            return "none", []
        return "open", []
    return status, sols


def satisfies(rows, rhs, alpha, E):
    X = {c: i for i, c in enumerate(alpha)}
    return all((sum(r[j] * X[AZ[j]] for j in range(26)) + r[26] * E - t) % 26 == 0 for r, t in zip(rows, rhs))


# ---------------------------------------------------------------- planted messages

def latin_square(rng):
    """A random 26 x 26 Latin square, built row by row as random perfect matchings (not a group table)."""
    rows = []
    used = [set() for _ in range(26)]        # symbols already in each column
    for _ in range(26):
        match = {}                            # symbol -> column
        cols = list(range(26))
        rng.shuffle(cols)

        def aug(c, seen):
            syms = [s for s in range(26) if s not in used[c]]
            rng.shuffle(syms)
            for s in syms:
                if s in seen:
                    continue
                seen.add(s)
                if s not in match or aug(match[s], seen):
                    match[s] = c
                    return True
            return False
        for c in cols:
            assert aug(c, set())
        row = [0] * 26
        for s, c in match.items():
            row[c] = s
            used[c].add(s)
        rows.append(row)
    rng.shuffle(rows)
    return rows


def is_latin(sq):
    return all(len(set(r)) == 26 for r in sq) and all(len({r[c] for r in sq}) == 26 for c in range(26))


def plant_text(rng, shift=0):
    from .round11 import english97
    pt = list(english97(rng))
    for p, ch in clue_plain(shift)[1].items():
        pt[p] = ch
    return "".join(pt)


def key_letter(model, i, pt, out, primer):
    kind, val = model
    if kind == "plain":
        return pt[i - val] if i - val >= 0 else primer[i]
    if kind == "cipher":
        return out[i - val] if i - val >= 0 else primer[i]
    return val[i]                                         # running key text


def encrypt_square(pt, model, sq, primer):
    out = []
    for i, p in enumerate(pt):
        k = key_letter(model, i, pt, out, primer)
        out.append(AZ[sq[IZ[k]][IZ[p]]])
    return "".join(out)


def encrypt_hidden(pt, model, alpha, a, b, E, primer, numeric=None):
    X = {c: i for i, c in enumerate(alpha)}
    out = []
    for i, p in enumerate(pt):
        k = key_letter(model, i, pt, out, primer)
        kv = numeric[k] if numeric else X[k]
        out.append(alpha[(a * X[p] + b * kv + E) % 26])
    return "".join(out)


def model_spec(model, shift=0):
    """Index spec for a planted ('plain'|'cipher', lag) model, as in fixed_models (look-back)."""
    pos, pt = clue_plain(shift)
    kind, L = model
    if kind == "plain":
        return [(i, i - L, "P") for i in pos if i - L in pt]
    return [(i, i - L, "C") for i in pos if i - L >= 0]

