"""Idea 86: solve a keyword alphabet from its alphabetical tail, with no dictionary.

A keyword alphabet M is a keyword of m different letters followed by the other 26 - m letters in
A-Z order. So the position of a letter x in M is

    its slot 0..m-1                          if x is a keyword letter
    m + x - (keyword letters before x)       otherwise (x = 0 for A ... 25 for Z)

A clue test (same key letter at two clue places, for example) is a linear equation mod 26 in the
positions of a few letters. This module finds EVERY keyword alphabet with a keyword of m letters
that satisfies a list of such equations. Nothing is guessed from a word list.

The search places the letters that occur in the equations one at a time (most constrained first).
A letter is given either a free keyword slot or "tail, with c keyword letters before it". Tail
choices must agree with each other: between two tail letters x < y the count c may only grow by
the number of keyword letters between them. As soon as all letters of an equation but one are
placed, the last one's position is forced. Letters that occur in no equation are not searched: the
number of ways to finish the alphabet is counted exactly (and listed when asked).

An alphabet with a keyword of m - 1 letters is also one with m letters (add the first tail letter
to the keyword), so the count at m includes the count at m - 1.
"""
import itertools
import math

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET

IZ = {c: i for i, c in enumerate(AZ)}
IK = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
LAYOUTS = ("M/M", "M/AZ", "M/KR", "AZ/M", "KR/M")     # plaintext side / ciphertext side
FORMS = ("vig", "beau")
B1, B2 = list(range(21, 34)), list(range(63, 74))
POS = B1 + B2

# SOLV[coef][r] = positions p with coef * p + r = 0 mod 26
SOLV = [[tuple(p for p in range(26) if (c * p + r) % 26 == 0) for r in range(26)] for c in range(26)]


class Budget(Exception):
    """The node budget ran out before the search finished."""


def keyword_alphabet(word):
    seen, out = set(), []
    for ch in word + AZ:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


def minimal_keyword(alpha):
    """The shortest keyword that gives this alphabet (drop the part that is already in A-Z order)."""
    n = 26
    while n > 0 and (n == 26 or alpha[n - 1] < alpha[n]):
        n -= 1
    # alpha[n:] is increasing; the keyword is alpha[:n] unless alpha[n-1] < alpha[n] held throughout
    return alpha[:n]


# ---------------------------------------------------------------- equations from the clues

def _side(kind, ch):
    """A letter's number on one side of the tableau, as (coefficients {letter: c}, constant)."""
    if kind == "M":
        return {IZ[ch]: 1}, 0
    return {}, (IZ if kind == "AZ" else IK)[ch]


def _add(e1, e2, s=1):
    co = dict(e1[0])
    for l, c in e2[0].items():
        co[l] = co.get(l, 0) + s * c
    return co, e1[1] + s * e2[1]


def key_exprs(ct, cribs, layout, form, pos=POS):
    """{clue place: key value as a linear expression}. vig: k = C - P, beau: k = C + P."""
    a, b = layout.split("/")
    out = {}
    for i in pos:
        out[i] = _add(_side(b, ct[i]), _side(a, cribs[i]), -1 if form == "vig" else 1)
    return out


def _norm(e):
    co = tuple(sorted((l, c % 26) for l, c in e[0].items() if c % 26))
    return co, e[1] % 26


def equations(ct, cribs, layout, form, rule, n, pos=POS):
    """The clue equations for a key rule. Returns (equations, impossible).

    rule 'rep': repeating key of length n (same place mod n, same key letter).
    rule 'slide': sliding key, the step from one key letter to the next repeats every n
    (the key is the running sum of a repeating word). When every step is known the jump
    from the first clue block to the second is one more equation."""
    k = key_exprs(ct, cribs, layout, form, pos)
    raw = []
    if rule == "rep":
        first = {}
        for i in pos:
            j = first.setdefault(i % n, i)
            if j != i:
                raw.append(_add(k[i], k[j], -1))
    else:
        step, first = {}, {}
        for i in pos:
            if i + 1 in k:
                step[i + 1] = _add(k[i + 1], k[i], -1)          # w[(i+1) mod n]
        for t in sorted(step):
            j = first.setdefault(t % n, t)
            if j != t:
                raw.append(_add(step[t], step[j], -1))
        runs = _runs(pos)
        for (a0, a1), (b0, b1) in zip(runs, runs[1:]):
            e = _add(k[pos[b0]], k[pos[a1 - 1]], -1)
            for t in range(pos[a1 - 1] + 1, pos[b0] + 1):
                if t % n not in first:
                    e = None
                    break
                e = _add(e, step[first[t % n]], -1)
            if e is not None:
                raw.append(e)
    eqs, seen = [], set()
    for e in raw:
        e = _norm(e)
        if not e[0]:
            if e[1]:
                return [], True
            continue
        if e not in seen:
            seen.add(e)
            eqs.append(e)
    return eqs, False


def _runs(pos):
    out, s = [], 0
    for j in range(1, len(pos) + 1):
        if j == len(pos) or pos[j] != pos[j - 1] + 1:
            out.append((s, j))
            s = j
    return out


# ---------------------------------------------------------------- the search

def plan(eqs):
    """Order the letters so equations close as early as possible.
    Returns (order, per-depth list of (coef of this letter, constant, other letters))."""
    pending = [dict(co) for co, _ in eqs]
    consts = [c for _, c in eqs]
    freq = {}
    for co in pending:
        for l in co:
            freq[l] = freq.get(l, 0) + 1
    placed, order, closes = set(), [], []
    left = set(range(len(pending)))
    while left:
        # the letter that closes most equations now; else one from the equation nearest to closing
        best, bl = -1, None
        cand = {l for e in left for l in pending[e] if l not in placed}
        for l in sorted(cand):
            n = sum(1 for e in left if all(x in placed or x == l for x in pending[e]))
            if n > best or (n == best and freq[l] > freq[bl]):
                best, bl = n, l
        if best == 0:
            e = min(left, key=lambda e: (sum(1 for x in pending[e] if x not in placed), e))
            bl = max((x for x in pending[e] if x not in placed), key=lambda x: (freq[x], -x))
        placed.add(bl)
        order.append(bl)
        done = [e for e in sorted(left) if all(x in placed for x in pending[e])]
        closes.append([(pending[e][bl], consts[e], tuple((l, c) for l, c in pending[e].items() if l != bl))
                       for e in done])
        left -= set(done)
    return order, closes


def _pc(v):
    return bin(v).count("1")


def solve(eqs, m, max_nodes=10 ** 9, list_cap=0):
    """Every keyword alphabet (keyword of m different letters, then A-Z order) meeting all equations.

    Returns {"count": exact number of alphabets, "nodes": search steps, "alphas": the first
    list_cap of them}. Raises Budget if more than max_nodes steps are needed."""
    order, closes = plan(eqs)
    n = len(order)
    pos, cv = [0] * 26, [0] * 26
    st = {"nodes": 0, "count": 0}
    alphas = []
    fact = math.factorial
    solv = SOLV

    def leaf(tail, kw, used):
        prev, cprev, total, r, parts = -1, 0, 1, 0, []
        t = tail | (1 << 26)
        while t:
            y = (t & -t).bit_length() - 1
            t &= t - 1
            cy = m if y == 26 else cv[y]
            inside = (kw >> (prev + 1)) & ((1 << (y - prev - 1)) - 1)
            a = _pc(inside)
            u, need = y - prev - 1 - a, cy - cprev - a
            total *= math.comb(u, need) if hasattr(math, "comb") else fact(u) // fact(need) // fact(u - need)
            r += need
            if need:
                parts.append(([x for x in range(prev + 1, y) if not kw >> x & 1], need))
            prev, cprev = y, cy
        total *= fact(r)
        st["count"] += total
        if len(alphas) < list_cap:
            free = [s for s in range(m) if not used >> s & 1]
            for choice in itertools.product(*[itertools.combinations(xs, k) for xs, k in parts]):
                extra = [x for c in choice for x in c]
                for perm in itertools.permutations(extra):
                    word = [None] * m
                    for x in range(26):
                        if kw >> x & 1:
                            word[pos[x]] = x
                    for s, x in zip(free, perm):
                        word[s] = x
                    inkw = set(word)
                    alphas.append("".join(AZ[x] for x in word) + "".join(AZ[x] for x in range(26) if x not in inkw))
                    if len(alphas) >= list_cap:
                        return

    def rec(d, tail, kw, used):
        if d == n:
            leaf(tail, kw, used)
            return
        st["nodes"] += 1
        if st["nodes"] > max_nodes:
            raise Budget()
        x = order[d]
        below = tail & ((1 << x) - 1)
        if below:
            xl = below.bit_length() - 1
            cl = cv[xl]
        else:
            xl, cl = -1, 0
        above = tail >> (x + 1)
        if above:
            y = x + (above & -above).bit_length()
            cr = cv[y]
        else:
            y, cr = 26, m
        base = cl + _pc((kw >> (xl + 1)) & ((1 << (x - xl - 1)) - 1))
        ar = _pc((kw >> (x + 1)) & ((1 << (y - x - 1)) - 1))
        lo, hi = max(base, cr - (y - x - 1)), min(cl + x - xl - 1, cr - ar)
        kwok = cr - base - ar >= 1
        E = closes[d]
        if E:
            cand = None
            for coef, const, others in E:
                r = const
                for l, c in others:
                    r += c * pos[l]
                s = solv[coef][r % 26]
                cand = s if cand is None else [p for p in cand if p in s]
                if not cand:
                    return
            for p in cand:
                if p < m:
                    if kwok and not used >> p & 1:
                        pos[x] = p
                        rec(d + 1, tail, kw | 1 << x, used | 1 << p)
                elif lo <= m + x - p <= hi:
                    pos[x], cv[x] = p, m + x - p
                    rec(d + 1, tail | 1 << x, kw, used)
        else:
            if kwok:
                for p in range(m):
                    if not used >> p & 1:
                        pos[x] = p
                        rec(d + 1, tail, kw | 1 << x, used | 1 << p)
            for c in range(lo, hi + 1):
                pos[x], cv[x] = m + x - c, c
                rec(d + 1, tail | 1 << x, kw, used)

    rec(0, 0, 0, 0)
    return {"count": st["count"], "nodes": st["nodes"], "alphas": alphas}


def climb(eqs, impossible, mmax, max_nodes, list_cap):
    """Run m = 1, 2, ... mmax until the system has used max_nodes search steps in all.

    Returns (rows, done, list_m, alphas): rows are (m, count, nodes) per finished level, done is
    the last finished m, and alphas is the complete list of solutions at list_m, the highest
    finished level with at most list_cap solutions."""
    if impossible:
        return [(m, 0, 0) for m in range(1, mmax + 1)], mmax, mmax, []
    rows, alphas, done, list_m, listing, left = [], [], 0, 0, True, max_nodes
    for m in range(1, mmax + 1):
        try:
            r = solve(eqs, m, left, list_cap if listing else 0)
        except Budget:
            break
        left -= r["nodes"]
        rows.append((m, r["count"], r["nodes"]))
        done = m
        if listing and r["count"] <= list_cap:
            alphas, list_m = r["alphas"], m
        else:
            listing = False
    return rows, done, list_m, alphas


def brute_count(eqs, m):
    """Slow check of solve(): try every keyword of m letters."""
    n = 0
    for word in itertools.permutations(range(26), m):
        s = set(word)
        p = {x: i for i, x in enumerate(list(word) + [x for x in range(26) if x not in s])}
        if all((sum(c * p[l] for l, c in co) + k) % 26 == 0 for co, k in eqs):
            n += 1
    return n


# ---------------------------------------------------------------- reading a solution

def read(alpha, ct, cribs, layout, form, rule, n, pos=POS):
    """Fill in every plaintext letter the clues force for this alphabet.
    Returns (text with '.' where nothing is forced, key letters as numbers or None, ok)."""
    a, b = layout.split("/")
    im = {c: i for i, c in enumerate(alpha)}
    ia = im if a == "M" else (IZ if a == "AZ" else IK)
    ib = im if b == "M" else (IZ if b == "AZ" else IK)
    pa = alpha if a == "M" else (AZ if a == "AZ" else KRYPTOS_ALPHABET)
    sg = -1 if form == "vig" else 1
    k = {i: (ib[ct[i]] + sg * ia[cribs[i]]) % 26 for i in pos}
    N = len(ct)
    key, ok = [None] * N, True
    if rule == "rep":
        slot = {}
        for i in pos:
            if slot.setdefault(i % n, k[i]) != k[i]:
                ok = False
        for i in range(N):
            key[i] = slot.get(i % n)
    else:
        w = {}
        for i in pos:
            if i + 1 in k:
                if w.setdefault((i + 1) % n, (k[i + 1] - k[i]) % 26) != (k[i + 1] - k[i]) % 26:
                    ok = False
        for i in pos:
            key[i] = k[i]
        for i in range(1, N):                      # forward
            if key[i - 1] is not None and i % n in w:
                v = (key[i - 1] + w[i % n]) % 26
                if key[i] is None:
                    key[i] = v
                elif key[i] != v:
                    ok = False
        for i in range(N - 1, 0, -1):              # backward
            if key[i] is not None and key[i - 1] is None and i % n in w:
                key[i - 1] = (key[i] - w[i % n]) % 26
    out = []
    for i in range(N):
        if key[i] is None:
            out.append(".")
        else:
            x = ib[ct[i]]
            out.append(pa[(x - key[i]) % 26 if form == "vig" else (key[i] - x) % 26])
    pt = "".join(out)
    if any(pt[i] != cribs[i] for i in pos):
        ok = False
    return pt, key, ok


def encrypt(pt, alpha, layout, form, rule, word):
    """Encrypt with keyword alphabet `alpha`. word: key numbers (repeating key, or the steps of a sliding key)."""
    a, b = layout.split("/")
    im = {c: i for i, c in enumerate(alpha)}
    ia = im if a == "M" else (IZ if a == "AZ" else IK)
    pb = alpha if b == "M" else (AZ if b == "AZ" else KRYPTOS_ALPHABET)
    out, t = [], 0
    for i, ch in enumerate(pt):
        t = word[i % len(word)] if rule == "rep" else (t + word[i % len(word)]) % 26
        x = ia[ch]
        out.append(pb[(x + t) % 26 if form == "vig" else (t - x) % 26])
    return "".join(out)


def extra_score(pt, big, clue=frozenset(POS)):
    """English score per quadgram over the forced letters OUTSIDE the clues (a quadgram counts if all
    four letters are forced and at least one is not a clue letter). Returns (score or None, quadgrams)."""
    tot, cnt = 0.0, 0
    get, fl = big.logp.get, big.floor
    for i in range(len(pt) - 3):
        q = pt[i:i + 4]
        if "." in q or (i in clue and i + 3 in clue):
            continue
        tot += get(q, fl)
        cnt += 1
    return (tot / cnt if cnt else None), cnt
