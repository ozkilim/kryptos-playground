"""Idea 131: Quagmire IV where BOTH alphabets are keyword alphabets whose keywords need not be words.

This extends idea 86's tail solver (`kryptos/idea86_tail.py`) to two unknown alphabets at once.

A keyword alphabet is a keyword of m different letters followed by the other letters in A-Z order.
A letter x then sits at

    its keyword slot 0..m-1                      if x is a keyword letter
    m + x - (keyword letters before x)           otherwise (its "tail" place)

The two transposition-mixed forms of round 11 (`kryptos.round11.mixes`) write that alphabet in rows
of width m and read it off by columns ("cols") or by columns in the alphabetical order of the
keyword letters ("keyed"). For "cols" the final place is a fixed permutation F_m of the keyword
place, so it is handled exactly by the same search (a forced final place r means keyword place
F_m^-1(r)). "keyed" depends on the order of the keyword letters and is not handled here.

Quagmire IV, repeating key of length L:
    Vigenere form   c(C_i) - p(P_i) = k[i mod L]
    Beaufort form   c(C_i) + p(P_i) = k[i mod L]
with p() the places in the plain alphabet and c() the places in the cipher alphabet. Two clue
places with the same i mod L give one linear equation in two plain and two cipher places. Turning
either alphabet round is the same as adding a constant to the key, so canonical alphabets lose
nothing.

Variables: plain letter x is variable x, cipher letter y is variable 26 + y. The search places the
variables one at a time (idea 86's ordering), each side with its own keyword length and its own
tail bookkeeping, and forces the last variable of every equation. Letters in no equation are
counted per side at the leaf (the two sides complete independently), not searched.
"""
import itertools
import math

from .ciphers.substitution import AZ
from .idea86_tail import Budget, SOLV, keyword_alphabet, plan

B1, B2 = list(range(21, 34)), list(range(63, 74))
POS = B1 + B2


def _pc(v):
    return bin(v).count("1")


def cols_perm(m):
    """F[q] = final place of keyword-alphabet place q when read off by columns of width m."""
    if m < 3:
        return list(range(26))
    order = [q for c in range(m) for q in range(c, 26, m)]
    F = [0] * 26
    for r, q in enumerate(order):
        F[q] = r
    return F


def apply_form(alpha, form, m):
    """The final alphabet: the keyword alphabet as is ('kw') or read off by columns of width m ('cols')."""
    if form == "kw" or m < 3:
        return alpha
    return "".join(alpha[c::m] for c in range(m))


def equations(ct, cribs, L, form, pos=POS):
    """Clue equations for Quagmire IV with a repeating key of length L. Returns (eqs, impossible).
    Each equation is (((var, coef), ...), const) meaning sum coef * place(var) + const = 0 mod 26."""
    sg = -1 if form == "vig" else 1                  # k = c - p  or  k = c + p
    first, raw = {}, []
    for i in pos:
        j = first.setdefault(i % L, i)
        if j == i:
            continue
        co = {}
        for v, c in ((26 + ord(ct[i]) - 65, 1), (26 + ord(ct[j]) - 65, -1),
                     (ord(cribs[i]) - 65, sg), (ord(cribs[j]) - 65, -sg)):
            co[v] = co.get(v, 0) + c
        raw.append(tuple(sorted((v, c % 26) for v, c in co.items() if c % 26)))
    eqs, seen = [], set()
    for co in raw:
        if not co:
            continue
        if co not in seen:
            seen.add(co)
            eqs.append((co, 0))
    return eqs, False


def side_count(m, tail, kw, cv):
    """Number of ways to finish one side, given its placed tail and keyword letters."""
    prev, cprev, total, r = -1, 0, 1, 0
    t = tail | (1 << 26)
    while t:
        y = (t & -t).bit_length() - 1
        t &= t - 1
        cy = m if y == 26 else cv[y]
        a = _pc((kw >> (prev + 1)) & ((1 << (y - prev - 1)) - 1))
        u, need = y - prev - 1 - a, cy - cprev - a
        if need < 0 or need > u:
            return 0
        total *= math.comb(u, need)
        r += need
        prev, cprev = y, cy
    return total * math.factorial(r)


def side_alphas(m, tail, kw, cv, q, cap):
    """List up to cap keyword alphabets (as strings, keyword-alphabet order) finishing one side.
    q[x] = keyword place of placed letter x."""
    prev, cprev, parts = -1, 0, []
    t = tail | (1 << 26)
    while t:
        y = (t & -t).bit_length() - 1
        t &= t - 1
        cy = m if y == 26 else cv[y]
        a = _pc((kw >> (prev + 1)) & ((1 << (y - prev - 1)) - 1))
        need = cy - cprev - a
        if need:
            parts.append(([x for x in range(prev + 1, y) if not kw >> x & 1], need))
        prev, cprev = y, cy
    used = {q[x] for x in range(26) if kw >> x & 1}
    free = [s for s in range(m) if s not in used]
    out = []
    for choice in itertools.product(*[itertools.combinations(xs, k) for xs, k in parts]):
        extra = [x for c in choice for x in c]
        for perm in itertools.permutations(extra):
            word = [None] * m
            for x in range(26):
                if kw >> x & 1:
                    word[q[x]] = x
            for s, x in zip(free, perm):
                word[s] = x
            out.append(keyword_alphabet("".join(AZ[x] for x in word)))
            if len(out) >= cap:
                return out
    return out


def solve(eqs, ms, forms, max_nodes=10 ** 9, keep=0):
    """Every pair of alphabets (plain keyword of ms[0] letters, cipher keyword of ms[1]) meeting eqs.

    forms = (plain form, cipher form), each 'kw' or 'cols'. Returns {"count": exact number of
    alphabet pairs, "nodes": steps, "partials": first `keep` leaves as dicts}. Raises Budget."""
    order, closes = plan(eqs)
    n = len(order)
    F = [cols_perm(ms[s]) if forms[s] == "cols" else list(range(26)) for s in (0, 1)]
    Finv = [[0] * 26 for _ in (0, 1)]
    for s in (0, 1):
        for qq, r in enumerate(F[s]):
            Finv[s][r] = qq
    pos = [0] * 52          # final place
    qk = [0] * 52           # keyword-alphabet place
    cv = [0] * 52
    tail, kw, used = [0, 0], [0, 0], [0, 0]
    st = {"nodes": 0, "count": 0}
    partials = []

    def leaf():
        c0 = side_count(ms[0], tail[0], kw[0], cv[0:26])
        if not c0:
            return
        c1 = side_count(ms[1], tail[1], kw[1], cv[26:52])
        if not c1:
            return
        st["count"] += c0 * c1
        if len(partials) < keep:
            partials.append({"q": list(qk), "cv": list(cv), "tail": list(tail), "kw": list(kw),
                             "count": (c0, c1)})

    def rec(d):
        if d == n:
            leaf()
            return
        st["nodes"] += 1
        if st["nodes"] > max_nodes:
            raise Budget()
        v = order[d]
        s, x = divmod(v, 26)
        m, T, K, U, off = ms[s], tail[s], kw[s], used[s], 26 * s
        below = T & ((1 << x) - 1)
        if below:
            xl = below.bit_length() - 1
            cl = cv[off + xl]
        else:
            xl, cl = -1, 0
        above = T >> (x + 1)
        if above:
            y = x + (above & -above).bit_length()
            cr = cv[off + y]
        else:
            y, cr = 26, m
        base = cl + _pc((K >> (xl + 1)) & ((1 << (x - xl - 1)) - 1))
        ar = _pc((K >> (x + 1)) & ((1 << (y - x - 1)) - 1))
        lo, hi = max(base, cr - (y - x - 1)), min(cl + x - xl - 1, cr - ar)
        kwok = cr - base - ar >= 1
        E = closes[d]
        if E:
            cand = None
            for coef, const, others in E:
                r = const
                for l, c in others:
                    r += c * pos[l]
                sl = SOLV[coef][r % 26]
                cand = sl if cand is None else [p for p in cand if p in sl]
                if not cand:
                    return
            opts = []
            for p in cand:
                qq = Finv[s][p]
                if qq < m:
                    if kwok and not U >> qq & 1:
                        opts.append((qq, None))
                elif lo <= m + x - qq <= hi:
                    opts.append((qq, m + x - qq))
        else:
            opts = [(qq, None) for qq in range(m) if not U >> qq & 1] if kwok else []
            opts += [(m + x - c, c) for c in range(lo, hi + 1)]
        Fs = F[s]
        for qq, c in opts:
            pos[v], qk[v] = Fs[qq], qq
            if c is None:
                kw[s], used[s] = K | 1 << x, U | 1 << qq
                rec(d + 1)
                kw[s], used[s] = K, U
            else:
                cv[v] = c
                tail[s] = T | 1 << x
                rec(d + 1)
                tail[s] = T

    rec(0)
    return {"count": st["count"], "nodes": st["nodes"], "partials": partials}


def expand(part, ms, forms, cap):
    """Full final alphabets (plain list, cipher list) for a stored leaf, each side capped."""
    out = []
    for s in (0, 1):
        al = side_alphas(ms[s], part["tail"][s], part["kw"][s], part["cv"][26 * s:26 * s + 26],
                         part["q"][26 * s:26 * s + 26], cap)
        out.append([apply_form(a, forms[s], ms[s]) for a in al])
    return out


def encrypt(pt, pa, ca, form, key):
    ip = {c: i for i, c in enumerate(pa)}
    out = []
    for i, ch in enumerate(pt):
        k = key[i % len(key)]
        out.append(ca[(ip[ch] + k) % 26] if form == "vig" else ca[(k - ip[ch]) % 26])
    return "".join(out)


def decrypt(ct, pa, ca, form, L, cribs, pos=POS):
    """Decrypt with the key the clues force; None where the key slot is not covered, or if inconsistent."""
    ic = {c: i for i, c in enumerate(ca)}
    ip = {c: i for i, c in enumerate(pa)}
    key = {}
    for i in pos:
        k = (ic[ct[i]] - ip[cribs[i]]) % 26 if form == "vig" else (ic[ct[i]] + ip[cribs[i]]) % 26
        if key.setdefault(i % L, k) != k:
            return None
    out = []
    for i, ch in enumerate(ct):
        k = key.get(i % L)
        if k is None:
            out.append(".")
        else:
            out.append(pa[(ic[ch] - k) % 26] if form == "vig" else pa[(k - ic[ch]) % 26])
    return "".join(out)


def brute_count(eqs, ms, forms, words0, words1):
    """Slow check: count pairs from explicit keyword lists that satisfy eqs (for tests)."""
    def places(w, s):
        al = apply_form(keyword_alphabet(w), forms[s], ms[s])
        return {ord(ch) - 65 + 26 * s: i for i, ch in enumerate(al)}
    n = 0
    P0 = [places(w, 0) for w in words0]
    P1 = [places(w, 1) for w in words1]
    for a in P0:
        for b in P1:
            p = dict(a)
            p.update(b)
            if all((sum(c * p[v] for v, c in co) + k) % 26 == 0 for co, k in eqs):
                n += 1
    return n


def chance(ms, neq):
    perm = lambda m: math.factorial(26) / math.factorial(26 - m)
    return perm(ms[0]) * perm(ms[1]) / 26.0 ** neq
