"""Idea 130: exact decision for Quagmire III (one unknown alphabet on both sides) with a repeating key.

Unknown: the place x[ch] in 0..25 of every letter in the mixed alphabet (all different).
Beaufort form: key = x[C] + x[P] mod 26.  Vigenere form: key = x[C] - x[P] mod 26.
Two clue positions in the same residue class mod L share a key value, so each such pair gives a
linear equation in at most four letter places. The question "is there any alphabet?" is then:
does some injective map letters -> Z_26 satisfy the equations?

Two independent ways to answer it:

* certificate(): linear algebra mod 2 and mod 13 (kryptos.round9). If the equations imply
  x[X] - x[Y] = 0 mod 26 for two different letters X, Y, no alphabet can exist. Short and checkable
  by hand.
* decide(): complete backtracking over the letters that occur in the equations, in an order that
  closes equations early, every place distinct. The gauge is fixed (first letter at 0, the second
  at 1, 2 or 13, which covers every alphabet up to shift and unit multiple, both of which keep the
  equations). It says SAT with a witness or UNSAT after an exhaustive search.

enumerate_fixed() lists every alphabet that agrees with a given one outside a chosen set of free
letters (used for the planted "listed and read back" test).
"""
from .round9 import POS

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class Budget(Exception):
    pass


def classes(L, pos=POS):
    cl = {}
    for i in pos:
        cl.setdefault(i % L, []).append(i)
    return [v for v in cl.values() if len(v) > 1]


def equations(ct, cribs, L, form="beau", pos=POS):
    """Rows as dicts {letter: coef mod 26} meaning sum coef * x[letter] = 0 mod 26 (rows that
    cancel to nothing are dropped)."""
    s = 1 if form == "beau" else -1
    rows = []
    for cls in classes(L, pos):
        a = cls[0]
        for b in cls[1:]:
            d = {}
            for ch, c in ((ct[a], 1), (cribs[a], s), (ct[b], -1), (cribs[b], -s)):
                d[ch] = (d.get(ch, 0) + c) % 26
            d = {k: v for k, v in d.items() if v}
            if d:
                rows.append(d)
    return rows


def letters_of(rows):
    out = []
    for r in rows:
        for ch in sorted(r):
            if ch not in out:
                out.append(ch)
    return out


def _rank(rows, p):
    """Rank of integer rows over GF(p)."""
    m = [[v % p for v in r] for r in rows]
    rk, n = 0, len(m[0]) if m else 0
    for c in range(n):
        s = next((i for i in range(rk, len(m)) if m[i][c]), None)
        if s is None:
            continue
        m[rk], m[s] = m[s], m[rk]
        inv = pow(m[rk][c], p - 2, p) if p > 2 else 1
        m[rk] = [(v * inv) % p for v in m[rk]]
        for i in range(len(m)):
            if i != rk and m[i][c]:
                f = m[i][c]
                m[i] = [(a - f * b) % p for a, b in zip(m[i], m[rk])]
        rk += 1
    return rk


def certificate(rows):
    """Pairs (X, Y) of different letters whose places the equations force to be equal mod 26.
    Any such pair proves that no alphabet exists."""
    lets = letters_of(rows)
    if not rows:
        return []
    mat = [[r.get(ch, 0) for ch in lets] for r in rows]
    base = {p: _rank(mat, p) for p in (2, 13)}
    out = []
    for i, x in enumerate(lets):
        for j in range(i + 1, len(lets)):
            v = [0] * len(lets)
            v[i], v[j] = 1, 25
            if all(_rank(mat + [v], p) == base[p] for p in (2, 13)):
                out.append((x, lets[j]))
    return out


def order(rows):
    """Greedy letter order: next letter is the one that closes the most equations, then the one in
    the most still-open equations."""
    lets = letters_of(rows)
    done, seq = set(), []
    while len(seq) < len(lets):
        best = None
        for ch in lets:
            if ch in done:
                continue
            closes = sum(1 for r in rows if ch in r and all(k in done or k == ch for k in r))
            touch = sum(1 for r in rows if ch in r and not all(k in done for k in r))
            key = (closes, touch, -lets.index(ch))
            if best is None or key > best[0]:
                best = (key, ch)
        seq.append(best[1])
        done.add(best[1])
    return seq


def _search(rows, seq, fixed, gauge, count_cap, max_nodes):
    """Backtracking. fixed: {letter: place} (assigned in advance, not searched). Returns
    (count, first_solution, nodes, capped)."""
    seq = [ch for ch in seq if ch not in fixed]
    lets = list(fixed) + seq
    idx = {ch: i for i, ch in enumerate(lets)}
    n = len(lets)
    clos = [[] for _ in range(n)]
    for r in rows:
        last = max(idx[ch] for ch in r)
        clos[last].append([(idx[ch], c) for ch, c in r.items()])
    val = [None] * n
    used = [False] * 26
    for ch, v in fixed.items():
        if used[v]:
            return 0, None, 0, False
        val[idx[ch]] = v
        used[v] = True
    nf = len(fixed)
    for i in range(nf):           # rows entirely inside the fixed part
        for r in clos[i]:
            if sum(val[j] * c for j, c in r) % 26:
                return 0, None, 0, False
    st = {"count": 0, "first": None, "nodes": 0, "capped": False}

    def cand(i):
        if gauge and i == nf and nf == 0:
            return [0]
        if gauge and i == nf + 1 and nf == 0:
            return [1, 2, 13]
        # a closing row with a unit coefficient on this letter forces its value
        for r in clos[i]:
            c0, rest = 0, 0
            for j, c in r:
                if j == i:
                    c0 = c
                else:
                    rest += val[j] * c
            if c0 % 2 and c0 % 13:
                return [(-rest * pow(c0, -1, 26)) % 26]
        return range(26)

    def rec(i):
        st["nodes"] += 1
        if st["nodes"] > max_nodes:
            raise Budget()
        if i == n:
            st["count"] += 1
            if st["first"] is None:
                st["first"] = {lets[j]: val[j] for j in range(n)}
            if count_cap and st["count"] >= count_cap:
                st["capped"] = True
                raise StopIteration
            return
        for v in cand(i):
            if used[v]:
                continue
            val[i] = v
            ok = True
            for r in clos[i]:
                if sum(val[j] * c for j, c in r) % 26:
                    ok = False
                    break
            if ok:
                used[v] = True
                rec(i + 1)
                used[v] = False
        val[i] = None

    try:
        rec(nf)
    except StopIteration:
        pass
    return st["count"], st["first"], st["nodes"], st["capped"]


def decide(rows, max_nodes=10 ** 8):
    """'SAT' with a witness, or 'UNSAT' (exhaustive), or raises Budget."""
    if not rows:
        return "SAT", {}, 0
    seq = order(rows)
    cnt, first, nodes, _ = _search(rows, seq, {}, True, 1, max_nodes)
    return ("SAT" if cnt else "UNSAT"), first, nodes


def count(rows, cap=10 ** 6, max_nodes=10 ** 8):
    """Gauge-fixed solutions on the letters in the equations, up to cap. Returns (count, capped, nodes)."""
    seq = order(rows)
    cnt, _, nodes, capped = _search(rows, seq, {}, True, cap, max_nodes)
    return cnt, capped, nodes


def check(alpha, rows):
    x = {ch: i for i, ch in enumerate(alpha)}
    return all(sum(x[ch] * c for ch, c in r.items()) % 26 == 0 for r in rows)


def enumerate_fixed(rows, alpha, free):
    """Every alphabet that keeps the letters of the equations outside `free` at their place in
    alpha, puts the free letters on ANY other places (all different) and satisfies the equations.
    Letters outside the equations keep their place in alpha when it is still free, and otherwise
    fill the leftover places in A-Z order. Free letters are placed one at a time and each closed
    equation is checked at once."""
    x = {ch: i for i, ch in enumerate(alpha)}
    lets = letters_of(rows)
    fixed = {ch: x[ch] for ch in lets if ch not in free}
    seq = [ch for ch in order(rows) if ch in free]
    pos_in = {ch: i for i, ch in enumerate(seq)}
    clos = [[] for _ in seq]
    for r in rows:
        if any(ch in pos_in for ch in r):
            clos[max(pos_in[ch] for ch in r if ch in pos_in)].append(r)
        elif sum(fixed[ch] * c for ch, c in r.items()) % 26:
            return []
    out = []
    cur = dict(fixed)
    used = set(fixed.values())

    def rec(i):
        if i == len(seq):
            a = [None] * 26
            for ch, v in cur.items():
                a[v] = ch
            others = [ch for ch in AZ if ch not in cur]
            late = []
            for ch in others:
                if a[x[ch]] is None:
                    a[x[ch]] = ch
                else:
                    late.append(ch)
            it = iter(late)
            out.append("".join(c if c else next(it) for c in a))
            return
        ch = seq[i]
        for v in range(26):
            if v in used:
                continue
            cur[ch] = v
            if all(sum(cur[k] * c for k, c in r.items()) % 26 == 0 for r in clos[i]):
                used.add(v)
                rec(i + 1)
                used.discard(v)
            del cur[ch]

    rec(0)
    return out


def encrypt(pt, alpha, word, form="beau"):
    x = {ch: i for i, ch in enumerate(alpha)}
    L = len(word)
    out = []
    for i, ch in enumerate(pt):
        k = word[i % L]
        v = (k - x[ch]) % 26 if form == "beau" else (x[ch] + k) % 26
        out.append(alpha[v])
    return "".join(out)


def read(alpha, ct, cribs, L, form="beau", pos=POS):
    """Decrypt ct with alphabet alpha and the key values the clues force; '?' where the key slot
    has no clue position. Returns (plaintext, consistent)."""
    x = {ch: i for i, ch in enumerate(alpha)}
    s = 1 if form == "beau" else -1
    key, ok = {}, True
    for i in pos:
        k = (x[ct[i]] + s * x[cribs[i]]) % 26
        if key.setdefault(i % L, k) != k:
            ok = False
    out = []
    for i, ch in enumerate(ct):
        k = key.get(i % L)
        if k is None:
            out.append("?")
        else:
            v = (k - x[ch]) % 26 if form == "beau" else (x[ch] - k) % 26
            out.append(alpha[v])
    return "".join(out), ok
