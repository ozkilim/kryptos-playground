"""Idea 138: exact decision of Quagmire I, II, IV (and III, as a regression check) with a repeating key,
for every alphabet (pair), from the 24 carved clue letters.

Notation (ACA definitions). x[P] = place of plaintext letter P in the plain-side alphabet, y[C] = place of
ciphertext letter C in the cipher-side alphabet. Straight sides are A-Z, so their places are KNOWN numbers.

    Quagmire I    plain side keyed (x unknown), cipher side A-Z (y[C] = C's number)
    Quagmire II   plain side A-Z (x[P] = P's number), cipher side keyed (y unknown)
    Quagmire III  one keyed alphabet on both sides (x = y unknown)
    Quagmire IV   two independent keyed alphabets (x and y unknown)

Vigenere form: key[i mod L] = y[C_i] - x[P_i].  Beaufort form: key = y[C_i] + x[P_i]  (mod 26).
Two clue positions in the same class mod L share the key, so each pair gives one linear equation
    sum coef * place + const = 0 (mod 26).
For Quagmire I and II the straight side contributes a constant (the equations are affine); for III and IV
there is no constant. For I, II and IV the Beaufort form is the Vigenere form with one keyed alphabet
reversed (x -> -x is again an alphabet), so the two forms must give the same verdicts (checked, not assumed).

Two independent deciders:

* certificate(): linear algebra mod 2 and mod 13 (Z_26 = Z_2 x Z_13). The system is inconsistent mod p, or
  it forces place[a] = place[b] mod 26 for two different letters of the same alphabet. Either proves that
  no alphabet (pair) exists, whatever the key.
* decide(): complete backtracking over the places of the letters in the equations, all places in one
  alphabet different. Gauge symmetries are found automatically from the rows: a group whose coefficients
  sum to 0 in every row may be shifted (its first letter is fixed at 0); if no row has a constant, a joint
  unit multiple is free (one letter then takes 1, 2 or 13). Returns SAT with a witness or UNSAT.
"""
from .round9 import POS

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NUM = {ch: i for i, ch in enumerate(AZ)}
MODELS = ("QI", "QII", "QIII", "QIV")


class Budget(Exception):
    pass


def classes(L, pos=POS):
    cl = {}
    for i in pos:
        cl.setdefault(i % L, []).append(i)
    return [v for v in cl.values() if len(v) > 1]


def _terms(model, c, p):
    """Key value at a clue position as (dict var->coef, const), Vigenere form with sign s on the plain part
    applied by the caller. Vars are (group, letter)."""
    if model == "QI":
        return [(None, NUM[c]), (("x", p), 1)]
    if model == "QII":
        return [(("y", c), 1), (None, NUM[p])]
    if model == "QIII":
        return [(("a", c), 1), (("a", p), 1)]
    if model == "QIV":
        return [(("y", c), 1), (("x", p), 1)]
    raise ValueError(model)


def key_expr(model, form, c, p):
    s = -1 if form == "vig" else 1
    (vc, cc), (vp, cp) = _terms(model, c, p)
    d, const = {}, 0
    # cipher part
    if vc is None:
        const += cc
    else:
        d[vc] = d.get(vc, 0) + 1
    # plain part, sign s
    if vp is None:
        const += s * cp
    else:
        d[vp] = d.get(vp, 0) + s
    return d, const


def equations(ct, cribs, L, model, form="vig", pos=POS):
    """Rows (dict var->coef mod 26, const mod 26) meaning sum coef*var + const = 0 (mod 26).
    Rows with nothing left are dropped if trivially true; a row 0 = const != 0 is kept (contradiction)."""
    rows = []
    for cls in classes(L, pos):
        a = cls[0]
        da, ka = key_expr(model, form, ct[a], cribs[a])
        for b in cls[1:]:
            db, kb = key_expr(model, form, ct[b], cribs[b])
            d = dict(da)
            for v, c in db.items():
                d[v] = d.get(v, 0) - c
            d = {v: c % 26 for v, c in d.items() if c % 26}
            const = (ka - kb) % 26
            if d or const:
                rows.append((d, const))
    return rows


def vars_of(rows):
    out = []
    for d, _ in rows:
        for v in sorted(d):
            if v not in out:
                out.append(v)
    return out


def _rank(mat, p):
    m = [[v % p for v in r] for r in mat]
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
    """List of reasons no solution exists: ('inconsistent', p) or ('equal', var_a, var_b) for two different
    letters of the same alphabet forced to one place mod 26. Empty list = no linear certificate."""
    if not rows:
        return []
    vs = vars_of(rows)
    A = [[d.get(v, 0) for v in vs] for d, _ in rows]
    Ab = [r + [(-c) % 26] for r, (_, c) in zip(A, rows)]
    out = []
    base = {}
    for p in (2, 13):
        ra, rb = _rank(A, p), _rank(Ab, p)
        if ra < rb:
            out.append(("inconsistent", p))
        base[p] = rb
    if out:
        return out
    for i, a in enumerate(vs):
        for j in range(i + 1, len(vs)):
            b = vs[j]
            if a[0] != b[0]:
                continue
            v = [0] * (len(vs) + 1)
            v[i], v[j] = 1, 25
            if all(_rank(Ab + [v], p) == base[p] for p in (2, 13)):
                out.append(("equal", a, b))
    return out


def order(rows):
    vs = vars_of(rows)
    done, seq = set(), []
    while len(seq) < len(vs):
        best = None
        for v in vs:
            if v in done:
                continue
            closes = sum(1 for d, _ in rows if v in d and all(k in done or k == v for k in d))
            touch = sum(1 for d, _ in rows if v in d and not all(k in done for k in d))
            key = (closes, touch, -vs.index(v))
            if best is None or key > best[0]:
                best = (key, v)
        seq.append(best[1])
        done.add(best[1])
    return seq


def gauges(rows):
    """(groups that may be shifted, whether a joint unit multiple is free)."""
    groups = sorted({v[0] for d, _ in rows for v in d})
    shift = [g for g in groups if all(sum(c for v, c in d.items() if v[0] == g) % 26 == 0 for d, _ in rows)]
    mult = all(c == 0 for _, c in rows)
    return shift, mult


def _search(rows, seq, count_cap, max_nodes):
    n = len(seq)
    idx = {v: i for i, v in enumerate(seq)}
    clos = [[] for _ in range(n)]
    for d, c in rows:
        if not d:
            if c:
                return 0, None, 0
            continue
        clos[max(idx[v] for v in d)].append(([(idx[v], cf) for v, cf in d.items()], c))
    shift, mult = gauges(rows)
    gauge = [None] * n
    seen, mult_used = {}, False
    for i, v in enumerate(seq):
        g = v[0]
        k = seen.get(g, 0)
        if g in shift and k == 0:
            gauge[i] = [0]
        elif mult and not mult_used and g in shift and k == 1:
            gauge[i] = [1, 2, 13]
            mult_used = True
        seen[g] = k + 1
    grp = [v[0] for v in seq]
    used = {g: [False] * 26 for g in set(grp)}
    val = [0] * n
    st = {"count": 0, "first": None, "nodes": 0}

    def cand(i):
        if gauge[i] is not None:
            return gauge[i]
        for r, c in clos[i]:
            c0, rest = 0, c
            for j, cf in r:
                if j == i:
                    c0 = cf
                else:
                    rest += val[j] * cf
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
                st["first"] = {seq[j]: val[j] for j in range(n)}
            if count_cap and st["count"] >= count_cap:
                raise StopIteration
            return
        u = used[grp[i]]
        for x in cand(i):
            if u[x]:
                continue
            val[i] = x
            if all((sum(val[j] * cf for j, cf in r) + c) % 26 == 0 for r, c in clos[i]):
                u[x] = True
                rec(i + 1)
                u[x] = False
        val[i] = 0

    try:
        rec(0)
    except StopIteration:
        pass
    return st["count"], st["first"], st["nodes"]


def decide(rows, max_nodes=10 ** 7):
    """('SAT', witness, nodes) or ('UNSAT', None, nodes); raises Budget."""
    if any(not d and c for d, c in rows):
        return "UNSAT", None, 0
    rows = [(d, c) for d, c in rows if d]
    if not rows:
        return "SAT", {}, 0
    cnt, first, nodes = _search(rows, order(rows), 1, max_nodes)
    return ("SAT" if cnt else "UNSAT"), first, nodes


def complete(wit, group):
    """Full alphabet for one group from a witness; letters outside the equations fill the free places."""
    a = [None] * 26
    for (g, ch), v in wit.items():
        if g == group:
            a[v] = ch
    rest = iter(ch for ch in AZ if ch not in a)
    return "".join(c if c else next(rest) for c in a)


def alphabets(model, wit):
    """(plain-side alphabet, cipher-side alphabet) strings for a witness."""
    if model == "QI":
        return complete(wit, "x"), AZ
    if model == "QII":
        return AZ, complete(wit, "y")
    if model == "QIII":
        a = complete(wit, "a")
        return a, a
    return complete(wit, "x"), complete(wit, "y")


def encrypt(pt, palpha, calpha, key, form="vig"):
    x = {ch: i for i, ch in enumerate(palpha)}
    L = len(key)
    out = []
    for i, ch in enumerate(pt):
        k = key[i % L]
        v = (x[ch] + k) % 26 if form == "vig" else (k - x[ch]) % 26
        out.append(calpha[v])
    return "".join(out)


def clue_key(palpha, calpha, ct, cribs, L, form="vig", pos=POS):
    """Key slots the clues force; (key dict, consistent)."""
    x = {ch: i for i, ch in enumerate(palpha)}
    y = {ch: i for i, ch in enumerate(calpha)}
    s = -1 if form == "vig" else 1
    key, ok = {}, True
    for i in pos:
        k = (y[ct[i]] + s * x[cribs[i]]) % 26
        if key.setdefault(i % L, k) != k:
            ok = False
    return key, ok


def read(palpha, calpha, ct, cribs, L, form="vig", pos=POS):
    """Decrypt with the clue-forced key ('?' where a slot has no clue). Returns (text, consistent)."""
    key, ok = clue_key(palpha, calpha, ct, cribs, L, form, pos)
    y = {ch: i for i, ch in enumerate(calpha)}
    out = []
    for i, ch in enumerate(ct):
        k = key.get(i % L)
        if k is None:
            out.append("?")
        else:
            v = (y[ch] - k) % 26 if form == "vig" else (k - y[ch]) % 26
            out.append(palpha[v])
    return "".join(out), ok


def random_pair(model, rng):
    """Random alphabets for a model: (plain side, cipher side)."""
    a = "".join(rng.sample(AZ, 26))
    if model == "QI":
        return a, AZ
    if model == "QII":
        return AZ, a
    if model == "QIII":
        return a, a
    return a, "".join(rng.sample(AZ, 26))


def fmt_row(row):
    d, c = row
    parts = []
    for (g, ch), cf in sorted(d.items()):
        parts.append(("+" if cf < 13 else "-") + ("" if cf in (1, 25) else str(min(cf, 26 - cf))) + g + "[" + ch + "]")
    return " ".join(parts) + (" %+d" % (c if c < 13 else c - 26) if c else "") + " = 0"
