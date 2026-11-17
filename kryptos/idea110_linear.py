"""Idea 110: any linear rule for the key, tested without naming the rule.

If each key letter is a fixed linear mix of the few key letters before it,

    K[i] = a1 K[i-1] + ... + aR K[i-R] + c            (mod 26)

then the 13 + 11 key letters the clues force must obey it inside each clue block, whatever the
coefficients are and wherever the blocks sit in the text. With R = 5 that is 8 + 6 equations in
6 unknowns: 8 exact checks. Z_26 is not a field, so every system is solved mod 2 and mod 13.
The mod 2 half is done on bit masks (bit j = equation at clue letter j), which is what makes
the text-fed test (324 settings per key stream) affordable; the mod 13 half reuses
kryptos.round9.solve_mod_p.

Tests (all on one key stream = one tableau layout, Vigenere or Beaufort form):
  A   order 5, free coefficients and constant, same rule in both blocks        8 checks
  A2  order 5 plus a term e*i in the position (needs the carved gap)            7 checks
  A6  order 6, gauge only                                                       5 checks
  B   K[i] = a1 K[i-1] + a2 K[i-2] + u P[i-s] + v C[i-t] + c, s, t = 1..6,
      P and C each numbered on the tableau alphabet, A-Z or KRYPTOS             7-15 checks
  C1  K[i] = g(K[i-d]) for an arbitrary table g, d = 1..6                      forced repeats
  C2  K[i] = g(P[i-d]) or g(C[i-d]) for an arbitrary table g, d = 1..6         forced repeats
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round9 import solve_mod_p

MIN_CHECKS = 7
GAUGE = 5
LAYS_M = (("M/M", 0, 0), ("M/AZ", 0, 1), ("AZ/M", 1, 0), ("M/KR", 0, 2), ("KR/M", 2, 0))
LAYS_AZ = (("AZ/AZ", 1, 1), ("AZ/KR", 1, 2), ("KR/AZ", 2, 1), ("KR/KR", 2, 2))
NUMS = ("M", "AZ", "KR")
IZ = {c: i for i, c in enumerate(AZ)}
IK = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
MAXLAG = 6


def bits(vals):
    """Integer whose bit j is the parity of vals[j]."""
    n = 0
    for j, v in enumerate(vals):
        if v & 1:
            n |= 1 << j
    return n


def in_span2(t, vecs):
    """Is bit vector t a sum (mod 2) of some of vecs? Returns (yes/no, rank of vecs)."""
    basis = []
    for v in vecs:
        for b in basis:
            if v ^ b < v:
                v ^= b
        if v:
            basis.append(v)
    for b in basis:
        if t ^ b < t:
            t ^= b
    return t == 0, len(basis)


class Plan:
    """Everything that depends only on the clue letters (not on the tableau)."""

    def __init__(self, pl, cl, pos, blocks=((0, 13), (13, 24))):
        self.pl, self.cl, self.pos, self.blocks = list(pl), list(cl), list(pos), tuple(blocks)
        self.xp = [None, [IZ[c] for c in pl], [IK[c] for c in pl]]
        self.xc = [None, [IZ[c] for c in cl], [IK[c] for c in cl]]
        self.pb = [None, bits(self.xp[1]), bits(self.xp[2])]
        self.cb = [None, bits(self.xc[1]), bits(self.xc[2])]
        self.posbits = bits(self.pos)
        self.mask, self.neq = {}, {}
        for L in range(1, MAXLAG + 1):
            js = [j for a, b in self.blocks for j in range(a + L, b)]
            self.mask[L] = sum(1 << j for j in js)
            self.neq[L] = len(js)
        # table tests: which (feed, lag) have enough forced repeats
        self.c2 = []
        for feed, x in (("plain", self.pl), ("cipher", self.cl)):
            for d in range(1, MAXLAG + 1):
                inp = tuple(self.lagged(x, d))
                checks = len(inp) - len(set(inp))
                if checks >= GAUGE:
                    self.c2.append((feed, d, inp, len(set(inp)), checks))

    def lagged(self, x, d):
        """x[j-d] for every clue letter j that has a letter d back in its own block."""
        out = []
        for a, b in self.blocks:
            out += x[a:b - d]
        return out

    def current(self, x, d):
        out = []
        for a, b in self.blocks:
            out += x[a + d:b]
        return out

    def b_settings(self):
        """(s, numbering of P, t, numbering of C) for test B, in the order the scan indexes them."""
        return [(pi // 3 + 1, pi % 3, ci // 3 + 1, ci % 3) for pi in range(18) for ci in range(18)]

    def expected(self, streams):
        """Chance passes per test for `streams` random key streams (systems of full rank)."""
        e = {"A": streams * 26.0 ** -(self.neq[5] - 6),
             "A2": streams * 26.0 ** -(self.neq[5] - 7),
             "A6": streams * 26.0 ** -(self.neq[6] - 7)}
        per = 0.0
        for s in range(1, 7):
            for t in range(1, 7):
                per += 9 * 26.0 ** -(self.neq[max(2, s, t)] - 5)
        e["B"] = streams * per
        e["C2"] = streams * sum(26.0 ** -c for _, _, _, _, c in self.c2 if c >= MIN_CHECKS)
        e["C2g"] = streams * sum(26.0 ** -c for _, _, _, _, c in self.c2 if c < MIN_CHECKS)
        return e


def system(plan, k, order, xp=None, s=0, xc=None, t=0, with_i=False):
    """Rows and right side of K[j] = sum a_d K[j-d] (+ u xp[j-s] + v xc[j-t]) + c (+ e pos[j])."""
    L = max(order, s, t)
    rows, rhs = [], []
    for a, b in plan.blocks:
        for j in range(a + L, b):
            r = [k[j - d] for d in range(1, order + 1)]
            if xp is not None:
                r.append(xp[j - s])
                r.append(xc[j - t])
            r.append(1)
            if with_i:
                r.append(plan.pos[j])
            rows.append(r)
            rhs.append(k[j])
    return rows, rhs


def new_tally():
    return {"streams": 0, "A_mod2": 0, "A2_mod2": 0, "A6_mod2": 0, "B_stage1": 0, "B_mod2": 0,
            "C1_judged": 0, "C1_exp": 0.0, "C1g_judged": 0, "C1g_exp": 0.0, "hits": []}


def scan(plan, name, alpha, res):
    """All tests for one alphabet. Hits go to res['hits'] as (test, name, alphabet, layout, form, params)."""
    im = {c: i for i, c in enumerate(alpha)}
    xp = [[im[c] for c in plan.pl], plan.xp[1], plan.xp[2]]
    xc = [[im[c] for c in plan.cl], plan.xc[1], plan.xc[2]]
    pb = [bits(xp[0]), plan.pb[1], plan.pb[2]]
    cb = [bits(xc[0]), plan.cb[1], plan.cb[2]]
    mask = plan.mask
    m5, m6 = mask[5], mask[6]
    hits = res["hits"]
    # test B, stage 1 tables: every value u*P + v*C can take on the 6-back equations, mod 2
    pv = [(pb[n] << s) & m6 for s in range(1, 7) for n in range(3)]
    cv = [(cb[n] << t) & m6 for t in range(1, 7) for n in range(3)]
    wp, wc, wpc = {}, {}, {}
    for pi, p in enumerate(pv):
        wp.setdefault(p, []).append(pi)
        base = pi * 18
        for ci, c in enumerate(cv):
            wpc.setdefault(p ^ c, []).append(base + ci)
    for ci, c in enumerate(cv):
        wc.setdefault(c, []).append(ci)
    lagged, current = plan.lagged, plan.current
    for lay, na, nb in (LAYS_AZ if alpha == AZ else LAYS_M):
        a, b = xp[na], xc[nb]
        forms = (("vig", [(y - x) % 26 for x, y in zip(a, b)]), ("beau", [(y + x) % 26 for x, y in zip(a, b)]))
        kb = bits(forms[0][1])                      # the same for both forms: y - x = y + x mod 2
        res["streams"] += 2
        # ---- A, A2: order 5 (+ position term)
        sh = [(kb << d) & m5 for d in range(1, 6)]
        if in_span2(kb & m5, sh + [m5])[0]:
            res["A_mod2"] += 2
            for form, k in forms:
                rows, rhs = system(plan, k, 5)
                if solve_mod_p(rows, rhs, 13) is not None:
                    hits.append(("A", name, alpha, lay, form, (5, False)))
        if in_span2(kb & m5, sh + [m5, plan.posbits & m5])[0]:
            res["A2_mod2"] += 2
            for form, k in forms:
                rows, rhs = system(plan, k, 5, with_i=True)
                if solve_mod_p(rows, rhs, 13) is not None:
                    hits.append(("A2", name, alpha, lay, form, (5, True)))
        # ---- A6: order 6, gauge
        if in_span2(kb & m6, [(kb << d) & m6 for d in range(1, 7)] + [m6])[0]:
            res["A6_mod2"] += 2
            for form, k in forms:
                rows, rhs = system(plan, k, 6)
                if solve_mod_p(rows, rhs, 13) is not None:
                    hits.append(("A6", name, alpha, lay, form, (6, False)))
        # ---- B: two key taps + plain letter + cipher letter
        base, k1, k2 = kb & m6, (kb << 1) & m6, (kb << 2) & m6
        cand = set()
        for t0 in (base, base ^ k1, base ^ k2, base ^ k1 ^ k2):
            for tt in (t0, t0 ^ m6):
                if tt == 0:
                    cand.update(range(324))
                    continue
                for pi in wp.get(tt, ()):
                    cand.update(range(pi * 18, pi * 18 + 18))
                for ci in wc.get(tt, ()):
                    cand.update(range(ci, 324, 18))
                cand.update(wpc.get(tt, ()))
        res["B_stage1"] += 2 * len(cand)
        for idx in cand:
            pi, ci = divmod(idx, 18)
            s, n_p, t, n_c = pi // 3 + 1, pi % 3, ci // 3 + 1, ci % 3
            L = max(2, s, t)
            if L < 6:
                mL = mask[L]
                if not in_span2(kb & mL, [(kb << 1) & mL, (kb << 2) & mL, (pb[n_p] << s) & mL,
                                          (cb[n_c] << t) & mL, mL])[0]:
                    continue
            res["B_mod2"] += 2
            for form, k in forms:
                rows, rhs = system(plan, k, 2, xp[n_p], s, xc[n_c], t)
                if solve_mod_p(rows, rhs, 13) is not None:
                    hits.append(("B", name, alpha, lay, form, (s, n_p, t, n_c)))
        # ---- C: arbitrary tables
        for form, k in forms:
            for d in range(1, MAXLAG + 1):
                inp, out = lagged(k, d), current(k, d)
                nd = len(set(inp))
                checks = len(inp) - nd
                if checks < GAUGE:
                    continue
                g = "" if checks >= MIN_CHECKS else "g"
                res["C1%s_judged" % g] += 1
                res["C1%s_exp" % g] += 26.0 ** -checks
                if len(set(zip(inp, out))) == nd:
                    hits.append(("C1" + g, name, alpha, lay, form, (d, checks)))
            for feed, d, inp, nd, checks in plan.c2:
                if len(set(zip(inp, current(k, d)))) == nd:
                    hits.append(("C2" if checks >= MIN_CHECKS else "C2g", name, alpha, lay, form, (feed, d, checks)))


# ---------------------------------------------------------------- pool workers

_S = {}


def init(pl, cl, pos, blocks=((0, 13), (13, 24))):
    _S["plan"] = Plan(pl, cl, pos, blocks)


def work(chunk):
    res = new_tally()
    plan = _S["plan"]
    for name, alpha in chunk:
        scan(plan, name, alpha, res)
    return res


def merge(total, part):
    for key, v in part.items():
        total[key] += v
    return total


# ---------------------------------------------------------------- planting and reading back

def side(tag, alpha):
    return {"M": alpha, "AZ": AZ, "KR": KRYPTOS_ALPHABET}[tag]


def lay_alphabets(lay, alpha):
    """(plain strip, cipher strip) of a layout name such as 'M/AZ'."""
    x, y = lay.split("/")
    return side(x, alpha), side(y, alpha)


def encrypt(pt, pa, cb, form, keyfn):
    """Encipher with key values from keyfn(i, K so far, plain text, cipher so far). Returns (ct, K)."""
    ia = {c: i for i, c in enumerate(pa)}
    K, C = [], []
    for i, ch in enumerate(pt):
        k = keyfn(i, K, pt, C) % 26
        K.append(k)
        C.append(cb[(ia[ch] + k) % 26] if form == "vig" else cb[(k - ia[ch]) % 26])
    return "".join(C), K


def linear_keyfn(rule, seeds, nump=None, numc=None):
    """K[i] = sum a_d K[i-d] + c + e i + u nump[P[i-s]] + v numc[C[i-t]]; the first letters use `seeds`."""
    a, c, e = rule["a"], rule.get("c", 0), rule.get("e", 0)
    u, v, s, t = rule.get("u", 0), rule.get("v", 0), rule.get("s", 0), rule.get("t", 0)
    L = max(len(a), s, t)

    def fn(i, K, P, C):
        if i < L:
            return seeds[i]
        x = c + e * i + sum(ad * K[i - d - 1] for d, ad in enumerate(a))
        if u:
            x += u * nump[P[i - s]]
        if v:
            x += v * numc[C[i - t]]
        return x
    return fn


def poly_keyfn(coefs):
    return lambda i, K, P, C: sum(cf * i ** n for n, cf in enumerate(coefs))


def table_keyfn(kind, d, g, seeds):
    """K[i] = g[K[i-d]] (kind 'key'), g[P[i-d]] ('plain') or g[C[i-d]] ('cipher')."""
    def fn(i, K, P, C):
        if i < d:
            return seeds[i]
        return g[{"key": K, "plain": P, "cipher": C}[kind][i - d]]
    return fn


def crt(v13, v2):
    return [(x + 13 * ((x + y) % 2)) % 26 for x, y in zip(v13, v2)]


def _few(sol, p):
    part, basis = sol
    out = [part]
    for bvec in basis[:6]:
        out.append([(x + y) % p for x, y in zip(part, bvec)])
    return out


def solve26(rows, rhs):
    """(checks mod 13, checks mod 2, a few solutions mod 26) or None if the system has no solution."""
    s13, s2 = solve_mod_p(rows, rhs, 13), solve_mod_p(rows, rhs, 2)
    if s13 is None or s2 is None:
        return None
    n = len(rows[0])
    sols = [crt(x, y) for x in _few(s13, 13) for y in _few(s2, 2)]
    return len(rows) - (n - len(s13[1])), len(rows) - (n - len(s2[1])), sols


def fill(ct, pa, cb, form, rule, cribs, nump=None, numc=None):
    """Run a linear rule over the whole text from the clue letters and decrypt.

    Forward from the first clue block to the end; inside the second block the predicted key is
    compared with the forced one (`join` = how many of its letters the run reproduces) and then
    replaced by it. Pure key rules also run backwards to the start when the last tap can be
    inverted. Returns (text with ? where nothing is known, join, letters in block 2)."""
    n = len(ct)
    ia = {c: i for i, c in enumerate(pa)}
    ib = {c: i for i, c in enumerate(cb)}
    a, c, e = rule["a"], rule.get("c", 0), rule.get("e", 0)
    u, v, s, t = rule.get("u", 0), rule.get("v", 0), rule.get("s", 0), rule.get("t", 0)
    K, P = [None] * n, [None] * n
    for i, ch in cribs.items():
        P[i] = ch
        K[i] = (ib[ct[i]] - ia[ch]) % 26 if form == "vig" else (ib[ct[i]] + ia[ch]) % 26
    first = min(cribs)
    run = first
    while run + 1 in cribs:
        run += 1
    join = total = 0
    for i in range(run + 1, n):
        x = c + e * i
        ok = True
        for d, ad in enumerate(a):
            if ad:
                if i - d - 1 < 0 or K[i - d - 1] is None:
                    ok = False
                    break
                x += ad * K[i - d - 1]
        if ok and u:
            if P[i - s] is None:
                ok = False
            else:
                x += u * nump[P[i - s]]
        if ok and v:
            x += v * numc[ct[i - t]]
        if i in cribs:
            total += 1
            join += bool(ok and x % 26 == K[i])
            continue
        if not ok:
            continue
        K[i] = x % 26
        P[i] = pa[(ib[ct[i]] - K[i]) % 26] if form == "vig" else pa[(K[i] - ib[ct[i]]) % 26]
    if not u and not v:
        r = max((d + 1 for d, ad in enumerate(a) if ad % 26), default=0)
        if r and a[r - 1] % 2 and a[r - 1] % 13:
            inv = pow(a[r - 1], 11, 26)             # a^-1 mod 26 (the unit group has exponent 12)
            for i in range(first - 1, -1, -1):
                j = i + r
                x = K[j] - c - e * j - sum(a[d] * K[j - d - 1] for d in range(r - 1))
                K[i] = (x * inv) % 26
                P[i] = pa[(ib[ct[i]] - K[i]) % 26] if form == "vig" else pa[(K[i] - ib[ct[i]]) % 26]
    return "".join(ch or "?" for ch in P), join, total


def fill_table(ct, pa, cb, form, kind, d, cribs):
    """Read on with a table rule K[i] = g(x[i-d]) as far as the table learnt from the clues goes."""
    n = len(ct)
    ia = {c: i for i, c in enumerate(pa)}
    ib = {c: i for i, c in enumerate(cb)}
    K, P = [None] * n, [None] * n
    for i, ch in cribs.items():
        P[i] = ch
        K[i] = (ib[ct[i]] - ia[ch]) % 26 if form == "vig" else (ib[ct[i]] + ia[ch]) % 26
    src = {"key": K, "plain": P, "cipher": ct}[kind]
    g = {}
    for i in cribs:
        if i - d in cribs:
            g[src[i - d]] = K[i]
    for i in range(n):
        if K[i] is None and i - d >= 0 and src[i - d] is not None and src[i - d] in g:
            K[i] = g[src[i - d]]
            P[i] = pa[(ib[ct[i]] - K[i]) % 26] if form == "vig" else pa[(K[i] - ib[ct[i]]) % 26]
    return "".join(ch or "?" for ch in P), len(g)


def resolve(hit, ct, cribs, plan):
    """Solve a hit mod 26, run its rule over the text. Returns a dict (checks, rule, text, join)."""
    test, name, alpha, lay, form, params = hit
    pa, cb = lay_alphabets(lay, alpha)
    ia = {c: i for i, c in enumerate(pa)}
    ib = {c: i for i, c in enumerate(cb)}
    k = [(ib[y] - ia[x]) % 26 if form == "vig" else (ib[y] + ia[x]) % 26 for x, y in zip(plan.pl, plan.cl)]
    out = {"test": test, "name": name, "lay": lay, "form": form, "params": params}
    if test.startswith("C"):
        kind, d = ("key", params[0]) if test.startswith("C1") else (params[0], params[1])
        text, size = fill_table(ct, pa, cb, form, kind, d, cribs)
        out.update(checks=params[-1], text=text, join=None, rule="K[i] = g(%s[i-%d]), %d table entries known"
                   % (kind, d, size))
        return out
    nump = numc = None
    if test == "B":
        s, n_p, t, n_c = params
        nump = {c: i for i, c in enumerate(side(NUMS[n_p], alpha))}
        numc = {c: i for i, c in enumerate(side(NUMS[n_c], alpha))}
        rows, rhs = system(plan, k, 2, [nump[c] for c in plan.pl], s, [numc[c] for c in plan.cl], t)
    else:
        order, with_i = params
        rows, rhs = system(plan, k, order, with_i=with_i)
    sol = solve26(rows, rhs)
    if sol is None:
        return None
    c13, c2, sols = sol
    out.update(checks=min(c13, c2), checks13=c13, checks2=c2, readings=[])
    for x in sols:
        if test == "B":
            rule = {"a": x[:2], "u": x[2], "v": x[3], "c": x[4], "s": s, "t": t}
        else:
            rule = {"a": x[:order], "c": x[order], "e": x[order + 1] if with_i else 0}
        text, join, total = fill(ct, pa, cb, form, rule, cribs, nump, numc)
        out["readings"].append((text, join, total, rule))
    return out
