"""Idea 142: plaintext autokey at lags 9..14 (back or ahead) with a short repeating word on top.

Model (i = the place of the letter being enciphered):

    key[i] = sign * number(plaintext letter at i - L) + word[i mod p]        look-back  ("back")
    key[i] = sign * number(plaintext letter at i + L) + word[i mod p]        look-ahead ("ahead")
    Vigenere form:  cipher = plain + key      Beaufort form:  cipher = key - plain      (mod 26)

Plain and cipher letters are numbered in a keyword alphabet M, A-Z or KRYPTOS (five layouts); the fed
letter is numbered in M, A-Z or KRYPTOS; L = 9..14; p = 2, 3, 4. With p = 1 this is idea 100.

How it is decided. As in idea 100, one relation links two neighbours of a class of places (i, i+L, ...):

    T(upper letter) + S(lower letter) = W(keyed place) - word[keyed place mod p]

so two clue letters of one class are joined by a chain of 1 to 5 steps through unknown letters. Every
chain is one exact equation in the word letters its steps use. There are checks(L) = 15, 14, 13, 12, 11,
11 chains at L = 9..14, so after paying for the p word letters 7 to 13 checks are left.

The word is not tried 26^p times. A plan, built once per (direction, L, p) from the clue positions alone,
solves it from the chains:

    direct   a one-step chain gives its word letter at once
    solve    a chain with one unknown word letter used once: walk in from both ends, read the letter off
    join     two three-step chains that use the same three unknown letters in the same order (a, b, c):
             b = W2 - A[a] - C[c] in both, so tabulate A1[a] - A2[a] and C1[c] - C2[c] and match (a hash
             join, about 26 of the 676 pairs survive)
    branch   26 values of one letter (only when nothing above applies)
    check    every other chain, walked from its lower clue letter to its upper one

The plan lists every word that satisfies all chains (nothing is cut off), so the fast test is exact.
All places come from true text positions (class = position mod L); no run of clue indices is used, so
the run-break mistake idea 105 found in attack 90 cannot happen here.

forced() / encrypt() are a separate, slow, plain implementation of the same model; every survivor of the
fast test is re-checked with it, and a test compares both on all 26^p words.
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .idea100_chains import SIGNED, _signed, checks, extra_score, numberings
from .round11 import B1, B2, pmap

N = 97
LAGS = (9, 10, 11, 12, 13, 14)
PERIODS = (2, 3, 4)
CLUE = B1 + B2
DIRS = ("back", "ahead")
MIN_CHECKS = 7
R26 = tuple(range(26))
_S = {}


def chains(d, L):
    """[(clue index of the lower letter, of the upper letter, keyed places of the steps)], shortest first."""
    off = 0 if d == "back" else -L
    cls = {}
    for j, q in enumerate(CLUE):                     # CLUE is in position order
        cls.setdefault(q % L, []).append((q, j))
    out = []
    for mem in cls.values():
        for (p0, j0), (p1, j1) in zip(mem, mem[1:]):
            n = (p1 - p0) // L
            out.append((j0, j1, tuple(p0 + k * L + off for k in range(1, n + 1))))
    out.sort(key=lambda c: (len(c[2]), c[2]))
    assert len(out) == checks(L)
    return out


def build_plan(d, L, p):
    """The list of steps (see the module text) that solves the word for one direction, lag and length."""
    todo = [(j0, j1, ws, tuple(w % p for w in ws)) for j0, j1, ws in chains(d, L)]
    known, ops = set(), []
    while todo:
        done = [c for c in todo if all(r in known for r in c[3])]
        if done:
            c = done[0]
            ops.append(("check",) + c)
            todo.remove(c)
            continue
        one = [c for c in todo if len(c[2]) == 1]
        if one:
            c = one[0]
            ops.append(("direct",) + c)
            known.add(c[3][0])
            todo.remove(c)
            continue
        sol = [(c, [k for k, r in enumerate(c[3]) if r not in known]) for c in todo]
        sol = [(c, ks) for c, ks in sol if len(ks) == 1]
        if sol:
            c, ks = sol[0]
            ops.append(("solve",) + c + (ks[0],))
            known.add(c[3][ks[0]])
            todo.remove(c)
            continue
        three = [c for c in todo if len(c[2]) == 3 and len(set(c[3])) == 3 and not set(c[3]) & known]
        pair = [(a, b) for i, a in enumerate(three) for b in three[i + 1:] if a[3] == b[3]]
        if pair:
            a, b = pair[0]
            ops.append(("join", a, b))
            known.update(a[3])
            todo.remove(a)
            todo.remove(b)
            continue
        c = min(todo, key=lambda c: (len({r for r in c[3] if r not in known}), len(c[2])))
        unk = [r for r in c[3] if r not in known]
        r = max(set(unk), key=unk.count)
        ops.append(("branch", r))
        known.add(r)
    assert known == set(range(p)), (d, L, p)        # every word letter is tied down by some chain
    return tuple(ops)


PLANS = {(d, L, p): build_plan(d, L, p) for d in DIRS for L in LAGS for p in PERIODS}
CELLS = tuple((L, p, PLANS["back", L, p], PLANS["ahead", L, p]) for L in LAGS for p in PERIODS)


def solve(ops, p, W, ST, TS, SP, TP):
    """Every word (list of p values) that satisfies all chains. ST, TS: the tables three times over."""
    cands = [[None] * p]
    for op in ops:
        kind = op[0]
        if kind == "check":
            _, j0, j1, ws, rs = op
            n1 = len(ws) - 1
            keep = []
            for x in cands:
                s = SP[j0]
                for k in range(n1):
                    s = ST[W[ws[k]] - x[rs[k]] - s]
                if (W[ws[n1]] - x[rs[n1]] - s - TP[j1]) % 26 == 0:
                    keep.append(x)
            cands = keep
        elif kind == "direct":
            _, j0, j1, ws, rs = op
            v = (W[ws[0]] - SP[j0] - TP[j1]) % 26
            for x in cands:
                x[rs[0]] = v
            continue
        elif kind == "solve":
            _, j0, j1, ws, rs, at = op
            n = len(ws)
            for x in cands:
                s = SP[j0]
                for k in range(at):
                    s = ST[W[ws[k]] - x[rs[k]] - s]
                t = TP[j1]
                for k in range(n - 1, at, -1):
                    t = TS[W[ws[k]] - x[rs[k]] - t]
                x[rs[at]] = (W[ws[at]] - s - t) % 26
            continue
        elif kind == "branch":
            r = op[1]
            new = []
            for x in cands:
                for v in R26:
                    y = x[:]
                    y[r] = v
                    new.append(y)
            cands = new
            continue
        else:                                           # join
            (j0, j1, (a1, a2, a3), (ra, rb, rc)), (k0, k1, (b1, b2, b3), _) = op[1], op[2]
            wa1, wb1 = W[a1] - SP[j0], W[b1] - SP[k0]
            wa3, wb3 = W[a3] - TP[j1], W[b3] - TP[k1]
            wa2 = W[a2]
            dd = wa2 - W[b2]
            G = {}
            for c in R26:
                tA = TS[wa3 - c]
                G.setdefault((dd - tA + TS[wb3 - c]) % 26, []).append((c, tA))
            new = []
            for x in cands:
                for a in R26:
                    sA = ST[wa1 - a]
                    g = G.get((sA - ST[wb1 - a]) % 26)
                    if g:
                        for c, tA in g:
                            y = x[:]
                            y[ra], y[rb], y[rc] = a, (wa2 - sA - tA) % 26, c
                            new.append(y)
            cands = new
        if not cands:
            return cands
    return cands


def _tab(a, b):
    (al, av), (bl, bv) = a, b
    return [bv[ch] for ch in al] * 3, [av[ch] for ch in bl] * 3


_CONST = {(pn, ps, fn, fs): _tab(SIGNED[pn][ps], SIGNED[fn][fs])
          for pn in ("AZ", "KR") for ps in (0, 1) for fn in ("AZ", "KR") for fs in (0, 1)}


def primitive(word):
    """The shortest word that repeats to the same key (ABAB -> AB)."""
    word = tuple(word)
    for q in range(1, len(word)):
        if len(word) % q == 0 and word == word[:q] * (len(word) // q):
            return word[:q]
    return word


def survivors(m, ct, pl, lags=LAGS, periods=PERIODS):
    """All settings of one alphabet that pass every chain:
    {(layout, form, feed numbering, sign, direction, lag, word)}, the word cut to its shortest period."""
    sg = dict(SIGNED)
    sg["M"] = _signed(m)
    plain, feeds = numberings(m)
    W = {cn: [sg[cn][0][1][ch] for ch in ct] for cn in ("M", "AZ", "KR") if cn != "M" or m != AZ}
    P = {(nm, s): [sg[nm][s][1][ch] for ch in pl] for nm in sg for s in (0, 1)}
    cells = CELLS if lags is LAGS and periods is PERIODS else [c for c in CELLS if c[0] in lags and c[1] in periods]
    out = set()
    for pn, cnums in plain:
        for ps, form in ((0, "vig"), (1, "beau")):
            a, aP = sg[pn][ps], P[pn, ps]
            for fn in feeds:
                for fs, sign in ((0, 1), (1, -1)):
                    bP = P[fn, fs]
                    stb, sta = _CONST.get((pn, ps, fn, fs)) or _tab(a, sg[fn][fs])
                    for cn in cnums:
                        w = W[cn]
                        for L, p, opb, opa in cells:
                            r = solve(opb, p, w, stb, sta, bP, aP)
                            if r:
                                for x in r:
                                    out.add((pn + "/" + cn, form, fn, sign, "back", L, primitive(x)))
                            r = solve(opa, p, w, sta, stb, aP, bP)
                            if r:
                                for x in r:
                                    out.add((pn + "/" + cn, form, fn, sign, "ahead", L, primitive(x)))
    return out


def views_per_alphabet(m):
    plain, feeds = numberings(m)
    return sum(len(cn) for _, cn in plain) * 2 * len(feeds) * 2          # layouts x form x feed numbering x sign


def settings_per_alphabet(m):
    return views_per_alphabet(m) * len(DIRS) * len(LAGS) * sum(26 ** p for p in PERIODS)


# ---------------------------------------------------------------- the plain, slow model (independent of the above)

def _nums(m, lay, fn):
    side = {"M": m, "AZ": AZ, "KR": KRYPTOS_ALPHABET}
    a, b = lay.split("/")
    return [(side[x], {ch: i for i, ch in enumerate(side[x])}) for x in (a, b, fn)]


def encrypt(pt, m, spec, rng):
    """Encrypt with the model. Letters with nothing L places back (ahead) use a random primer letter."""
    lay, form, fn, sign, d, L, word = spec
    (_, ia), (ab, _), (ax, ix) = _nums(m, lay, fn)
    p = len(word)
    ct = []
    for i, ch in enumerate(pt):
        f = i - L if d == "back" else i + L
        fed = pt[f] if 0 <= f < len(pt) else ax[rng.randrange(26)]
        k = (sign * ix[fed] + word[i % p]) % 26
        ct.append(ab[(ia[ch] + k) % 26 if form == "vig" else (k - ia[ch]) % 26])
    return "".join(ct)


def forced(ct, cribs, m, spec):
    """(consistent, text): every plaintext letter the clue letters force, '.' where nothing is known."""
    lay, form, fn, sign, d, L, word = spec
    (aa, ia), (_, ib), (ax, ix) = _nums(m, lay, fn)
    n, p = len(ct), len(word)
    pt = [cribs.get(i) for i in range(n)]
    step = L if d == "back" else -L                 # keyed place q is fed from q - step

    def keyed(q, fed):
        k = (sign * ix[fed] + word[q % p]) % 26
        return aa[(ib[ct[q]] - k) % 26] if form == "vig" else aa[(k - ib[ct[q]]) % 26]

    def feeder(q, plain):
        k = (ib[ct[q]] - ia[plain]) % 26 if form == "vig" else (ib[ct[q]] + ia[plain]) % 26
        return ax[(sign * (k - word[q % p])) % 26]

    ok = True
    for r in range(L):
        known = [i for i in range(r, n, L) if pt[i]]
        if not known:
            continue
        q = known[0]
        while 0 <= q + step < n:                    # towards the letters keyed by what we know
            q += step
            v = keyed(q, pt[q - step])
            if pt[q] and pt[q] != v:
                ok = False
            pt[q] = pt[q] or v
        q = known[0]
        while 0 <= q - step < n:                    # towards the letters that keyed what we know
            v = feeder(q, pt[q])
            q -= step
            if pt[q] and pt[q] != v:
                ok = False
            pt[q] = pt[q] or v
    return ok, "".join(ch or "." for ch in pt)


def word_text(word):
    return "".join(AZ[v] for v in word)


# ---------------------------------------------------------------- the search over many alphabets

def init(ct, cribs, big_path):
    from .score import Quadgrams
    big = Quadgrams(big_path)
    _S.update(ct=ct, cribs=cribs, logp=big.logp, floor=big.floor)


def work(chunk):
    """[(english score, quadgrams, forced text, alphabet name, spec)] for every setting that passes."""
    ct, cribs, logp, floor = _S["ct"], _S["cribs"], _S["logp"], _S["floor"]
    pl = [cribs[i] for i in CLUE]
    hits = []
    for name, m in chunk:
        for spec in survivors(m, ct, pl):
            ok, text = forced(ct, cribs, m, spec)
            if not ok:
                raise AssertionError("fast and slow tests disagree: %s %s" % (name, spec))
            sc, cnt = extra_score(text, logp, floor)
            hits.append((sc if sc is not None else -99.0, cnt, text, name, spec))
    return hits


def search(ct, cribs, alphas, big_path, chunk=500, procs=None):
    hits = []
    for h in pmap(work, alphas, init, (ct, cribs, str(big_path)), chunk=chunk, procs=procs):
        hits += h
    return sorted(hits, reverse=True)


def plant(rng, alphas, d, L, p, pt=None):
    """A planted message: (ct, cribs, alphabet name, spec, plaintext, alphabet). The word has true length p."""
    from .round11 import english97
    pt = pt or english97(rng)
    name, m = rng.choice(alphas)
    lay = rng.choice(["M/M", "M/AZ", "AZ/M", "M/KR", "KR/M"])
    while True:
        word = tuple(rng.randrange(26) for _ in range(p))
        if primitive(word) == word:
            break
    spec = (lay, rng.choice(["vig", "beau"]), rng.choice(["M", "AZ", "KR"]), rng.choice([1, -1]), d, L, word)
    ct = encrypt(pt, m, spec, rng)
    return ct, {i: pt[i] for i in CLUE}, name, spec, pt, m
