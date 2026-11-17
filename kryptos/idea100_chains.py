"""Idea 100: plaintext autokey at a long lag (9..33), decided by chains through the unknown letters.

Model (every letter i that has a letter L places back, or ahead):

    key[i] = sign * number(plaintext letter at i - L) + c        look-back  ("back")
    key[i] = sign * number(plaintext letter at i + L) + c        look-ahead ("ahead")
    Vigenere form:  cipher = plain + key      Beaufort form:  cipher = key - plain      (mod 26)

Plain and cipher letters are numbered in a keyword alphabet M, A-Z or KRYPTOS (five layouts); the fed
letter is numbered in M, A-Z or KRYPTOS. A setting is (alphabet, layout, form, feed numbering, sign,
direction, lag, c).

Why this can be tested although no two clue letters sit exactly one long lag apart: with the tableau
known, a known plaintext letter and the cipher letter one lag on give the next plaintext letter (and
the other way round). So one known letter fixes its whole class of positions (i, i+L, i+2L, ...), and
a class that holds two clue letters gives one exact check per extra clue letter:

    checks(L) = 24 - (number of classes mod L that hold a clue letter)

    lag     9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 | 24 25 26 27 28 29 30 31 32 33
    checks 15 14 13 12 11 11  9  8  7  7  9 11 11  9  7 |  5  3  1  0  0  0  1  2  3  4

Lags 9-23 (7+ checks): a setting passes only if every check holds. Lags 24-33: a setting that passes
the few checks it has forces 58-86 of the 97 letters, and those are read on the big English model.

Speed. One relation links two neighbours of a class:  T(upper) + S(lower) = W - c  (all mod 26), where
for look-back T numbers the keyed letter, S the fed letter and W is the cipher letter at the upper place;
for look-ahead S and T swap and W is the cipher letter at the lower place. c is solved from the first
chain (one step: directly; two steps: the unknown middle letter X must have T(X) - S(X) equal to a known
value, a 26-entry table; three steps: 26 values of c in one line), then the other chains are checked.
One thing to know: when the fed letter is numbered like the plaintext and the key is symmetric in the two
letters (Vigenere with +, Beaufort with -), a two-step chain does not depend on c. At lags where every
chain has two steps (18-23) such a view then passes for all 26 values of c together or for none; the
checks are still exact, and the 26 readings differ in every second letter of a class.
forced() below is a separate, slow, plain implementation of the same model; every survivor of the fast
test is re-checked with it.
"""
import heapq

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round11 import B1, B2, pmap

N = 97
LAGS = tuple(range(9, 34))
CLUE = B1 + B2
MIN_CHECKS = 7
DIRS = ("back", "ahead")
R26 = tuple(range(26))
GATE = (-7.0, -13.0, -18.5)     # running big-model sums a forced run must reach after 4, 8 and 11-12 letters
WEAK = -22.0                    # ... and the other run must reach this sum (noise sits near -25.5)
KEEP = -6.2                     # low-lag texts scoring at least this are returned (English is about -4.3)
TOP = 12
_S = {}


def checks(L):
    return len(CLUE) - len({p % L for p in CLUE})


LOW = tuple(L for L in LAGS if checks(L) < MIN_CHECKS)
HIGH = tuple(L for L in LAGS if checks(L) >= MIN_CHECKS)
FREE = tuple(L for L in LAGS if checks(L) == 0)         # no check at all: c cannot be solved


def _signed(alpha):
    """(value -> letter string, letter -> value) for numbering +alpha and -alpha."""
    return ((alpha, {ch: i for i, ch in enumerate(alpha)}),
            (alpha[0] + alpha[:0:-1], {ch: (-i) % 26 for i, ch in enumerate(alpha)}))


SIGNED = {"AZ": _signed(AZ), "KR": _signed(KRYPTOS_ALPHABET)}


def build_plans():
    """Per direction, per lag: (L, checks, kind of first chain, first chain, other chains, up run, down run).

    A chain joins two clue letters that are neighbours in their class: (clue index of the lower,
    clue index of the upper, W places of the steps). kind = steps of the first chain (0: no chain)."""
    plans = {}
    for d in DIRS:
        out = []
        for L in LAGS:
            off = 0 if d == "back" else -L          # relation with upper place p reads the cipher letter at p + off
            cls = {}
            for j, p in enumerate(CLUE):
                cls.setdefault(p % L, []).append((p, j))
            chains = []
            for mem in cls.values():
                for (p0, j0), (p1, j1) in zip(mem, mem[1:]):
                    n = (p1 - p0) // L
                    chains.append((n, j0, j1, tuple(p0 + k * L + off for k in range(1, n + 1))))
            chains.sort()
            assert len(chains) == checks(L)
            kind = chains[0][0] if chains else 0
            assert kind <= 3
            first = (chains[0][1], chains[0][2]) + chains[0][3] if chains else ()
            rest = tuple((j0, j1, ws[:-1], ws[-1]) for _, j0, j1, ws in chains[1:])
            upw = tuple(B1[k] + L + off for k in range(12))            # one step up from the first clue
            dnw = tuple(p + off for p in B2)                           # one step down from the second clue
            out.append((L, len(chains), kind, first, rest, upw, dnw))
        plans[d] = out
    return plans


PLANS = build_plans()


def _tables(a, b):
    """Look-back and look-ahead tables for keyed-side numbering a and fed-side numbering b."""
    (al, av), (bl, bv) = a, b
    stb = [bv[ch] for ch in al]                 # T-value -> S-value of the same letter (look-back: T = a, S = b)
    sta = [av[ch] for ch in bl]                 # look-ahead: T = b, S = a (the inverse table)
    hb, ha = [()] * 26, [()] * 26
    for t in R26:
        hb[(t - stb[t]) % 26] += (t,)
        ha[(t - sta[t]) % 26] += (t,)
    return stb, sta, hb, ha, stb + stb, sta + sta


_CONST = {(pn, ps, fn, fs): _tables(SIGNED[pn][ps], SIGNED[fn][fs])
          for pn in ("AZ", "KR") for ps in (0, 1) for fn in ("AZ", "KR") for fs in (0, 1)}


def numberings(m):
    """(plain numberings with their cipher numberings, feed numberings) for alphabet m."""
    if m == AZ:
        return (("AZ", ("AZ", "KR")), ("KR", ("AZ", "KR"))), ("AZ", "KR")
    return (("M", ("M", "AZ", "KR")), ("AZ", ("M",)), ("KR", ("M",))), ("M", "AZ", "KR")


def settings_per_alphabet(m, allc):
    plain, feeds = numberings(m)
    views = sum(len(cn) for _, cn in plain) * 2 * len(feeds) * 2 * 2          # layouts x form x feed x sign x direction
    return views * ((len(LAGS) - len(FREE)) * 26 + len(FREE) * (26 if allc else 1))


def _gate(W, c, SP, TP, Tl, Sl, upw, dnw, get, fl):
    """Cheap English gate for a low-lag survivor, on the big model. The 12 letters one step above the first
    clue and the 11 letters one step below the second clue are forced directly. One of the two runs must
    reach the running sums GATE (after 4, 8 and all letters) and the other must not be hopeless (WEAK)."""
    g1, g2, g3 = GATE
    up = None
    s = get(Tl[(W[upw[0]] - c - SP[0]) % 26] + Tl[(W[upw[1]] - c - SP[1]) % 26]
            + Tl[(W[upw[2]] - c - SP[2]) % 26] + Tl[(W[upw[3]] - c - SP[3]) % 26], fl)
    if s >= g1:
        s += get(Tl[(W[upw[4]] - c - SP[4]) % 26] + Tl[(W[upw[5]] - c - SP[5]) % 26]
                 + Tl[(W[upw[6]] - c - SP[6]) % 26] + Tl[(W[upw[7]] - c - SP[7]) % 26], fl)
        if s >= g2:
            s += get(Tl[(W[upw[8]] - c - SP[8]) % 26] + Tl[(W[upw[9]] - c - SP[9]) % 26]
                     + Tl[(W[upw[10]] - c - SP[10]) % 26] + Tl[(W[upw[11]] - c - SP[11]) % 26], fl)
            if s >= g3:
                up = s
    s = get(Sl[(W[dnw[0]] - c - TP[13]) % 26] + Sl[(W[dnw[1]] - c - TP[14]) % 26]
            + Sl[(W[dnw[2]] - c - TP[15]) % 26] + Sl[(W[dnw[3]] - c - TP[16]) % 26], fl)
    if up is None and s < g1:
        return False
    s += get(Sl[(W[dnw[4]] - c - TP[17]) % 26] + Sl[(W[dnw[5]] - c - TP[18]) % 26]
             + Sl[(W[dnw[6]] - c - TP[19]) % 26] + Sl[(W[dnw[7]] - c - TP[20]) % 26], fl)
    if up is None and s < g2:
        return False
    s += get(Sl[(W[dnw[7]] - c - TP[20]) % 26] + Sl[(W[dnw[8]] - c - TP[21]) % 26]
             + Sl[(W[dnw[9]] - c - TP[22]) % 26] + Sl[(W[dnw[10]] - c - TP[23]) % 26], fl)
    if up is not None:
        return s >= WEAK
    if s < g3:
        return False
    return sum(get("".join(Tl[(W[upw[k]] - c - SP[k]) % 26] for k in range(o, o + 4)), fl) for o in (0, 4, 8)) >= WEAK


def _run(plans, W, ST, TS2, ST2, H, SP, TP, Tl, Sl, c_free, get, fl, gate):
    """Every (lag, c) of one view and direction that passes all its checks (and the gate, for low lags)."""
    out = []
    for L, nchk, kind, first, rest, upw, dnw in plans:
        if kind == 1:
            j0, jn, w = first
            cands = ((W[w] - SP[j0] - TP[jn]) % 26,)
        elif kind == 2:
            j0, jn, w1, w2 = first
            u = W[w1] - SP[j0]
            hs = H[(u - W[w2] + TP[jn]) % 26]
            if not hs:
                continue
            cands = [(u - t) % 26 for t in hs]
        elif kind == 3:
            j0, jn, w1, w2, w3 = first
            a, b, w = (W[w1] - SP[j0]) % 26, (W[w3] - TP[jn]) % 26, W[w2]
            cands = [c for c in R26 if (TS2[b - c] + ST2[a - c] + c - w) % 26 == 0]
        else:
            cands = c_free
        for c in cands:
            for j0, jn, head, wl in rest:
                s = SP[j0]
                for w in head:
                    s = ST[(W[w] - c - s) % 26]
                if (W[wl] - c - s - TP[jn]) % 26:
                    break
            else:
                if nchk >= MIN_CHECKS or not gate or _gate(W, c, SP, TP, Tl, Sl, upw, dnw, get, fl):
                    out.append((L, c))
    return out


def survivors(m, ct, pl, allc=False, logp=None, floor=0.0, gate=True, lags=None):
    """All settings of one alphabet that pass: [(layout, form, feed numbering, sign, direction, lag, c)].

    pl: the 24 clue plaintext letters in position order. Low lags are gated on English when gate is set
    (logp = big-model table needed); lags without any check use c = 0 only unless allc."""
    sg = dict(SIGNED)
    sg["M"] = _signed(m)
    plain, feeds = numberings(m)
    W = {cn: [sg[cn][0][1][ch] for ch in ct] for cn in ("M", "AZ", "KR") if cn in sg and (cn != "M" or m != AZ)}
    P = {(nm, s): [sg[nm][s][1][ch] for ch in pl] for nm in sg for s in (0, 1)}
    get = logp.get if logp is not None else None
    c_free = R26 if allc else (0,)
    plans = PLANS if lags is None else {d: [p for p in PLANS[d] if p[0] in lags] for d in DIRS}
    pb, pa = plans["back"], plans["ahead"]
    out = []
    for pn, cnums in plain:
        for ps, form in ((0, "vig"), (1, "beau")):
            a, aP = sg[pn][ps], P[pn, ps]
            for fn in feeds:
                for fs, sign in ((0, 1), (1, -1)):
                    b, bP = sg[fn][fs], P[fn, fs]
                    stb, sta, hb, ha, stb2, sta2 = _CONST.get((pn, ps, fn, fs)) or _tables(a, b)
                    for cn in cnums:
                        w = W[cn]
                        lay = pn + "/" + cn
                        for L, c in _run(pb, w, stb, sta2, stb2, hb, bP, aP, a[0], b[0], c_free, get, floor, gate):
                            out.append((lay, form, fn, sign, "back", L, c))
                        for L, c in _run(pa, w, sta, stb2, sta2, ha, aP, bP, b[0], a[0], c_free, get, floor, gate):
                            out.append((lay, form, fn, sign, "ahead", L, c))
    return out


# ---------------------------------------------------------------- the plain, slow model (independent of the above)

def _nums(m, lay, fn):
    side = {"M": m, "AZ": AZ, "KR": KRYPTOS_ALPHABET}
    a, b = lay.split("/")
    return [(side[x], {ch: i for i, ch in enumerate(side[x])}) for x in (a, b, fn)]


def encrypt(pt, m, spec, rng):
    """Encrypt with the model. Letters with nothing L places back (ahead) use a random primer letter."""
    lay, form, fn, sign, d, L, c = spec
    (_, ia), (ab, _), (ax, ix) = _nums(m, lay, fn)
    ct = []
    for i, ch in enumerate(pt):
        f = i - L if d == "back" else i + L
        fed = pt[f] if 0 <= f < len(pt) else ax[rng.randrange(26)]
        k = (sign * ix[fed] + c) % 26
        ct.append(ab[(ia[ch] + k) % 26 if form == "vig" else (k - ia[ch]) % 26])
    return "".join(ct)


def forced(ct, cribs, m, spec):
    """(consistent, text): every plaintext letter the clue letters force, '.' where nothing is known."""
    lay, form, fn, sign, d, L, c = spec
    (aa, ia), (_, ib), (ax, ix) = _nums(m, lay, fn)
    n = len(ct)
    pt = [cribs.get(i) for i in range(n)]
    step = L if d == "back" else -L                 # keyed place q is fed from q - step

    def keyed(q, fed):
        k = (sign * ix[fed] + c) % 26
        return aa[(ib[ct[q]] - k) % 26] if form == "vig" else aa[(k - ib[ct[q]]) % 26]

    def feeder(q, plain):
        k = (ib[ct[q]] - ia[plain]) % 26 if form == "vig" else (ib[ct[q]] + ia[plain]) % 26
        return ax[(sign * (k - c)) % 26]

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


def extra_score(pt, logp, floor, clue=frozenset(CLUE)):
    """English per quadgram over forced letters outside the clues. Returns (score or None, quadgrams)."""
    tot, cnt = 0.0, 0
    get = logp.get
    for i in range(len(pt) - 3):
        q = pt[i:i + 4]
        if "." in q or (i in clue and i + 3 in clue):
            continue
        tot += get(q, floor)
        cnt += 1
    return (tot / cnt if cnt else None), cnt


# ---------------------------------------------------------------- the search over many alphabets

def init(ct, cribs, allc_names, big_path):
    from .score import Quadgrams
    big = Quadgrams(big_path)
    _S.update(ct=ct, cribs=cribs, allc=allc_names, logp=big.logp, floor=big.floor)


def work(chunk):
    """([hits at lags with 7+ checks], [best low-lag readings], low-lag settings past the gate)."""
    ct, cribs, logp, floor = _S["ct"], _S["cribs"], _S["logp"], _S["floor"]
    pl = [cribs[i] for i in CLUE]
    hits, low, nlow = [], [], 0
    for name, m in chunk:
        for spec in survivors(m, ct, pl, name in _S["allc"], logp, floor):
            ok, text = forced(ct, cribs, m, spec)
            if not ok:
                raise AssertionError("fast and slow tests disagree: %s %s" % (name, spec))
            sc, cnt = extra_score(text, logp, floor)
            row = (sc if sc is not None else -99.0, cnt, text, name, spec)
            if checks(spec[5]) >= MIN_CHECKS:
                hits.append(row)
            else:
                nlow += 1
                if row[0] >= KEEP:
                    low.append(row)
    return hits, heapq.nlargest(TOP, low), nlow


def search(ct, cribs, alphas, allc_names, big_path, chunk=1000, procs=None):
    hits, low, nlow = [], [], 0
    for h, lo, n in pmap(work, alphas, init, (ct, cribs, frozenset(allc_names), str(big_path)), chunk=chunk, procs=procs):
        hits += h
        low += lo
        nlow += n
    return sorted(hits, reverse=True), heapq.nlargest(TOP, low), nlow


def plant(rng, alphas, d, L, c=None, pt=None):
    """A planted message: (ct, cribs, alphabet name, spec, plaintext, alphabet)."""
    from .round11 import english97
    pt = pt or english97(rng)
    name, m = rng.choice(alphas)
    lay = rng.choice(["M/M", "M/AZ", "AZ/M", "M/KR", "KR/M"])
    spec = (lay, rng.choice(["vig", "beau"]), rng.choice(["M", "AZ", "KR"]), rng.choice([1, -1]), d, L,
            rng.randrange(26) if c is None else c)
    ct = encrypt(pt, m, spec, rng)
    return ct, {i: pt[i] for i in CLUE}, name, spec, pt, m
