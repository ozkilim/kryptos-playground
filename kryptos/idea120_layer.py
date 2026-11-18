"""Idea 120: the K1/K2 machine as a KNOWN first (or last) layer, then the whole key-rule battery on a
second tableau.

Known layer L: tableau T (KRYPTOS alphabet as carved, or plain A-Z), key word W (ABSCISSA,
PALIMPSEST, PALIMPCEST, KRYPTOS), direction e = +1 (encipher as K1/K2 were) or -1 (decipher),
phase f (key letter W[f] sits on K4 letter 1, so letter i uses W[(i + f) mod len W]):

    L(x, i) = T[ T^-1(x) + e * T^-1(W[(i + f) mod len W]) ]

Order "first": P -> L -> Y -> layer two -> C. The layer-two test sees Y = L(P) at the clue places
in place of EASTNORTHEAST / BERLINCLOCK.
Order "last":  P -> layer two -> Y -> L -> C. The layer-two test sees Y = L^-1(C) as its cipher.

Either way a variant is simply a new (ciphertext, clue letters) pair, and the layer-two test is the
standard battery: round11.battery's rules (repeating 1-17, sliding 1-15, progressive 1-12, autokey
lags 1-6 fed on M, chain addition; through idea114_flaw.check, which runs the same exact rules) plus
idea 104's hole fixes (every stacked pair exactly, autokey fed letter numbered on A-Z / KRYPTOS,
progressive key moved on in another alphabet's order). 7+ checks.

A hit is (checks, alphabet name, layout, form, rule, variant label, info, variant index).
"""
import os

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET as KR
from .round11 import POS, battery, pmap, streams
from . import idea104_holes as H
from . import idea114_flaw as F

SMOKE = os.environ.get("KRYPTOS_SMOKE")
MIN_CHECKS = 7
WORDS = ("ABSCISSA", "PALIMPSEST", "PALIMPCEST", "KRYPTOS")
TABS = (("KR", KR), ("AZ", AZ))
PARTS104 = ("base", "autokey", "progressive")
CHAIN_ONLY = ("repeating", "sliding", "progressive", "autokey", "stacked")


# ------------------------------------------------------------------ the known layer

def layer(text, tab, word, e, phase, start=0, inverse=False):
    """Apply (or undo) the known layer to `text`, whose first letter is K4 letter `start`."""
    it = {c: i for i, c in enumerate(tab)}
    n = len(word)
    s = -1 if inverse else 1
    return "".join(tab[(it[x] + s * e * it[word[(start + j + phase) % n]]) % 26] for j, x in enumerate(text))


def layer_at(x, i, v, inverse=False):
    """The known layer on one letter at K4 position i, variant v."""
    return layer(x, v["tab"], v["word"], v["e"], v["phase"], start=i, inverse=inverse)


def variants(tabs=TABS, words=WORDS, phases=None):
    """Every variant: dict(tab name, tab, word, e, phase, order, label)."""
    out = []
    for tname, tab in tabs:
        for word in words:
            for e in (1, -1):
                for f in (range(len(word)) if phases is None else phases):
                    for order in ("first", "last"):
                        out.append(dict(tname=tname, tab=tab, word=word, e=e, phase=f, order=order,
                                        label="%s %s %s phase %d, known layer %s" % (
                                            tname, word, "enc" if e == 1 else "dec", f, order)))
    return out


def transform(v, ct, cribs):
    """(ct', cribs') the layer-two test sees under variant v."""
    if v["order"] == "first":
        return ct, {i: layer_at(c, i, v) for i, c in cribs.items()}
    return layer(ct, v["tab"], v["word"], v["e"], v["phase"], inverse=True), dict(cribs)


def untransform(v, reading):
    """Plaintext from a layer-two reading ('?' kept)."""
    if v["order"] == "last":
        return reading
    return "".join("?" if c == "?" else layer_at(c, i, v, inverse=True) for i, c in enumerate(reading))


# ------------------------------------------------------------------ the layer-two battery on one alphabet

def test_alphabet(name, m, pl, cl, feeds=None):
    """[(checks, name, layout, form, rule, variant, info)] for one tableau alphabet."""
    hits = []
    for lay, form, k, xp, xc in streams(m, pl, cl):
        for ck, rule in F.check(k, xp, xc):
            if ck >= MIN_CHECKS:
                hits.append((ck, name, lay, form, rule, "battery", ("bat", rule)))
        for ck, rule in battery(k, POS, xp=xp, xc=xc, min_checks=MIN_CHECKS, skip=CHAIN_ONLY):
            hits.append((ck, name, lay, form, rule, "battery", ("bat", rule)))
    hits += H.test_alphabet(name, m, pl, cl, ("base", "autokey"), feeds)
    hits += progressive_other(name, m, pl, cl)
    return hits


def _tables(g2):
    """26 bytes.translate tables: t[c][v] = g2[v + c]."""
    return [bytes(g2[v + c] for v in range(26)) + bytes(230) for c in range(26)]


def prog_fast(k, tabs):
    """Same result as idea104_holes.progressive_hits(k, g2) (compared in tests/test_idea_120.py)."""
    out = []
    kb = bytes(k)
    ok = H._progressive_ok
    for c in range(26):
        o = kb.translate(tabs[c])
        o0 = o[0]
        e = (o0 - o[1]) % 26
        for p in range(1, 12):
            if (o[p] - o[p + 1]) % 26 == e:
                s = ok(o, p)
                if s:
                    out.append((22 - p, c, p, s))
        if not (o[19] - o0 - 4 * (o[12] - o0)) % 26:
            s = ok(o, 12)
            if s:
                out.append((10, c, 12, s))
    return out


def progressive_other(name, m, pl, cl):
    """idea104_holes.test_alphabet's 'progressive' part (key moved on in another alphabet's order)."""
    hits, tabs = [], {}
    for lay, form, k, _, _ in streams(m, pl, cl):
        cipher = _faces(lay, m)[1]
        for on, order in (("AZ", AZ), ("KR", KR), ("M", m)):
            if order == cipher or (on == "M" and m in (AZ, KR)):
                continue
            t = tabs.get((on, cipher))
            if t is None:
                io = {c: i for i, c in enumerate(order)}
                t = tabs[on, cipher] = _tables([io[c] for c in cipher] * 2)
            for ck, c, p, s in prog_fast(k, t):
                hits.append((ck, name, lay, form, "progressive p=%d step=%d" % (p, s),
                             "key moved on in %s order" % on, ("pg", on, c, p, s)))
    return hits


def chance_per_alphabet(m_is_az=False):
    """Expected chance passes per alphabet for a uniformly random 24-letter stream set (10 streams)."""
    per_stream = F.chance_per_stream()
    # chain addition: taps (t, m), m = 2..6, every same-block pair is one check
    from .round11 import _plan
    lag = _plan(POS)["lag"]
    per_stream += sum((m - 1) * 26.0 ** -len(lag[m]) for m in range(2, 7) if len(lag[m]) >= MIN_CHECKS)
    sz = H.sizes()
    return 10 * per_stream + sum(sz[p][1] for p in PARTS104)


_S = {}


def init(jobs):
    """jobs: [(variant index, pl, cl)] that every alphabet is run against."""
    _S["jobs"] = [(vi, pl, cl, H.make_feeds(pl, cl)) for vi, pl, cl in jobs]


def work(chunk):
    hits = []
    for name, m in chunk:
        for vi, pl, cl, feeds in _S["jobs"]:
            for h in test_alphabet(name, m, pl, cl, feeds):
                hits.append(h + (vi,))
    return hits


def jobs_for(vs, ct, cribs, idx=None):
    out = []
    for j, v in enumerate(vs):
        c2, p2 = transform(v, ct, cribs)
        out.append((j if idx is None else idx[j], [p2[i] for i in POS], [c2[i] for i in POS]))
    return out


def search(vs, ct, cribs, alphas, chunk=None, procs=None, idx=None):
    jobs = jobs_for(vs, ct, cribs, idx)
    if chunk is None:
        nproc = procs or os.cpu_count() or 4
        chunk = max(1, min(2000, 60000 // max(1, len(jobs)), -(-len(alphas) // (4 * nproc))))
    hits = []
    for h in pmap(work, alphas, init, (jobs,), chunk=chunk, procs=procs):
        hits += h
    return hits


# ------------------------------------------------------------------ reading a survivor in full

def _faces(lay, m):
    a, b = lay.split("/")
    pick = {"M": m, "AZ": AZ, "KR": KR}
    return pick[a], pick[b]


def read(hit, v, m, ct, cribs):
    """All 97 plaintext letters through both layers ('?' where the clue letters do not fix the key)."""
    c2, p2 = transform(v, ct, cribs)
    info = hit[6]
    if info[0] == "bat":
        lay, form, rule = hit[2], hit[3], info[1]
        a_alpha, b_alpha = _faces(lay, m)
        kclue = None
        for l2, f2, k, _, _ in streams(m, [p2[i] for i in POS], [c2[i] for i in POS]):
            if (l2, f2) == (lay, form):
                kclue = k
        if rule.startswith("chain"):
            y = "".join(p2.get(i, "?") for i in range(len(ct)))   # chain addition: clue letters only
        else:
            y = F.decrypt(c2, p2, m, a_alpha, b_alpha, form, None, rule, kclue)
    else:
        y = H.read(hit[:7], m, c2, p2)
    return untransform(v, y)


# ------------------------------------------------------------------ planted encryptors (plain arithmetic)

def layer2_encrypt(pt, m, lay, form, key, feed=None):
    """Layer two on alphabet m, layout lay, form vig/beau. key: list of values, or for autokey
    ('autokey', 'plain'|'cipher', lag, sign, c0, primer) with the fed letter numbered on m."""
    a_alpha, b_alpha = _faces(lay, m)
    ia, im = {c: i for i, c in enumerate(a_alpha)}, {c: i for i, c in enumerate(m)}
    out = []
    for i, ch in enumerate(pt):
        if isinstance(key, tuple):
            _, fd, lag, sg, c0, primer = key
            src = pt if fd == "plain" else "".join(out)
            kv = (c0 + sg * (im[src[i - lag]] if i >= lag else primer[i])) % 26
        else:
            kv = key[i]
        x = ia[ch]
        out.append(b_alpha[(x + kv) % 26 if form == "vig" else (kv - x) % 26])
    return "".join(out)


def encrypt(pt, v, m, lay, form, key):
    """Whole two-layer encryption under variant v and a layer-two key."""
    if v["order"] == "first":
        return layer2_encrypt(layer(pt, v["tab"], v["word"], v["e"], v["phase"]), m, lay, form, key)
    return layer(layer2_encrypt(pt, m, lay, form, key), v["tab"], v["word"], v["e"], v["phase"])
