"""Idea 124 helpers: sentence keys on a keyword tableau, grown outward from the clues.

A setting is (alphabet M, layout, form, key reading, offset c):

  layout   plain/cipher alphabets: Q1 M/A-Z, Q2 A-Z/M, Q3 M/M, Q4a M/KRYPTOS, Q4b KRYPTOS/M
  form     shift s at a letter: vig s = C - P, beau s = C + P, var s = P - C, diana s = -(C + P)
           (C, P = places of the cipher and plain letter in their alphabets)
  reading  the key letter is R[s + c] with R = A-Z, M or KRYPTOS and c = 0..25
           (A-Z+c is attack 57's reading; M[s+c] and KRYPTOS[s+c] close the idea-105 gap)

For a setting, each plain letter at a position fixes the key letter there, so a setting turns
K4 into a pair of strings (plain, key) that must both be English.

Stage 1 scores the 13 + 11 key letters the clues force (as attack 57) and keeps the best N.
Stage 2 runs a beam search over plain letters: from block 1 to block 2 across the 29 unknown
letters (the bridge), and 12 letters outward on each side; each step's score is the big-model
quadgram of the plain string plus that of the key string.
"""
import heapq
import os
import random

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import DATA_DIR
from .score import Quadgrams

B1, B2 = list(range(21, 34)), list(range(63, 74))
LAYOUTS = ("Q1", "Q2", "Q3", "Q4a", "Q4b")
FORMS = ("vig", "beau", "var", "diana")
READS = ("AZ", "M", "KR")
NV = len(LAYOUTS) * len(FORMS)        # 20 views
NR = len(READS) * 26                  # 78 key readings per view
LO, HI = 9, 86                        # the strings grown: positions 9..85 (12 left of block 1, 12 right of block 2)
ENGLISH = -5.1                        # per-quadgram bar both strings must clear over 21..73
_Q = None
_ST = {}


def quad_table():
    """Big English model as a flat list indexed by ((a*26+b)*26+c)*26+d."""
    global _Q
    if _Q is None:
        q = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        tab = [q.floor] * (26 ** 4)
        for g, lp in q.logp.items():
            if len(g) == 4 and g.isalpha():
                a, b, c, d = (ord(x) - 65 for x in g)
                tab[((a * 26 + b) * 26 + c) * 26 + d] = lp
        _Q = tab
    return _Q


def qmean(v, tab=None):
    """Mean quadgram log10 probability of a list of letter numbers."""
    tab = tab or quad_table()
    n = len(v) - 3
    return sum(tab[((v[i] * 26 + v[i + 1]) * 26 + v[i + 2]) * 26 + v[i + 3]] for i in range(n)) / n


def nums(s):
    return [ord(c) - 65 for c in s]


def faces(lay, m):
    return {"Q1": (m, AZ), "Q2": (AZ, m), "Q3": (m, m), "Q4a": (m, KRYPTOS_ALPHABET), "Q4b": (KRYPTOS_ALPHABET, m)}[lay]


def shift(form, c, p):
    if form == "vig":
        return (c - p) % 26
    if form == "beau":
        return (c + p) % 26
    if form == "var":
        return (p - c) % 26
    return (-c - p) % 26


def reader(read, m):
    return nums({"AZ": AZ, "M": m, "KR": KRYPTOS_ALPHABET}[read])


def key_table(ct, m, lay, form, read, off):
    """kt[i][p] = key letter number at position i when the plain letter there is p."""
    pa, ca = faces(lay, m)
    ip = [pa.index(AZ[p]) for p in range(26)]
    r = reader(read, m)
    out = []
    for ch in ct:
        ci = ca.index(ch)
        out.append([r[(shift(form, ci, ip[p]) + off) % 26] for p in range(26)])
    return out


def encrypt(pt, key, m, lay, form, read, off):
    """Inverse of key_table: plain + key text -> cipher text."""
    pa, ca = faces(lay, m)
    r = reader(read, m)
    ir = {v: i for i, v in enumerate(r)}
    out = []
    for p, k in zip(pt, key):
        s = (ir[ord(k) - 65] - off) % 26
        pi = pa.index(p)
        ci = {"vig": pi + s, "beau": s - pi, "var": pi - s, "diana": -s - pi}[form] % 26
        out.append(ca[ci])
    return "".join(out)


# ---------------------------------------------------------------- stage 1: forced key letters

def init1(ct, cribs, keep):
    _ST.update(ct=ct, cribs=cribs, keep=keep)
    quad_table()


def views(m, ct, cribs):
    """Yield (view number, shift list over B1 + B2)."""
    v = 0
    for lay in LAYOUTS:
        pa, ca = faces(lay, m)
        for form in FORMS:
            yield v, [shift(form, ca.index(ct[i]), pa.index(cribs[i])) for i in B1 + B2]
            v += 1


QI = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 14, 15, 16, 17, 18, 19, 20)   # quadgram starts in the 24-letter fragment


def work1(chunk):
    """chunk: [(alphabet index, alphabet)] -> best `keep` (score, alphabet index, view, reading)."""
    tab = quad_table()
    g = tab.__getitem__
    ct, cribs, keep = _ST["ct"], _ST["cribs"], _ST["keep"]
    rk = nums(KRYPTOS_ALPHABET)
    raz = list(range(26))
    heap, low = [], -1e9
    for ai, m in chunk:
        rm = nums(m)
        rd = (raz + raz, rm + rm, rk + rk)
        for vi, s in views(m, ct, cribs):
            for ri in range(3):
                R = rd[ri]
                for c in range(26):
                    v = [R[x + c] for x in s]
                    sc = sum(map(g, [v[i] * 17576 + v[i + 1] * 676 + v[i + 2] * 26 + v[i + 3] for i in QI]))
                    if sc > low:
                        item = (sc, ai, vi, ri * 26 + c)
                        if len(heap) < keep:
                            heapq.heappush(heap, item)
                            if len(heap) == keep:
                                low = heap[0][0]
                        else:
                            heapq.heapreplace(heap, item)
                            low = heap[0][0]
    return heap


def stage1(ct, cribs, alphas, keep, procs=None):
    """alphas: [(name, alphabet)]. Returns the best `keep` as (mean score, alphabet index, view, reading)."""
    from multiprocessing import Pool
    procs = procs or os.cpu_count()
    items = list(enumerate(m for _, m in alphas))
    n = max(1, len(items) // (procs * 4))
    chunks = [items[i:i + n] for i in range(0, len(items), n)]
    res = []
    with Pool(procs, initializer=init1, initargs=(ct, cribs, keep)) as pool:
        for r in pool.imap_unordered(work1, chunks):
            res.extend(r)
    return [(s / 18.0, a, v, r) for s, a, v, r in heapq.nlargest(keep, res)]


def setting(alphas, ai, vi, rc):
    """Readable setting: (alphabet name, alphabet, layout, form, reading, offset)."""
    name, m = alphas[ai]
    return name, m, LAYOUTS[vi // 4], FORMS[vi % 4], READS[rc // 26], rc % 26


def frag(ct, cribs, m, lay, form, read, off):
    kt = key_table(ct, m, lay, form, read, off)
    return "".join(AZ[kt[i][ord(cribs[i]) - 65]] for i in B1) + "|" + "".join(AZ[kt[i][ord(cribs[i]) - 65]] for i in B2)


# ---------------------------------------------------------------- stage 2: the beam

def _beam(kt, tab, start, stop, step, pctx, kctx, width, closing=()):
    """Grow plain letters from `start` towards `stop` (exclusive) in direction step (+1 / -1).
    pctx/kctx: the 3 plain / key letters next to the start on the fixed side (in text order).
    closing: [(plain, key)] fixed letters met after the last step (scored as they join).
    Returns [(score, plain letters in text order)] best first."""
    if step > 0:
        tp = (pctx[0] * 26 + pctx[1]) * 26 + pctx[2]
        tk = (kctx[0] * 26 + kctx[1]) * 26 + kctx[2]
    else:
        tp = (pctx[0] * 26 + pctx[1]) * 26 + pctx[2]
        tk = (kctx[0] * 26 + kctx[1]) * 26 + kctx[2]
    beam = [(0.0, tp, tk, "")]
    P26 = range(26)
    for i in range(start, stop, step):
        row = kt[i]
        cand = []
        if step > 0:
            for sc, tp, tk, s in beam:
                bp, bk = tp * 26, tk * 26
                cand.extend((sc + tab[bp + p] + tab[bk + row[p]], p, tp, tk, s) for p in P26)
        else:
            for sc, tp, tk, s in beam:
                cand.extend((sc + tab[p * 17576 + tp] + tab[row[p] * 17576 + tk], p, tp, tk, s) for p in P26)
        cand.sort(reverse=True)
        nb, seen = [], set()
        for sc, p, tp, tk, s in cand:
            if step > 0:
                ntp = (tp % 676) * 26 + p
                ntk = (tk % 676) * 26 + row[p]
            else:
                ntp = p * 676 + tp // 26
                ntk = row[p] * 676 + tk // 26
            if ntp in seen:      # same last three plain letters = same future (keys follow from plains)
                continue
            seen.add(ntp)
            nb.append((sc, ntp, ntk, s + chr(65 + p)))
            if len(nb) >= width:
                break
        beam = nb
    out = []
    for sc, tp, tk, s in beam:
        for p, k in closing:
            if step > 0:
                sc += tab[tp * 26 + p] + tab[tk * 26 + k]
                tp, tk = (tp % 676) * 26 + p, (tk % 676) * 26 + k
        out.append((sc, s if step > 0 else s[::-1]))
    out.sort(reverse=True)
    return out


def grow(ct, cribs, m, lay, form, read, off, width, sides=True):
    """Beam-grow plain and key. Returns dict with the bridge score (21..73) and, if sides, 9..85."""
    tab = quad_table()
    kt = key_table(ct, m, lay, form, read, off)
    pn = {i: ord(cribs[i]) - 65 for i in B1 + B2}
    kn = {i: kt[i][pn[i]] for i in pn}
    closing = [(pn[i], kn[i]) for i in (63, 64, 65)]
    gap = _beam(kt, tab, 34, 63, 1, [pn[31], pn[32], pn[33]], [kn[31], kn[32], kn[33]], width, closing)
    best = gap[0][1]
    plain = [pn[i] for i in B1] + nums(best) + [pn[i] for i in B2]
    key = [kn[i] for i in B1] + [kt[34 + j][x] for j, x in enumerate(nums(best))] + [kn[i] for i in B2]
    r = {"plain_bridge": qmean(plain, tab), "key_bridge": qmean(key, tab)}
    r["joint"] = r["plain_bridge"] + r["key_bridge"]
    r["bridges"] = r["plain_bridge"] > ENGLISH and r["key_bridge"] > ENGLISH
    if sides:
        left = _beam(kt, tab, 20, LO - 1, -1, [pn[21], pn[22], pn[23]], [kn[21], kn[22], kn[23]], width)[0][1]
        right = _beam(kt, tab, 74, HI, 1, [pn[71], pn[72], pn[73]], [kn[71], kn[72], kn[73]], width)[0][1]
        fp = nums(left) + plain + nums(right)
        fk = [kt[LO + j][x] for j, x in enumerate(fp)]
        r["plain"] = "".join(AZ[x] for x in fp)
        r["key"] = "".join(AZ[x] for x in fk)
        r["plain_all"], r["key_all"] = qmean(fp, tab), qmean(fk, tab)
    else:
        r["plain"] = "".join(AZ[x] for x in plain)
        r["key"] = "".join(AZ[x] for x in key)
    return r


def init2(ct, cribs, alphas, width, sides):
    _ST.update(ct=ct, cribs=cribs, alphas=alphas, width=width, sides=sides)
    quad_table()


def work2(chunk):
    """chunk: [(tag, alphabet index, view, reading)] -> [(joint, tag, ai, vi, rc, result)]."""
    out = []
    for tag, ai, vi, rc in chunk:
        _, m, lay, form, read, off = setting(_ST["alphas"], ai, vi, rc)
        r = grow(_ST["ct"], _ST["cribs"], m, lay, form, read, off, _ST["width"], _ST["sides"])
        out.append((r["joint"], tag, ai, vi, rc, r))
    return out


def stage2(ct, cribs, alphas, settings, width, sides=False, procs=None):
    """settings: [(tag, ai, vi, rc)]. Returns all results, best joint first."""
    from multiprocessing import Pool
    procs = procs or os.cpu_count()
    n = max(1, min(200, len(settings) // (procs * 4)))
    chunks = [settings[i:i + n] for i in range(0, len(settings), n)]
    res = []
    with Pool(procs, initializer=init2, initargs=(ct, cribs, alphas, width, sides)) as pool:
        for r in pool.imap_unordered(work2, chunks):
            res.extend(r)
    res.sort(key=lambda t: -t[0])
    return res


def random_settings(rng, n_alphas, n):
    return [(rng.randrange(n_alphas), rng.randrange(NV), rng.randrange(NR)) for _ in range(n)]


def code(lay, form, read, off):
    """(view, reading) numbers of a setting."""
    return LAYOUTS.index(lay) * 4 + FORMS.index(form), READS.index(read) * 26 + off
