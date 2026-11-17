"""Helpers for idea 108: the strip is moved by a text, so the key is the running sum of that text.

    k[i] = k[i-1] + t[i]                 t[i] = sign * (number of the moving text's i-th letter + off)
    second order:  d[i] = d[i-1] + t[i],  k[i] = k[i-1] + d[i]

Inside a clue block the key values are known for every dictionary tableau, so the differences
k[i] - k[i-1] are known too: 12 in EASTNORTHEAST and 10 in BERLINCLOCK (11 + 9 second differences).
Turned back into letters they must be the moving text itself.

Everything is kept as bytes of base-26 digits (0-9, a-p) so that a six-letter piece becomes a number
with int(piece, 26) and can be looked up in a bit map of every six-letter piece of the known texts.
"""
import heapq
import importlib.util
import os
from bisect import bisect_right
from pathlib import Path

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import DATA_DIR
from .round11 import B1, B2, POS, streams

DIG = "0123456789abcdefghijklmnop"
TO_DIG = {c: d for c, d in zip(AZ, DIG)}
FROM_DIG = {ord(d): c for c, d in zip(AZ, DIG)}
GAP = B2[0] - B1[0]          # 42: distance in the moving text between the two blocks
SEP = b"|"
NBITS = 26 ** 6
G = {}


def dig(s):
    return "".join(TO_DIG[c] for c in s).encode()


def undig(b):
    return "".join(FROM_DIG[x] for x in b)


def attack58():
    p = Path(__file__).resolve().parent.parent / "attacks" / "58_sculpture_readings.py"
    spec = importlib.util.spec_from_file_location("attack58", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def text_streams(max_skip, min_len=22):
    """[(name, letters)]: every reading of attack 58 (panels, K1-K3 plaintext, Morse; rows, columns,
    diagonals, back-and-forth, reversed) taking every d-th letter, d = 1..max_skip. Duplicates dropped."""
    a = attack58()
    seen, out = set(), []
    for gname, rows in a.grids().items():
        for rname, s in a.readings(rows):
            for d in range(1, max_skip + 1):
                if len(s) // d < min_len:
                    break
                for st in range(d):
                    t = s[st::d]
                    if len(t) >= min_len and t not in seen:
                        seen.add(t)
                        out.append(("%s / %s / every %d from %d" % (gname, rname, d, st), t))
    return out


def build_index(strs, folder):
    """Write the joined texts and the bit map of their six-letter pieces; returns the two paths."""
    bm = bytearray(NBITS // 8 + 1)
    parts = []
    for _, s in strs:
        t = dig(s)
        parts.append(t)
        for o in range(len(t) - 5):
            c = int(t[o:o + 6], 26)
            bm[c >> 3] |= 1 << (c & 7)
    big = SEP.join(parts) + SEP
    pb, pm = os.path.join(folder, "big.bin"), os.path.join(folder, "bitmap.bin")
    with open(pb, "wb") as f:
        f.write(big)
    with open(pm, "wb") as f:
        f.write(bm)
    return pb, pm


def stream_starts(big):
    out, p = [0], big.find(SEP)
    while p >= 0:
        out.append(p + 1)
        p = big.find(SEP, p + 1)
    return out


# ---------------------------------------------------------------- numbering tables

def _tables_for(name, alpha):
    """bytes.translate tables: difference value -> digit of the moving-text letter."""
    out = []
    for sign in (1, -1):
        for off in (0, 1):
            row = [TO_DIG[alpha[(sign * d - off) % 26]] for d in range(26)]
            out.append(("%s from %d, %s" % (name, off, "forward" if sign == 1 else "backward"),
                        ("".join(row) + "?" * 230).encode()))
    return out


FIXED_TABLES = _tables_for("A-Z", AZ) + _tables_for("KRYPTOS", KRYPTOS_ALPHABET)


def tables(m):
    if m == AZ or m == KRYPTOS_ALPHABET:
        return FIXED_TABLES
    return FIXED_TABLES + _tables_for("tableau alphabet", m)


def diffs(k):
    """First differences (12 + 10) and second differences (11 + 9) of the forced key values, as bytes."""
    a = [(k[j + 1] - k[j]) % 26 for j in range(12)]
    b = [(k[j + 1] - k[j]) % 26 for j in range(13, 23)]
    return (bytes(a), bytes(b),
            bytes([(a[j + 1] - a[j]) % 26 for j in range(11)]),
            bytes([(b[j + 1] - b[j]) % 26 for j in range(9)]))


# ---------------------------------------------------------------- worker side

def quad_dict():
    from .score import Quadgrams
    q = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    out = {}
    for a in DIG:
        for b in DIG:
            for c in DIG:
                for d in DIG:
                    out[(a + b + c + d).encode()] = q.floor
    for g, lp in q.logp.items():
        if len(g) == 4 and g.isalpha():
            out[dig(g)] = lp
    return out


def init(pb, pm, pl, cl, parts, thresh):
    G["pl"], G["cl"], G["parts"], G["thresh"] = pl, cl, parts, thresh
    if "A" in parts or "C" in parts:
        with open(pb, "rb") as f:
            G["big"] = f.read()
        with open(pm, "rb") as f:
            G["bm"] = f.read()
        G["starts"] = stream_starts(G["big"])
    if "B" in parts:
        G["q"] = quad_dict()


def _occ(big, nd):
    p = big.find(nd)
    while p >= 0:
        yield p
        p = big.find(nd, p + 1)


def locate(t1, t2, big=None, starts=None):
    """Best placement of the two fragments in the known texts.

    Returns (fixed, fixed_pos, free, free_pos1, free_pos2): matches with block 2 exactly GAP letters
    after block 1 in the same reading, and with the gap free (same reading, any distance)."""
    big = G["big"] if big is None else big
    starts = G["starts"] if starts is None else starts
    n1, n2 = len(t1), len(t2)

    def cands(t, n):
        out = set()
        for off in (0, n - 6):
            for p in _occ(big, t[off:off + 6]):
                out.add((p - off, bisect_right(starts, p) - 1))
        return out

    def count(t, s, st):
        a, b = starts[st], starts[st + 1] - 1
        return sum(1 for j, ch in enumerate(t) if a <= s + j < b and big[s + j] == ch)

    c1, c2 = cands(t1, n1), cands(t2, n2)
    fixed = (0, -1)
    best1, best2 = {}, {}
    for s, st in c1:
        x = count(t1, s, st)
        if x > best1.get(st, (0, 0))[0]:
            best1[st] = (x, s)
        y = x + count(t2, s + GAP, st)
        if y > fixed[0]:
            fixed = (y, s)
    for s, st in c2:
        x = count(t2, s, st)
        if x > best2.get(st, (0, 0))[0]:
            best2[st] = (x, s)
        y = x + count(t1, s - GAP, st)
        if y > fixed[0]:
            fixed = (y, s - GAP)
    free = (0, -1, -1)
    for st, (x, s) in best1.items():
        if st in best2 and x + best2[st][0] > free[0]:
            free = (x + best2[st][0], s, best2[st][1])
    return fixed[0], fixed[1], free[0], free[1], free[2]


def scan(chunk):
    """One chunk of (name, alphabet). Returns counts, located seeds and the best English fragments.

    Known texts (parts A and C): a setting is a seed when both six-letter halves of its block-1
    fragment and the first six letters of its block-2 fragment occur somewhere in the texts; every
    seed is then placed exactly (locate). A full match is always a seed, so nothing exact is lost."""
    pl, cl, parts, thresh = G["pl"], G["cl"], G["parts"], G["thresh"]
    do_a, do_b, do_c = "A" in parts, "B" in parts, "C" in parts
    bm, q = G.get("bm"), G.get("q")
    sa, sc = [0, 0, 0, 0], [0, 0, 0, 0]
    seeds_a, seeds_c, top, above, n = [], [], [], 0, 0
    worst = -1e9
    for name, m in chunk:
        tabs = tables(m)
        for lay, form, k, _, _ in streams(m, pl, cl):
            d1, d2, e1, e2 = diffs(k)
            for label, tab in tabs:
                n += 1
                t1 = d1.translate(tab)
                t2 = d2.translate(tab)
                if do_a:
                    c = int(t1[:6], 26)
                    if bm[c >> 3] >> (c & 7) & 1:
                        sa[0] += 1
                        c = int(t1[6:], 26)
                        if bm[c >> 3] >> (c & 7) & 1:
                            sa[1] += 1
                            c = int(t2[:6], 26)
                            if bm[c >> 3] >> (c & 7) & 1:
                                sa[2] += 1
                                c = int(t2[4:], 26)
                                sa[3] += bm[c >> 3] >> (c & 7) & 1
                                seeds_a.append((locate(t1, t2), name, lay, form, label, t1, t2))
                if do_b:
                    s = (q[t1[0:4]] + q[t1[1:5]] + q[t1[2:6]] + q[t1[3:7]] + q[t1[4:8]] + q[t1[5:9]]
                         + q[t1[6:10]] + q[t1[7:11]] + q[t1[8:12]]
                         + q[t2[0:4]] + q[t2[1:5]] + q[t2[2:6]] + q[t2[3:7]] + q[t2[4:8]] + q[t2[5:9]]
                         + q[t2[6:10]])
                    if thresh is not None and s > thresh:
                        above += 1
                    if s > worst:
                        item = (s, name, lay, form, label, t1, t2)
                        if len(top) < 200:
                            heapq.heappush(top, item)
                        else:
                            heapq.heapreplace(top, item)
                            worst = top[0][0]
                if do_c:
                    u1 = e1.translate(tab)
                    c = int(u1[:6], 26)
                    if bm[c >> 3] >> (c & 7) & 1:
                        sc[0] += 1
                        c = int(u1[5:], 26)
                        if bm[c >> 3] >> (c & 7) & 1:
                            sc[1] += 1
                            u2 = e2.translate(tab)
                            c = int(u2[:6], 26)
                            if bm[c >> 3] >> (c & 7) & 1:
                                sc[2] += 1
                                c = int(u2[3:], 26)
                                sc[3] += bm[c >> 3] >> (c & 7) & 1
                                seeds_c.append((locate(u1, u2), name, lay, form, label, u1, u2))
    return {"n": n, "sa": sa, "sc": sc, "seeds_a": seeds_a, "seeds_c": seeds_c, "top": top, "above": above}


# ---------------------------------------------------------------- the cipher itself (for planting)

def encrypt(pt, m, lay, form, text, numbering, off=0, sign=1, order=1, k0=0):
    """Encipher pt on the tableau of alphabet m; the strip is moved by `text` (letters numbered on
    `numbering`, from `off`), or with order=2 the text moves a strip that moves the strip."""
    names = {"M": m, "AZ": AZ, "KR": KRYPTOS_ALPHABET}
    a, b = (names[x] for x in lay.split("/"))
    ia = {c: i for i, c in enumerate(a)}
    num = {c: i for i, c in enumerate(numbering)}
    k, d, out = k0, 0, []
    for p, ch in zip(pt, text):
        t = sign * (num[ch] + off)
        if order == 2:
            d += t
            k += d
        else:
            k += t
        out.append(b[(ia[p] + k) % 26] if form == "vig" else b[(k - ia[p]) % 26])
    return "".join(out)


def clue_letters(ct, cribs):
    return [cribs[i] for i in POS], [ct[i] for i in POS]
