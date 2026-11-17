"""Idea 95: two rotors in series, one wired from a keyword (known), one hidden.

    Y = R1[P + s] - s        first rotor, fast turn s
    C = R2[Y + t] - t        second rotor, slow turn t

Idea 82 showed that two hidden wirings cannot be judged from 24 clue letters. With ONE wiring
known the middle letter Y is known at every clue letter, and the other rotor is tested exactly
as in idea 72: each clue letter is one wire, and a real wiring never sends one contact to two
places or two contacts to one place.

  form A  hidden rotor first (fast), keyword rotor second (slow).
          Y = R2back[C + t] - t is known; wires of R1: contact P + s -> Y + s.
          The number of forced coincidences depends only on the fast rule (and the clue letters).
          A constant added to s only renames the hidden contacts; the start of t matters.
  form B  keyword rotor first (fast), hidden rotor second (slow).
          Y = R1[P + s] - s is known; wires of R2: contact Y + t -> C + t.
          The number of forced coincidences depends only on the slow rule (and the cipher letters).
          The start of s matters (every rule is tried with +0..25); the start of t does not.

The search never loops over (wiring x rule x slow setting). Form A: for each keyword wiring and
each turn t, the rules that fit clue block 1 (and block 2) are looked up through one forced
pair of wires, then the two blocks are joined. Form B: the rules are indexed by their turn at
two forced pairs; a keyword wiring looks up only the rules that satisfy both.
"""
import collections
import itertools

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round11 import POS

ALPH = (("AZ", AZ), ("KR", KRYPTOS_ALPHABET))
NUM = dict(ALPH)
AZI = {c: i for i, c in enumerate(AZ)}
N1 = 13                     # clue block 1 = the first 13 clue positions, block 2 = the other 11
MINREC = 5                  # coincidences needed to record a setting; the headline threshold is 7
MIN = 7
EMPTY = frozenset()
_O = [(i + off) // 26 for off in range(26) for i in range(97)]


# ---- the pieces: wirings, fast rules, slow shapes ----------------------------------------------

def wiring(m, form):
    """A keyword alphabet m as a rotor wiring (contact number -> contact number).

    'strip/A-Z'    contact x is joined to the letter m[x] (strip read against A-Z)
    'A-Z/strip'    the same strip read the other way
    'strip+k'      the strip against itself, k places on: letter m[j] is joined to m[j + k]"""
    w1 = [AZI[ch] for ch in m]
    if form == "strip/A-Z":
        return w1
    w2 = [0] * 26
    for i, x in enumerate(w1):
        w2[x] = i
    if form == "A-Z/strip":
        return w2
    k = int(form[6:])
    return [w1[(w2[x] + k) % 26] for x in range(26)]


def forms(small):
    return ["strip/A-Z", "A-Z/strip"] + (["strip+%d" % k for k in range(1, 26)] if small else [])


def inverse(w):
    out = [0] * 26
    for i, x in enumerate(w):
        out[x] = i
    return out


def fast_rules(ct, theme, keymax=3):
    """[(name, turn at each of the 97 places)], without a start constant. Duplicates dropped."""
    out, seen = [], set()

    def add(name, s):
        s = tuple(x % 26 for x in s)
        if s not in seen:
            seen.add(s)
            out.append((name, s))
    for a in range(26):
        add("speed %d" % a, [a * i for i in range(97)])
    for nn, num in ALPH:
        v = [num.index(ch) for ch in ct]
        add("previous cipher letter (%s)" % nn, [0] + v[:-1])
        add("running sum of cipher text (%s)" % nn, [sum(v[:i]) for i in range(97)])
    for p in range(2, keymax + 1):
        for tail in itertools.product(range(26), repeat=p - 1):
            key = (0,) + tail
            add("key " + "".join(AZ[x] for x in key), [key[i % p] for i in range(97)])
    for w in theme:
        p = len(w)
        for nn, num in ALPH:
            vals = [num.index(ch) for ch in w]
            add("word %s (%s)" % (w, nn), [vals[i % p] for i in range(97)])
            run, t = [], 0
            for i in range(97):
                t += vals[i % p]
                run.append(t)
            add("sliding word %s (%s)" % (w, nn), run)
    return out


def slow_shapes():
    """[(name, slow turn at the 24 clue places relative to the first)]: block 2 shifted by d,
    and one step per 26 letters (every offset; those with no step inside a clue are the same
    as d = 1 or 2 and are dropped)."""
    out = [("block 2 is %d on" % d, (0,) * N1 + (d,) * (24 - N1)) for d in range(26)]
    seen = set(r for _, r in out)
    for off in range(26):
        full = _O[off * 97:(off + 1) * 97]
        rel = tuple(full[i] - full[POS[0]] for i in POS)
        if rel not in seen:
            seen.add(rel)
            out.append(("one step per 26 letters (offset %d)" % off, rel))
    return out


def slow_streams(shape, t0):
    """The slow turn at all 97 places for a shape (several when the place of the jump between
    the clues is not fixed by the shape)."""
    if shape.startswith("block 2 is"):
        d = int(shape.split()[3])
        if d == 0:
            return [[t0] * 97]
        return [[t0] * j + [t0 + d] * (97 - j) for j in range(34, 64)]
    off = int(shape.split("offset ")[1][:-1])
    full = _O[off * 97:(off + 1) * 97]
    return [[t0 + x - full[POS[0]] for x in full]]


def views(ct, cribs, names=None):
    out = []
    for an, a in ALPH:
        for bn, b in ALPH:
            name = "pt%s/ct%s" % (an, bn)
            if names is None or name in names:
                out.append((name, [a.index(cribs[i]) for i in POS], [b.index(ct[i]) for i in POS]))
    return out


def wires_ok(u, v):
    """True if the wires u[i] -> v[i] can all belong to one real wiring."""
    f, g = {}, {}
    for a, b in zip(u, v):
        if f.setdefault(a, b) != b or g.setdefault(b, a) != a:
            return False
    return True


def _chain(vals):
    """Group equal values: returns (coincidences, [(i, j)] consecutive members of each group)."""
    groups = {}
    for j, x in enumerate(vals):
        groups.setdefault(x, []).append(j)
    pairs = []
    for g in groups.values():
        pairs += list(zip(g, g[1:]))
    return len(vals) - len(groups), pairs


# ---- form A: hidden rotor first, keyword rotor second ------------------------------------------

def plan_a(rules, pv, minrec=MINREC):
    """Index the fast rules by one forced pair of wires in each clue block."""
    rec, idx1, idx2, n1, n2 = [], {}, {}, set(), set()
    kcount = collections.Counter()
    for ridx, (_, s) in enumerate(rules):
        s24 = [s[i] for i in POS]
        u = [(p + x) % 26 for p, x in zip(pv, s24)]
        k, pairs = _chain(u)
        kcount[k] += 1
        if k < minrec:
            continue
        # equal inputs need equal outputs: Y[a] + s[a] = Y[b] + s[b]
        need = [(a, b, (s24[b] - s24[a]) % 26) for a, b in pairs]
        p1 = [x for x in need if x[1] < N1]
        p2 = [(a - N1, b - N1, d) for a, b, d in need if a >= N1]
        r = len(rec)
        rec.append((ridx, s24, u, k, [x for x in need if x[0] < N1 <= x[1]], need))
        for p, idx, none in ((p1, idx1, n1), (p2, idx2, n2)):
            if p:
                a, b, d = p[0]
                idx.setdefault((a, b), {}).setdefault(d, []).append((r, p[1:]))
            else:
                none.add(r)
    return {"rec": rec, "idx1": [(a, b, dd) for (a, b), dd in idx1.items()],
            "idx2": [(a, b, dd) for (a, b), dd in idx2.items()],
            "n1": frozenset(n1 - n2), "n2": frozenset(n2 - n1), "nn": len(n1 & n2), "kcount": kcount}


def _pset(idx, y):
    out = None
    for a, b, dd in idx:
        lst = dd.get((y[a] - y[b]) % 26)
        if lst:
            for r, rest in lst:
                for i, j, d in rest:
                    if (y[i] - y[j]) % 26 != d:
                        break
                else:
                    if out is None:
                        out = set()
                    out.add(r)
    return out or EMPTY


def run_a(plan, cv, kinv, shapes, split):
    """Every (fast rule, slow shape, slow start) for one keyword wiring (kinv = R2 backwards).
    Returns [(coincidences, rule index, shape index, t0)]. Shapes with a step inside a clue
    block are only tried when split is true, and then only for rules with a forced pair of
    wires in the other block."""
    rec, n1, n2 = plan["rec"], plan["n1"], plan["n2"]
    c1, c2 = cv[:N1], cv[N1:]
    rows, y1, y2, p1, p2 = [], [], [], [], []
    for t in range(26):
        row = [(kinv[(c + t) % 26] - t) % 26 for c in range(26)]
        rows.append(row)
        a = [row[c] for c in c1]
        b = [row[c] for c in c2]
        y1.append(a)
        y2.append(b)
        p1.append(_pset(plan["idx1"], a))
        p2.append(_pset(plan["idx2"], b))
    hits = []
    b2 = [(n1 & p) if p else EMPTY for p in p2] if n1 else [EMPTY] * 26
    for t0 in range(26):
        q1 = p1[t0]
        a1 = (q1 & n2) if q1 and n2 else EMPTY
        for d in range(26):
            t2 = (t0 + d) % 26
            q2 = p2[t2]
            cand = (q1 & q2) if q1 and q2 else EMPTY
            if a1 or b2[t2]:
                cand = cand | a1 | b2[t2]
            if cand:
                y = y1[t0] + y2[t2]
                for r in cand:
                    _, s24, u, k, cross, _n = rec[r]
                    for i, j, dl in cross:           # wires that meet across the two blocks
                        if (y[i] - y[j]) % 26 != dl:
                            break
                    else:
                        if wires_ok(u, [(a + b) % 26 for a, b in zip(y, s24)]):
                            hits.append((k, rec[r][0], d, t0))
    if split:
        for si in range(26, len(shapes)):
            rel = shapes[si][1]
            if len(set(rel[:N1])) == 1:              # block 1 steady: candidates from block 1
                for t0 in range(26):
                    if p1[t0]:
                        y = y1[t0] + [rows[(t0 + rel[N1 + j]) % 26][c] for j, c in enumerate(c2)]
                        for r in p1[t0]:
                            _, s24, u, k, _c, need = rec[r]
                            for i, j, dl in need:
                                if (y[i] - y[j]) % 26 != dl:
                                    break
                            else:
                                if wires_ok(u, [(a + b) % 26 for a, b in zip(y, s24)]):
                                    hits.append((k, rec[r][0], si, t0))
            else:                                    # block 2 steady
                e = rel[N1]
                for t0 in range(26):
                    q = p2[(t0 + e) % 26]
                    if q:
                        y = [rows[(t0 + rel[j]) % 26][c] for j, c in enumerate(c1)] + y2[(t0 + e) % 26]
                        for r in q:
                            _, s24, u, k, _c, need = rec[r]
                            for i, j, dl in need:
                                if (y[i] - y[j]) % 26 != dl:
                                    break
                            else:
                                if wires_ok(u, [(a + b) % 26 for a, b in zip(y, s24)]):
                                    hits.append((k, rec[r][0], si, t0))
    return hits


# ---- form B: keyword rotor first, hidden rotor second ------------------------------------------

def plan_b(rules, cv, shapes, minrec=MINREC):
    """Group the slow shapes by two forced pairs of wires and index every rule (with every
    start constant) by its turn at those two pairs."""
    s24 = []
    for _, s in rules:
        base = [s[i] for i in POS]
        for c in range(26):
            s24.append([(x + c) % 26 for x in base])
    groups, kshape = {}, {}
    for si, (_, rel) in enumerate(shapes):
        b = [(c + t) % 26 for c, t in zip(cv, rel)]
        k, pairs = _chain(b)
        kshape[si] = k
        if k < minrec:
            continue
        # equal outputs need equal inputs: Y[a] + t[a] = Y[b] + t[b]
        need = [(i, j, (rel[j] - rel[i]) % 26) for i, j in pairs]
        in1 = [x for x in need if x[1] < N1]
        in2 = [x for x in need if x[0] >= N1]
        if len(set(rel[:N1])) == 1 and len(in1) >= 2:
            sig = tuple(in1[:2])
        elif len(set(rel[N1:])) == 1 and len(in2) >= 2:
            sig = tuple(in2[:2])
        else:
            sig = tuple(need[:2])
        groups.setdefault(sig, []).append((si, rel, b, k, [x for x in need if x not in sig]))
    out = []
    for sig, members in groups.items():
        (i1, j1, d1), (i2, j2, d2) = sig
        idx = {}
        for rid, s in enumerate(s24):
            idx.setdefault((s[i1], s[j1]), {}).setdefault((s[i2], s[j2]), []).append(rid)
        common = set(members[0][4])
        for m in members[1:]:
            common &= set(m[4])
        common = sorted(common)
        out.append((sig, idx, common, [(si, rel, b, k, [x for x in need if x not in common])
                                       for si, rel, b, k, need in members]))
    return {"s24": s24, "groups": out, "kshape": kshape,
            "judged": sum(len(g[3]) for g in out)}


def _matches(g, pa, pb, d):
    """All (x, y) with g[x][pa] - g[y][pb] = d (mod 26)."""
    inv = {}
    for y in range(26):
        inv.setdefault(g[y][pb], []).append(y)
    out = []
    for x in range(26):
        for y in inv.get((g[x][pa] - d) % 26, ()):
            out.append((x, y))
    return out


def run_b(plan, pv, k):
    """Every (fast rule + start, slow shape) for one keyword wiring k = R1.
    Returns [(coincidences, rule id = rule index * 26 + start, shape index, 0)]."""
    g = [[(k[(p + s) % 26] - s) % 26 for p in range(26)] for s in range(26)]
    s24, hits = plan["s24"], []
    for sig, idx, common, members in plan["groups"]:
        (i1, j1, d1), (i2, j2, d2) = sig
        l2 = _matches(g, pv[i2], pv[j2], d2)
        for key1 in _matches(g, pv[i1], pv[j1], d1):
            sub = idx.get(key1)
            if not sub:
                continue
            for key2 in l2:
                lst = sub.get(key2)
                if not lst:
                    continue
                for rid in lst:
                    s = s24[rid]
                    for i, j, d in common:
                        if (g[s[i]][pv[i]] - g[s[j]][pv[j]]) % 26 != d:
                            break
                    else:
                        y = [g[x][p] for x, p in zip(s, pv)]
                        for si, rel, b, kk, need in members:
                            for i, j, d in need:
                                if (y[i] - y[j]) % 26 != d:
                                    break
                            else:
                                if wires_ok([(a + t) % 26 for a, t in zip(y, rel)], b):
                                    hits.append((kk, rid, si, 0))
    return hits


# ---- the model itself, and reading a survivor --------------------------------------------------

def encrypt(pn, r1, r2, s, t):
    return [(r2[(r1[(p + a) % 26] - a + b) % 26] - b) % 26 for p, a, b in zip(pn, s, t)]


def read(cfg, kw, pn_clue, cn, s, t):
    """Decrypt all 97 places with the keyword wiring kw and the part of the hidden wiring the
    clue letters force. pn_clue = {position: plain number}. Returns a list of numbers / None,
    or None if the wires clash."""
    kb = inverse(kw)
    back = {}
    for i, p in pn_clue.items():
        if cfg == "A":      # R1[P + s] = Y + s, Y from the keyword rotor
            y = (kb[(cn[i] + t[i]) % 26] - t[i]) % 26
            u, v = (p + s[i]) % 26, (y + s[i]) % 26
        else:               # R2[Y + t] = C + t, Y from the keyword rotor
            y = (kw[(p + s[i]) % 26] - s[i]) % 26
            u, v = (y + t[i]) % 26, (cn[i] + t[i]) % 26
        if back.setdefault(v, u) != u:
            return None
    if len(set(back.values())) != len(back):
        return None
    out = []
    for i, c in enumerate(cn):
        if cfg == "A":
            y = (kb[(c + t[i]) % 26] - t[i]) % 26
            u = back.get((y + s[i]) % 26)
            out.append(None if u is None else (u - s[i]) % 26)
        else:
            u = back.get((c + t[i]) % 26)
            out.append(None if u is None else (kb[(u - t[i] + s[i]) % 26] - s[i]) % 26)
    return out


def read_score(pt, big):
    """Big-model score per quadgram over the stretches that are known; -99 if under 15 quadgrams."""
    q = [pt[i:i + 4] for i in range(len(pt) - 3) if "?" not in pt[i:i + 4]]
    return sum(big.logp.get(x, big.floor) for x in q) / len(q) if len(q) >= 15 else -99.0
