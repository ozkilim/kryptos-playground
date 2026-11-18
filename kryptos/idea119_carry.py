"""Idea 119: the key is added like a number, with carries (long addition in base 26 or 27).

Model. Letters are numbered on the tableau alphabets, from 0 (base n = 26) or from 1 (base n = 27).
The message and the key stream are added (or subtracted) digit by digit as two long numbers:

  add    C = P + K + c          carry out = 1 when P + K + c >= n
  sub    C = P - K - c          borrow out = 1 when P - K - c < 0       (variant Beaufort form)
  beau   C = K - P - c          borrow out = 1 when K - P - c < 0       (Beaufort form)

all digits mod n. The carry c runs right to left (the last letter is the units digit, as in a
written sum) or left to right. Optionally the number restarts at each row (carved rows 4+31+31+31,
or rows of 7, 14, 21, 31, 42): the carry into the first digit of a row's sum is 0, and the key
either runs on or restarts with the row.

The exact reduction. Inside a clue block plaintext and ciphertext are known. Fix the carry that
enters the block (one bit). Then at the first digit worked the key digit is forced,
K = C - P - c (add), so the sum and therefore the next carry are known, and so on along the block.
Every key value in the block follows; only the entering bit is free. Two blocks give at most four
24-value key vectors per stream, form, base and direction. A key rule (repeating word, sliding key,
progressive key, the rest of the round-11 battery) is then an exact test on each vector, with the
usual count of independent checks. No approximation is needed.

A hit is completed by decrypting all 97 letters from the far end (the carry there is 0; the
decryption is unique once the key is known) and must give back all 24 clue letters, which also
checks that the carries entering the blocks were what the hit assumed.
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round11 import POS

FORMS = ("add", "sub", "beau")
DIRS = ("RL", "LR")
BASES = ((26, 0), (27, 1))            # (modulus, number of the first letter)
B1, B2 = list(range(13)), list(range(13, 24))   # indexes into the 24 clue values
ROWS = {"carved": [0, 4, 35, 66]}
for _w in (7, 14, 21, 31, 42):
    ROWS["w%d" % _w] = list(range(0, 97, _w))
MIN_CHECKS = 7
LMAX = 12


def row_start(i, starts):
    s = 0
    for t in starts:
        if t <= i:
            s = t
    return s


# ------------------------------------------------------------------------------------------ models

def models(full=True):
    """[(name, reset rows or None, key restarts with the row)]."""
    out = [("plain", None, False)]
    if full:
        for r in ROWS:
            out.append(("carry-restart/" + r, r, False))
            out.append(("restart/" + r, r, True))
    return out


def key_index(model):
    """Key place of each clue position under a model (the battery's `pos`)."""
    _, r, restart = model
    if not restart:
        return list(POS)
    return [i - row_start(i, ROWS[r]) for i in POS]


def _pattern(block, d, r):
    """Positions (indexes into the 24) whose incoming carry is forced to 0, and whether the
    block's entering carry is forced to 0, for rows r (None: no restarts) and direction d."""
    if r is None:
        return (), False
    starts = set(ROWS[r])
    pos = [POS[j] for j in block]
    if d == "RL":
        forced = tuple(j for j in block[:-1] if POS[j] + 1 in starts)
        enter = pos[-1] + 1 in starts
    else:
        forced = tuple(j for j in block[1:] if POS[j] in starts)
        enter = pos[0] in starts
    return forced, enter


def block_keys(P, C, n, form, d, block, forced, e):
    """Key values of one block given the entering carry e (dict index -> key)."""
    order = block[::-1] if d == "RL" else block
    c, out = e, {}
    for j in order:
        if j in forced:
            c = 0
        p, y = P[j], C[j]
        if form == "add":
            k = (y - p - c) % n
            c = 1 if p + k + c >= n else 0
        elif form == "sub":
            k = (p - y - c) % n
            c = 1 if p - k - c < 0 else 0
        else:
            k = (y + p + c) % n
            c = 1 if k - p - c < 0 else 0
        out[j] = k
    return out


def vectors(P, C, n, form, d, mods):
    """Distinct (key vector, model index list, (e1, e2)) for one stream/form/direction."""
    cache, res = {}, {}
    for mi, (name, r, restart) in enumerate(mods):
        per = []
        for block in (B1, B2):
            forced, enter = _pattern(block, d, r)
            opts = []
            for e in ((0,) if enter else (0, 1)):
                key = (block[0], forced, e)
                v = cache.get(key)
                if v is None:
                    v = cache[key] = block_keys(P, C, n, form, d, block, forced, e)
                opts.append((e, v))
            per.append(opts)
        for e1, v1 in per[0]:
            for e2, v2 in per[1]:
                k = tuple(v1[j] for j in B1) + tuple(v2[j] for j in B2)
                kk = (k, restart and r)
                res.setdefault(kk, []).append((mi, (e1, e2)))
    return res


# ------------------------------------------------------------------------------------ fast rules

_PLANS = {}


def plan(pos):
    """Pair lists for repeating / sliding / progressive keys, L = 1..LMAX, on key places pos."""
    key = tuple(pos)
    pl = _PLANS.get(key)
    if pl is not None:
        return pl
    runs, s = [], 0
    for j in range(1, 25):
        if j == 24 or pos[j] != pos[j - 1] + 1:
            runs.append((s, j))
            s = j
    cons = [(j, j + 1) for a, b in runs for j in range(a, b - 1)]      # consecutive key places
    rep, sl, pr = [], [], []
    for L in range(1, LMAX + 1):
        anchor, pairs = {}, []
        for j, i in enumerate(pos):
            a = anchor.setdefault(i % L, j)
            if a != j:
                pairs.append((a, j))
        if len(pairs) >= MIN_CHECKS:
            rep.append((L, pairs))
        anchor, pairs = {}, []
        for t, (a, b) in enumerate(cons):
            x = anchor.setdefault(pos[b] % L, t)
            if x != t:
                pairs.append((x, t))
        if len(pairs) >= MIN_CHECKS:
            sl.append((L, pairs))
        lagp = [(j, j + L) for a, b in runs for j in range(a, b - L)]
        if lagp:
            anchor, pairs = {}, []
            for j, i in enumerate(pos):
                a = anchor.setdefault(i % L, j)
                if a != j:
                    pairs.append((a, j, i // L - pos[a] // L))
            if len(pairs) - 1 >= MIN_CHECKS:
                pr.append((L, lagp[0], pairs))
    pl = _PLANS[key] = (cons, rep, sl, pr)
    return pl


def fast_rules(k, pos, n):
    """[(checks, rule)] for repeating, sliding and progressive keys (L 1..12) with >= 7 checks."""
    cons, rep, sl, pr = plan(pos)
    out = []
    for L, pairs in rep:
        for a, b in pairs:
            if k[a] != k[b]:
                break
        else:
            out.append((len(pairs), "repeating p=%d" % L))
    d = [(k[b] - k[a]) % n for a, b in cons]
    for L, pairs in sl:
        for a, b in pairs:
            if d[a] != d[b]:
                break
        else:
            out.append((len(pairs), "sliding p=%d" % L))
    for L, (a0, b0), pairs in pr:
        s = (k[b0] - k[a0]) % n
        if not s:
            continue
        for a, b, q in pairs:
            if (k[b] - k[a] - s * q) % n:
                break
        else:
            out.append((len(pairs) - 1, "progressive p=%d step=%d" % (L, s)))
    return out


def expected(pos, n):
    """Chance passes of fast_rules on one random vector: sum of n^-checks over its rules."""
    cons, rep, sl, pr = plan(pos)
    e = sum(float(n) ** -len(p) for _, p in rep) + sum(float(n) ** -len(p) for _, p in sl)
    e += sum((n - 1.0) / n * float(n) ** -(len(p) - 1) for _, _, p in pr)
    return e


# ------------------------------------------------------------------------------------ layouts

def layouts(m):
    iz = {c: i for i, c in enumerate(AZ)}
    ik = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    im = {c: i for i, c in enumerate(m)}
    if m == AZ:
        return (("AZ/AZ", iz, iz), ("AZ/KR", iz, ik), ("KR/AZ", ik, iz), ("KR/KR", ik, ik))
    if m == KRYPTOS_ALPHABET:            # M/KR and KR/M would repeat M/M
        return (("M/M", im, im), ("M/AZ", im, iz), ("AZ/M", iz, im))
    return (("M/M", im, im), ("M/AZ", im, iz), ("AZ/M", iz, im), ("M/KR", im, ik), ("KR/M", ik, im))


def layout_maps(m, lay):
    for name, ia, ib in layouts(m):
        if name == lay:
            return ia, ib
    raise KeyError(lay)


# ------------------------------------------------------------------------------------ search core

def test_alphabet(name, m, pl, cl, mods, battery_fn=None):
    """All hits for one alphabet: (checks, name, layout, base, form, dir, rule, models, es, key vector)."""
    hits, tested, exp = [], 0, 0.0
    for lay, ia, ib in layouts(m):
        a, b = [ia[c] for c in pl], [ib[c] for c in cl]
        for n, o in BASES:
            P = [x + o for x in a]
            C = [y + o for y in b]
            for form in FORMS:
                for d in DIRS:
                    for (k, rr), lst in vectors(P, C, n, form, d, mods).items():
                        pos = key_index(mods[lst[0][0]])
                        tested += 1
                        ek = (tuple(pos), n)
                        e = _EXP.get(ek)
                        if e is None:
                            e = _EXP[ek] = expected(pos, n)
                        exp += e
                        rules = fast_rules(k, pos, n)
                        if battery_fn is not None:      # autokey, two stacked keys, chain addition
                            rules += battery_fn(k, pos, n, xp=a, xc=b, min_checks=MIN_CHECKS,
                                                skip=("repeating", "sliding", "progressive"))
                        for ck, rule in rules:
                            hits.append((ck, name, lay, n, form, d, rule,
                                         tuple(mods[mi][0] for mi, _ in lst),
                                         tuple(es for _, es in lst), k))
    return hits, tested, exp


_EXP = {}


# ------------------------------------------------------------------------------------ decryption

def key_stream(k, pos_all, rule, n, mod_pos):
    """Key values at all 97 places from a hit (None where unknown). pos_all: key place of every
    text position; mod_pos: key places of the 24 clue values."""
    kind = rule.split()[0]
    L = int(rule.split("p=")[1].split()[0])
    if kind == "repeating":
        w = {}
        for v, t in zip(k, mod_pos):
            w[t % L] = v
        return [w.get(t % L) for t in pos_all]
    if kind == "progressive":
        s = int(rule.split("step=")[1])
        w = {}
        for v, t in zip(k, mod_pos):
            w[t % L] = (v - s * (t // L)) % n
        return [None if w.get(t % L) is None else (w[t % L] + s * (t // L)) % n for t in pos_all]
    if kind == "sliding":
        if pos_all != list(range(97)):
            return [None] * 97
        w = {}
        for j in range(23):
            if mod_pos[j + 1] == mod_pos[j] + 1:
                w[mod_pos[j + 1] % L] = (k[j + 1] - k[j]) % n
        if len(w) < L:
            return [None] * 97
        out = [None] * 97
        out[POS[0]] = k[0]
        for i in range(POS[0] + 1, 97):
            out[i] = (out[i - 1] + w[i % L]) % n
        for i in range(POS[0] - 1, -1, -1):
            out[i] = (out[i + 1] - w[(i + 1) % L]) % n
        return out
    return [None] * 97


def decrypt(ct, ia, ib, n, o, form, d, keys, reset_rows=None):
    """Plaintext letter indexes (None where not determined) for a carry cipher, given 97 key values."""
    starts = set(ROWS[reset_rows]) if reset_rows else set()
    order = range(96, -1, -1) if d == "RL" else range(97)
    inv_a = {v: c for c, v in ia.items()}
    out = [None] * 97
    c = 0
    for i in order:
        if (d == "RL" and i + 1 in starts) or (d == "LR" and i in starts):
            c = 0
        k = keys[i]
        if k is None or c is None:
            c = None
            continue
        y = ib[ct[i]] + o
        if form == "add":
            p = (y - k - c) % n
            c = 1 if p + k + c >= n else 0
        elif form == "sub":
            p = (y + k + c) % n
            c = 1 if p - k - c < 0 else 0
        else:
            p = (k - y - c) % n
            c = 1 if k - p - c < 0 else 0
        x = p - o
        out[i] = inv_a.get(x) if 0 <= x < 26 else "#"
    return "".join(ch if ch else "?" for ch in out)


def encrypt(pt, ia, ib, n, o, form, d, keys, reset_rows=None):
    """The model's encryptor (for planted tests and the prefilter)."""
    starts = set(ROWS[reset_rows]) if reset_rows else set()
    order = range(len(pt) - 1, -1, -1) if d == "RL" else range(len(pt))
    inv_b = {v: c for c, v in ib.items()}
    out = [None] * len(pt)
    c = 0
    for i in order:
        if (d == "RL" and i + 1 in starts) or (d == "LR" and i in starts):
            c = 0
        p, k = ia[pt[i]] + o, keys[i]
        if form == "add":
            s = p + k + c
            y, c = s % n, (1 if s >= n else 0)
        elif form == "sub":
            s = p - k - c
            y, c = s % n, (1 if s < 0 else 0)
        else:
            s = k - p - c
            y, c = s % n, (1 if s < 0 else 0)
        if not (0 <= y - o < 26):
            return None                     # base 27: the digit 0 is not a letter
        out[i] = inv_b[y - o]
    return "".join(out)
