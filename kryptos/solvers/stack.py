"""Stack engine: (transposition) x (key model), tested with only the 24 clue letters.

A transposition is a position map m: plaintext letter i lands at ciphertext
position m[i]. The substitution S (Vigenere / Beaufort / variant, on the A-Z
or KRYPTOS alphabet) sits either
  before:  C = T(S(P))   key index = plaintext position i
  after:   C = S(T(P))   key index = ciphertext position j = m[i]

Key models (each a tuple):
  ("periodic", p)            k = base[t % p]
  ("progressive", p, s)      k = base[t % p] + s * (t // p)      (s = 1..25)
  ("ctauto", L)              k = the substitution's OUTPUT L places back
  ("ptauto", L)              k = the substitution's INPUT L places back
  ("shift", name, values)    every k in a small fixed set (digits 0-9, -3..3, ...), no period

For each (map, alphabet, variant, model, placement), every testable clue
equality must hold; a survivor also needs at least MIN_TESTS of them so
chance fits stay rare. Families of maps are built inside worker processes
from small descriptors, so millions of maps never get pickled.
"""

from itertools import islice, permutations
from multiprocessing import Pool, cpu_count

from ..ciphers import AZ, KRYPTOS_ALPHABET, KEY_FROM, PLAIN_FROM, columnar_decrypt

N = 97
MIN_TESTS = 6
ALPHABETS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
SHIFT_SETS = {
    "digits0-9": frozenset(range(10)),
    "pm3": frozenset([0, 1, 2, 3, 23, 24, 25]),
    "pm5": frozenset([0, 1, 2, 3, 4, 5, 21, 22, 23, 24, 25]),
}


# ---------------------------------------------------------------- key models

def models(kinds, max_period=26, max_prog_period=13, max_lag=60):
    out = []
    if "periodic" in kinds:
        out += [("periodic", p) for p in range(1, max_period + 1)]
    if "progressive" in kinds:
        out += [("progressive", p, s) for p in range(1, max_prog_period + 1) for s in range(1, 26)]
    if "ctauto" in kinds:
        out += [("ctauto", L) for L in range(1, max_lag + 1)]
    if "ptauto" in kinds:
        out += [("ptauto", L) for L in range(1, max_lag + 1)]
    if "shift" in kinds:
        out += [("shift", name, vals) for name, vals in SHIFT_SETS.items()]
    return out


def _variants_for(model):
    # For periodic/progressive, variant Beaufort is Vigenere with the key negated: same test.
    return ("vigenere", "beaufort") if model[0] in ("periodic", "progressive") else VARIANTS


def check_map(m, ct_vals, crib_pos, crib_vals, f, model, place, minv=None):
    """(passed, tests) for one map / alphabet / variant / model / placement."""
    kind = model[0]
    if kind == "shift":
        allowed = model[2]
        for i in crib_pos:
            if f(ct_vals[m[i]], crib_vals[i]) not in allowed:
                return False, 0
        return True, len(crib_pos)
    tests = 0
    if kind in ("periodic", "progressive"):
        p = model[1]
        s = model[2] if kind == "progressive" else 0
        seen = {}
        for i in crib_pos:
            t = i if place == "before" else m[i]
            base = (f(ct_vals[m[i]], crib_vals[i]) - s * (t // p)) % 26
            r = t % p
            prev = seen.get(r)
            if prev is None:
                seen[r] = base
            else:
                tests += 1
                if prev != base:
                    return False, tests
        return tests >= MIN_TESTS, tests
    L = model[1]
    for i in crib_pos:
        need = f(ct_vals[m[i]], crib_vals[i])
        if kind == "ctauto":
            if place == "before":
                if i < L:
                    continue
                key = ct_vals[m[i - L]]          # Y[i-L] = C[m[i-L]]
            else:
                j = m[i]
                if j < L:
                    continue
                key = ct_vals[j - L]             # C[j-L]
        else:  # ptauto
            if place == "before":
                src = i - L                      # P[i-L]
            else:
                j = m[i]
                if j < L:
                    continue
                src = minv[j - L]                # X[j-L] = P[minv[j-L]]
            if src < 0 or src not in crib_vals:
                continue
            key = crib_vals[src]
        tests += 1
        if key != need:
            return False, tests
    return tests >= MIN_TESTS, tests


# ------------------------------------------------------------- map families

def columnar_map(order):
    return columnar_decrypt(list(range(N)), list(order))


def compose(m1, m2):
    """T1 then T2: letter i -> m2[m1[i]]."""
    return [m2[a] for a in m1]


def decimation_map(a, b):
    return [(a * i + b) % N for i in range(N)]


def _grid_read(rows, cols, route):
    """Write 0..N-1 row-wise into rows x cols (pads = None), read by route."""
    g = [[r * cols + c if r * cols + c < N else None for c in range(cols)] for r in range(rows)]
    seq = []
    if route == "cols":
        seq = [g[r][c] for c in range(cols) for r in range(rows)]
    elif route == "cols_snake":
        for c in range(cols):
            rr = range(rows) if c % 2 == 0 else range(rows - 1, -1, -1)
            seq += [g[r][c] for r in rr]
    elif route == "rows_snake":
        for r in range(rows):
            cc = range(cols) if r % 2 == 0 else range(cols - 1, -1, -1)
            seq += [g[r][c] for c in cc]
    elif route.startswith("spiral"):
        top, bot, left, right = 0, rows - 1, 0, cols - 1
        while top <= bot and left <= right:
            seq += [g[top][c] for c in range(left, right + 1)]
            seq += [g[r][right] for r in range(top + 1, bot + 1)]
            if top < bot:
                seq += [g[bot][c] for c in range(right - 1, left - 1, -1)]
            if left < right:
                seq += [g[r][left] for r in range(bot - 1, top, -1)]
            top, bot, left, right = top + 1, bot - 1, left + 1, right - 1
    elif route == "diag":
        for d in range(rows + cols - 1):
            seq += [g[r][d - r] for r in range(rows) if 0 <= d - r < cols]
    elif route == "antidiag":
        for d in range(rows + cols - 1):
            seq += [g[r][cols - 1 - (d - r)] for r in range(rows) if 0 <= d - r < cols]
    return [x for x in seq if x is not None]


ROUTES = ("cols", "cols_snake", "rows_snake", "spiral", "diag", "antidiag")


def route_map(rows, cols, route, flip=False):
    """Plaintext written in rows, read off by `route`; flip = read the result backwards."""
    seq = _grid_read(rows, cols, route)
    if flip:
        seq = seq[::-1]
    m = [0] * N
    for j, i in enumerate(seq):
        m[i] = j
    return m


def rotation_map(w1, w2, pad_to):
    """K3's double rotation on the text padded to pad_to letters (pads dropped)."""
    def rot(seq, w):
        rows = [seq[k:k + w] for k in range(0, len(seq), w)]
        h = len(rows)
        return [rows[h - 1 - r][c] for c in range(w) for r in range(h)]
    seq = list(range(N)) + [None] * (pad_to - N)
    seq = rot(rot(seq, w1), w2)
    seq = [x for x in seq if x is not None]
    m = [0] * N
    for j, i in enumerate(seq):
        m[i] = j
    return m


def myszkowski_map(word):
    """Myszkowski: columns with the same key letter are read together, row by row."""
    word = word.upper()
    w = len(word)
    rows = [list(range(r, min(r + w, N))) for r in range(0, N, w)]
    seq = []
    for letter in sorted(set(word)):
        cols = [c for c, ch in enumerate(word) if ch == letter]
        for row in rows:
            seq += [row[c] for c in cols if c < len(row)]
    m = [0] * N
    for j, i in enumerate(seq):
        m[i] = j
    return m


def family_maps(desc):
    """Yield (label, map) for one job descriptor."""
    kind = desc[0]
    if kind == "columnar":
        _, w, start, stop = desc
        for o in islice(permutations(range(w)), start, stop):
            yield ("columnar", o), columnar_map(o)
    elif kind == "double":
        _, o1, w2, start, stop = desc
        m1 = columnar_map(o1)
        for o2 in islice(permutations(range(w2)), start, stop):
            yield ("double", o1, o2), compose(m1, columnar_map(o2))
    elif kind == "decimation":
        _, a = desc
        for b in range(N):
            yield ("decimation", a, b), decimation_map(a, b)
    elif kind == "route":
        _, rows, cols = desc
        for route in ROUTES:
            for flip in (False, True):
                yield ("route", rows, cols, route, flip), route_map(rows, cols, route, flip)
    elif kind == "rotation":
        _, pad_to, w1, w2 = desc
        yield ("rotation", pad_to, w1, w2), rotation_map(w1, w2, pad_to)
    elif kind == "myszkowski":
        _, words = desc
        for wd in words:
            yield ("myszkowski", wd), myszkowski_map(wd)
    elif kind == "maps":  # explicit maps (tests)
        _, items = desc
        yield from items


# ------------------------------------------------------------------ the scan

_S = {}


def _init(ct, cribs, model_list, places, alphabets=None):
    _S["crib_pos"] = sorted(cribs)
    _S["models"] = model_list
    _S["places"] = places
    tabs = []
    for aname, alpha in (alphabets or ALPHABETS).items():
        idx = {c: i for i, c in enumerate(alpha)}
        tabs.append((aname, [idx[c] for c in ct], {i: idx[cribs[i]] for i in cribs}))
    _S["tabs"] = tabs


def _work(desc):
    crib_pos, places, mods = _S["crib_pos"], _S["places"], _S["models"]
    needs_inv = any(md[0] == "ptauto" for md in mods) and "after" in places
    tested, hits = 0, []
    for label, m in family_maps(desc):
        minv = None
        if needs_inv:
            minv = [0] * N
            for i, j in enumerate(m):
                minv[j] = i
        for aname, cv, pv in _S["tabs"]:
            for md in mods:
                for variant in _variants_for(md):
                    f = KEY_FROM[variant]
                    for place in (("any",) if md[0] == "shift" else places):
                        tested += 1
                        ok, t = check_map(m, cv, crib_pos, pv, f, md, place, minv)
                        if ok:
                            hits.append((label, aname, variant, md[:2] if md[0] != "progressive" else md,
                                         place, t))
    return tested, hits


def scan(ct, cribs, jobs, kinds, places=("before", "after"), procs=None, alphabets=None, **model_kw):
    """Run every job descriptor. Returns (hypotheses tested, survivors)."""
    mods = models(kinds, **model_kw)
    tested, hits = 0, []
    if procs == 1:
        _init(ct, cribs, mods, places, alphabets)
        for d in jobs:
            t, h = _work(d)
            tested += t
            hits += h
        return tested, hits
    with Pool(procs or cpu_count(), initializer=_init, initargs=(ct, cribs, mods, places, alphabets)) as pool:
        for t, h in pool.imap_unordered(_work, jobs, chunksize=1):
            tested += t
            hits += h
    return tested, hits


def columnar_jobs(wmin, wmax, chunk=2000):
    from math import factorial
    return [("columnar", w, s, min(s + chunk, factorial(w)))
            for w in range(wmin, wmax + 1) for s in range(0, factorial(w), chunk)]


# --------------------------------------------- planted-cipher helpers (tests)

def encrypt_stack(pt, m, alpha, variant, model, place, key=None, primer=None):
    """Encrypt pt under transposition m + key model (used to plant test answers)."""
    idx = {c: i for i, c in enumerate(alpha)}
    enc = {"vigenere": lambda p, k: (p + k) % 26, "beaufort": lambda p, k: (k - p) % 26,
           "variant_beaufort": lambda p, k: (p - k) % 26}[variant]

    def sub(text):
        out = []
        for t, ch in enumerate(text):
            kind = model[0]
            if kind in ("periodic", "progressive"):
                p_ = model[1]
                s = model[2] if kind == "progressive" else 0
                k = (key[t % p_] + s * (t // p_)) % 26
            elif kind == "shift":
                k = key[t]
            elif kind == "ctauto":
                L = model[1]
                k = primer[t] if t < L else idx[out[t - L]]
            else:  # ptauto
                L = model[1]
                k = primer[t] if t < L else idx[text[t - L]]
            out.append(alpha[enc(idx[ch], k)])
        return "".join(out)

    def trans(text):
        out = [None] * N
        for i, ch in enumerate(text):
            out[m[i]] = ch
        return "".join(out)

    return trans(sub(pt)) if place == "before" else sub(trans(pt))


# ------------------------------------------------------- survivors -> text

def map_from_label(label):
    kind = label[0]
    if kind == "columnar":
        return columnar_map(label[1])
    if kind == "double":
        return compose(columnar_map(label[1]), columnar_map(label[2]))
    if kind == "decimation":
        return decimation_map(label[1], label[2])
    if kind == "route":
        return route_map(*label[1:])
    if kind == "rotation":
        return rotation_map(label[2], label[3], label[1])
    if kind == "myszkowski":
        return myszkowski_map(label[1])
    return list(range(N))


def decrypt_hit(ct, cribs, hit, alphabets=None):
    """Plaintext for a survivor where the model allows it (unknown key letters
    become 'A'); None for models that can't be decrypted from the clues alone."""
    label, aname, variant, model, place, _ = hit
    kind = model[0]
    if kind in ("shift", "ptauto"):
        return None
    alpha = (alphabets or ALPHABETS)[aname]
    idx = {c: i for i, c in enumerate(alpha)}
    f, dec = KEY_FROM[variant], PLAIN_FROM[variant]
    m = map_from_label(label)
    cv = [idx[c] for c in ct]
    out = [None] * N
    if kind == "ctauto":
        L = model[1]
        for i in range(N):
            if place == "before":
                k = cv[m[i - L]] if i >= L else 0
            else:
                k = cv[m[i] - L] if m[i] >= L else 0
            out[i] = alpha[dec(cv[m[i]], k)]
        return "".join(out)
    p = model[1]
    s = model[2] if kind == "progressive" else 0
    base = {}
    for i in cribs:
        t = i if place == "before" else m[i]
        base[t % p] = (f(cv[m[i]], idx[cribs[i]]) - s * (t // p)) % 26
    for i in range(N):
        t = i if place == "before" else m[i]
        k = (base.get(t % p, 0) + s * (t // p)) % 26
        out[i] = alpha[dec(cv[m[i]], k)]
    return "".join(out)
