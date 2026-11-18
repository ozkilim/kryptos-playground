"""Idea 115 helpers: the key is two sculpture texts laid over each other (K = T1 + T2 or T1 - T2).

Every text is a list of numbers (letters numbered on A-Z or KRYPTOS). A window is a (stream, start)
pair: stream letter a+i lines up with K4 letter i. A free constant c is allowed in the key (it covers
numbering from 0 or 1 and any shift of the tableau), so all values are compared after subtracting the
value at the first clue position of the block: a block of n clue letters gives n-1 exact checks.

Meet in the middle: the normalised windows of the second text go in a dict keyed by their first Q
values; for every first-text window the forced key minus that window is looked up, and the few
candidates are checked on every letter of the block.
"""
import json

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import DATA_DIR, letters, load

B1, B2 = list(range(21, 34)), list(range(63, 74))
POS = B1 + B2
NUMS = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
Q = 4
MORSE = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUSHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ"
# English for planted tests: not on the sculpture.
PLANT_TEXT = letters(
    "THE OLD MAP SHOWED A NARROW ROAD THAT RAN FROM THE RIVER UP INTO THE HILLS AND THE TRAVELLERS "
    "FOLLOWED IT FOR THREE DAYS UNTIL THEY REACHED A SMALL STONE HOUSE WHERE A WOMAN GAVE THEM BREAD "
    "AND WATER AND TOLD THEM THAT THE BRIDGE AHEAD HAD FALLEN IN THE WINTER STORMS SO THEY MUST WAIT "
    "FOR THE BOATMAN WHO CAME ONLY WHEN THE MOON WAS FULL AND THE WIND WAS QUIET")


def base_texts():
    """[(name, string)] before reversal: the texts on the sculpture, letters only."""
    k1, k2, k3 = load("k1"), load("k2"), load("k3")
    pt_c = letters(k1["plaintext"] + k2["plaintext"] + k3["plaintext"])
    pt_f = letters(k1["plaintext"].replace("IQLUSION", "ILLUSION") + k2["plaintext_corrected"]
                   + k3["plaintext"].replace("DESPARATLY", "DESPERATELY"))
    ct_c = letters(k1["ciphertext"] + k2["ciphertext"] + k3["ciphertext"])
    ct_f = letters(k1["ciphertext"] + k2["ciphertext_corrected"] + k3["ciphertext"])
    lay = json.load(open(DATA_DIR / "sculpture_layout.json"))

    def cols(rows):
        w = max(len(r) for r in rows)
        g = [r.ljust(w) for r in rows]
        return letters("".join(g[r][c] for c in range(w) for r in range(len(g))))
    cp, tp = lay["cipher_panel"], lay["tableau_panel"]
    from .data import K4
    return [("K1-K3 plain (carved)", pt_c), ("K1-K3 plain (corrected)", pt_f),
            ("K1-K3 cipher (carved)", ct_c), ("K1-K3 cipher (K2 corrected)", ct_f),
            ("cipher panel rows", letters("".join(cp))), ("cipher panel columns", cols(cp)),
            ("tableau panel rows", letters("".join(tp))), ("tableau panel columns", cols(tp)),
            ("Morse", MORSE), ("K4 cipher", K4)]


def all_texts():
    out = []
    for n, s in base_texts():
        out.append((n, s))
        out.append((n + " reversed", s[::-1]))
    return out


def numbered(texts, nums=("AZ", "KR")):
    """{num: [list of ints per text]}."""
    out = {}
    for nn in nums:
        idx = {c: i for i, c in enumerate(NUMS[nn])}
        out[nn] = [[idx[c] for c in s] for _, s in texts]
    return out


def windows(vals, pos):
    """[(sid, a, normalised tuple over pos)] for every start a with all of pos inside the text."""
    out = []
    p0, lo, hi = pos[0], min(pos), max(pos)
    for sid, v in enumerate(vals):
        for a in range(-lo, len(v) - hi):
            r = v[a + p0]
            out.append((sid, a, tuple((v[a + p] - r) % 26 for p in pos)))
    return out


def pack(t):
    return ((t[1] * 26 + t[2]) * 26 + t[3]) * 26 + t[4]


def table(wins):
    """Second-text table: {packed first-Q normalised values: [(sid, b, tuple)]} for s2 = +1 and -1."""
    plus, minus = {}, {}
    for sid, b, t in wins:
        plus.setdefault(pack(t), []).append((sid, b, t))
        neg = tuple((-x) % 26 for x in t)
        minus.setdefault(pack(neg), []).append((sid, b, neg))
    return plus, minus


def join(kn, wins1, tab, agree_hist=None):
    """Pairs (sid1, a, sid2, b) with T1 window + T2' window == kn on every letter (T2' = +-T2 as in tab).

    kn: the forced key over the block, normalised. agree_hist: optional list counting how many letters
    of the block agree for every prefix candidate (a gauge near the bar)."""
    k1, k2, k3, k4 = kn[1], kn[2], kn[3], kn[4]
    n = len(kn)
    get = tab.get
    hits = []
    for sid, a, u in wins1:
        key = ((((k1 - u[1]) % 26) * 26 + (k2 - u[2]) % 26) * 26 + (k3 - u[3]) % 26) * 26 + (k4 - u[4]) % 26
        lst = get(key)
        if lst:
            for sid2, b, t in lst:
                ag = 5
                for j in range(5, n):
                    if (u[j] + t[j] - kn[j]) % 26 == 0:
                        ag += 1
                if agree_hist is not None:
                    agree_hist[ag] += 1
                if ag == n:
                    hits.append((sid, a, sid2, b))
    return hits


# ---------------------------------------------------------------- forced key and tableaux

def forced_keys(ct, cribs, alphabets):
    """[(alpha name, layout, view, {pos: k})] for each tableau alphabet in its layouts and 4 views.

    views: vig  k = C - P;  var  k = P - C;  beau  k = C + P;  diana k = -C - P (positions on the
    plain / cipher alphabets of the layout)."""
    iz = {c: i for i, c in enumerate(AZ)}
    ik = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    out = []
    for an, m in alphabets:
        im = {c: i for i, c in enumerate(m)}
        if m == AZ:
            lays = (("AZ/AZ", iz, iz), ("AZ/KR", iz, ik), ("KR/AZ", ik, iz), ("KR/KR", ik, ik))
        elif m == KRYPTOS_ALPHABET:
            lays = (("KR/KR", ik, ik), ("KR/AZ", ik, iz), ("AZ/KR", iz, ik))
        else:
            lays = (("M/M", im, im), ("M/AZ", im, iz), ("AZ/M", iz, im), ("M/KR", im, ik), ("KR/M", ik, im))
        for lay, ia, ib in lays:
            for view in VIEWS:
                out.append((an, lay, view, {i: VIEWS[view](ib[ct[i]], ia[cribs[i]]) % 26 for i in cribs}))
    return out


VIEWS = {"vig": lambda c, p: c - p, "var": lambda c, p: p - c,
         "beau": lambda c, p: c + p, "diana": lambda c, p: -c - p}


def layout_alphas(m, lay):
    d = {"AZ": AZ, "KR": KRYPTOS_ALPHABET, "M": m}
    a, b = lay.split("/")
    return d[a], d[b]


def encrypt(pt, key, m, lay, view):
    """Encrypt with key values key[i] (None = leave as '?') on the layout and view."""
    pa, ca = layout_alphas(m, lay)
    ip = {c: i for i, c in enumerate(pa)}
    out = []
    for i, ch in enumerate(pt):
        k, x = key[i], ip[ch]
        if view == "vig":
            y = k + x
        elif view == "var":
            y = x - k
        elif view == "beau":
            y = k - x
        else:
            y = -k - x
        out.append(ca[y % 26])
    return "".join(out)


def decrypt(ct, key, m, lay, view):
    pa, ca = layout_alphas(m, lay)
    ic = {c: i for i, c in enumerate(ca)}
    out = []
    for i, ch in enumerate(ct):
        k = key[i]
        if k is None:
            out.append("?")
            continue
        y = ic[ch]
        if view == "vig":
            x = y - k
        elif view == "var":
            x = y + k
        elif view == "beau":
            x = k - y
        else:
            x = -k - y
        out.append(pa[x % 26])
    return "".join(out)


def pair_key(v1, a, v2, b, s2, kforced, n=97, p0=POS[0]):
    """Full key K[i] = T1[a+i] + s2*T2[b+i] + c (c from the clue letter at p0); None where a text ends."""
    c = (kforced[p0] - v1[a + p0] - s2 * v2[b + p0]) % 26
    out = []
    for i in range(n):
        if 0 <= a + i < len(v1) and 0 <= b + i < len(v2):
            out.append((v1[a + i] + s2 * v2[b + i] + c) % 26)
        else:
            out.append(None)
    return out


# ---------------------------------------------------------------- Part B: one text plus a word

def periodic(r, L):
    """True if the residues r (dict pos -> value) repeat with period L on the clue positions."""
    seen = {}
    for p in POS:
        q = p % L
        x = seen.get(q)
        if x is None:
            seen[q] = r[p]
        elif x != r[p]:
            return False
    return True


def sliding_word(r, L):
    """True if r[p] = c + sum_{j<=p} w[j mod L] for some word w (sliding = running sum of a word)."""
    w = {}
    for blk in (B1, B2):
        for p, q in zip(blk, blk[1:]):
            d = (r[q] - r[p]) % 26
            x = w.get(q % L)
            if x is None:
                w[q % L] = d
            elif x != d:
                return False
    if len(w) < L:
        return True          # never happens for L <= 12 (block 1 alone covers 12 residues)
    gap = sum(w[j % L] for j in range(B1[-1] + 1, B2[0] + 1)) % 26
    return (r[B2[0]] - r[B1[-1]]) % 26 == gap


def checks_periodic(L):
    return len(POS) - len({p % L for p in POS})


def functionals(kind, L):
    """Linear tests (coefficient dicts over the 24 clue indices) that the remainder R = K - T must pass.

    'rep': R repeats with period L (T plus a repeating word).
    'slide': R is a constant plus the running sum of a word of length L (T plus a sliding word)."""
    idx = {p: j for j, p in enumerate(POS)}
    out = []
    if kind == "rep":
        first = {}
        for j, p in enumerate(POS):
            q = p % L
            if q in first:
                out.append({j: 1, first[q]: -1})
            else:
                first[q] = j
        return out
    diff = {}            # q -> {index: coef} for D_q = R[q] - R[q-1]
    for blk in (B1, B2):
        for p, q in zip(blk, blk[1:]):
            diff[q] = {idx[q]: 1, idx[p]: -1}
    rep = {}
    for q in sorted(diff):
        r = q % L
        if r not in rep:
            rep[r] = q
        else:
            f = dict(diff[q])
            for j, c in diff[rep[r]].items():
                f[j] = f.get(j, 0) - c
            out.append(f)
    assert len(rep) == L
    g = {idx[B2[0]]: 1, idx[B1[-1]]: -1}
    for j in range(B1[-1] + 1, B2[0] + 1):
        for i, c in diff[rep[j % L]].items():
            g[i] = g.get(i, 0) - c
    out.append(g)
    return out


def signature(v, funcs):
    return tuple(sum(c * v[j] for j, c in f.items()) % 26 for f in funcs)


def cumulative(vals):
    """Running-sum streams: S[j] = T[0] + ... + T[j] (a text used as a sliding key)."""
    out = []
    for v in vals:
        s, c = [], 0
        for x in v:
            c = (c + x) % 26
            s.append(c)
        out.append(s)
    return out
