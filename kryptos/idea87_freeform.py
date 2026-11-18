"""Helpers for idea 87: a repeating (or sliding) key where the encoder picks, letter by letter,
which of two or three cipher systems to use.

A *system* turns (plain letter, key) into a cipher letter. It is given by the plaintext alphabet,
the ciphertext alphabet, the form (Vigenere, Beaufort or variant Beaufort) and the naming of the key:

    vig   b = a + k        beau  b = k - a        var   b = a - k        (mod 26)

where a = place of the plain letter in the plain alphabet, b = place of the cipher letter in the
cipher alphabet, k = key number. The key *label* is what the key word holds: for systems on one
tableau the label is the key number itself; when the choice is between two tableaux the label is
the key letter, read in each tableau's own alphabet (K1/K2 style: row K of the KRYPTOS tableau).

For a clue letter (p, c) each system forces one label, so the clue gives a SET of 1-3 labels, held
as a 26-bit mask. A repeating key fits only if, in every residue class, the sets share a label.

Strength of a test (how often random sets would pass it) is measured like an exact check count:
expected chance solutions = 26^free * prod(|S_i| / 26), so

    strength = sum_i log26(26 / |S_i|) - free

with free = key letters the clues touch (repeating), or touched word letters + 1 or 2 block
starts (sliding). With one system per letter this is the usual 'clue letters minus key letters'.
"""
import math

from .ciphers import AZ, KRYPTOS_ALPHABET

FULL = (1 << 26) - 1
LOG26 = math.log(26)
FORMS = ("vig", "beau", "var")
B1, B2 = list(range(21, 34)), list(range(63, 74))
POS = B1 + B2
IDX = {c: i for i, c in enumerate(AZ)}


def _index(alpha):
    return [alpha.index(ch) for ch in AZ]          # AZ letter number -> place in alpha


def system(plain_alpha, cipher_alpha, form, name_alpha=None):
    """(pa, cb, pinv, cinv, form, name, ninv). name/ninv: key number <-> label (identity if None)."""
    pa, cb = _index(plain_alpha), _index(cipher_alpha)
    pinv, cinv = [IDX[ch] for ch in plain_alpha], [IDX[ch] for ch in cipher_alpha]
    if name_alpha is None:
        name = list(range(26))
    else:
        name = [IDX[ch] for ch in name_alpha]
    ninv = [0] * 26
    for k, lab in enumerate(name):
        ninv[lab] = k
    return (pa, cb, pinv, cinv, form, name, ninv)


def key_label(sy, p, c):
    """Label the system forces for plain letter number p and cipher letter number c."""
    pa, cb, _, _, form, name, _ = sy
    a, b = pa[p], cb[c]
    k = (b - a) if form == "vig" else (b + a) if form == "beau" else (a - b)
    return name[k % 26]


def enc_letter(sy, p, lab):
    pa, _, _, cinv, form, _, ninv = sy
    a, k = pa[p], ninv[lab]
    b = (a + k) if form == "vig" else (k - a) if form == "beau" else (a - k)
    return cinv[b % 26]


def dec_letter(sy, c, lab):
    _, cb, pinv, _, form, _, ninv = sy
    b, k = cb[c], ninv[lab]
    a = (b - k) if form == "vig" else (k - b) if form == "beau" else (b + k)
    return pinv[a % 26]


def masks(systems, pl, cl):
    """One 26-bit label mask per clue letter (pl, cl: letter numbers)."""
    out = []
    for p, c in zip(pl, cl):
        m = 0
        for sy in systems:
            m |= 1 << key_label(sy, p, c)
        out.append(m)
    return out


def popcount(m):
    return bin(m).count("1")


def logsum(ms):
    return sum(math.log(26.0 / popcount(m)) for m in ms) / LOG26


# ---- repeating key ----------------------------------------------------------------------------

def rep_groups(pos, lengths):
    """{L: [list of indices into pos with the same residue]} ."""
    out = {}
    for L in lengths:
        g = {}
        for j, i in enumerate(pos):
            g.setdefault(i % L, []).append(j)
        out[L] = [g[r] for r in sorted(g)]
    return out


def rep_test(ms, groups):
    """Intersections per class, or None if some class is empty."""
    out = []
    for g in groups:
        m = FULL
        for j in g:
            m &= ms[j]
            if not m:
                return None
        out.append(m)
    return out


# ---- sliding key: k_i = k_(i-1) + w_(i mod L) ---------------------------------------------------

def rot(m, y):
    """Mask of {x - y : x in m}."""
    y %= 26
    return ((m >> y) | (m << (26 - y))) & FULL


def bits(m):
    return [v for v in range(26) if m >> v & 1]


def diff_masks(ms, pos):
    """[(index j, absolute position, mask of k_j - k_(j-1))] for consecutive clue positions."""
    out = []
    for j in range(1, len(pos)):
        if pos[j] == pos[j - 1] + 1:
            d = 0
            for y in bits(ms[j - 1]):
                d |= rot(ms[j], y)
            out.append((j, pos[j], d))
    return out


def slide_groups(pos, lengths):
    out = {}
    dpos = [pos[j] for j in range(1, len(pos)) if pos[j] == pos[j - 1] + 1]
    for L in lengths:
        g = {}
        for t, i in enumerate(dpos):
            g.setdefault(i % L, []).append(t)
        touched = len(g)
        out[L] = ([g[r] for r in sorted(g)], touched, 1 if touched == L else 2)
    return out


def slide_filter(dms, groups):
    for g in groups:
        m = FULL
        for t in g:
            m &= dms[t][2]
            if not m:
                return False
    return True


def slide_solve(ms, pos, L, limit=64):
    """Every (w, k at each clue position) with k_i in S_i, w repeating with period L. Block starts are
    free unless every w is known, then the second block's start follows from the first (one stream)."""
    sols, w = [], [-1] * L
    n = len(pos)
    ks = [0] * n
    sets = [bits(m) for m in ms]

    def rec(j, kprev):
        if len(sols) >= limit:
            return
        if j == n:
            sols.append((list(w), list(ks)))
            return
        i = pos[j]
        if j == 0 or pos[j] != pos[j - 1] + 1:
            if j and all(x >= 0 for x in w):
                k = (kprev + sum(w[t % L] for t in range(pos[j - 1] + 1, i + 1))) % 26
                if ms[j] >> k & 1:
                    ks[j] = k
                    rec(j + 1, k)
                return
            for k in sets[j]:
                ks[j] = k
                rec(j + 1, k)
            return
        r = i % L
        if w[r] >= 0:
            k = (kprev + w[r]) % 26
            if ms[j] >> k & 1:
                ks[j] = k
                rec(j + 1, k)
            return
        for k in sets[j]:
            w[r] = (k - kprev) % 26
            ks[j] = k
            rec(j + 1, k)
        w[r] = -1

    rec(0, 0)
    return sols


def slide_key(w, k0, i0, n=97):
    """Key labels at every position from k at i0 and word w (None where w is unknown)."""
    L = len(w)
    out = [None] * n
    out[i0] = k0
    for i in range(i0 + 1, n):
        out[i] = None if out[i - 1] is None or w[i % L] < 0 else (out[i - 1] + w[i % L]) % 26
    for i in range(i0 - 1, -1, -1):
        out[i] = None if out[i + 1] is None or w[(i + 1) % L] < 0 else (out[i + 1] - w[(i + 1) % L]) % 26
    return out


# ---- encrypt / decrypt with a free choice per letter ------------------------------------------

def encrypt(pt, systems, key_at, rng):
    """key_at(i) -> label; the system for each letter is drawn from rng (the encoder's whim)."""
    return "".join(AZ[enc_letter(rng.choice(systems), IDX[ch], key_at(i))] for i, ch in enumerate(pt))


def candidates(ct, systems, labels, fixed=None):
    """Per position the possible plain letters (sorted string); '?' if the key is unknown."""
    out = []
    for i, ch in enumerate(ct):
        if fixed and i in fixed:
            out.append(fixed[i])
        elif labels[i] is None:
            out.append("?")
        else:
            out.append("".join(sorted(set(AZ[dec_letter(sy, IDX[ch], labels[i])] for sy in systems))))
    return out


def beam(cands, logp, floor, width=400):
    """Best reading of a candidate lattice on a quadgram table: (score per quadgram, text)."""
    states = [(0.0, "")]
    for opts in cands:
        nxt = []
        for sc, s in states:
            for ch in opts:
                t = s + ch
                if len(t) >= 4 and "?" not in t[-4:]:
                    nxt.append((sc + logp.get(t[-4:], floor), t))
                else:
                    nxt.append((sc, t))
        if len(nxt) > width:
            nxt.sort(key=lambda x: -x[0])
            nxt = nxt[:width]
        states = nxt
    sc, s = max(states)
    q = sum(1 for i in range(len(s) - 3) if "?" not in s[i:i + 4])
    return (sc / q if q else -99.0), s

