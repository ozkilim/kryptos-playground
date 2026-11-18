"""Idea 127 helpers: Gromark with one dictionary alphabet and the other free, as an exact hash join.

Model:  C_i = CA[(PA(P_i) + f * d_i) mod 26],  f = +1 (Gromark) or -1 (subtractive form; Beaufort
is the same test as f = -1 because the free side absorbs a reflection).

  side "A": the plain alphabet PA is a dictionary alphabet, the cipher alphabet CA is free.
            Equal cipher letters at clue positions a, b force PA(P_b) - PA(P_a) = f (d_a - d_b);
            the 24 slots PA(P_i) + f d_i must be equal exactly when the cipher letters are.
  side "B": the cipher alphabet CA is a dictionary alphabet, PA is free.
            Equal plain letters at a, b force CA'(C_a) - CA'(C_b) = f (d_a - d_b);
            the 24 values CA'(C_i) - f d_i must be equal exactly when the plain letters are.

The left-hand sides depend only on the alphabet, the right-hand sides only on the digit stream, so
each side is a join on the vector of (d_a - d_b) mod 26 over the equal pairs ("signature"). An
alphabet stores its signature for f = +1 and for f = -1 (negated), so one lookup covers both forms.
"""
import random
from array import array
from bisect import bisect_left
from itertools import product

from .ciphers.substitution import AZ
from .data import CRIBS

POS = sorted(CRIBS)
L = max(POS) + 1                      # stream needed up to position 73
RULES = ("fib", "fib3", "ends")


def stream(primer, base, rule="fib", n=L):
    """fib: d_i = d_{i-m} + d_{i-m+1}; fib3: + d_{i-m+2} too; ends: d_i = d_{i-m} + d_{i-1}. All mod base."""
    k = list(primer)
    m = len(k)
    if rule == "fib":
        for i in range(m, n):
            k.append((k[i - m] + k[i - m + 1]) % base)
    elif rule == "fib3":
        for i in range(m, n):
            k.append((k[i - m] + k[i - m + 1] + k[i - m + 2]) % base)
    elif rule == "ends":
        for i in range(m, n):
            k.append((k[i - m] + k[i - 1]) % base)
    else:
        raise ValueError(rule)
    return k


def spaces(cap_fib=5_000_000, cap_other=1_100_000, bases=range(3, 17)):
    """[(rule, base, primer length)]: fib lengths 2-7, fib3 and ends lengths 3-7, capped by size."""
    out = []
    for rule in RULES:
        cap = cap_fib if rule == "fib" else cap_other
        for b in bases:
            for m in range(2 if rule == "fib" else 3, 8):
                if b ** m <= cap:
                    out.append((rule, b, m))
    return out


def edges(ct, cribs, side):
    """Equal pairs (a, b) as a chain per group: cipher letters for side A, plain letters for side B."""
    groups = {}
    for i in POS:
        groups.setdefault(ct[i] if side == "A" else cribs[i], []).append(i)
    return tuple((g[0], x) for g in groups.values() for x in g[1:])


def alpha_sig(alpha, ct, cribs, side, f, eds):
    """Signature an alphabet needs from the stream: entries (d_a - d_b) mod 26."""
    ix = {c: i for i, c in enumerate(alpha)}
    s, w = 0, 1
    for a, b in eds:
        if side == "A":
            v = (ix[cribs[b]] - ix[cribs[a]]) * f
        else:
            v = (ix[ct[a]] - ix[ct[b]]) * f
        s += (v % 26) * w
        w *= 26
    return s


def stream_sig(d, eds):
    s, w = 0, 1
    for a, b in eds:
        s += ((d[a] - d[b]) % 26) * w
        w *= 26
    return s


def distinct_ok(alpha, ct, cribs, side, f, d):
    """The injectivity condition: slot values equal exactly when the free-side letters are equal."""
    ix = {c: i for i, c in enumerate(alpha)}
    seen, back = {}, {}
    for i in POS:
        if side == "A":
            v, lab = (ix[cribs[i]] + f * d[i]) % 26, ct[i]
        else:
            v, lab = (ix[ct[i]] - f * d[i]) % 26, cribs[i]
        if seen.setdefault(lab, v) != v or back.setdefault(v, lab) != lab:
            return False
    return True


# ---------------------------------------------------------------- the join

class Texts:
    """The texts searched together (K4, controls, plants) with their edges for both sides."""

    def __init__(self, texts):
        self.texts = texts                      # [(label, ct, cribs)]
        self.ea = [edges(ct, cr, "A") for _, ct, cr in texts]
        self.eb = [edges(ct, cr, "B") for _, ct, cr in texts]
        self.ebu = sorted(set(self.eb))          # side-B edges are shared by texts with equal cribs
        self.ebk = [self.ebu.index(e) for e in self.eb]

    def alpha_arrays(self, alphas):
        """Sorted 64-bit signature arrays, one per (text, side), both forms in each."""
        out = []
        for t, (_, ct, cr) in enumerate(self.texts):
            for side, eds in (("A", self.ea[t]), ("B", self.eb[t])):
                v = sorted({alpha_sig(m, ct, cr, side, f, eds) for _, m in alphas for f in (1, -1)})
                out.append(array("Q", v))
        return out


def _contains(arr, x):
    j = bisect_left(arr, x)
    return j < len(arr) and arr[j] == x


def scan(T, arrays, rule, base, m, first, limit=None):
    """All primers of (rule, base, m) starting with digit `first`. Returns [(t, side, primer)] hits."""
    hits = []
    na = len(T.texts)
    ea, ebu, ebk = T.ea, T.ebu, T.ebk
    n = 0
    for rest in product(range(base), repeat=m - 1):
        primer = (first,) + rest
        d = stream(primer, base, rule)
        sb = [stream_sig(d, e) for e in ebu]
        for t in range(na):
            if _contains(arrays[2 * t], stream_sig(d, ea[t])):
                hits.append((t, "A", primer))
            if _contains(arrays[2 * t + 1], sb[ebk[t]]):
                hits.append((t, "B", primer))
        n += 1
        if limit and n >= limit:
            break
    return hits


def resolve(T, alphas, hits, rule, base):
    """Pass 2: which alphabets match the hit signatures, and pass the distinct-slot check.
    hits: [(t, side, primer)] all of one (rule, base). Returns [(t, side, f, alpha index, primer)]."""
    want = {}
    for t, side, primer in hits:
        d = stream(primer, base, rule)
        eds = T.ea[t] if side == "A" else T.eb[t]
        want.setdefault((t, side, stream_sig(d, eds)), []).append((primer, d))
    keys = {(t, side) for t, side, _ in want}
    out = []
    for ai, (_, alpha) in enumerate(alphas):
        for t, side in keys:
            _, ct, cr = T.texts[t]
            eds = T.ea[t] if side == "A" else T.eb[t]
            for f in (1, -1):
                for primer, d in want.get((t, side, alpha_sig(alpha, ct, cr, side, f, eds)), ()):
                    if distinct_ok(alpha, ct, cr, side, f, d):
                        out.append((t, side, f, ai, primer))
    return out


# ---------------------------------------------------------------- decrypt and complete

def forced(alpha, ct, cribs, side, f, d):
    """What the clues fix: (partial plaintext with '.', free letters, free slots, slot map)."""
    ix = {c: i for i, c in enumerate(alpha)}
    if side == "A":                         # cipher letter -> slot known for clue cipher letters
        slot = {ct[i]: (ix[cribs[i]] + f * d[i]) % 26 for i in POS}
        pt = []
        for i, c in enumerate(ct):
            pt.append(alpha[(slot[c] - f * d[i]) % 26] if c in slot else ".")
        free_l = sorted(set(ct) - set(slot))
        free_s = sorted(set(range(26)) - set(slot.values()))
    else:                                   # plain slot -> letter known for clue plain letters
        at = {(ix[ct[i]] - f * d[i]) % 26: cribs[i] for i in POS}
        pt = []
        for i, c in enumerate(ct):
            pt.append(at.get((ix[c] - f * d[i]) % 26, "."))
        slot = at
        free_l = sorted(set(AZ) - set(at.values()))
        free_s = sorted(set(range(26)) - set(at))
    return "".join(pt), free_l, free_s, slot


def complete(alpha, ct, cribs, side, f, d, q, rng, iters=20000, restarts=4):
    """Fill the free part to maximise English (quadgram mean on q). Returns (score, plaintext)."""
    ix = {c: i for i, c in enumerate(alpha)}
    _, free_l, free_s, slot = forced(alpha, ct, cribs, side, f, d)
    logp, fl = q.logp, q.floor

    def score(p):
        return sum(logp.get(p[i:i + 4], fl) for i in range(len(p) - 3)) / (len(p) - 3)

    if side == "A":
        # the free cipher letters take free slots; keep as many slots as letters (choose which)
        def build(assign):
            s = dict(slot)
            s.update(zip(free_l, assign))
            return "".join(alpha[(s[c] - f * d[i]) % 26] for i, c in enumerate(ct))
        pool = list(free_s)
    else:
        need = [(ix[c] - f * d[i]) % 26 for i, c in enumerate(ct)]

        def build(assign):
            at = dict(slot)
            at.update(zip(free_s, assign))
            return "".join(at[v] for v in need)
        pool = list(free_l)
    best = (-99.0, "")
    k = len(free_l) if side == "A" else len(free_s)
    for _ in range(restarts):
        cur = pool[:]
        rng.shuffle(cur)
        cs = score(build(cur[:k]))
        temp = 0.15
        for it in range(iters):
            i, j = rng.randrange(len(cur)), rng.randrange(len(cur))
            if i == j or (i >= k and j >= k):
                continue
            cur[i], cur[j] = cur[j], cur[i]
            ns = score(build(cur[:k]))
            if ns >= cs or rng.random() < 2.718 ** ((ns - cs) / temp):
                cs = ns
            else:
                cur[i], cur[j] = cur[j], cur[i]
            temp = max(0.005, temp * 0.9997)
        p = build(cur[:k])
        sc = score(p)
        if sc > best[0]:
            best = (sc, p)
    return best


# ---------------------------------------------------------------- planting

def encrypt(pt, pa, ca, d, f):
    return "".join(ca[(pa.index(p) + f * d[i]) % 26] for i, p in enumerate(pt))


def plant(rng, pt, alphas, side, base, m, rule="fib", f=1):
    """A planted message: one side a dictionary alphabet from `alphas`, the other random."""
    name, dic = rng.choice(alphas[1:])
    rand = "".join(rng.sample(AZ, 26))
    pa, ca = (dic, rand) if side == "A" else (rand, dic)
    primer = tuple(rng.randrange(base) for _ in range(m))
    d = stream(primer, base, rule, n=len(pt))
    ct = encrypt(pt, pa, ca, d, f)
    return ct, {i: pt[i] for i in POS}, {"name": name, "alpha": dic, "side": side, "f": f, "rule": rule,
                                         "base": base, "primer": primer}


def random_cribs_text(rng):
    return "".join(rng.choice(AZ) for _ in range(97))
