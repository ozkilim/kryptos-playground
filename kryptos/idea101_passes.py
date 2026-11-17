"""Idea 101: the key word comes round again, but the second pass is not the same as the first.

Every model here says: "these clue letters must show the same key letter". A model is a
*setting* (a tuple); `cells(setting)` gives, for each of the 97 letters, the key slot it uses and
how the key meets the letter there (the tag). Families:

  ("mirror", f, lp, T, c)       key stream u with u[x] = u[(c - x) mod T], x = letter count mod T.
                                T = 0: no repeat at all, one fold: u[x] = u[c - x].
  ("slide",  f, lp, T, c)       the same, for the STEP between neighbouring key values (a strip
                                moved on by a word read back and forth).
  ("period", f, T)              plain repeating key of length T (the baseline the mirror halves).
  ("alt",   (f0, f1), lp, L, o) word of length L; even passes use form f0, odd passes form f1.
  ("shift",  f, lp, L, o)       word of length L; odd passes use the word moved by a constant s.
  ("tab", conv, Z, (fM, fZ), lp, L, o)
                                word of length L; even passes on the keyword tableau M (form fM),
                                odd passes on tableau Z = "AZ" or "KR" (form fZ). The key LETTER
                                is the same; conv says how a key letter picks its row: "own" (its
                                place in that tableau's own alphabet) or "label" (its place in A-Z).

Forms f (a = place of the plain letter, b = place of the cipher letter, k = key value):
  V  k = b - a  (Vigenere)      B  k = b + a  (Beaufort)
  N  k = a - b  (variant)       O  k = -a - b
lp = 0: letters counted through the whole text (o / c carry the start); lp = 1: the count
restarts at each carved row (K4 letters 1, 5, 36, 67).

The fast test. For one alphabet and layout all key values the clue letters force are put in one
list w (one entry per form and clue letter). A setting is a list of pairs of entries that must be
equal (a spanning tree of each key slot). Each test is filed under its first pair; for every pair
of equal entries in w (found by bucketing) only the tests filed there are looked at. "shift" has
pairs that must all differ by the same non-zero constant instead.
"""
import collections

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET as KR
from .round11 import POS

NP = len(POS)
N = 97
STEP_OK = [j > 0 and POS[j] == POS[j - 1] + 1 for j in range(NP)]   # step into clue letter j is known
IZ = {c: i for i, c in enumerate(AZ)}
IK = {c: i for i, c in enumerate(KR)}
FI = {"V": 0, "B": 1, "N": 2, "O": 3}
ALPH = {"AZ": AZ, "KR": KR}
MAXP = 52                 # the clue letters are at most 52 apart: no longer period ties two of them
LAYS = ("M/M", "M/AZ", "AZ/M", "M/KR", "KR/M")
ALT_PAIRS = (("V", "B"), ("V", "N"), ("B", "N"), ("B", "O"))
SYMMETRIC = (("V", "N"), ("B", "O"))        # swapping the passes only negates the key
NA = 144                  # entries per layout: V B N O (4 x 24), step of V, step of B
NC = 360                  # entries for "tab": M own, M label (per alphabet); AZ, KR own, KR label (fixed)

Test = collections.namedtuple("Test", "eng fam checks eq cross aliases")


def row_g(i):
    return i if i < 4 else (i - 4) % 31


def g_of(lp, i):
    return i if lp == 0 else row_g(i)


def val(f, a, b):
    if f == "V":
        return (b - a) % 26
    if f == "B":
        return (b + a) % 26
    if f == "N":
        return (a - b) % 26
    return (-a - b) % 26


def inv(f, b, v):
    """Place of the plain letter, from the cipher letter's place b and the key value v."""
    if f == "V":
        return (b - v) % 26
    if f == "B":
        return (v - b) % 26
    if f == "N":
        return (v + b) % 26
    return (-v - b) % 26


def enc(f, a, v):
    """Place of the cipher letter, from the plain letter's place a and the key value v."""
    if f == "V":
        return (a + v) % 26
    if f == "B":
        return (v - a) % 26
    if f == "N":
        return (a - v) % 26
    return (-v - a) % 26


def cells(st):
    """[(key slot, tag)] for the 97 letters. For "slide" the slot is that of the step INTO the letter."""
    fam, out = st[0], []
    if fam in ("mirror", "slide"):
        _, f, lp, T, c = st
        for i in range(N):
            r = g_of(lp, i)
            if T:
                r %= T
                out.append((min(r, (c - r) % T), f))
            else:
                out.append((min(r, c - r) if c - r >= 0 else r, f))
    elif fam == "period":
        out = [(i % st[2], st[1]) for i in range(N)]
    else:
        lp, L, o = st[-3:]
        for i in range(N):
            par, slot = divmod((g_of(lp, i) - o) % (2 * L), L)
            if fam == "alt":
                tag = st[1][par]
            elif fam == "shift":
                tag = (st[1], par)
            else:
                tag = ("M", st[3][0]) if par == 0 else (st[2], st[3][1])
            out.append((slot, tag))
    return out


# ---- the slow, plain version: key letters forced, decrypt, encrypt ----------------------------

def layout_ctx(m, lay):
    a, b = lay.split("/")
    return ("lay", m if a == "M" else ALPH[a], m if b == "M" else ALPH[b])


def tok(ctx, tag, p, c):
    """The key token a plain/cipher letter pair forces."""
    if ctx[0] == "lay":
        return val(tag if isinstance(tag, str) else tag[0], ctx[1].index(p), ctx[2].index(c))
    x = ctx[1] if tag[0] == "M" else ALPH[tag[0]]
    v = val(tag[1], x.index(p), x.index(c))
    return IZ[x[v]] if ctx[2] == "own" else v


def untok(ctx, tag, c, t):
    """The plain letter, from the cipher letter and the key token."""
    if ctx[0] == "lay":
        return ctx[1][inv(tag if isinstance(tag, str) else tag[0], ctx[2].index(c), t)]
    x = ctx[1] if tag[0] == "M" else ALPH[tag[0]]
    v = x.index(AZ[t]) if ctx[2] == "own" else t
    return x[inv(tag[1], x.index(c), v)]


def solve(st, ctx, ct, cribs):
    """What the clue letters force. None if they contradict the setting.
    slide -> (steps by slot, key values by position); shift -> (word by slot, s); else word by slot."""
    cl, fam = cells(st), st[0]
    if fam == "slide":
        kv = {i: tok(ctx, cl[i][1], cribs[i], ct[i]) for i in cribs}
        w = {}
        for i in sorted(cribs):
            if i - 1 in cribs:
                d = (kv[i] - kv[i - 1]) % 26
                if w.setdefault(cl[i][0], d) != d:
                    return None
        return w, kv
    if fam == "shift":
        seen = {}
        for i in sorted(cribs):
            t = tok(ctx, cl[i][1], cribs[i], ct[i])
            if seen.setdefault((cl[i][0], cl[i][1][1]), t) != t:
                return None
        ss = set((seen[s, 1] - seen[s, 0]) % 26 for s, par in seen if par == 1 and (s, 0) in seen)
        if len(ss) != 1 or 0 in ss:
            return None
        s = ss.pop()
        return dict((slot, (t - s * par) % 26) for (slot, par), t in seen.items()), s
    key = {}
    for i in sorted(cribs):
        t = tok(ctx, cl[i][1], cribs[i], ct[i])
        if key.setdefault(cl[i][0], t) != t:
            return None
    return key


def decrypt(st, ctx, ct, sol):
    """All 97 letters, '?' where the forced key does not reach."""
    cl, fam = cells(st), st[0]
    if fam == "slide":
        w, k = sol[0], dict(sol[1])
        for i in range(1, N):
            if i not in k and i - 1 in k and cl[i][0] in w:
                k[i] = (k[i - 1] + w[cl[i][0]]) % 26
        for i in range(N - 2, -1, -1):
            if i not in k and i + 1 in k and cl[i + 1][0] in w:
                k[i] = (k[i + 1] - w[cl[i + 1][0]]) % 26
        return "".join(untok(ctx, cl[i][1], ct[i], k[i]) if i in k else "?" for i in range(N))
    if fam == "shift":
        key, s = sol
        return "".join(untok(ctx, cl[i][1], ct[i], (key[cl[i][0]] + s * cl[i][1][1]) % 26)
                       if cl[i][0] in key else "?" for i in range(N))
    return "".join(untok(ctx, cl[i][1], ct[i], sol[cl[i][0]]) if cl[i][0] in sol else "?" for i in range(N))


def key_text(st, sol):
    """The forced key over one round of the word (or one period of the mirror), '?' where unknown."""
    fam = st[0]
    key = sol[0] if fam in ("slide", "shift") else sol
    if fam in ("mirror", "slide"):
        T, c = st[3], st[4]
        if not T:
            return "".join(AZ[key[s]] if s in key else "?" for s in range(c // 2 + 1))
        return "".join(AZ[key[min(r, (c - r) % T)]] if min(r, (c - r) % T) in key else "?" for r in range(T))
    n = st[2] if fam == "period" else st[-2]
    return "".join(AZ[key[s]] if s in key else "?" for s in range(n))


# planting: explicit encryptors that do not use cells()

def mirror_stream(word, ends, o, lp=0):
    """A word (list of numbers) read forwards then backwards. ends = how many end letters are
    written twice (2: ABCDDCBA, 1: ABCDDCB, 0: ABCDCB). o = letter count where the word starts.
    Returns (key stream for 97 letters, T, c)."""
    w = list(word)
    u = w + (w[::-1] if ends == 2 else w[:0:-1] if ends == 1 else w[-2:0:-1])
    T = len(u)
    return [u[(g_of(lp, i) - o) % T] for i in range(N)], T, ((T - 1 if ends == 2 else 0) + 2 * o) % T


def encrypt_stream(pt, a, b, f, ks):
    return "".join(b[enc(f, a.index(ch), k)] for ch, k in zip(pt, ks))


def encrypt_slide(pt, a, b, f, steps, start=0):
    k, out = start, []
    for ch, d in zip(pt, steps):
        k = (k + d) % 26
        out.append(b[enc(f, a.index(ch), k)])
    return "".join(out)


def encrypt_alt(pt, a, b, forms, word, o, lp=0):
    L, out = len(word), []
    for i, ch in enumerate(pt):
        par, slot = divmod((g_of(lp, i) - o) % (2 * L), L)
        out.append(b[enc(forms[par], a.index(ch), word[slot])])
    return "".join(out)


def encrypt_shift(pt, a, b, f, word, s, o, lp=0):
    L, out = len(word), []
    for i, ch in enumerate(pt):
        par, slot = divmod((g_of(lp, i) - o) % (2 * L), L)
        out.append(b[enc(f, a.index(ch), (word[slot] + s * par) % 26)])
    return "".join(out)


def encrypt_tab(pt, m, z, conv, forms, word, o, lp=0):
    """word = key letters. Even passes on tableau m, odd passes on tableau z ("AZ" / "KR")."""
    L, out = len(word), []
    for i, ch in enumerate(pt):
        par, slot = divmod((g_of(lp, i) - o) % (2 * L), L)
        x = m if par == 0 else ALPH[z]
        v = x.index(word[slot]) if conv == "own" else IZ[word[slot]]
        out.append(x[enc(forms[par], x.index(ch), v)])
    return "".join(out)


# ---- the catalogue of tests ---------------------------------------------------------------------

def _canon(labels):
    """Slots renumbered in order of first use; a slot only one clue letter uses becomes None (it
    ties nothing), so settings that tie the clue letters the same way get the same value."""
    n = collections.Counter(x for x in labels if x is not None)
    m = {}
    return tuple(None if x is None or n[x] < 2 else m.setdefault(x, len(m)) for x in labels)


def _edges(classes, pars):
    """same = [(parity, j0, j)] equal within a slot and parity; link = [(j even, j odd)] one per
    slot that holds both parities."""
    groups = {}
    for j, c in enumerate(classes):
        if c is not None:
            groups.setdefault(c, {}).setdefault(pars[j], []).append(j)
    same, link = [], []
    for bypar in groups.values():
        for par, mem in bypar.items():
            same.extend((par, mem[0], j) for j in mem[1:])
        if len(bypar) == 2:
            link.append((bypar[0][0], bypar[1][0]))
    return same, link


def _cnode(conv, tab, f, j):
    base = (0 if conv == "own" else 72) if tab == "M" else 144 if tab == "AZ" else (216 if conv == "own" else 288)
    return base + FI[f] * 24 + j


def catalogue(min_checks=5):
    """Every distinct test with at least min_checks checks. Settings that tie the clue letters in
    exactly the same way are one test with several aliases (they differ only off the clues)."""
    tests = []
    zero = (0,) * NP
    # mirror / slide / period: one form, slots only
    one = collections.OrderedDict()                      # (fam, classes) -> [settings without f]
    for T in list(range(16, MAXP + 1)) + [0]:
        for c in (range(T) if T else range(2 * POS[0], 2 * POS[-1] + 1)):
            for fam in ("mirror", "slide"):
                st = (fam, "V", 0, T, c)
                cl = cells(st)
                if fam == "slide":
                    cls = _canon([cl[POS[j]][0] if STEP_OK[j] else None for j in range(NP)])
                else:
                    cls = _canon([cl[i][0] for i in POS])
                one.setdefault((fam, cls), []).append((0, T, c))
        if T:
            for c in (T - 1, 0):                         # rows: the word starts where the row starts
                cls = _canon([cells(("mirror", "V", 1, T, c))[i][0] for i in POS])
                one.setdefault(("mirror", cls), []).append((1, T, c))
    for T in range(18, MAXP + 1):
        one.setdefault(("period", _canon([i % T for i in POS])), []).append((T,))
    for (fam, cls), al in one.items():
        same, _ = _edges(cls, zero)
        if len(same) < min_checks:
            continue
        for f in "VB":
            base = FI[f] * 24 if fam != "slide" else 96 + FI[f] * 24
            tests.append(Test("A", fam, len(same), [(base + x, base + y) for _, x, y in same], [],
                              [(fam, f) + a for a in al]))
    # two kinds of pass: alt / shift / tab share the (parity, slot) patterns
    two = collections.OrderedDict()                      # (parities, classes) -> [(lp, L, o)]
    for L in range(2, MAXP + 1):
        for lp, o in [(0, o) for o in range(2 * L)] + [(1, 0), (1, L)]:
            pc = [divmod((g_of(lp, i) - o) % (2 * L), L) for i in POS]
            cls = _canon([s for _, s in pc])
            pars = tuple(p if c is not None else None for (p, _), c in zip(pc, cls))
            two.setdefault((pars, cls), []).append((lp, L, o))
    for (pars, cls), al in two.items():
        same, link = _edges(cls, pars)
        if not link:                                     # no slot seen in both kinds of pass: nothing new
            continue
        n = len(same) + len(link)
        half = [a for a in al if a[2] < a[1]]            # for the symmetric families
        if n >= min_checks:
            for fs in ALT_PAIRS:
                use = half if fs in SYMMETRIC else al
                if use:
                    nd = [FI[fs[0]] * 24, FI[fs[1]] * 24]
                    tests.append(Test("A", "alt", n, [(nd[p] + x, nd[p] + y) for p, x, y in same] +
                                      [(nd[0] + x, nd[1] + y) for x, y in link], [],
                                      [("alt", fs) + a for a in use]))
            for conv in ("own", "label"):
                for z in ("AZ", "KR"):
                    for fm in "VBN":
                        for fz in "VBN":
                            nd = [lambda j: _cnode(conv, "M", fm, j), lambda j: _cnode(conv, z, fz, j)]
                            tests.append(Test("C", "tab", n, [(nd[p](x), nd[p](y)) for p, x, y in same] +
                                              [(nd[0](x), nd[1](y)) for x, y in link], [],
                                              [("tab", conv, z, (fm, fz)) + a for a in al]))
        if n - 1 >= min_checks and half:
            for f in "VB":
                b = FI[f] * 24
                tests.append(Test("A", "shift", n - 1, [(b + x, b + y) for _, x, y in same],
                                  [(b + x, b + y) for x, y in link], [("shift", f) + a for a in half]))
    return tests


# ---- the fast scan ------------------------------------------------------------------------------

_KOFF = [0] * 96 + [64] * 24 + [128] * 24      # keeps the three kinds of entry in separate buckets


def _ok(w, rec):
    for x, y in rec[0]:
        if w[x] != w[y]:
            return False
    cr = rec[1]
    if cr:
        s = (w[cr[0][1]] - w[cr[0][0]]) % 26
        if not s:
            return False
        for x, y in cr[1:]:
            if (w[y] - w[x]) % 26 != s:
                return False
    return True


class EngineA:
    """Tests on one layout's key values. scan(w) -> [test index]."""

    def __init__(self, tests):
        self.piv, self.direct, self.n = {}, [], 0
        for tid, t in enumerate(tests):
            if t.eng != "A":
                continue
            self.n += 1
            eq = [(min(x, y), max(x, y)) for x, y in t.eq]
            if eq:
                self.piv.setdefault(eq[0][0] * NA + eq[0][1], []).append((tuple(eq[1:]), tuple(t.cross), tid))
            else:
                (a, b), (c, d) = t.cross[0], t.cross[1]
                self.direct.append((a, b, c, d, tuple(t.cross[2:]), tid))

    @staticmethod
    def vector(ia, ib, pl, cl):
        a, b = [ia[c] for c in pl], [ib[c] for c in cl]
        v = [(y - x) % 26 for x, y in zip(a, b)]
        bb = [(y + x) % 26 for x, y in zip(a, b)]
        return (v + bb + [(26 - k) % 26 for k in v] + [(26 - k) % 26 for k in bb] +
                [(v[j] - v[j - 1]) % 26 if STEP_OK[j] else 32 + j for j in range(NP)] +
                [(bb[j] - bb[j - 1]) % 26 if STEP_OK[j] else 32 + j for j in range(NP)])

    def scan(self, w):
        piv, hits, seen = self.piv, [], {}
        i = 0
        for x, off in zip(w, _KOFF):
            lst = seen.get(x + off)
            if lst is None:
                seen[x + off] = [i]
            else:
                for j in lst:
                    recs = piv.get(j * NA + i)
                    if recs:
                        for rec in recs:
                            if _ok(w, rec):
                                hits.append(rec[2])
                lst.append(i)
            i += 1
        for a, b, c, d, rest, tid in self.direct:
            s = (w[b] - w[a]) % 26
            if s and (w[d] - w[c]) % 26 == s:
                for x, y in rest:
                    if (w[y] - w[x]) % 26 != s:
                        break
                else:
                    hits.append(tid)
        return hits


class EngineC:
    """Tableau-alternation tests for one ciphertext: the A-Z and KRYPTOS key letters are fixed, so
    tests that already fail among them are dropped once. scan(m) -> [test index]."""

    def __init__(self, tests, pl, cl):
        self.pl, self.cl = pl, cl
        fix = []
        for x, own in ((AZ, True), (KR, True), (KR, False)):
            ix = {c: i for i, c in enumerate(x)}
            for f in "VBN":
                for p, c in zip(pl, cl):
                    v = val(f, ix[p], ix[c])
                    fix.append(IZ[x[v]] if own else v)
        self.fix, self.piv, self.n = fix, {}, 0
        w = [None] * 144 + fix
        partners = set()
        for tid, t in enumerate(tests):
            if t.eng != "C":
                continue
            self.n += 1
            eq = [(min(x, y), max(x, y)) for x, y in t.eq]
            if any(w[x] != w[y] for x, y in eq if x >= 144):
                continue
            eq = sorted((e for e in eq if e[0] < 144), key=lambda e: e[1] >= 144)   # M-M pairs first
            self.piv.setdefault(eq[0][0] * NC + eq[0][1], []).append((tuple(eq[1:]), (), tid))
            if eq[0][1] >= 144:
                partners.add(eq[0][1])
        # fixed entries that are the far end of a first pair, by value, for the own and the label half
        self.far = [[[y for y in sorted(partners) if w[y] == v and (y < 288) == own] for v in range(26)]
                    for own in (True, False)]

    def scan(self, m):
        im = {c: i for i, c in enumerate(m)}
        a, b = [im[c] for c in self.pl], [im[c] for c in self.cl]
        lab = ([(y - x) % 26 for x, y in zip(a, b)] + [(y + x) % 26 for x, y in zip(a, b)] +
               [(x - y) % 26 for x, y in zip(a, b)])
        mz = [IZ[c] for c in m]
        w = [mz[v] for v in lab] + lab + self.fix
        piv, hits, seen = self.piv, [], {}
        for i in range(72):
            x = lab[i]
            lst = seen.get(x)
            if lst is None:
                seen[x] = [i]
            else:
                for j in lst:                            # the same pairs are equal in the own half
                    for key in (j * NC + i, (j + 72) * NC + i + 72):
                        recs = piv.get(key)
                        if recs:
                            for rec in recs:
                                if _ok(w, rec):
                                    hits.append(rec[2])
                lst.append(i)
        for half, far in ((0, self.far[0]), (72, self.far[1])):
            for i in range(half, half + 72):
                for y in far[w[i]]:
                    recs = piv.get(i * NC + y)
                    if recs:
                        for rec in recs:
                            if _ok(w, rec):
                                hits.append(rec[2])
        return hits


def layouts(m):
    """[(layout name, plain index, cipher index)] without the doubles A-Z and KRYPTOS would give."""
    im = {c: i for i, c in enumerate(m)}
    if m == AZ:
        return [("M/M", im, im)]
    out = [("M/M", im, im), ("M/AZ", im, IZ), ("AZ/M", IZ, im)]
    if m != KR:
        out += [("M/KR", im, IK), ("KR/M", IK, im)]
    return out


def scan_alphabet(m, pl, cl, ea, ec, tests):
    """Every test on one tableau alphabet -> [(layout name or "tab", test index)]."""
    out = []
    for lay, ia, ib in layouts(m):
        for tid in ea.scan(EngineA.vector(ia, ib, pl, cl)):
            out.append((lay, tid))
    if m != AZ:
        for tid in ec.scan(m):
            if m == KR and tests[tid].aliases[0][2] == "KR":
                continue                                 # KRYPTOS against itself is family "alt"
            out.append(("tab", tid))
    return out


def slow_pass(st, ctx, pl, cl):
    """The same answer as the fast scan for one setting (for tests): True if the clue letters fit."""
    cribs = dict(zip(POS, pl))
    ct = dict(zip(POS, cl))
    return solve(st, ctx, ct, cribs) is not None
