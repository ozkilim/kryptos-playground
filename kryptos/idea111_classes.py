"""Tools for idea 111: the key place of a letter depends on the KIND of letters before it.

Model A   two key words. A vowel takes V[vowels so far mod p], a consonant W[consonants so far mod q].
Model B   one repeating key of length L that holds (does not move on), or moves two, at or after
          the letters of a set S.
Model C   the same with the class read from the cipher letter, or with Vigenere for one class and
          Beaufort for the other.

Every test is "these clue key letters must be equal". A key stream (24 key values, the 13 of
EASTNORTHEAST then the 11 of BERLINCLOCK) is turned once into a bit mask of its equal pairs; a
test is a mask of pairs it needs, so a test costs one AND. Tests are indexed by one needed pair
(the pivot), so a stream only meets the tests whose pivot pair it has.

The phase of every word at BERLINCLOCK is free (the 29 letters between the clues are unknown).
checks = coincidences - log26(phases tried).
"""
import math

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round11 import B1, B2, POS

VOWELS = frozenset("AEIOU")
VOWELS_Y = frozenset("AEIOUY")
N1, N = len(B1), len(POS)
MIN_CHECKS = 7
LOW = 4                      # near misses (model A only), to compare K4 with the controls where chance gives something
LOG26 = math.log(26)
EPS = 1e-9

PID = [[0] * N for _ in range(N)]
BITS = []
for _a in range(N):
    for _b in range(_a + 1, N):
        PID[_a][_b] = PID[_b][_a] = len(BITS)
        BITS.append(1 << len(BITS))


def eq_mask(k):
    """(mask of equal pairs, list of their pair numbers) for 24 key values."""
    g = {}
    for i, v in enumerate(k):
        if v in g:
            g[v].append(i)
        else:
            g[v] = [i]
    if len(g) == N:
        return 0, ()
    eq, pids = 0, []
    for idx in g.values():
        n = len(idx)
        if n > 1:
            for x in range(n - 1):
                row = PID[idx[x]]
                for y in range(x + 1, n):
                    pids.append(row[idx[y]])
    for p in pids:
        eq |= BITS[p]
    return eq, pids


def need_of(pairs):
    """pairs: [(clue index, key slot)] in rising index order -> (mask of needed equal pairs, coincidences)."""
    first, need = {}, 0
    for i, s in pairs:
        if s in first:
            need |= BITS[PID[first[s]][i]]
        else:
            first[s] = i
    return need, len(pairs) - len(first)


class Index:
    """Tests by pivot pair. add(need, info); query(eq, pids) -> infos of every test the stream passes."""

    def __init__(self):
        self.by_need = {}

    def add(self, need, info):
        self.by_need.setdefault(need, []).append(info)

    def freeze(self):
        self.free = self.by_need.pop(0, [])
        self.piv = [[] for _ in BITS]
        for need, infos in self.by_need.items():
            self.piv[(need & -need).bit_length() - 1].append((need, infos))
        self.size = len(self.by_need)
        return self

    def query(self, eq, pids):
        out = []
        piv = self.piv
        for p in pids:
            for need, infos in piv[p]:
                if need & eq == need:
                    out += infos
        return out


# ---------------------------------------------------------------- Model A / C: two words by class

P_MAX, Q_MAX = 8, 16
CLASSINGS = ("plain", "cipher", "cipherY")


def class_vectors(pl, cl):
    """{classing: [0 for a vowel, 1 for a consonant] over the 24 clue letters}, identical vectors merged."""
    out = {"plain": [0 if c in VOWELS else 1 for c in pl],
           "cipher": [0 if c in VOWELS else 1 for c in cl],
           "cipherY": [0 if c in VOWELS_Y else 1 for c in cl]}
    if out["cipherY"] == out["cipher"]:
        del out["cipherY"]
    return out


def side_tests(members, lmax):
    """Every (period, phase of block 2) for one class: [(need, L, d, coincidences, phases tried)]."""
    i1 = [i for i in members if i < N1]
    i2 = [i for i in members if i >= N1]
    if not members:
        return [(0, 1, 0, 0, 1)]
    out = []
    for L in range(1, lmax + 1):
        nph = L if i1 and i2 else 1
        for d in range(nph):
            need, c = need_of([(i, j % L) for j, i in enumerate(i1)] + [(i, (d + j) % L) for j, i in enumerate(i2)])
            out.append((need, L, d, c, nph))
    return out


def passes_a(cv, cc, nv, nc, thr=MIN_CHECKS):
    return cv + cc - math.log(nv * nc) / LOG26 >= thr - EPS


def build_a(pl, cl):
    """(index over all side tests, {classing: (vowel tests, consonant tests)}, expected chance passes per
    key-stream pair at MIN_CHECKS and at LOW, number of (p, phase, q, phase) settings per key-stream pair)."""
    idx, tabs, chance, low, settings = Index(), {}, 0.0, 0.0, 0
    for name, vec in class_vectors(pl, cl).items():
        vt = side_tests([i for i in range(N) if vec[i] == 0], P_MAX)
        ct = side_tests([i for i in range(N) if vec[i] == 1], Q_MAX)
        tabs[name] = (vt, ct)
        for side, tests in ((0, vt), (1, ct)):
            for need, L, d, c, nph in tests:
                idx.add(need, (name, side, L, d, c, nph))
        settings += len(vt) * len(ct)
        for _, _, _, cv, nv in vt:
            for _, _, _, cc, nc in ct:
                if passes_a(cv, cc, nv, nc):
                    chance += 26.0 ** -(cv + cc)
                if passes_a(cv, cc, nv, nc, LOW):
                    low += 26.0 ** -(cv + cc)
    return idx.freeze(), tabs, (chance, low), settings


def combine_a(got_v, got_c, free):
    """got_v / got_c: infos passed by the vowel-side stream and the consonant-side stream.

    Returns [(checks, classing, p, dp, q, dq, cv, cc)] with at least LOW checks."""
    out = []
    by = {}
    for name, side, L, d, c, nph in got_v:
        if side == 0:
            by.setdefault(name, ([], []))[0].append((L, d, c, nph))
    for name, side, L, d, c, nph in got_c:
        if side == 1:
            by.setdefault(name, ([], []))[1].append((L, d, c, nph))
    for name, (vs, cs) in by.items():
        fv, fc = free.get(name, ([], []))
        vs, cs = vs + fv, cs + fc
        if not vs or not cs or max(v[2] for v in vs) + max(c[2] for c in cs) < LOW:
            continue
        for p, dp, cv, nv in vs:
            for q, dq, cc, nc in cs:
                if passes_a(cv, cc, nv, nc, LOW):
                    out.append((cv + cc - math.log(nv * nc) / LOG26, name, p, dp, q, dq, cv, cc))
    return out


def free_a(idx):
    """{classing: (free vowel tests, free consonant tests)}: the tests with no coincidence at all."""
    out = {}
    for name, side, L, d, c, nph in idx.free:
        out.setdefault(name, ([], []))[side].append((L, d, c, nph))
    return out


def minimal_a(hits):
    """Drop a hit whose periods are multiples of another hit's periods (same classing)."""
    keep = []
    for h in hits:
        _, name, p, _, q, _, _, _ = h
        if not any(o[1] == name and (o[2], o[4]) != (p, q) and p % o[2] == 0 and q % o[4] == 0 for o in hits):
            keep.append(h)
    return keep


# ---------------------------------------------------------------- Model B: one key that holds or skips

VARIANTS = ("hold-after", "skip-after", "hold-at", "skip-at")
L_MAX = 16
L_MAX_SUBSETS = 12


def offsets(mem, variant):
    """Key place of each clue letter, counted from the first letter of its block.

    mem[i]: clue letter i belongs to the set. hold = the key does not move, skip = it moves two;
    'after' = the move after a set letter is changed, 'at' = the move onto a set letter."""
    step = 0 if variant.startswith("hold") else 2
    out = []
    for lo, hi in ((0, N1), (N1, N)):
        o = 0
        out.append(0)
        for j in range(lo + 1, hi):
            o += step if mem[j - 1 if variant.endswith("after") else j] else 1
            out.append(o)
    return tuple(out)


def named_sets(pl, cl, ct=None, pos=POS):
    """[(label, spec, membership over the 24 clue letters)]. spec = (text, letters or 'doubled')."""
    out = []

    def add(label, text, letters_):
        src = pl if text == "pt" else cl
        out.append((label, (text, frozenset(letters_)), [c in letters_ for c in src]))

    for text, src in (("pt", pl), ("ct", cl)):
        add(text + " vowels", text, VOWELS)
        add(text + " vowels+Y", text, VOWELS_Y)
        add(text + " consonants", text, frozenset(AZ) - VOWELS)
        add(text + " consonants-Y", text, frozenset(AZ) - VOWELS_Y)
        add(text + " letters of KRYPTOS", text, frozenset("KRYPTOS"))
        for ch in sorted(set(src)):
            add(text + " letter " + ch, text, ch)
    if ct is not None:
        out.append(("ct letter equal to the one before", ("ct", "doubled"), [ct[i] == ct[i - 1] for i in pos]))
    return out


def patterns_b(sets):
    """{offsets: [(label, spec, variant)]}; the plain repeating key (nothing held) comes first."""
    pats = {offsets([False] * N, "hold-after"): [("no hold (plain repeating key, free phase)", None, "hold-after")]}
    for label, spec, mem in sets:
        for v in VARIANTS:
            pats.setdefault(offsets(mem, v), []).append((label + ", " + v, spec, v))
    return pats


def phase_need(off, L, d):
    return need_of([(i, off[i] % L) for i in range(N1)] + [(i, (d + off[i]) % L) for i in range(N1, N)])


def build_b(pl, cl, ct=None):
    """(index of (pattern, L, phase) tests, patterns list, expected chance passes per key stream, settings)."""
    pats = list(patterns_b(named_sets(pl, cl, ct)).items())
    idx = Index()
    for n, (off, _) in enumerate(pats):
        for L in range(2, L_MAX + 1):
            for d in range(L):
                need, c = phase_need(off, L, d)
                if c - math.log(L) / LOG26 >= MIN_CHECKS - EPS:
                    idx.add(need, (n, L, d, c))
    idx.freeze()
    assert not idx.free
    chance = sum(26.0 ** -infos[0][3] for lst in idx.piv for _, infos in lst)
    settings = sum(len(infos) for lst in idx.piv for _, infos in lst)
    return idx, pats, chance, settings


def minimal_b(hits):
    """hits: [(pattern number, L, d, coincidences)]; drop multiples of a shorter passing key."""
    return [h for h in hits if not any(o[0] == h[0] and o[1] < h[1] and h[1] % o[1] == 0 for o in hits)]


_SUB = {}


def build_subsets(pl):
    """Two-level tables for every subset of the distinct clue plaintext letters (hold or skip, at or after).

    Level 1: (pattern, L) with the pairs needed inside each block. Level 2 (phases) is done directly."""
    key = tuple(pl)
    if key in _SUB:
        return _SUB[key]
    lets = sorted(set(pl))
    pats = {}
    for mask in range(1, 1 << len(lets)):
        s = frozenset(ch for b, ch in enumerate(lets) if mask >> b & 1)
        mem = [c in s for c in pl]
        for v in VARIANTS:
            pats.setdefault(offsets(mem, v), []).append((s, v))
    pats = list(pats.items())
    idx = Index()
    for n, (off, _) in enumerate(pats):
        for L in range(2, L_MAX_SUBSETS + 1):
            need, c = need_of([(i, off[i] % L) for i in range(N1)] + [(i, 100 + off[i] % L) for i in range(N1, N)])
            idx.add(need, (n, L))
    idx.freeze()
    assert not idx.free
    chance = 0.0
    for off, _ in pats:
        for L in range(2, L_MAX_SUBSETS + 1):
            r1, r2 = [o % L for o in off[:N1]], off[N1:]
            s1 = set(r1)
            for d in range(L):
                chance += 26.0 ** -(N - len(s1 | {(d + o) % L for o in r2}))
    _SUB[key] = (idx, pats, chance, len(pats) * sum(range(2, L_MAX_SUBSETS + 1)), len(lets))
    return _SUB[key]


def subset_hits(k, pl):
    """[(pattern number, L, d, coincidences)] for every subset pattern the key stream fits."""
    idx, pats = build_subsets(pl)[:2]
    eq, pids = eq_mask(k)
    out = []
    for n, L in idx.query(eq, pids):
        off = pats[n][0]
        for d in range(L):
            seen = {}
            for i in range(N):
                r = (off[i] if i < N1 else d + off[i]) % L
                if seen.setdefault(r, k[i]) != k[i]:
                    break
            else:
                c = N - len(seen)
                if c - math.log(L) / LOG26 >= MIN_CHECKS - EPS:
                    out.append((n, L, d, c))
    return out


# ---------------------------------------------------------------- tableaux, encryptors, readers

def layout(lay, m):
    a, b = lay.split("/")
    pick = {"M": m, "AZ": AZ, "KR": KRYPTOS_ALPHABET}
    return pick[a], pick[b]


def enc(ch, k, form, ia, b):
    return b[(ia[ch] + k) % 26] if form == "vig" else b[(k - ia[ch]) % 26]


def dec(ch, k, form, a, ib):
    return a[(ib[ch] - k) % 26] if form == "vig" else a[(k - ib[ch]) % 26]


def mixed_stream(kv, kb, vec, vowel_form):
    """Key values when vowels are done in one form and consonants in the other."""
    if vowel_form == "vig":
        return [kv[i] if vec[i] == 0 else kb[i] for i in range(N)]
    return [kb[i] if vec[i] == 0 else kv[i] for i in range(N)]


def encrypt_a(pt, m, lay, fv, fc, vword, wword, v0=0, w0=0, vowels=VOWELS):
    """Model A with the class read from the plain letter."""
    a, b = layout(lay, m)
    ia = {c: i for i, c in enumerate(a)}
    out, v, w = [], v0, w0
    for ch in pt:
        if ch in vowels:
            out.append(enc(ch, vword[v % len(vword)], fv, ia, b))
            v += 1
        else:
            out.append(enc(ch, wword[w % len(wword)], fc, ia, b))
            w += 1
    return "".join(out)


def encrypt_b(pt, m, lay, form, key, variant, letters_, start=0, mix=None):
    """Model B with the set read from the plain letter. mix = (vowel form, consonant form) or None."""
    a, b = layout(lay, m)
    ia = {c: i for i, c in enumerate(a)}
    step = 0 if variant.startswith("hold") else 2
    after = variant.endswith("after")
    out, idx = [], start
    for i, ch in enumerate(pt):
        if i:
            idx += step if (pt[i - 1] if after else ch) in letters_ else 1
        f = form if mix is None else mix[0] if ch in VOWELS else mix[1]
        out.append(enc(ch, key[idx % len(key)], f, ia, b))
    return "".join(out)


def words_a(kvow, kcon, vec, p, dp, q, dq):
    """The two words (lists of key values, None where the clues do not reach) from the clue key values."""
    vw, ww = [None] * p, [None] * q
    for lo, hi, d_v, d_c in ((0, N1, 0, 0), (N1, N, dp, dq)):
        jv = jc = 0
        for i in range(lo, hi):
            if vec[i] == 0:
                vw[(d_v + jv) % p] = kvow[i]
                jv += 1
            else:
                ww[(d_c + jc) % q] = kcon[i]
                jc += 1
    return vw, ww


def _beam(n, starts, expand, lm, beam, cap):
    """Level by level search over readings. State (score, a, b, text); expand(i, a, b, text) yields
    (a2, b2, letter). With a quadgram model lm the best `beam` states per letter are kept; equal
    states (same counters, same last three letters) are merged, keeping the better one.
    Returns (readings best first, number of consistent readings in all)."""
    get, fl = (lm.logp.get, lm.floor) if lm is not None else (None, 0.0)
    states = [(0.0, a, b, "", 1) for a, b in starts]
    for i in range(n):
        nxt = {}
        for sc, a, b, txt, cnt in states:
            for a2, b2, ch in expand(i, a, b, txt):
                t2 = txt + ch
                s2 = sc
                if lm is not None and i >= 3 and "?" not in t2[-4:]:
                    s2 += get(t2[-4:], fl)
                key = (a2, b2, t2[-3:])
                old = nxt.get(key)
                if old is None:
                    nxt[key] = (s2, a2, b2, t2, cnt)
                elif s2 > old[0]:
                    nxt[key] = (s2, a2, b2, t2, cnt + old[4])
                else:
                    nxt[key] = old[:4] + (cnt + old[4],)
        states = sorted(nxt.values(), reverse=True)[:beam]
        if not states:
            return [], 0
    return [s[3] for s in states[:cap]], sum(s[4] for s in states)


def decrypt_a(ct, m, lay, fv, fc, vw, ww, classing="plain", vowels=VOWELS, cribs=None, lm=None, beam=400, cap=5,
              count=False):
    """Read a Model A message left to right, for every start phase of the two words.

    The class of each decrypted letter moves the right counter; where both classes are possible
    both are followed, so one message can have many readings: the best by the quadgram model lm
    are returned ('?' where a key letter is unknown). The words are numbered so that
    EASTNORTHEAST (position 21) starts at place 0 of both. count=True also returns the number of
    consistent readings (exact while the beam is not full)."""
    a, b = layout(lay, m)
    ib = {c: i for i, c in enumerate(b)}
    p, q = len(vw), len(ww)
    cvow = VOWELS if classing == "cipher" else VOWELS_Y

    def expand(i, v, w, txt):
        if i == B1[0] and (v or w):
            return
        c = ct[i]
        for cls in (0, 1):
            if classing != "plain" and (c in cvow) != (cls == 0):
                continue
            k = vw[v] if cls == 0 else ww[w]
            if k is None:
                ch = "?"
            else:
                ch = dec(c, k, fv if cls == 0 else fc, a, ib)
                if classing == "plain" and (ch in vowels) != (cls == 0):
                    continue
            if cribs and i in cribs and ch != "?" and ch != cribs[i]:
                continue
            yield ((v + 1) % p, w, ch) if cls == 0 else (v, (w + 1) % q, ch)

    out, total = _beam(len(ct), [(v, w) for v in range(p) for w in range(q)], expand, lm, beam, cap)
    return (out, total) if count else out


def key_b(k, off, L, d):
    key = [None] * L
    for i in range(N):
        key[(off[i] if i < N1 else d + off[i]) % L] = k[i]
    return key


def decrypt_b(ct, m, lay, form, key, spec, variant, mix=None, cribs=None, lm=None, beam=400, cap=5):
    """Read a Model B message left to right for every start place of the key.

    spec = None (nothing held), ('pt' or 'ct', set of letters) or ('ct', 'doubled'). The key is
    numbered so that position 21 uses place 0."""
    a, b = layout(lay, m)
    ib = {c: i for i, c in enumerate(b)}
    L = len(key)
    step = 0 if variant.startswith("hold") else 2
    after = variant.endswith("after")
    forms = (form,) if mix is None else mix

    def member(i, ch):
        if spec is None:
            return False
        text, s = spec
        if s == "doubled":
            return i > 0 and ct[i] == ct[i - 1]
        return (ch if text == "pt" else ct[i]) in s

    def expand(i, prev, _, txt):               # prev = key place used by letter i-1 (or the start place)
        if i == 0:
            moves = (0,)
        elif after:
            moves = (step,) if txt[-1] != "?" and member(i - 1, txt[-1]) else (1,)
        elif spec is not None and spec[0] == "ct":
            moves = (step,) if member(i, None) else (1,)
        else:
            moves = (1, step) if spec is not None else (1,)
        for mv in moves:
            idx = (prev + mv) % L
            if i == B1[0] and idx:
                continue
            k = key[idx]
            for fi, f in enumerate(forms):
                if k is None:
                    ch = "?"
                    if fi:
                        continue
                else:
                    ch = dec(ct[i], k, f, a, ib)
                    if mix is not None and (ch in VOWELS) != (fi == 0):
                        continue
                    if i and not after and spec is not None and spec[0] == "pt" and member(i, ch) != (mv == step):
                        continue
                if cribs and i in cribs and ch != "?" and ch != cribs[i]:
                    continue
                yield idx, 0, ch

    return _beam(len(ct), [(s0, 0) for s0 in range(L)], expand, lm, beam, cap)[0]
