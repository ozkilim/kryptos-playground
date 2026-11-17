"""Helpers for idea 109: every plain letter keeps its own place in the key word.

    C = Tab(P, W[n mod L])        n = how many times this plain letter has occurred before

Tab is a Vigenere-type tableau with plain alphabet a and cipher alphabet b (key value k):

    vig    C = b[ a^-1(P) + k ]       beau   C = b[ k - a^-1(P) ]       var   C = b[ a^-1(P) - k ]

The key value k is the place of the key letter in a "label" alphabet (a, b or A-Z).
Everything here is exact; nothing guesses a key.
"""
import itertools

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round11 import B1, B2

KR = KRYPTOS_ALPHABET
FORMS = ("vig", "beau", "var")
IDX = {}


def index_of(alpha):
    d = IDX.get(alpha)
    if d is None:
        if len(IDX) > 50000:
            IDX.clear()
        d = IDX[alpha] = {c: i for i, c in enumerate(alpha)}
    return d


def layouts(m):
    """[(name, plain alphabet, cipher alphabet)] for a keyword alphabet m, without repeats."""
    if m == KR:
        return [("KR/KR", KR, KR)]
    if m == AZ:
        return [("AZ/AZ", AZ, AZ), ("AZ/KR", AZ, KR), ("KR/AZ", KR, AZ)]
    return [("M/M", m, m), ("M/AZ", m, AZ), ("AZ/M", AZ, m), ("M/KR", m, KR), ("KR/M", KR, m)]


def layout(m, lay):
    return next((a, b) for n, a, b in layouts(m) if n == lay)


def labels(a, b):
    """[(name, alphabet)]: the alphabets a key letter may be read in (its place there is the key value)."""
    out, seen = [], set()
    for n, x in (("plain", a), ("cipher", b), ("A-Z", AZ)):
        if x not in seen:
            seen.add(x)
            out.append((n, x))
    return out


def label_alphabet(a, b, lab):
    return dict(labels(a, b))[lab]


def keyvals(pa, cb, form):
    if form == "vig":
        return [(y - x) % 26 for x, y in zip(pa, cb)]
    if form == "beau":
        return [(y + x) % 26 for x, y in zip(pa, cb)]
    return [(x - y) % 26 for x, y in zip(pa, cb)]


def clue_keyvals(ct, cribs, a, b, form):
    ia, ib = index_of(a), index_of(b)
    pos = sorted(cribs)
    return keyvals([ia[cribs[i]] for i in pos], [ib[ct[i]] for i in pos], form)


def encrypt(pt, a, b, form, wv, starts=()):
    """wv: the key word as key values. starts: positions where every counter goes back to 0."""
    ia, L, cnt, out = index_of(a), len(wv), {}, []
    for i, ch in enumerate(pt):
        if i in starts:
            cnt = {}
        n = cnt.get(ch, 0)
        cnt[ch] = n + 1
        k, p = wv[n % L], ia[ch]
        out.append(b[(p + k) % 26 if form == "vig" else (k - p) % 26 if form == "beau" else (p - k) % 26])
    return "".join(out)


def readings(ct, a, b, form, wv, cribs, logp, floor, starts=(), beam=2000):
    """Every plaintext the key gives that holds the clue letters: [(english per quadgram, text)], best first.

    A cipher letter can come from any plain letter whose own next key letter leads to it, so the
    text is found by a tree search (kept to the `beam` best branches on the quadgram model)."""
    ia, ib, L = index_of(a), index_of(b), len(wv)
    sign = {"vig": (1, 1), "beau": (-1, 1), "var": (1, -1)}[form]
    states = [(0.0, "", (0,) * 26)]
    for i, ch in enumerate(ct):
        c = ib[ch]
        if i in starts:
            states = [(s, t, (0,) * 26) for s, t, _ in states]
        want = (ia[cribs[i]],) if i in cribs else range(26)
        new = []
        for sc, txt, cnt in states:
            for p in want:
                if (sign[0] * p + sign[1] * wv[cnt[p] % L]) % 26 == c:
                    t = txt + a[p]
                    cn = list(cnt)
                    cn[p] += 1
                    new.append((sc + (logp.get(t[-4:], floor) if len(t) >= 4 else 0.0), t, tuple(cn)))
        if not new:
            return []
        if len(new) > beam:
            new.sort(reverse=True)
            new = new[:beam]
        states = new
    return sorted(((s / (len(ct) - 3), t) for s, t, _ in states), reverse=True)


# ---- what the clue letters force ----------------------------------------------------------------

def chains(cribs, blocks=(B1, B2)):
    """For each plain letter seen twice or more in the clues: [(index into the sorted clue
    positions, block number)], in text order."""
    blk = {i: n for n, b in enumerate(blocks) for i in b}
    out = {}
    for j, i in enumerate(sorted(cribs)):
        out.setdefault(cribs[i], []).append((j, blk[i]))
    return [v for _, v in sorted(out.items()) if len(v) > 1]


def near_pairs(chs):
    """Next occurrences inside one clue block: the two key letters are neighbours in the key word."""
    return [(x[0], y[0]) for ch in chs for x, y in zip(ch, ch[1:]) if x[1] == y[1]]


def near_runs(chs):
    """Maximal runs of occurrences with known consecutive counts: [[index, index, ...]]."""
    out = []
    for ch in chs:
        run = [ch[0][0]]
        for x, y in zip(ch, ch[1:]):
            if x[1] == y[1]:
                run.append(y[0])
            else:
                out.append(run)
                run = [y[0]]
        out.append(run)
    return [r for r in out if len(r) > 1]


def chain_fits(wv, k, chs, far=True, dmax=8):
    """Can every letter's chain be laid on the key word (cyclically)? Inside a block the next
    occurrence takes the next key letter; across the gap between the blocks the key moved on by
    1..dmax places (far=True) or by anything (far=False). None in wv matches nothing."""
    L = len(wv)
    for ch in chs:
        cur = set(j for j in range(L) if wv[j] == k[ch[0][0]])
        for x, y in zip(ch, ch[1:]):
            if not cur:
                break
            want = k[y[0]]
            if x[1] == y[1]:
                cur = set((c + 1) % L for c in cur if wv[(c + 1) % L] == want)
            elif far:
                cur = set((c + s) % L for c in cur for s in range(1, dmax + 1) if wv[(c + s) % L] == want)
            else:
                cur = set(j for j in range(L) if wv[j] == want)
        if not cur:
            return False
    return True


def short_keys(k, chs, lmax=5):
    """Every key of ANY letters and length <= lmax that holds the neighbour pairs: [key values],
    None where the clues leave a letter free. One per rotation class."""
    near = near_pairs(chs)
    pairs = sorted(set((k[i], k[j]) for i, j in near))
    out, seen = [], set()
    for L in range(1, lmax + 1):
        if len(pairs) > L:
            continue
        for slots in itertools.permutations(range(L), len(pairs)):
            w, ok = [None] * L, True
            for (x, y), s in zip(pairs, slots):
                for q, v in ((s, x), ((s + 1) % L, y)):
                    if w[q] is None:
                        w[q] = v
                    elif w[q] != v:
                        ok = False
            if not ok or not chain_fits(w, k, chs, far=False):
                continue
            canon = min(tuple(w[r:] + w[:r]) for r in range(L))
            key = tuple(-1 if v is None else v for v in canon)
            if key not in seen:
                seen.add(key)
                out.append(list(canon))
    return out


# ---- the word index -----------------------------------------------------------------------------

def word_values(word, lab):
    il = index_of(lab)
    return [il[c] for c in word]


def cyclic_grams(word, r):
    L = len(word)
    return set(tuple(word[(i + t) % L] for t in range(r)) for i in range(L))


def build_index(words):
    """676 bit sets: bit w of entry x*26+y is set when word w holds letters x,y as cyclic neighbours."""
    nb = (len(words) + 7) // 8
    arrs = {}
    for wid, w in enumerate(words):
        v = [ord(c) - 65 for c in w]
        L = len(v)
        for code in set(v[i] * 26 + v[(i + 1) % L] for i in range(L)):
            arr = arrs.get(code)
            if arr is None:
                arr = arrs[code] = bytearray(nb)
            arr[wid >> 3] |= 1 << (wid & 7)
    bits = [int.from_bytes(arrs[c], "little") if c in arrs else 0 for c in range(676)]
    cnts = [bin(x).count("1") for x in bits]
    return bits, cnts


def bit_ids(x):
    out = []
    while x:
        low = x & -x
        out.append(low.bit_length() - 1)
        x ^= low
    return out


def chance_per_reading(words, chs):
    """Expected number of words that hold the within-block chains of one key-stream reading, if
    the key values were independent and uniform."""
    runs = [len(r) for r in near_runs(chs)]
    tot = 0.0
    for w in words:
        p = 1.0
        for r in runs:
            p *= len(cyclic_grams(w, r)) / 26.0 ** r
        tot += p
    return tot


# ---- counters that restart at each row ----------------------------------------------------------

def restart_groups(starts, cribs, blocks=(B1, B2)):
    """{n: [indices into the sorted clue positions]}: clue letters whose count since the last
    restart is known to be n (the restart falls inside the same clue block). All letters of one
    group use the same key letter W[n]."""
    bstart = {i: b[0] for b in blocks for i in b}
    groups = {}
    for j, i in enumerate(sorted(cribs)):
        s = max([x for x in starts if x <= i] or [0])
        if s >= bstart[i]:
            n = sum(1 for t in range(s, i) if cribs[t] == cribs[i])
            groups.setdefault(n, []).append(j)
    return groups


def restart_fit(wv, k, cribs, starts, blocks=(B1, B2)):
    """Do the clue letters alone allow key word wv with counters restarting at `starts`? Letters whose
    row began before the clue block have an unknown count: any one starting place will do."""
    blk = {i: n for n, b in enumerate(blocks) for i in b}
    bstart = {i: b[0] for b in blocks for i in b}
    L, runs = len(wv), {}
    for j, i in enumerate(sorted(cribs)):
        s = max([x for x in starts if x <= i] or [0])
        runs.setdefault((s, blk[i], cribs[i]), (s >= bstart[i], []))[1].append(j)
    for known, js in runs.values():
        if known:
            if any(wv[t % L] != k[j] for t, j in enumerate(js)):
                return False
        elif not any(all(wv[(c + t) % L] == k[j] for t, j in enumerate(js)) for c in range(L)):
            return False
    return True


def restart_plans(cribs, n=97, wmax=48, min_checks=6):
    """Rows of every width 2..wmax with every first-row length (the carved rows are width 31,
    first row 4). Returns {equalities: (checks, groups, [(width, first row)])}, one entry per
    distinct test."""
    out = {}
    for w in range(2, wmax + 1):
        for o in range(w):
            starts = [0] + list(range(o, n, w)) if o else list(range(0, n, w))
            g = restart_groups(starts, cribs)
            eqs = tuple(sorted((x[0], y) for x in g.values() for y in x[1:]))
            if len(eqs) >= min_checks:
                out.setdefault(eqs, (len(eqs), g, []))[2].append((w, o))
    return out


def row_starts(w, o, n=97):
    return set([0] + list(range(o, n, w)) if o else range(0, n, w))


# ---- hidden tableaux picked by the counter ------------------------------------------------------

def hidden_tableaux_possible(m, ct, cribs):
    """Can m unknown tableaux (each any one-to-one alphabet), picked by the letter's own counter
    mod m, hold the clue letters? Exact search over the unknown counter phases."""
    pos = sorted(cribs)
    chs = chains(cribs)
    runs = near_runs(chs)
    inrun = set(j for r in runs for j in r)
    runs = runs + [[j] for j in range(len(pos)) if j not in inrun]
    fwd = [dict() for _ in range(m)]
    back = [dict() for _ in range(m)]

    def place(ri):
        if ri == len(runs):
            return True
        for r in range(m):
            done, ok = [], True
            for t, j in enumerate(runs[ri]):
                tb, p, c = (r + t) % m, cribs[pos[j]], ct[pos[j]]
                if fwd[tb].get(p, c) != c or back[tb].get(c, p) != p:
                    ok = False
                    break
                if p not in fwd[tb]:
                    fwd[tb][p] = c
                    back[tb][c] = p
                    done.append((tb, p, c))
            if ok and place(ri + 1):
                return True
            for tb, p, c in done:
                del fwd[tb][p]
                del back[tb][c]
        return False

    return place(0)
