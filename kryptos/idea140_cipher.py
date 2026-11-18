"""Helpers for idea 140: the key steps with each repeat of the CIPHER letter.

    C_i = Tab(P_i, W[n_i mod L])     n_i = how many times the cipher letter C_i occurred before

n_i comes from the ciphertext alone, so a reader can decrypt letter by letter. The count may run
from K4's first letter or from any point of the K1-K3 ciphertext before it ("start" s: the count
runs through K1K2K3[s:] and then K4; s = len(K1K2K3) means from K4's first letter).

Tab is a Vigenere-type tableau with plain alphabet a and cipher alphabet b (key value k):

    vig    C = b[ a^-1(P) + k ]       beau   C = b[ k - a^-1(P) ]       var   C = b[ a^-1(P) - k ]

Two facts used everywhere:
  * Any fixed key letter gives a one-to-one map plain -> cipher on ANY tableau (hidden ones too).
    So two clue positions with the same residue n mod L must have (same plain) == (same cipher).
    This "tableau-free" test needs no alphabet at all.
  * On a known tableau the 24 clue letters force 24 key values; clue positions with the same
    residue must carry the same key value. Checks = 24 - number of residues used.
"""
from .ciphers.substitution import AZ
from .data import letters, load

FORMS = ("vig", "beau", "var")


def k13():
    """K1, K2, K3 ciphertext as carved, letters only, in carving order."""
    return letters("".join(load(k)["ciphertext"] for k in ("k1", "k2", "k3")))


def counts(ct, prefix=""):
    """n_i for every position of ct: earlier occurrences of ct[i], counting through prefix first."""
    cnt = {}
    for c in prefix:
        cnt[c] = cnt.get(c, 0) + 1
    out = []
    for c in ct:
        n = cnt.get(c, 0)
        out.append(n)
        cnt[c] = n + 1
    return out


def residue_groups(n, pos, L):
    """{residue: [indices into pos]}"""
    g = {}
    for j, i in enumerate(pos):
        g.setdefault(n[i] % L, []).append(j)
    return g


def tableau_free_ok(groups, pl, cl):
    """Same residue -> same key letter -> one-to-one map: same plain iff same cipher."""
    for grp in groups.values():
        seenp, seenc = {}, {}
        for j in grp:
            if seenp.setdefault(pl[j], cl[j]) != cl[j] or seenc.setdefault(cl[j], pl[j]) != pl[j]:
                return False
    return True


def settings(ct, cribs, starts, lmax=26, min_checks=7):
    """Every (start, L) whose residues pass the tableau-free test with min_checks+ checks.

    Returns (n_settings_tested, n_tableau_free_dead, plans) where plans maps a partition of the
    clue indices (tuple of tuples, groups of 2+) to [(start, L, residue per clue index)]."""
    pos = sorted(cribs)
    pl, cl = [cribs[i] for i in pos], [ct[i] for i in pos]
    pre = k13()
    plans, tested, dead = {}, 0, 0
    for s in starts:
        n = counts(ct, pre[s:])
        for L in range(1, lmax + 1):
            tested += 1
            g = residue_groups(n, pos, L)
            if not tableau_free_ok(g, pl, cl):
                dead += 1
                continue
            if len(pos) - len(g) < min_checks:
                continue
            part = tuple(sorted(tuple(x) for x in g.values() if len(x) > 1))
            res = [0] * len(pos)
            for r, grp in g.items():
                for j in grp:
                    res[j] = r
            plans.setdefault(part, []).append((s, L, tuple(res)))
    return tested, dead, plans


def keyvals(pa, cb, form):
    if form == "vig":
        return [(y - x) % 26 for x, y in zip(pa, cb)]
    if form == "beau":
        return [(y + x) % 26 for x, y in zip(pa, cb)]
    return [(x - y) % 26 for x, y in zip(pa, cb)]


def index_of(alpha):
    return {c: i for i, c in enumerate(alpha)}


def layouts(m):
    """[(name, plain alphabet, cipher alphabet)] for a keyword alphabet m."""
    from .ciphers.substitution import KRYPTOS_ALPHABET as KR
    if m == KR:
        return [("KR/KR", KR, KR)]
    if m == AZ:
        return [("AZ/AZ", AZ, AZ), ("AZ/KR", AZ, KR), ("KR/AZ", KR, AZ)]
    return [("M/M", m, m), ("M/AZ", m, AZ), ("AZ/M", AZ, m), ("M/KR", m, KR), ("KR/M", KR, m)]


def labels(a, b):
    out, seen = [], set()
    for n, x in (("plain", a), ("cipher", b), ("A-Z", AZ)):
        if x not in seen:
            seen.add(x)
            out.append((n, x))
    return out


def decrypt(ct, a, b, form, wv, prefix=""):
    """wv: key values (None = unknown, gives '?')."""
    ia, ib, L = index_of(a), index_of(b), len(wv)
    out = []
    for c, n in zip(ct, counts(ct, prefix)):
        k = wv[n % L]
        if k is None:
            out.append("?")
            continue
        y = ib[c]
        out.append(a[(y - k) % 26 if form == "vig" else (k - y) % 26 if form == "beau" else (y + k) % 26])
    return "".join(out)


def encrypt(pt, a, b, form, wv, prefix="", rng=None, limit=200000):
    """Encipher by search. The writer must find a cipher letter c whose own next key letter turns P
    into c; there may be none or several (a choice of homophones). Depth-first with backtracking
    (choices in random order if rng). Returns the ciphertext, or None if no ciphertext exists
    (or the search hit `limit` steps)."""
    ia, ib, L = index_of(a), index_of(b), len(wv)
    cnt0 = [0] * 26
    for c in prefix:
        cnt0[ib[c]] += 1
    steps = [0]

    def options(p, cnt):
        out = []
        for y in range(26):
            k = wv[cnt[y] % L]
            x = (y - k) % 26 if form == "vig" else (k - y) % 26 if form == "beau" else (y + k) % 26
            if x == p:
                out.append(y)
        if rng is not None:
            rng.shuffle(out)
        return out

    path, cnt, stack = [], cnt0[:], [options(ia[pt[0]], cnt0)] if pt else []
    while stack:
        steps[0] += 1
        if steps[0] > limit:
            return None
        if not stack[-1]:
            stack.pop()
            if path:
                cnt[path.pop()] -= 1
            continue
        y = stack[-1].pop()
        path.append(y)
        cnt[y] += 1
        if len(path) == len(pt):
            return "".join(b[v] for v in path)
        stack.append(options(ia[pt[len(path)]], cnt))
    return None


def greedy_fail_rate(texts, a, b, form, wv, prefix=""):
    """How often a writer going letter by letter (taking the first homophone, no going back)
    gets stuck: (stuck, total)."""
    ia, ib, L = index_of(a), index_of(b), len(wv)
    stuck = 0
    for pt in texts:
        cnt = [0] * 26
        for c in prefix:
            cnt[ib[c]] += 1
        for ch in pt:
            p = ia[ch]
            for y in range(26):
                k = wv[cnt[y] % L]
                x = (y - k) % 26 if form == "vig" else (k - y) % 26 if form == "beau" else (y + k) % 26
                if x == p:
                    cnt[y] += 1
                    break
            else:
                stuck += 1
                break
    return stuck, len(texts)
