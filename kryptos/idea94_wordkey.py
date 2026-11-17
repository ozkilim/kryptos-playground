"""Idea 94: word autokey. Each plaintext word is enciphered with the word before it as the key.

Model. The message is a row of words. After a primer word, the key for letter j of a word is

    wrap     letter (j mod m) of the key word (m = its length)
    run-on   letter j of the key word while it lasts, then the word's own letters from its start
             (an ordinary autokey restarted at every word)

The key word is the previous word (back = 1) or the word two back (back = 2), read forwards or
reversed, taken as plaintext (plain feed) or as its cipher letters (cipher feed). Then

    key number = const + sign * number(fed letter)                         (mod 26)
    Vigenere form: cipher = plain + key        Beaufort form: cipher = key - plain

with plain and cipher letters numbered on a keyword alphabet M, A-Z or KRYPTOS (five layouts) and the
fed letter numbered on the plain-side or the cipher-side alphabet. Variant Beaufort is the Vigenere
form with the other sign and constant.

Inside the clues the key word is known, so every (keyed letter, fed letter) pair gives the value
key - sign * number(fed), which must be the same constant for all pairs: checks = pairs - 1.

A PART is the set of pairs one clue block gives for one way of splitting it into words
(EAST|NORTH|EAST, EAST|NORTHEAST, EASTNORTH|EAST, EASTNORTHEAST; BERLIN|CLOCK, BERLINCLOCK), one
mode (feed, order, wrap/run-on, back) and one length L of the unknown word in front of the block
(L matters for cipher feed, where that word's cipher letters are known, and for run-on, where a
short word in front lets the key run into the clue word itself). A TEST is one part from each block
in the same mode, or one part alone, with 8 or more pairs (7 or more checks).
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .round11 import B1, B2, pmap
from .round9 import solve_mod_p
from .idea93_hidden import solve_injective

N = 97
CLUE = B1 + B2
CLUESET = frozenset(CLUE)
PARSE1 = (("E|N|E", ((21, 4), (25, 5), (30, 4))), ("E|NE", ((21, 4), (25, 9))),
          ("EN|E", ((21, 9), (30, 4))), ("ENE", ((21, 13),)))
PARSE2 = (("B|C", ((63, 6), (69, 5))), ("BC", ((63, 11),)))
PARSES = (dict(PARSE1), dict(PARSE2))
MODES = [(feed, order, over, back) for feed in ("plain", "cipher") for order in ("fwd", "rev")
         for over in ("wrap", "run") for back in (1, 2)]
LENS = tuple(range(1, 13))          # lengths tried for the unknown word in front of a clue block
MIN_CHECKS = 7
MIN_PART = 4                        # a part needs this many pairs to be used at all
IZ = {c: i for i, c in enumerate(AZ)}
IK = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
_S = {}


def sources(s, n, q, m, order, over):
    """Text positions of the key letters for the word at s (length n), key word at q (length m)."""
    src = list(range(q, q + m))
    if order == "rev":
        src.reverse()
    if over == "wrap":
        return [src[j % m] for j in range(n)]
    return [src[j] if j < m else s + j - m for j in range(n)]


def part_pairs(words, mode, L):
    """[(keyed position, fed position)] for one clue block split into `words`, word of length L in front."""
    feed, order, over, back = mode
    start = words[0][0]
    seq = [None, (start - L, L) if L and start - L >= 0 else None] + list(words)
    out = []
    for t in range(2, len(seq)):
        prev = seq[t - back]
        if prev is None:
            continue
        s, n = seq[t]
        for j, a in enumerate(sources(s, n, prev[0], prev[1], order, over)):
            if feed == "cipher" or a in CLUESET:
                out.append((s + j, a))
    return tuple(out)


def build():
    """PARTS: [dict(mode, block, pairs, labels)], TESTS: [(mode, part index or None, part index or None)]."""
    parts, tests, seen = [], [], set()
    for mode in MODES:
        mine = ([], [])
        for b, parse in enumerate((PARSE1, PARSE2)):
            index = {}
            for pname, words in parse:
                for L in (None,) + LENS:
                    pairs = part_pairs(words, mode, L)
                    if len(pairs) < MIN_PART:
                        continue
                    if pairs not in index:
                        index[pairs] = len(parts)
                        mine[b].append(len(parts))
                        parts.append({"mode": mode, "block": b, "pairs": pairs, "labels": []})
                    parts[index[pairs]]["labels"].append((pname, L))
        feed, back = mode[0], mode[3]
        for n1 in mine[0] + [None]:
            for n2 in mine[1] + [None]:
                p1 = parts[n1]["pairs"] if n1 is not None else ()
                p2 = parts[n2]["pairs"] if n2 is not None else ()
                key = (feed, p1, p2)
                if len(p1) + len(p2) - 1 >= MIN_CHECKS and key not in seen:
                    seen.add(key)
                    tests.append((mode, n1, n2))
    return parts, tests


PARTS, TESTS = build()
# quick test: the first two pairs of each part must agree. Fed positions: plain a, cipher N + a.
_OFF = [N if p["mode"][0] == "cipher" else 0 for p in PARTS]
QI = [(p["pairs"][0][0], p["pairs"][1][0]) for p in PARTS]
QA = [(p["pairs"][0][1] + o, p["pairs"][1][1] + o) for p, o in zip(PARTS, _OFF)]
FULL = [[(i, a + o) for i, a in p["pairs"]] for p, o in zip(PARTS, _OFF)]
_TESTSET = {(n1, n2) for _, n1, n2 in TESTS}

# the core plain-feed tests with all 14 pairs, for the "how many letters agree" count
CORE = [(mode, n1, n2) for mode, n1, n2 in TESTS
        if mode[0] == "plain" and mode[3] == 1 and n1 is not None and n2 is not None
        and len(PARTS[n1]["pairs"]) + len(PARTS[n2]["pairs"]) == 14
        and any(L is None for _, L in PARTS[n1]["labels"]) and any(L is None for _, L in PARTS[n2]["labels"])]
UNIV = sorted({pr for _, n1, n2 in CORE for pr in PARTS[n1]["pairs"] + PARTS[n2]["pairs"]})
_UI = {pr: u for u, pr in enumerate(UNIV)}
CORE_IDX = [[_UI[pr] for pr in PARTS[n1]["pairs"] + PARTS[n2]["pairs"]] for _, n1, n2 in CORE]
COUNT_FLOOR = 6
# cipher feed, previous word: parts by (order, wrap/run-on) and block, for the count out of 24
CIPHER_GROUPS = {}
for _n, _p in enumerate(PARTS):
    if _p["mode"][0] == "cipher" and _p["mode"][3] == 1 and len(_p["pairs"]) in (13, 11):
        CIPHER_GROUPS.setdefault(_p["mode"], ([], []))[_p["block"]].append(_n)


def label(n):
    """Readable name of a part: its splits and the lengths of the word in front that give it."""
    if n is None:
        return "-"
    by = {}
    for pname, L in PARTS[n]["labels"]:
        by.setdefault(pname, []).append(L)
    return "; ".join("%s (word in front: %s)" % (k, "any length" if None in v else ",".join(map(str, v)))
                     for k, v in by.items())


def layouts(m):
    """[(name, plain index, cipher index, [(fed numbering name, index)])]."""
    im = {c: i for i, c in enumerate(m)}
    if m == AZ:
        return [("AZ/AZ", IZ, IZ, [("AZ", IZ)]), ("AZ/KR", IZ, IK, [("AZ", IZ), ("KR", IK)]),
                ("KR/AZ", IK, IZ, [("KR", IK), ("AZ", IZ)]), ("KR/KR", IK, IK, [("KR", IK)])]
    return [("M/M", im, im, [("M", im)]), ("M/AZ", im, IZ, [("M", im), ("AZ", IZ)]),
            ("AZ/M", IZ, im, [("AZ", IZ), ("M", im)]), ("M/KR", im, IK, [("M", im), ("KR", IK)]),
            ("KR/M", IK, im, [("KR", IK), ("M", im)])]


def views_per_alphabet(m):
    """(layout, form, fed numbering, sign) combinations."""
    return (6 if m == AZ else 9) * 2 * 2


def settings_per_alphabet(m):
    return views_per_alphabet(m) * len(TESTS)


def _feed(ix, fed):
    """Numbers of every possible fed letter, and the quick-test sets for sign + and -."""
    x = [ix[c] for c in fed]
    plus = {n * 26 + (x[a0] - x[a1]) % 26 for n, (a0, a1) in enumerate(QA)}
    minus = {n * 26 + (x[a1] - x[a0]) % 26 for n, (a0, a1) in enumerate(QA)}
    return x, plus, minus


def state(ct, cribs):
    """Everything about one ciphertext that does not depend on the alphabet."""
    pt = "".join(cribs.get(i, "A") for i in range(N))
    fed = pt + ct
    return {"ct": ct, "cribs": cribs, "pt": pt, "fed": fed,
            "AZ": _feed(IZ, fed), "KR": _feed(IK, fed)}


def _const(n, k, x, sg):
    """The constant of part n if all its pairs agree, else None."""
    pairs = FULL[n]
    i, a = pairs[0]
    c = (k[i] - sg * x[a]) % 26
    for i, a in pairs:
        if (k[i] - sg * x[a] - c) % 26:
            return None
    return c


def test_alphabet(name, m, S, hist=None, tops=None):
    """Passing settings for one alphabet: [(checks, name, layout, form, fed numbering, sign, const, n1, n2)].

    hist/tops (optional): filled with the count of agreeing pairs (out of 14) of the core plain-feed tests,
    hist[count] += 1 for count >= COUNT_FLOOR, tops gets (count, name, layout, form, fed, sign, core index)."""
    ct, pt = S["ct"], S["pt"]
    hits = []
    cache = {"AZ": S["AZ"], "KR": S["KR"]}
    for lay, ia, ib, feeds in layouts(m):
        a = [ia[c] for c in pt]
        b = [ib[c] for c in ct]
        for form in ("vig", "beau"):
            if form == "vig":
                k = [(y - u) % 26 for u, y in zip(a, b)]
            else:
                k = [(y + u) % 26 for u, y in zip(a, b)]
            codes = [n * 26 + (k[i0] - k[i1]) % 26 for n, (i0, i1) in enumerate(QI)]
            for fn, ix in feeds:
                if fn not in cache:
                    cache[fn] = _feed(ix, S["fed"])
                x, plus, minus = cache[fn]
                for sg, q in ((1, plus), (-1, minus)):
                    good = q.intersection(codes)
                    if good:
                        cons = []
                        for code in good:
                            n = code // 26
                            c = _const(n, k, x, sg)
                            if c is not None:
                                cons.append((n, c))
                        for n, c in cons:
                            p = PARTS[n]
                            key = (n, None) if p["block"] == 0 else (None, n)
                            if key in _TESTSET:
                                hits.append((len(p["pairs"]) - 1, name, lay, form, fn, sg, c) + key)
                            if p["block"] == 0:
                                for n2, c2 in cons:
                                    q2 = PARTS[n2]
                                    if q2["block"] == 1 and c2 == c and q2["mode"] == p["mode"] and (n, n2) in _TESTSET:
                                        hits.append((len(p["pairs"]) + len(q2["pairs"]) - 1, name, lay, form, fn, sg, c, n, n2))
                    if hist is not None:
                        v = [(k[i] - sg * x[f]) % 26 for i, f in UNIV]
                        for t, idx in enumerate(CORE_IDX):
                            vs = [v[u] for u in idx]
                            st = set(vs)
                            if len(st) <= 15 - COUNT_FLOOR:
                                cnt = max(map(vs.count, st))
                                if cnt >= COUNT_FLOOR:
                                    hist[cnt] = hist.get(cnt, 0) + 1
                                    if cnt >= 9:
                                        tops.append((cnt, name, lay, form, fn, sg, t))
    return hits


def cipher_count(name, m, S):
    """Best number of agreeing pairs out of 24 over the cipher-feed, previous-word tests of one alphabet."""
    ct, pt = S["ct"], S["pt"]
    best = (0, None)
    for lay, ia, ib, feeds in layouts(m):
        a = [ia[c] for c in pt]
        b = [ib[c] for c in ct]
        for form in ("vig", "beau"):
            k = [(y - u) % 26 if form == "vig" else (y + u) % 26 for u, y in zip(a, b)]
            for fn, ix in feeds:
                x = [ix[c] for c in S["fed"]]
                for sg in (1, -1):
                    for mode, (g1, g2) in CIPHER_GROUPS.items():
                        tot = []
                        for g in (g1, g2):
                            top = [0] * 26
                            for n in g:
                                vs = [(k[i] - sg * x[f]) % 26 for i, f in FULL[n]]
                                for u in set(vs):
                                    c = vs.count(u)
                                    if c > top[u]:
                                        top[u] = c
                            tot.append(top)
                        cnt = max(p + q for p, q in zip(*tot))
                        if cnt > best[0]:
                            best = (cnt, (name, lay, form, fn, sg, mode))
    return best


def init(ct, cribs):
    _S["s"] = state(ct, cribs)


def work(chunk):
    hits, hist, tops = [], {}, []
    for name, m in chunk:
        hits += test_alphabet(name, m, _S["s"], hist, tops)
    return hits, hist, tops


def work_cipher_count(chunk):
    return max(cipher_count(name, m, _S["s"]) for name, m in chunk)


def search(ct, cribs, alphas, chunk=1500, procs=None):
    """(passing settings, {count: settings} for the core plain tests, settings with 9+ of 14)."""
    hits, hist, tops = [], {}, []
    for h, hi, to in pmap(work, alphas, init, (ct, cribs), chunk=chunk, procs=procs):
        hits += h
        tops += to
        for c, v in hi.items():
            hist[c] = hist.get(c, 0) + v
    return sorted(set(hits), reverse=True), hist, sorted(tops, reverse=True)


def search_cipher_count(ct, cribs, alphas, chunk=100, procs=None):
    return max(pmap(work_cipher_count, alphas, init, (ct, cribs), chunk=chunk, procs=procs))


# ---------------------------------------------------------------- encrypt / decrypt

def _sides(m, lay, fn):
    im = {c: i for i, c in enumerate(m)}
    side = {"M": (m, im), "AZ": (AZ, IZ), "KR": (KRYPTOS_ALPHABET, IK)}
    a, b = lay.split("/")
    return side[a], side[b], side[fn]


def encrypt(words, m, lay, form, fn, sg, const, mode, primers):
    """Encrypt a list of words. primers: the words standing before the message (two are enough);
    they are their own cipher letters. Returns the ciphertext of the message only."""
    feed, order, over, back = mode
    (_, ia), (ab, _), (_, ix) = _sides(m, lay, fn)
    seq = list(primers) + list(words)
    pl = "".join(seq)
    cl = list("".join(primers))
    spans, p = [], 0
    for w in seq:
        spans.append((p, len(w)))
        p += len(w)
    for t in range(len(primers), len(seq)):
        s, n = spans[t]
        q, mlen = spans[t - back]
        for j, a in enumerate(sources(s, n, q, mlen, order, over)):
            f = pl[a] if feed == "plain" else cl[a]
            k = (const + sg * ix[f]) % 26
            cl.append(ab[(ia[pl[s + j]] + k) % 26 if form == "vig" else (k - ia[pl[s + j]]) % 26])
    return "".join(cl[len("".join(primers)):])


def _dec_word(base, text, start, ct, s, n, prev, st):
    """Decrypt the word at s. Known letters: base (full-length, '.' unknown) before `start`, `text` from there."""
    (aa, _), (_, ib), (_, ix), form, sg, const, feed, order, over = st
    out = []
    for j, a in enumerate(sources(s, n, prev[0], prev[1], order, over)):
        if feed == "cipher":
            f = ct[a] if a >= 0 else "."
        elif a >= s:
            f = out[a - s]
        elif a >= start:
            f = text[a - start]
        else:
            f = base[a] if a >= 0 else "."
        if f == ".":
            out.append(".")
            continue
        k = (const + sg * ix[f]) % 26
        out.append(aa[(ib[ct[s + j]] - k) % 26 if form == "vig" else (k - ib[ct[s + j]]) % 26])
    return "".join(out)


def _beam(ct, base, start, end, hist, st, back, logp, floor, width, check=None):
    """Best split of ct[start:end] into words of 1-12 letters, each decrypted with its key word.

    hist: the two words before `start` as (position, length) or None. check: (position, word) of a clue
    word right after `end`; splits whose last words do not decrypt it are pushed down."""
    layers = {start: [(0.0, "", tuple(hist))]}
    ctx0 = base[max(0, start - 3):start]
    for pos in range(start, end):
        states = sorted(layers.pop(pos, []), reverse=True)[:width]
        for sc, text, h in states:
            prev = h[2 - back]
            if prev is None:
                continue
            ctx = (ctx0 + text)[-3:]
            for n in range(1, min(12, end - pos) + 1):
                w = _dec_word(base, text, start, ct, pos, n, prev, st)
                t = ctx + w
                add = 0.0
                for i in range(len(t) - 3):
                    q = t[i:i + 4]
                    if "." not in q:
                        add += logp.get(q, floor)
                layers.setdefault(pos + n, []).append((sc + add, text + w, (h[1], (pos, n))))
    final = layers.get(end, [])
    if not final:
        return "." * (end - start), None
    if check:
        cpos, cword = check
        scored = []
        for sc, text, h in final:
            prev = h[2 - back]
            got = _dec_word(base, text, start, ct, cpos, len(cword), prev, st) if prev else ""
            scored.append((sc + 10.0 * sum(x == y for x, y in zip(got, cword)), text, h))
        final = scored
    sc, text, h = max(final)
    return text, h


def _choices(n, b):
    """The different word histories a part stands for: [(two-back, one-back)] at the end of its clue block."""
    if n is None:
        return [None]
    out = []
    for pname, L in PARTS[n]["labels"]:
        words = PARSES[b][pname]
        start = words[0][0]
        seq = [None, (start - L, L) if L and start - L >= 0 else None] + list(words)
        if (tuple(seq[-2:]), seq[2]) not in out:
            out.append((tuple(seq[-2:]), seq[2]))
    return out


def read_hit(ct, cribs, m, hit, quad, width=150):
    """Letters 34-62 and 74-96 as the setting decrypts them under its best split into words.

    Returns a 97-letter string ('.' where nothing is forced: everything before the first clue)."""
    _, _, lay, form, fn, sg, const, n1, n2 = hit
    feed, order, over, back = PARTS[n1 if n1 is not None else n2]["mode"]
    st = _sides(m, lay, fn) + (form, sg, const, feed, order, over)
    base = "".join(cribs.get(i, ".") for i in range(N))
    best = None
    for c1 in _choices(n1, 0):
        for c2 in _choices(n2, 1):
            out = list(base)
            if c1:
                check = (c2[1][0], base[c2[1][0]:c2[1][0] + c2[1][1]]) if c2 else None
                out[34:63] = _beam(ct, base, 34, 63, c1[0], st, back, quad.logp, quad.floor, width, check)[0]
            if c2:
                out[74:N] = _beam(ct, "".join(out), 74, N, c2[0], st, back, quad.logp, quad.floor, width)[0]
            text = "".join(out)
            sc = sum(quad.logp.get(text[i:i + 4], quad.floor) for i in range(N - 3) if "." not in text[i:i + 4])
            sc -= 20.0 * text.count(".")
            if best is None or sc > best[0]:
                best = (sc, text)
    return best[1]


def describe(hit):
    checks, name, lay, form, fn, sg, const, n1, n2 = hit
    mode = PARTS[n1 if n1 is not None else n2]["mode"]
    return "checks=%d %s %s %s fed letter on %s sign=%+d const=%d | %s feed, key word %s, %s, %d back | block 1: %s | block 2: %s" % (
        checks, name, lay, form, fn, sg, const, mode[0], "forwards" if mode[1] == "fwd" else "reversed",
        "wrap" if mode[2] == "wrap" else "run-on", mode[3], label(n1), label(n2))


# ---------------------------------------------------------------- any tableau, and one hidden alphabet

def triples(pairs, feed, ct, pt):
    """(plain, fed, cipher) letters of every pair."""
    return [(pt[i], pt[a] if feed == "plain" else ct[a], ct[i]) for i, a in pairs]


def latin_conflicts(tr):
    """Clashes that no tableau with distinct rows and columns allows: two of (plain, key, cipher) equal, third not."""
    out = set()
    for x in range(len(tr)):
        for y in range(x + 1, len(tr)):
            same = [u == v for u, v in zip(tr[x], tr[y])]
            if sum(same) == 2:
                out.add((tr[x], tr[y]))
    return sorted(out)


HIDDEN_FORMS = (("C = P + K", -1, 1), ("C = P - K", -1, -1), ("C = K - P", 1, 1), ("C = -P - K", 1, -1))
LI = IZ


def hidden_rows(tr, pcoef, sg):
    """One equation per pair: X[C] + pcoef*X[P] - sg*X[K] - E = 0 on the 26 unknown positions X and a constant E."""
    rows = []
    for p, f, c in tr:
        r = [0] * 27
        r[LI[c]] += 1
        r[LI[p]] += pcoef
        r[LI[f]] -= sg
        r[26] -= 1
        rows.append([v % 26 for v in r])
    return rows


def forced_equal(rows):
    """Pairs of letters that every solution puts in the same place (mod 13 and mod 2): no real alphabet then."""
    cols = [j for j in range(26) if any(r[j] for r in rows)]
    use = cols + [26]
    sub = [[r[j] for j in use] for r in rows]
    zero = [0] * len(sub)
    out = []
    for x in range(len(cols)):
        for y in range(x + 1, len(cols)):
            row = [0] * len(use)
            row[x], row[y] = 1, -1
            if (solve_mod_p(sub + [row], zero + [1], 13) is None
                    and solve_mod_p(sub + [row], zero + [1], 2) is None):
                out.append((AZ[cols[x]], AZ[cols[y]]))
    return out


def hidden_test(tr, pcoef, sg, max_points=31000):
    """Status of one hidden-alphabet system: 'tableau' (clash in any tableau), 'none' (no solution with
    distinct places), 'ok'/'capped' (solutions listed), 'open' (6 or more free dimensions mod 13: too many
    to list, and no forced collision). Returns (status, solutions)."""
    if latin_conflicts(tr):
        return "tableau", []
    rows = hidden_rows(tr, pcoef, sg)
    sols, status = solve_injective(rows, [0] * len(rows), max_points=max_points, max_sols=64)
    if status == "many":
        return ("none", []) if forced_equal(rows) else ("open", [])
    return status, sols


def hidden_work(chunk):
    s = _S["s"]
    out = []
    for t in chunk:
        mode, n1, n2 = TESTS[t]
        pairs = (PARTS[n1]["pairs"] if n1 is not None else ()) + (PARTS[n2]["pairs"] if n2 is not None else ())
        tr = triples(pairs, mode[0], s["ct"], s["pt"])
        for f, (fname, pcoef, sg) in enumerate(HIDDEN_FORMS):
            status, sols = hidden_test(tr, pcoef, sg)
            out.append((t, f, status, sols))
    return out


def hidden_search(ct, cribs, tests=None, chunk=40, procs=None):
    """[(test index, form index, status, solutions)] for every test and every form of one hidden alphabet."""
    tests = list(range(len(TESTS))) if tests is None else tests
    out = []
    for r in pmap(hidden_work, tests, init, (ct, cribs), chunk=chunk, procs=procs):
        out += r
    return sorted(out)


def hidden_encrypt(words, alpha, pcoef, sg, const, mode, primers):
    """Word autokey on one hidden alphabet `alpha` (all three letters on it)."""
    lay, fn = "M/M", "M"
    if pcoef == -1:                       # C = P + sg*K + const
        return encrypt(words, alpha, lay, "vig", fn, sg, const, mode, primers)
    return encrypt(words, alpha, lay, "beau", fn, sg, const, mode, primers)      # C = sg*K + const - P


def same_alphabet(sol, alpha, letters):
    """True if the solved positions are the true alphabet up to sliding and scaling."""
    X = {c: i for i, c in enumerate(alpha)}
    ls = [c for c in letters if c in sol]
    for u in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        if len({(sol[c] - u * X[c]) % 26 for c in ls}) == 1:
            return True
    return False


# ---------------------------------------------------------------- planted messages

TEXTS = ((("SLOWLY", "WE", "WALKED", "FROM", "THE"), ("UNTIL", "THE", "SHADOWS", "FELL", "OVER", "THE", "OLD"),
          ("WHEN", "TIME", "STOPPED", "FOR", "US", "ALL")),
         (("THEY", "CARRIED", "IT", "SLOWLY", "TO"), ("PAST", "THE", "WALLS", "AND", "UNDER", "THE", "BRIDGE"),
          ("THAT", "NO", "ONE", "HAD", "EVER", "WOUND", "UP")))
SPLIT = {"E|N|E": ("EAST", "NORTH", "EAST"), "E|NE": ("EAST", "NORTHEAST"), "EN|E": ("EASTNORTH", "EAST"),
         "ENE": ("EASTNORTHEAST",), "B|C": ("BERLIN", "CLOCK"), "BC": ("BERLINCLOCK",)}
PRIMERS = ("SHADOW", "LIGHT")


def planted_words(text, p1, p2):
    """97 letters of English as a list of words, the clue words in place and split as p1 / p2."""
    pre, mid, tail = TEXTS[text]
    words = list(pre) + list(SPLIT[p1]) + list(mid) + list(SPLIT[p2]) + list(tail)
    pt = "".join(words)
    assert len(pt) == N and pt[21:34] == "EASTNORTHEAST" and pt[63:74] == "BERLINCLOCK"
    return words, pt


def plant(rng, alphas, mode, p1="E|N|E", p2="B|C", text=0):
    """A planted message on a random keyword tableau: (ct, cribs, wanted setting, plaintext, alphabet)."""
    words, pt = planted_words(text, p1, p2)
    name, m = rng.choice(alphas)
    lay, _, _, feeds = rng.choice(layouts(m))
    fn = rng.choice(feeds)[0]
    form, sg, const = rng.choice(["vig", "beau"]), rng.choice([1, -1]), rng.randrange(26)
    ct = encrypt(words, m, lay, form, fn, sg, const, mode, PRIMERS)
    return ct, {i: pt[i] for i in CLUE}, (name, lay, form, fn, sg, const), pt, m


def wanted(hits, want, mode, p1, p2):
    """The hits that are the planted setting: same tableau and key rule, same mode, the planted splits."""
    out = []
    for h in hits:
        n1, n2 = h[7], h[8]
        if h[1:7] != want or n1 is None or n2 is None or PARTS[n1]["mode"] != mode:
            continue
        if any(a == p1 for a, _ in PARTS[n1]["labels"]) and any(a == p2 for a, _ in PARTS[n2]["labels"]):
            out.append(h)
    return sorted(out, reverse=True)
