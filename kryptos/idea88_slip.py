"""Idea 88: the key runs on over word spaces, so it slips one place at every word break.

If the plaintext sheet had spaces and the key letter was used up on each space, letter i of the
message sits at key position i + (word breaks before it). Inside the clues the breaks are known
(EAST|NORTH|EAST or EAST|NORTHEAST or none; BERLIN|CLOCK or none). The number of breaks before
the first clue only matters for the progressive rule (tried 0..11, which covers every count for
periods up to 12). The number of breaks between the clues is unknown: every extra offset 0..25.

`fast_hits` gives exactly what `kryptos.round11.battery` gives over all those position sets (see
`slow_hits`, the plain loop, and the test that compares them), but about 40 times faster: it
first applies cheap necessary conditions that share work between the 156 position sets, and
calls the real battery only on the few that pass.
"""
from .round9 import solve_mod_p
from .round11 import _plan, battery

MIN_CHECKS = 7
PARSE1 = (("EASTNORTHEAST", ()), ("EAST|NORTHEAST", (4,)), ("EAST|NORTH|EAST", (4, 9)))
PARSE2 = (("BERLINCLOCK", ()), ("BERLIN|CLOCK", (6,)))
OFFSETS = tuple(range(26))
STARTS = tuple(range(12))
FAMILIES = ("repeating", "sliding", "progressive", "stacked", "chain")


def positions(p1, p2, x, a=0):
    """Key positions of the 24 clue letters: i + breaks so far.

    p1 / p2 index PARSE1 / PARSE2; a = word breaks before EAST; x = word breaks from the end of
    EASTNORTHEAST up to and including the one just before BERLIN."""
    b1, b2 = PARSE1[p1][1], PARSE2[p2][1]
    pos = [21 + a + j + sum(1 for b in b1 if b <= j) for j in range(13)]
    return pos + [63 + a + len(b1) + x + j + sum(1 for b in b2 if b <= j) for j in range(11)]


def label(p1, p2):
    return PARSE1[p1][0] + " + " + PARSE2[p2][0]


def _only(fam):
    return tuple(f for f in FAMILIES + ("autokey",) if f != fam)


def slow_hits(k, min_checks=MIN_CHECKS):
    """The plain loop: the battery on every position set. Returns a set of (checks, p1, p2, x, rule).

    x = -1 for chain addition, which does not depend on the offset between the clues."""
    out = set()
    for p1 in range(3):
        for p2 in range(2):
            for ck, rule in battery(k, positions(p1, p2, 0), min_checks=min_checks, skip=_only("chain")):
                out.add((ck, p1, p2, -1, rule))
            for x in OFFSETS:
                for ck, rule in battery(k, positions(p1, p2, x), min_checks=min_checks,
                                        skip=("autokey", "chain", "progressive")):
                    out.add((ck, p1, p2, x, rule))
                for a in STARTS:
                    for ck, rule in battery(k, positions(p1, p2, x, a), min_checks=min_checks,
                                            skip=_only("progressive")):
                        if a < int(rule.split("=")[1].split()[0]):
                            out.add((ck, p1, p2, x, rule + " start+%d" % a))
    return out


# ------------------------------------------------------------------ the fast version

_T = {}


def _tree(groups):
    """Equalities that say 'all members of each group are equal': (first, other) pairs."""
    first, pairs = {}, []
    for g, idx in groups:
        f = first.setdefault(g, idx)
        if f != idx:
            pairs.append((f, idx))
    return pairs


def _tables(min_checks):
    t = _T.get(min_checks)
    if t is not None:
        return t
    rep, sli, sta, chain, prog = {}, {}, {}, {}, {}
    for p1 in range(3):
        for p2 in range(2):
            pos0 = positions(p1, p2, 0)
            pl0 = _plan(pos0)
            for m in range(2, 7):                      # chain addition: one first equation per (taps)
                pairs = pl0["lag"][m]
                if len(pairs) < min_checks:
                    break
                a, b = pairs[0]
                for tt in range(1, m):
                    chain.setdefault((a, b - tt, b), set()).add((p1, p2))
            for x in OFFSETS:
                pos = positions(p1, p2, x)
                pl = _plan(pos)
                lab = (p1, p2, x)
                for p in range(1, 18):
                    pairs = _tree(zip(pl["res"][p], range(24)))
                    if len(pairs) >= min_checks:
                        rep.setdefault(tuple(pairs), set()).add(lab)
                for p in range(1, 16):
                    pairs = _tree(zip(pl["lagres"][1, p], (j for j, _ in pl["lag"][1])))
                    if len(pairs) >= min_checks:
                        sli.setdefault(tuple(pairs), set()).add(lab)
                for p in range(2, 13):
                    for q in range(p + 1, 14):
                        if q % p == 0:
                            continue
                        pairs = _tree(zip(pl["lagres"][p, q], (p * 24 + j for j, _ in pl["lag"][p])))
                        pairs += _tree(zip(pl["lagres"][q, p], (q * 24 + j for j, _ in pl["lag"][q])))
                        if len(pairs) >= min_checks + 1:
                            sta.setdefault(tuple(pairs), set()).add(lab)
            for p in range(1, 13):                     # progressive: block-1 equations first, then per offset
                if not pl0["lag"][p]:
                    continue
                for a in range(p):
                    by_x = []
                    pre = None
                    for x in OFFSETS:
                        pos = positions(p1, p2, x, a)
                        tr = _tree(zip((i % p for i in pos), range(24)))
                        eq = [(i, j, pos[j] // p - pos[i] // p) for i, j in tr]
                        pre = [e for e in eq if e[1] < 13]
                        by_x.append([e for e in eq if e[1] >= 13] if len(eq) >= min_checks + 1 else None)
                    prog[p1, p2, p, a] = (pl0["lag"][p][0], pre, by_x)

    def index(d):
        out = {}
        for pairs, labs in d.items():
            out.setdefault(pairs[0], []).append((pairs[1:], sorted(labs)))
        return out

    t = _T[min_checks] = {"rep": index(rep), "sli": index(sli), "sta": index(sta),
                          "chain": sorted((tr, sorted(v)) for tr, v in chain.items()),
                          "prog": sorted(prog.items())}
    return t


def _equal_pairs(vals, idx):
    """Every pair (i, j), i before j, of indexes with equal values."""
    seen = {}
    for i, v in zip(idx, vals):
        g = seen.get(v)
        if g is None:
            seen[v] = [i]
        else:
            for h in g:
                yield h, i
            g.append(i)


_VALID = {L: [j for j in range(24 - L) if j + L <= 12 or j >= 13] for L in range(1, 14)}


def fast_hits(k, min_checks=MIN_CHECKS):
    """Same result as slow_hits, far fewer battery calls."""
    t = _tables(min_checks)
    cand = set()
    for h, i in _equal_pairs(k, range(24)):
        for rest, labs in t["rep"].get((h, i), ()):
            for a, b in rest:
                if k[a] != k[b]:
                    break
            else:
                cand.update(("repeating", lab) for lab in labs)
    d = [(k[j + 1] - k[j]) % 26 for j in range(23)]
    for h, i in _equal_pairs([d[j] for j in _VALID[1]], _VALID[1]):
        for rest, labs in t["sli"].get((h, i), ()):
            for a, b in rest:
                if d[a] != d[b]:
                    break
            else:
                cand.update(("sliding", lab) for lab in labs)
    sta = t["sta"]
    if sta:
        v = {}
        for L in range(2, 14):
            base = L * 24
            for j in _VALID[L]:
                v[base + j] = (k[j + L] - k[j]) % 26
        for L in range(2, 14):
            base = L * 24
            idx = [base + j for j in _VALID[L]]
            for h, i in _equal_pairs([v[e] for e in idx], idx):
                for rest, labs in sta.get((h, i), ()):
                    for a, b in rest:
                        if v[a] != v[b]:
                            break
                    else:
                        cand.update(("stacked", lab) for lab in labs)
    out = set()
    for fam, (p1, p2, x) in cand:
        for ck, rule in battery(k, positions(p1, p2, x), min_checks=min_checks, skip=_only(fam)):
            out.add((ck, p1, p2, x, rule))
    for (a, m, b), labs in t["chain"]:
        if (k[m] + k[a] - k[b]) % 26 == 0:
            for p1, p2 in labs:
                for ck, rule in battery(k, positions(p1, p2, 0), min_checks=min_checks, skip=_only("chain")):
                    out.add((ck, p1, p2, -1, rule))
    for (p1, p2, p, a), ((a0, b0), pre, by_x) in t["prog"]:
        s = (k[b0] - k[a0]) % 26
        if not s:
            continue
        for i, j, dd in pre:
            if (k[j] - k[i] - s * dd) % 26:
                break
        else:
            for x, eq in enumerate(by_x):
                if eq is None:
                    continue
                for i, j, dd in eq:
                    if (k[j] - k[i] - s * dd) % 26:
                        break
                else:
                    want = "progressive p=%d " % p
                    for ck, rule in battery(k, positions(p1, p2, x, a), min_checks=min_checks,
                                            skip=_only("progressive")):
                        if rule.startswith(want):
                            out.add((ck, p1, p2, x, rule + " start+%d" % a))
    return out


# ------------------------------------------------------------------ chance rate

def expected_chance(min_checks=MIN_CHECKS, slipped=True):
    """Expected hits per key stream if the 24 key values were uniformly random, per rule family.

    slipped=False gives the same count for the carved positions alone (no breaks, no offset), to
    show how much the offsets and parsings multiply the chance rate."""
    exp = dict.fromkeys(FAMILIES, 0.0)
    sets = [(p1, p2, x) for p1 in range(3) for p2 in range(2) for x in OFFSETS] if slipped else [(0, 0, 0)]
    for p1, p2, x in sets:
        pos = positions(p1, p2, x)
        pl = _plan(pos)
        for p in range(1, 18):
            c = 24 - len(set(pl["res"][p]))
            if c >= min_checks:
                exp["repeating"] += 26.0 ** -c
        for p in range(1, 16):
            c = len(pl["lag"][1]) - len(set(pl["lagres"][1, p]))
            if c >= min_checks:
                exp["sliding"] += 26.0 ** -c
        for p in range(2, 13):
            for q in range(p + 1, 14):
                if q % p == 0:
                    continue
                c12 = (len(pl["lag"][p]) - len(set(pl["lagres"][p, q]))
                       + len(pl["lag"][q]) - len(set(pl["lagres"][q, p])))
                if c12 < min_checks + 1:
                    continue
                rows = []
                for i in pos:
                    r = [0] * (p + q)
                    r[i % p] = 1
                    r[p + i % q] = 1
                    rows.append(r)
                zero = [0] * 24
                r13 = p + q - len(solve_mod_p(rows, zero, 13)[1])
                r2 = p + q - len(solve_mod_p(rows, zero, 2)[1])
                if 24 - r13 >= min_checks:
                    exp["stacked"] += 13.0 ** -(24 - r13) * 2.0 ** -(24 - r2)
        if x == 0:
            for m in range(2, 7):
                n = len(pl["lag"][m])
                if n >= min_checks:
                    exp["chain"] += (m - 1) * 26.0 ** -n
        for a in (STARTS if slipped else (0,)):
            posa = [i + a for i in pos]
            for p in range(1, 13):
                if a >= p or not pl["lag"][p]:
                    continue
                c = 24 - len(set(i % p for i in posa))
                if c - 1 >= min_checks:
                    exp["progressive"] += 25.0 / 26 * 26.0 ** -(c - 1)
    return exp


# ------------------------------------------------------------------ planted answers

SPACED = """SLOWLY DESPERATELY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY
WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A
LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT
PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST CAN YOU SEE ANYTHING IT WAS TOTALLY INVISIBLE HOWS THAT
POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGROUND TO AN UNKNOWN
LOCATION DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE WHO KNOWS THE EXACT LOCATION ONLY
THIS WAS HIS LAST MESSAGE BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF ILLUSION""".split()


def _words(rng, n):
    """Consecutive English words with exactly n letters in total."""
    while True:
        s = rng.randrange(len(SPACED) - 12)
        out, tot = [], 0
        for w in SPACED[s:s + 12]:
            out.append(w)
            tot += len(w)
            if tot >= n:
                break
        if tot == n:
            return out


def plant(rng, alphas, rule):
    """An English message with word spaces, enciphered with the key running over the spaces.

    The clues sit at 21-33 and 63-73 as in K4. Returns (ciphertext, cribs, truth) where truth is
    the hit the search must report: (alphabet, layout, form, p1, p2, x, rule)."""
    from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
    p1, p2 = rng.randrange(1, 3), rng.randrange(2)
    c1 = PARSE1[p1][0].split("|")
    c2 = PARSE2[p2][0].split("|")
    tail = _words(rng, 23)
    words = _words(rng, 21) + c1 + _words(rng, 29) + c2 + tail
    double = rng.randrange(2)                                 # one sentence break that eats two key letters
    name, m = rng.choice(alphas)
    lay, form = rng.choice((("M/M", "vig"), ("M/AZ", "beau"), ("KR/M", "vig"), ("M/M", "beau")))
    a_, b_ = {"M/M": (m, m), "M/AZ": (m, AZ), "KR/M": (KRYPTOS_ALPHABET, m)}[lay]
    if rule == "repeating":
        p = rng.randrange(5, 11)
    elif rule == "sliding":
        p = rng.randrange(5, 9)
    else:
        p = rng.randrange(4, 8)
    w = [rng.randrange(26) for _ in range(p)]
    while len(set(w)) < 3:
        w = [rng.randrange(26) for _ in range(p)]
    step = rng.randrange(1, 26)
    pt, stream, t = [], [], 0
    for wi, word in enumerate(words):
        if wi:
            t += 1                                            # the space uses up a key letter
        for ch in word:
            stream.append(t)
            pt.append(ch)
            t += 1
    ct = []
    # a double break: one extra slip somewhere strictly between the clues
    if double:
        cut = rng.randrange(40, 58)
        stream = [u + (1 if j >= cut else 0) for j, u in enumerate(stream)]
    sums, acc = [], 0
    for u in range(max(stream) + 1):
        acc = (acc + w[u % p]) % 26
        sums.append(acc)
    for ch, u in zip(pt, stream):
        if rule == "repeating":
            kv = w[u % p]
        elif rule == "sliding":
            kv = sums[u]
        else:
            kv = (w[u % p] + step * (u // p)) % 26
        x_ = a_.index(ch)
        ct.append(b_[(x_ + kv) % 26] if form == "vig" else b_[(kv - x_) % 26])
    pt, ct = "".join(pt), "".join(ct)
    assert len(pt) == 97 and pt[21:34] == "EASTNORTHEAST" and pt[63:74] == "BERLINCLOCK"
    a = stream[21] - 21
    x = stream[63] - 63 - a - len(PARSE1[p1][1])
    if rule == "progressive":
        rs = "progressive p=%d step=%d start+%d" % (p, step, a % p)
    else:
        rs = "%s p=%d" % (rule, p)
    return ct, {i: pt[i] for i in list(range(21, 34)) + list(range(63, 74))}, (name, lay, form, p1, p2, x, rs)
