"""Idea 112: the narrowest window of key values any hidden alphabet allows.

The 24 clue pairs (P, C) each give one key value once an alphabet is fixed. With the alphabet
free, "all 24 key values lie in a circular window of w consecutive values" is a constraint
problem over the places of the letters: each pair says  sc*x(C) + sp*x(P)  is in the window
(sc = 1; sp = -1 for Vigenere, +1 for Beaufort), and places inside one alphabet are distinct.

Layouts (the side that is not hidden is A-Z or KRYPTOS):
  same/vig    one hidden alphabet on both sides, k = x(C) - x(P)   (variant = mirror, same answer)
  same/beau   one hidden alphabet on both sides, k = x(C) + x(P)
  ptX/AZ, ptX/KR   hidden plain side, k = b(C) - x(P)
  ctX/AZ, ctX/KR   hidden cipher side, k = x(C) - b(P)
  two         two independent hidden alphabets, k = y(C) - x(P)
With one hidden side (or two different hidden alphabets) Vigenere and Beaufort are the same
problem: replace x by -x (a mirror alphabet is still an alphabet) and the window by its mirror.

Symmetry is fixed so every arrangement is counted once, "up to shifting":
  same/*  first variable pinned at 0, window start s = 0..25 all tried.
  ptX/ctX window start pinned at 0 (shifting x moves the window), no variable pinned.
  two     window start 0 and first plain variable pinned at 0.

Solver: backtracking over letter places with bitmask domains, smallest-domain-first, forward
checking along each clue pair, and a bipartite-matching test (all-different must still be
possible) at every node. It is exact: "infeasible" is a proof.
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET

N = 26
FULL = (1 << N) - 1
FIXED = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
LAYOUTS = ["same/vig", "same/beau", "ptX/AZ", "ptX/KR", "ctX/AZ", "ctX/KR", "two"]


def _rot(mask, t):
    t %= N
    return ((mask << t) | (mask >> (N - t))) & FULL


def _win(s, w):
    return _rot((1 << w) - 1, s) if w < N else FULL


def _neg(mask):
    out = 0
    for v in range(N):
        if mask >> v & 1:
            out |= 1 << ((-v) % N)
    return out


def _vals(mask):
    return [v for v in range(N) if mask >> v & 1]


class Model:
    """Variables, unary domains and binary pair constraints for one layout and window."""

    def __init__(self, layout, pl, cl):
        self.layout = layout
        self.pairs = list(zip(pl, cl))
        if layout.startswith("same"):
            self.sp = -1 if layout.endswith("vig") else 1
        else:
            self.sp = -1
        names = []
        self.ends = []           # per pair: (p_end, c_end); an end is ("v", idx) or ("c", value)
        index = {}

        def var(key):
            if key not in index:
                index[key] = len(names)
                names.append(key)
            return ("v", index[key])

        for p, c in self.pairs:
            if layout.startswith("same"):
                pe, ce = var(("X", p)), var(("X", c))
            elif layout.startswith("ptX"):
                pe, ce = var(("X", p)), ("c", FIXED[layout[4:]].index(c))
            elif layout.startswith("ctX"):
                pe, ce = ("c", FIXED[layout[4:]].index(p)), var(("X", c))
            else:
                pe, ce = var(("X", p)), var(("Y", c))
            self.ends.append((pe, ce))
        self.names = names
        self.group = [k[0] for k in names]
        self.n = len(names)
        self.pin = None
        if layout.startswith("same") or layout == "two":
            tie = {}
            for pe, ce in self.ends:
                for e in (pe, ce):
                    if e[0] == "v":
                        tie[e[1]] = tie.get(e[1], 0) + 1
            self.pin = max((i for i in range(self.n) if self.group[i] == "X"), key=lambda i: (tie.get(i, 0), -i))
        self.starts = range(N) if layout.startswith("same") else (0,)

    def build(self, s, w):
        """Initial domains and neighbour tables for window [s, s+w-1]."""
        A = _win(s, w)
        sp = self.sp
        dom = [FULL] * self.n
        nb = [[] for _ in range(self.n)]    # (other var, table: value -> allowed mask of other)
        for pe, ce in self.ends:
            if pe[0] == "v" and ce[0] == "v":
                u, v = ce[1], pe[1]
                if u == v:                     # same letter both sides: (1 + sp) x in A
                    m = 0
                    for a in range(N):
                        if A >> (((1 + sp) * a) % N) & 1:
                            m |= 1 << a
                    dom[u] &= m
                    continue
                # k = x_u + sp*x_v in A.  given x_u = a: x_v in sp*(A - a); given x_v = b: x_u in A - sp*b
                tv = [(_neg(_rot(A, -a)) if sp == -1 else _rot(A, -a)) for a in range(N)]
                tu = [_rot(A, -sp * b) for b in range(N)]
                nb[u].append((v, tv))
                nb[v].append((u, tu))
            elif ce[0] == "v":                 # x_c + sp*b in A
                dom[ce[1]] &= _rot(A, -sp * pe[1])
            else:                              # b + sp*x_p in A
                m = _rot(A, -ce[1])
                dom[pe[1]] &= _neg(m) if sp == -1 else m
        if self.pin is not None:
            dom[self.pin] &= 1
        return dom, nb


def _matchable(dom, idxs):
    """Can the variables idxs take distinct values inside their domains?"""
    owner = {}
    for i in idxs:
        seen = 0

        def aug(j):
            nonlocal seen
            m = dom[j] & ~seen
            while m:
                low = m & -m
                v = low.bit_length() - 1
                seen |= low
                if v not in owner or aug(owner[v]):
                    owner[v] = j
                    return True
                m &= m - 1
            return False

        if not aug(i):
            return False
    return True


def _propagate(d, nb, grp, queue):
    """Arc consistency on the pair constraints plus singleton all-different, in place.

    queue: variables whose domains changed. Returns -1, or the variable that was wiped out."""
    queue = list(queue)
    inq = set(queue)
    n = len(d)
    while queue:
        u = queue.pop()
        inq.discard(u)
        du = d[u]
        vals = _vals(du)
        for v, t in nb[u]:
            sup = 0
            for a in vals:
                sup |= t[a]
            nd = d[v] & sup
            if nd != d[v]:
                if not nd:
                    return v
                d[v] = nd
                if v not in inq:
                    queue.append(v)
                    inq.add(v)
        if du & (du - 1) == 0:           # singleton: remove from the rest of its alphabet
            g = grp[u]
            for v in range(n):
                if v != u and grp[v] == g and d[v] & du:
                    nd = d[v] & ~du
                    if not nd:
                        return v
                    d[v] = nd
                    if v not in inq:
                        queue.append(v)
                        inq.add(v)
    return -1


def _search(model, dom, nb, cap, prefer=None, out=None):
    """Count solutions up to cap. prefer: values tried first (planted check). out: first solution.

    Only "core" letters (tied by clue pairs to two or more other letters) are branched on when a
    plain yes/no is wanted: once they are placed, every other letter has a fixed set of allowed
    places (from its one neighbour and the fixed side) and only all-different is left, which the
    matching test decides exactly. Counting or a witness branches on every letter."""
    n = model.n
    grp = model.group
    count = 0
    full = cap > 1 or out is not None or prefer is not None
    nbs = [set(j for j, _ in x) for x in nb]
    core = [i for i in range(n) if len(nbs[i]) >= 2]
    deg = [len(x) for x in nbs]
    wt = [0] * n
    groups = [[i for i in range(n) if grp[i] == g] for g in sorted(set(grp))]

    def rec(dom):
        nonlocal count
        cand = [i for i in core if dom[i] & (dom[i] - 1)]
        if not cand and full:
            cand = [i for i in range(n) if dom[i] & (dom[i] - 1)]
        if not cand:
            count += 1
            if out is not None and not out:
                out.extend(dom[i].bit_length() - 1 for i in range(n))
            return count >= cap
        best, bc = None, None
        for i in cand:
            c = bin(dom[i]).count("1") / (1.0 + deg[i] + wt[i])
            if bc is None or c < bc:
                best, bc = i, c
        vals = _vals(dom[best])
        if prefer is not None and prefer[best] in vals:
            vals.remove(prefer[best])
            vals.insert(0, prefer[best])
        for a in vals:
            d = list(dom)
            d[best] = 1 << a
            f = _propagate(d, nb, grp, [best])
            if f >= 0:
                wt[f] += 1
                wt[best] += 1
                continue
            if not all(_matchable(d, g) for g in groups):
                wt[best] += 1
                continue
            if rec(d):
                return True
        return False

    dom = list(dom)
    if all(dom) and _propagate(dom, nb, grp, range(n)) < 0 and all(_matchable(dom, g) for g in groups):
        rec(dom)
    return count


def _starts(model, w):
    """Window starts to try, with their mirror. Mirroring the alphabet (x -> -x) turns a window
    [s, s+w-1] of key values into [-(s+w-1), -s] with the pinned letter still at 0, so in the
    one-alphabet layouts only one start of each mirror pair needs a search."""
    out = []
    for s in model.starts:
        if model.layout.startswith("same"):
            r = (-(s + w - 1)) % N
            if r < s:
                continue
            out.append((s, r))
        else:
            out.append((s, s))
    return out


def _run(model, w, cap):
    tot, starts = 0, []
    for s, r in _starts(model, w):
        dom, nb = model.build(s, w)
        c = _search(model, dom, nb, cap - tot)
        if c:
            starts += [s] if r == s else [s, r]
            tot += c if r == s else 2 * c
            if tot >= cap:
                break
    return min(tot, cap), sorted(starts)


def feasible(model, w, cap=1):
    """Total solutions (up to cap, summed over window starts) at window w, and the starts that work."""
    return _run(model, w, cap)


def min_window(layout, pl, cl, count_cap=1000):
    """Smallest feasible w, the number of arrangements at that w (capped), and the window starts."""
    m = Model(layout, pl, cl)
    for w in range(1, N + 1):
        ok, _ = _run(m, w, 1)
        if ok:
            cnt, starts = _run(m, w, count_cap)
            return w, cnt, starts
    raise AssertionError("w = 26 is always feasible")


def true_places(model, alphabets):
    """Places of the model's variables under the planted alphabets {'X': alph, 'Y': alph}."""
    return [alphabets[g].index(letter) for g, letter in model.names]


def planted_found(layout, pl, cl, alphabets, w):
    """Is the planted arrangement (shifted to the model's gauge) a solution the search reaches at w?

    The search is steered to try the true values first; it must return exactly the truth."""
    m = Model(layout, pl, cl)
    raw = true_places(m, alphabets)
    builds = {s: m.build(s, w) for s in m.starts}
    for tx in range(N):
        for ty in (range(N) if layout == "two" else (0,)):
            truth = [(v + (tx if g == "X" else ty)) % N for v, g in zip(raw, m.group)]
            for s, (dom, nb) in builds.items():
                if all(dom[i] >> truth[i] & 1 for i in range(m.n)):
                    out = []
                    _search(m, dom, nb, 1, prefer=truth, out=out)
                    if out == truth:
                        return True
    return False


def one_solution(layout, pl, cl, w):
    """A witness arrangement at window w: (window start, {letter-node: place}) or None."""
    m = Model(layout, pl, cl)
    for s in m.starts:
        dom, nb = m.build(s, w)
        out = []
        if _search(m, dom, nb, 1, out=out):
            return s, dict(zip(m.names, out))
    return None


def profile(pl, cl, blocks, count_cap=1000):
    """{(layout, part): (w, count, starts)} for every layout and part ('all', 'b1', 'b2')."""
    res = {}
    parts = [("all", list(range(len(pl))))] + [("b%d" % (j + 1), b) for j, b in enumerate(blocks)]
    for lay in LAYOUTS:
        for part, idx in parts:
            res[(lay, part)] = min_window(lay, [pl[i] for i in idx], [cl[i] for i in idx], count_cap)
    return res


def control_job(args):
    """Worker: profile of one shuffled K4 (module-level so spawned workers can import it)."""
    seed, ct, cribs, pos, cap = args
    from .round9 import shuffled_control
    sh = shuffled_control(seed, ct)
    pl, cl = [cribs[i] for i in pos], [sh[i] for i in pos]
    blocks = [list(range(13)), list(range(13, 24))]
    return seed, profile(pl, cl, blocks, cap)


def key_values(layout, pl, cl, alphabets):
    sp = -1 if layout != "same/beau" else 1
    xa = alphabets.get("X")
    out = []
    for p, c in zip(pl, cl):
        if layout.startswith("same"):
            a, b = xa.index(p), xa.index(c)
        elif layout.startswith("ptX"):
            a, b = xa.index(p), FIXED[layout[4:]].index(c)
        elif layout.startswith("ctX"):
            a, b = FIXED[layout[4:]].index(p), xa.index(c)
        else:
            a, b = xa.index(p), alphabets["Y"].index(c)
        out.append((b + sp * a) % N)
    return out


def encrypt(layout, pt, key, alphabets):
    """Encrypt pt with key values key[i] under the layout (inverse of key_values)."""
    sp = -1 if layout != "same/beau" else 1
    xa = alphabets.get("X")
    out = []
    for i, p in enumerate(pt):
        k = key[i]
        if layout.startswith("same"):
            out.append(xa[(k - sp * xa.index(p)) % N])
        elif layout.startswith("ptX"):
            out.append(FIXED[layout[4:]][(k + xa.index(p)) % N])
        elif layout.startswith("ctX"):
            out.append(xa[(k + FIXED[layout[4:]].index(p)) % N])
        else:
            out.append(alphabets["Y"][(k + xa.index(p)) % N])
    return "".join(out)
