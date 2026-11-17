"""Helpers for idea 103: pair ciphers on rectangles that hold 26 or 27 symbols.

A text is kept as a 98-symbol "stream": the carved ? followed by the 97 letters, so K4 letter i is
stream[i + 1] and the ? is letter -1. A pairing (w, o) pairs letter i with letter i + w inside blocks of
2w letters; o (0 .. 2w-1) says where a block starts, counted in K4 letters. Counting from the ? instead
only moves o by one, so both starts are in the same list; the ? itself gets a partner (letter w - 1) only
when a block starts on it, and only squares with 27 cells can use that pair.

Squares are "cell strings": the symbols read row by row. A config is (fill, qpos): fill "rows" or "cols",
qpos "" (26 cells), "first" or "last" (the ? before or after the 26 letters in the fill order).

Two-square, squares S1 (left) and S2 (right), plain pair (a, b), a found in S1, b in S2:
  order A: cipher = S2[row a][col b], S1[row b][col a]      (the textbook order)
  order B: cipher = S1[row b][col a], S2[row a][col b]      (the same two letters, written the other way)
"One above the other" is the same cipher with every square turned on its side (rows <-> columns), and the
grid list holds both shapes and both fills, so it needs no code of its own (vertical_encrypt proves it).

Four-square, plain squares P1 (top left), P2 (bottom right), cipher squares Q1 (top right), Q2 (bottom left):
  order A: cipher = Q1[row a][col b], Q2[row b][col a];  order B: the two letters the other way round.
"""
from collections import defaultdict

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
GRIDS = [(2, 13), (13, 2), (3, 9), (9, 3)]
N = 97
WMAX = 48
MIN_FULL = 6


def configs(grid):
    r, c = grid
    qs = ("",) if r * c == 26 else ("first", "last")
    return [(f, q) for f in ("rows", "cols") for q in qs]


def cells(alpha, grid, cfg):
    """The square as a cell string (row by row)."""
    fill, q = cfg
    seq = "?" + alpha if q == "first" else alpha + "?" if q == "last" else alpha
    if fill == "rows":
        return seq
    r = grid[0]
    return "".join(seq[i::r] for i in range(r))


def stream(ct):
    return ct if len(ct) == N + 1 else "?" + ct


# ---------------------------------------------------------------- pairings and Part 1

def pair_list(w, o, with_q=False):
    """[(i, j)] in K4 letter numbers (the ? is -1), j = i + w."""
    out = []
    for i in range(-1 if with_q else 0, N - w):
        if (i - o) % (2 * w) < w:
            out.append((i, i + w))
    return out


def all_pairings(wmax=WMAX):
    return [(w, o) for w in range(1, wmax + 1) for o in range(2 * w)]


def full_pairs(w, o, cribs):
    return [(i, j) for i, j in pair_list(w, o) if i in cribs and j in cribs]


def pair_substitution_ok(ct, cribs, w, o):
    """Part 1. Can ANY one-to-one table of letter pairs fit? Returns (ok, reason).

    Two equal cipher pairs must come from equal plain pairs (so their known plain letters must agree), and
    two different cipher pairs must come from different plain pairs."""
    known = {}
    for i, j in pair_list(w, o):
        cp = ct[i] + ct[j]
        k = known.setdefault(cp, [None, None])
        for s, pos in ((0, i), (1, j)):
            p = cribs.get(pos)
            if p is None:
                continue
            if k[s] is None:
                k[s] = p
            elif k[s] != p:
                return False, "cipher pair %s stands for two plain pairs (letter %d: %s and %s)" % (cp, s + 1, k[s], p)
    seen = {}
    for cp, (a, b) in known.items():
        if a and b:
            if a + b in seen:
                return False, "plain pair %s gives two cipher pairs (%s and %s)" % (a + b, seen[a + b], cp)
            seen[a + b] = cp
    return True, ""


def part1(ct, cribs, wmax=WMAX):
    """[(w, o, ok, number of full clue pairs, reason)] for every pairing."""
    out = []
    for w, o in all_pairings(wmax):
        ok, why = pair_substitution_ok(ct, cribs, w, o)
        out.append((w, o, ok, len(full_pairs(w, o, cribs)), why))
    return out


# ---------------------------------------------------------------- two-square

def ts_conditions(ct, cribs, w, o, order):
    """(col1, col2, links): col1 = letter pairs that share a column in S1, col2 the same for S2,
    links = (u, v): row of u in S1 = row of v in S2. Half-known pairs give conditions too."""
    col1, col2, links = [], [], []
    for i, j in pair_list(w, o):
        a, b, x, y = cribs.get(i), cribs.get(j), ct[i], ct[j]
        if order == "A":
            if a:
                col1.append((y, a))
                links.append((a, x))
            if b:
                col2.append((x, b))
                links.append((y, b))
        else:
            if a:
                col1.append((x, a))
                links.append((a, y))
            if b:
                col2.append((y, b))
                links.append((x, b))
    return col1, col2, links


class _UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        p = self.p
        p.setdefault(x, x)
        while p[x] != x:
            p[x] = p[p[x]]
            x = p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def ts_any_square(conds, grid):
    """A necessary test for two-square with ANY two squares on this grid. False = impossible.

    A column holds R letters, a row holds C letters of each square, and two different letters of one
    square cannot share both a row and a column."""
    col1, col2, links = conds
    r, c = grid
    cu, ru = _UF(), _UF()
    for sq, lst in ((1, col1), (2, col2)):
        for u, v in lst:
            cu.union((sq, u), (sq, v))
    for u, v in links:
        ru.union((1, u), (2, v))
    for u in list(cu.p):
        ru.find(u)
    for u in list(ru.p):
        cu.find(u)
    size = defaultdict(set)
    for node in cu.p:
        size[cu.find(node)].add(node)
    if any(len(s) > r for s in size.values()):
        return False
    rows = defaultdict(set)
    both = defaultdict(set)
    for node in ru.p:
        rows[ru.find(node), node[0]].add(node)
        both[ru.find(node), cu.find(node), node[0]].add(node)
    if any(len(s) > c for s in rows.values()):
        return False
    if any(len(s) > 1 for s in both.values()):
        return False
    return True


def rc(sq, grid):
    """{symbol: (row, col)} for a cell string."""
    c = grid[1]
    return {ch: divmod(k, c) for k, ch in enumerate(sq)}


def _ts_decrypt_pair(x, y, s1, s2, grid, order):
    c = grid[1]
    p1, p2 = rc(s1, grid), rc(s2, grid)
    try:
        if order == "A":                   # x in S2 at (row a, col b), y in S1 at (row b, col a)
            (ra, cb), (rb, ca) = p2[x], p1[y]
        else:                              # x in S1 at (row b, col a), y in S2 at (row a, col b)
            (rb, ca), (ra, cb) = p1[x], p2[y]
    except KeyError:
        return None
    return s1[ra * c + ca], s2[rb * c + cb]


def _ts_encrypt_pair(a, b, s1, s2, grid, order):
    c = grid[1]
    p1, p2 = rc(s1, grid), rc(s2, grid)
    try:
        (ra, ca), (rb, cb) = p1[a], p2[b]
    except KeyError:
        return None
    u, v = s2[ra * c + cb], s1[rb * c + ca]
    return (u, v) if order == "A" else (v, u)


def _fs_pair(x, y, p1, p2, q1, q2, grid, order, decrypt):
    c = grid[1]
    try:
        if decrypt:
            if order == "B":
                x, y = y, x
            (ra, cb), (rb, ca) = rc(q1, grid)[x], rc(q2, grid)[y]
            return p1[ra * c + ca], p2[rb * c + cb]
        (ra, ca), (rb, cb) = rc(p1, grid)[x], rc(p2, grid)[y]
    except KeyError:
        return None
    u, v = q1[ra * c + cb], q2[rb * c + ca]
    return (u, v) if order == "A" else (v, u)


def apply(text, w, o, grid, fn):
    """Run fn(x, y) -> (u, v) or None over the pairs of a 98-symbol stream. Returns (new stream, paired letters).

    Unpaired symbols and pairs fn cannot handle pass through unchanged."""
    s = list(stream(text))
    done = []
    for i, j in pair_list(w, o, with_q=grid[0] * grid[1] == 27):
        r = fn(s[i + 1], s[j + 1])
        if r is not None:
            s[i + 1], s[j + 1] = r
            done += [i, j]
    return "".join(s), sorted(done)


def two_square(text, w, o, grid, s1, s2, order="A", decrypt=False):
    f = _ts_decrypt_pair if decrypt else _ts_encrypt_pair
    return apply(text, w, o, grid, lambda x, y: f(x, y, s1, s2, grid, order))


def four_square(text, w, o, grid, p1, p2, q1, q2, order="A", decrypt=False):
    return apply(text, w, o, grid, lambda x, y: _fs_pair(x, y, p1, p2, q1, q2, grid, order, decrypt))


def transpose(sq, grid):
    r, c = grid
    return "".join(sq[i * c + j] for j in range(c) for i in range(r))


def vertical_encrypt(text, w, o, grid, top, bottom):
    """Two-square with one square above the other (textbook: a in the top square, b in the bottom one,
    cipher = top[row a][col b], bottom[row b][col a]; a pair in one column stays as it is)."""
    r, c = grid
    pt, pb = rc(top, grid), rc(bottom, grid)

    def f(a, b):
        if a not in pt or b not in pb:
            return None
        (ra, ca), (rb, cb) = pt[a], pb[b]
        return top[ra * c + cb], bottom[rb * c + ca]
    return apply(text, w, o, grid, f)


# ---------------------------------------------------------------- four-square

def plain_squares(grid):
    """[(name, cell string)]: A-Z or KRYPTOS written by rows (with the ? first or last on 27 cells)."""
    return [("%s%s" % (n, "+?" + q if q else ""), cells(a, grid, ("rows", q)))
            for n, a in (("AZ", AZ), ("KR", KR)) for q in (("",) if grid[0] * grid[1] == 26 else ("first", "last"))]


def fs_conditions(ct, cribs, w, o, grid, p1, p2, order):
    """({cell: letter} for Q1, the same for Q2), or None if two letters land on one cell or one letter
    on two cells (then no pair of cipher squares fits at all)."""
    c = grid[1]
    a1, a2 = rc(p1, grid), rc(p2, grid)
    q1, q2 = {}, {}
    for i, j in pair_list(w, o):
        a, b = cribs.get(i), cribs.get(j)
        if not (a and b):
            continue
        x, y = (ct[i], ct[j]) if order == "A" else (ct[j], ct[i])
        (ra, ca), (rb, cb) = a1[a], a2[b]
        for q, cell, ch in ((q1, ra * c + cb, x), (q2, rb * c + ca, y)):
            if q.setdefault(cell, ch) != ch:
                return None
    for q in (q1, q2):
        if len(set(q.values())) != len(q):
            return None
    return q1, q2


# ---------------------------------------------------------------- the dictionary scan (runs in workers)

class Plan:
    """Everything the scan needs for one text: which pairings go on, and the condition lists by grid."""

    def __init__(self, ct, cribs, wmax=WMAX, min_full=MIN_FULL):
        self.ct, self.cribs = ct, cribs
        self.part1 = part1(ct, cribs, wmax)
        self.pairings = [(w, o) for w, o, ok, nf, _ in self.part1 if ok and nf >= min_full]
        self.ts = {}          # lid -> (w, o, order, conds)
        self.ts_dead = {}     # (lid, grid) -> True when no squares at all can fit
        self.fs = {}          # sid -> (w, o, grid, p1 name, p2 name, order, q1 cells, q2 cells)
        self.fs_settings = 0
        self.fs_dead = 0
        for w, o in self.pairings:
            for order in "AB":
                lid = len(self.ts)
                conds = ts_conditions(ct, cribs, w, o, order)
                self.ts[lid] = (w, o, order, conds)
                for g in GRIDS:
                    self.ts_dead[lid, g] = not ts_any_square(conds, g)
                for g in GRIDS:
                    for n1, p1 in plain_squares(g):
                        for n2, p2 in plain_squares(g):
                            self.fs_settings += 1
                            q = fs_conditions(ct, cribs, w, o, g, p1, p2, order)
                            if q is None:
                                self.fs_dead += 1
                                continue
                            self.fs[len(self.fs)] = (w, o, g, n1, n2, order, q[0], q[1])
        # scan indexes
        self.ts_index = {}    # grid -> [((u, v) first condition or None, [(rest, lid, side, link letters)])]
        for g in GRIDS:
            idx = defaultdict(list)
            for lid, (w, o, order, (col1, col2, links)) in self.ts.items():
                if self.ts_dead[lid, g]:
                    continue
                for side, lst, lk in ((1, col1, [u for u, _ in links]), (2, col2, [v for _, v in links])):
                    cond = sorted({tuple(sorted(p)) for p in lst if p[0] != p[1]})
                    idx[cond[0] if cond else None].append((tuple(cond[1:]), lid, side, tuple(lk)))
            self.ts_index[g] = sorted(idx.items(), key=lambda kv: (kv[0] is not None, kv[0]))
        self.fs_index = {}    # grid -> {(cell, letter): [(rest, sid, square 1 or 2)]}
        for g in GRIDS:
            idx = defaultdict(list)
            for sid, (w, o, gg, n1, n2, order, q1, q2) in self.fs.items():
                if gg != g:
                    continue
                for sq, q in ((1, q1), (2, q2)):
                    cond = sorted(q.items())
                    idx[cond[0]].append((tuple(cond[1:]), sid, sq))
            self.fs_index[g] = dict(idx)
        self.cols = {g: [k % g[1] for k in range(g[0] * g[1])] for g in GRIDS}
        self.rows = {g: [k // g[1] for k in range(g[0] * g[1])] for g in GRIDS}
        self.cfgs = {g: configs(g) for g in GRIDS}

    def counts(self):
        ts_live = sum(not d for d in self.ts_dead.values())
        return {"pairings": len(self.part1), "part1_survivors": sum(1 for x in self.part1 if x[2]),
                "pairings_with_6plus_full_pairs": sum(1 for x in self.part1 if x[3] >= MIN_FULL),
                "part2_pairings": len(self.pairings),
                "two_square_settings": len(self.ts_dead), "two_square_possible_for_some_squares": ts_live,
                "four_square_settings": self.fs_settings,
                "four_square_possible_for_some_cipher_squares": len(self.fs)}


def scan(plan, chunk):
    """chunk: [(index, alphabet)]. Returns (two-square single-square survivors, four-square square hits).

    two-square: (grid number, lid, side, row key, alphabet index, config number)
    four-square: (sid, square 1 or 2, alphabet index, grid number, config number)"""
    out2, out4 = [], []
    for gi, g in enumerate(GRIDS):
        cols, rows = plan.cols[g], plan.rows[g]
        tsi, fsi = plan.ts_index[g], plan.fs_index[g]
        fget = fsi.get
        for ci, cfg in enumerate(plan.cfgs[g]):
            for ai, alpha in chunk:
                s = cells(alpha, g, cfg)
                col = dict(zip(s, cols))
                row = None
                for first, lst in tsi:
                    if first is not None and col[first[0]] != col[first[1]]:
                        continue
                    for rest, lid, side, lk in lst:
                        for u, v in rest:
                            if col[u] != col[v]:
                                break
                        else:
                            if row is None:
                                row = dict(zip(s, rows))
                            out2.append((gi, lid, side, bytes([row[t] for t in lk]), ai, ci))
                if fsi:
                    for k, ch in enumerate(s):
                        hit = fget((k, ch))
                        if hit:
                            for rest, sid, sq in hit:
                                for kk, cc in rest:
                                    if s[kk] != cc:
                                        break
                                else:
                                    out4.append((sid, sq, ai, gi, ci))
    return out2, out4


def join2(hits):
    """Two-square: pair up S1 and S2 survivors whose row keys agree. Yields (grid number, lid, s1 hit, s2 hit)."""
    left = defaultdict(list)
    for h in hits:
        if h[2] == 1:
            left[h[0], h[1], h[3]].append(h)
    for h in hits:
        if h[2] == 2:
            for m in left.get((h[0], h[1], h[3]), ()):
                yield h[0], h[1], m, h


def join4(hits):
    """Four-square: a setting needs a Q1 hit and a Q2 hit. Yields (sid, q1 hit, q2 hit)."""
    one = defaultdict(list)
    for h in hits:
        if h[1] == 1:
            one[h[0]].append(h)
    for h in hits:
        if h[1] == 2:
            for m in one.get(h[0], ()):
                yield h[0], m, h
