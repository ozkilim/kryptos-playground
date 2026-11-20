"""Helpers for idea 162: the coordinate-slip cipher ("shifting matrices" taken literally).

One hidden grid of R x C cells holds the 26 letters (spare cells stay empty). Every plain letter is written
as two digits, its row over its column. One line of digits is slid along, and the columns of digits are read
back as letters in the same grid:

  mode "RC" (straight):  row(c_i) = row(p_{i+u}) + a  (mod R)     col(c_i) = col(p_{i+w}) + b  (mod C)
  mode "CR" (crossed):   row(c_i) = col(p_{i+u})                  col(c_i) = row(p_{i+w})

The idea as stated has one line at home: (u, w) = (0, s) or (s, 0). Crossed digits only exist when the digit
is small enough for the other axis (a column digit 5 is not a row of a 5x6 grid), so on a grid that is not
square the crossed cipher cannot encipher every letter; the solver simply requires the clue letters to fit.

With the grid free, each clue letter gives statements "letter X is in the row of letter Y (plus a)". The
question "is there ANY grid of this shape that gives the clue letters?" is decided exactly by `feasible`:
weighted union-find, then backtracking over the classes with no two letters in one cell and no row or
column over its capacity (the method of idea 139, extended to one grid, added constants and crossed digits).

Only statements whose two letters are both inside the 97 are used, so the verdict holds whatever the
encipherer did at the ends of the text. The planted encryptor wraps round (mod 97).
"""
import random
from collections import defaultdict

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
GRIDS = ((2, 13), (13, 2), (3, 9), (9, 3), (4, 7), (7, 4), (5, 6), (6, 5))
N = 97


def gname(g):
    return "%dx%d" % g


# ---------------------------------------------------------------- the clue statements

def conditions(ct, cribs, mode, u, w, a=0, b=0, wrap=False):
    """[(node, node, d)]: value(node1) = value(node2) + d. A node is (letter, axis), axis 0 row, 1 column.

    wrap=False: only statements with both letters inside the text. wrap=True: the digit lines wrap round."""
    eq = []
    n = len(ct)
    for j, p in cribs.items():
        i = j - u
        if wrap or 0 <= i < n:
            i %= n
            eq.append(((ct[i], 0), (p, 0), a) if mode == "RC" else ((ct[i], 0), (p, 1), 0))
        i = j - w
        if wrap or 0 <= i < n:
            i %= n
            eq.append(((ct[i], 1), (p, 1), b) if mode == "RC" else ((ct[i], 1), (p, 0), 0))
    return eq


def overlap(u, w, n=N):
    """How many of the n letters have both digits inside the text when nothing wraps."""
    return max(0, n - max(u, w, 0) + min(u, w, 0))


class _Limit(Exception):
    pass


def feasible(eq, grid, mode, a=0, b=0, limit=200000):
    """Exact decision: (True, {letter: (row, col)}) / (False, None) / (None, None) when the node limit is hit."""
    R, C = grid
    size = (R, C)
    crossed = mode == "CR"
    # weighted union-find: off[x] = value(x) - value(root)   (mod the axis size; all zero when crossed)
    par, off = {}, {}

    def find(x):
        if x not in par:
            par[x] = x
            off[x] = 0
            return x, 0
        path = []
        while par[x] != x:
            path.append(x)
            x = par[x]
        tot = 0
        for y in reversed(path):
            tot += off[y]
            off[y] = tot
            par[y] = x
        return x, (off[path[0]] if path else 0)

    letters = set()
    for x, y, d in eq:
        letters.add(x[0])
        letters.add(y[0])
        m = size[x[1]]
        rx, ox = find(x)
        ry, oy = find(y)
        if rx == ry:
            if not crossed and (ox - oy - d) % m:
                return False, None
        else:
            par[rx] = ry
            off[rx] = (oy + d - ox) % m if not crossed else 0
    letters = sorted(letters)
    cls = {}                                   # root -> class number
    dom, system = [], []
    lr, lc = [], []                            # per letter: (class, offset) for row and for column
    for ch in letters:
        for ax, store in ((0, lr), (1, lc)):
            r, o = find((ch, ax))
            if r not in cls:
                cls[r] = len(cls)
                dom.append(size[ax])
                system.append(0 if crossed else ax)
            k = cls[r]
            if size[ax] < dom[k]:
                dom[k] = size[ax]
            store.append((k, 0 if crossed else o % size[ax]))
    ncls = len(cls)
    nl = len(letters)
    # quick tests: two letters forced into one cell; a row / column class over capacity
    seen = set()
    cnt = defaultdict(int)
    for n in range(nl):
        key = (lr[n], lc[n])
        if key in seen:
            return False, None
        seen.add(key)
        cnt[0, lr[n]] += 1
        cnt[1, lc[n]] += 1
    for (ax, _), m in cnt.items():
        if m > (C if ax == 0 else R):
            return False, None
    if crossed:
        # a letter whose row and column are the same class sits on the diagonal: fine, nothing to test
        pass
    touch = [[] for _ in range(ncls)]
    for n in range(nl):
        touch[lr[n][0]].append(n)
        if lc[n][0] != lr[n][0]:
            touch[lc[n][0]].append(n)
    # order: biggest class first, then the class that completes the most letters
    order, chosen, score = [], [False] * ncls, [0] * ncls
    while len(order) < ncls:
        k = max((x for x in range(ncls) if not chosen[x]), key=lambda x: (score[x], len(touch[x]), -dom[x]))
        chosen[k] = True
        order.append(k)
        for n in touch[k]:
            score[lr[n][0]] += 1
            score[lc[n][0]] += 1
    # symmetry: where no constant is added, digit names can be permuted, so hand values out in first-use
    # order. Crossed: one system, values below min(R, C) are one pool, the rest a second pool.
    # With a constant only a rotation is free: the first class of that system is put at 0.
    low = min(R, C) if crossed else None
    free = [True, True] if crossed else [a % R == 0, b % C == 0]
    val = [-1] * ncls
    occ = {}
    rowcnt, colcnt = [0] * R, [0] * C
    used = [0, 0]                              # straight: per axis. crossed: [low pool, high pool]
    started = [False, False]
    budget = [limit]

    def assign(k, v):
        val[k] = v
        done = []
        for n in touch[k]:
            (rk, ro), (ck, co) = lr[n], lc[n]
            if rk == k:
                x = (v + ro) % R if not crossed else v
                rowcnt[x] += 1
                done.append((0, x))
                if rowcnt[x] > C:
                    undo(done)
                    val[k] = -1
                    return None
            if ck == k:
                x = (v + co) % C if not crossed else v
                colcnt[x] += 1
                done.append((1, x))
                if colcnt[x] > R:
                    undo(done)
                    val[k] = -1
                    return None
            if val[rk] >= 0 and val[ck] >= 0:
                cell = ((val[rk] + ro) % R, (val[ck] + co) % C) if not crossed else (val[rk], val[ck])
                if cell in occ:
                    undo(done)
                    val[k] = -1
                    return None
                occ[cell] = n
                done.append((2, cell))
        return done

    def undo(done):
        for kind, x in reversed(done):
            if kind == 0:
                rowcnt[x] -= 1
            elif kind == 1:
                colcnt[x] -= 1
            else:
                del occ[x]

    def candidates(k):
        """[(value, undo token)]"""
        if crossed:
            out = [(v, None) for v in range(min(dom[k], used[0], low))]
            if used[0] < min(dom[k], low):
                out.append((used[0], 0))
            if dom[k] > low:
                out += [(v, None) for v in range(low, low + used[1])]
                if low + used[1] < dom[k]:
                    out.append((low + used[1], 1))
            return out
        s = system[k]
        if free[s]:
            out = [(v, None) for v in range(min(dom[k], used[s]))]
            if used[s] < dom[k]:
                out.append((used[s], s))
            return out
        if not started[s]:
            return [(0, s + 10)]
        return [(v, None) for v in range(dom[k])]

    def dfs(d):
        if d == ncls:
            return True
        budget[0] -= 1
        if budget[0] < 0:
            raise _Limit
        k = order[d]
        for v, tok in candidates(k):
            done = assign(k, v)
            if done is None:
                continue
            if tok is not None:
                if tok >= 10:
                    started[tok - 10] = True
                else:
                    used[tok] += 1
            if dfs(d + 1):
                return True
            if tok is not None:
                if tok >= 10:
                    started[tok - 10] = False
                else:
                    used[tok] -= 1
            undo(done)
            val[k] = -1
        return False

    try:
        ok = dfs(0)
    except _Limit:
        return None, None
    if not ok:
        return False, None
    place = {}
    for n, ch in enumerate(letters):
        (rk, ro), (ck, co) = lr[n], lc[n]
        place[ch] = ((val[rk] + ro) % R, (val[ck] + co) % C) if not crossed else (val[rk], val[ck])
    return True, place


def decide(ct, cribs, grid, mode, u, w, a=0, b=0, limit=200000, wrap=False):
    return feasible(conditions(ct, cribs, mode, u, w, a, b, wrap), grid, mode, a, b, limit)


# ---------------------------------------------------------------- grids

def build_grid(place, grid, rng=None):
    """Complete a partial placement into a full grid string (row by row, '.' for an empty cell)."""
    R, C = grid
    rng = rng or random.Random(0)
    cells = ["."] * (R * C)
    for ch, (r, c) in place.items():
        assert cells[r * C + c] == ".", "two letters in one cell"
        cells[r * C + c] = ch
    rest = [ch for ch in AZ if ch not in place]
    spots = [k for k in range(R * C) if cells[k] == "."]
    rng.shuffle(spots)
    for ch, k in zip(rest, spots):
        cells[k] = ch
    return "".join(cells)


def positions(cells, C):
    return {ch: divmod(k, C) for k, ch in enumerate(cells) if ch != "."}


def check_grid(ct, cribs, cells, grid, mode, u, w, a=0, b=0, wrap=False):
    """Independent check of a full grid against every clue statement, straight from the cipher rule."""
    R, C = grid
    pos = positions(cells, C)
    if len(pos) != 26:
        return False
    n = len(ct)
    for j, p in cribs.items():
        pr, pc = pos[p]
        i = j - u
        if wrap or 0 <= i < n:
            if pos[ct[i % n]][0] != ((pr + a) % R if mode == "RC" else pc):
                return False
        i = j - w
        if wrap or 0 <= i < n:
            if pos[ct[i % n]][1] != ((pc + b) % C if mode == "RC" else pr):
                return False
    return True


def random_grid(grid, rng):
    R, C = grid
    cells = list(AZ) + ["."] * (R * C - 26)
    rng.shuffle(cells)
    return "".join(cells)


FILLS = ("rows", "cols", "rows.first", "cols.first")


def keyword_grid(alpha, grid, fill="rows"):
    """A 26-letter alphabet written into the grid by rows or by columns; spare cells last (or first)."""
    R, C = grid
    spare = R * C - 26
    seq = ("." * spare + alpha) if fill.endswith(".first") else (alpha + "." * spare)
    if fill.startswith("rows"):
        return seq
    cells = [None] * (R * C)
    for k, ch in enumerate(seq):
        c, r = divmod(k, R)
        cells[r * C + c] = ch
    return "".join(cells)


# ---------------------------------------------------------------- the cipher itself

def encrypt(pt, cells, grid, mode, u, w, a=0, b=0):
    """Wraps round the end of the text. Returns None when a digit pair is not a cell of the grid, and puts
    '.' where the pair lands on an empty cell."""
    R, C = grid
    pos = positions(cells, C)
    n = len(pt)
    out = []
    for i in range(n):
        p1, p2 = pos[pt[(i + u) % n]], pos[pt[(i + w) % n]]
        if mode == "RC":
            r, c = (p1[0] + a) % R, (p2[1] + b) % C
        else:
            r, c = p1[1], p2[0]
            if r >= R or c >= C:
                return None
        out.append(cells[r * C + c])
    return "".join(out)


def decrypt(ct, cells, grid, mode, u, w, a=0, b=0, wrap=True):
    """'?' where the letter cannot be read (empty cell, digit out of range, or off the end with wrap=False)."""
    R, C = grid
    pos = positions(cells, C)
    n = len(ct)
    out = []
    for j in range(n):
        i1, i2 = j - u, j - w
        if not wrap and not (0 <= i1 < n and 0 <= i2 < n):
            out.append("?")
            continue
        q1, q2 = pos.get(ct[i1 % n]), pos.get(ct[i2 % n])
        if q1 is None or q2 is None:
            out.append("?")
            continue
        if mode == "RC":
            r, c = (q1[0] - a) % R, (q2[1] - b) % C
        else:
            r, c = q2[1], q1[0]
            if r >= R or c >= C:
                out.append("?")
                continue
        ch = cells[r * C + c]
        out.append("?" if ch == "." else ch)
    return "".join(out)


def ioc(s):
    n = len(s)
    cnt = defaultdict(int)
    for ch in s:
        cnt[ch] += 1
    return sum(v * (v - 1) for v in cnt.values()) / (n * (n - 1))


# ---------------------------------------------------------------- dictionary grids for a surviving setting

def dictionary_hits(ct, cribs, alphabets, grid, mode, u, w, a=0, b=0, fills=FILLS, wrap=False):
    """[(name, fill, cells)] for every keyword grid that gives all the clue statements."""
    R, C = grid
    eq = conditions(ct, cribs, mode, u, w, a, b, wrap)
    size = (R, C)
    # as index tests on the alphabet: coordinate of a letter from its place k in the fill sequence
    spare = R * C - 26
    hits = []
    for fill in fills:
        shift = spare if fill.endswith(".first") else 0
        byrows = fill.startswith("rows")
        coord = []                              # coord[k] = (row, col) of the letter at alphabet place k
        for k in range(26):
            q = k + shift
            coord.append(divmod(q, C) if byrows else (q % R, q // R))
        tests = []
        for (x, ax), (y, ay), d in eq:
            tests.append((x, ax, y, ay, d, size[ax]))
        if fill.endswith(".first") and not spare:
            continue                            # same grid as the plain fill
        for name, alpha in alphabets:
            idx = alpha.index
            for x, ax, y, ay, d, m in tests:
                vx, vy = coord[idx(x)][ax], coord[idx(y)][ay]
                if (vx != (vy + d) % m) if mode == "RC" else (vx != vy):
                    break
            else:
                hits.append((name, fill, keyword_grid(alpha, grid, fill)))
    return hits
