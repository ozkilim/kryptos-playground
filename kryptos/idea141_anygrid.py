"""Idea 141 helpers: king moves on ANY hidden letter grid.

Idea 123 wrote listed alphabets into grids and asked whether every clue pair (plain, cipher) is one
compass step apart. Here the grid is free: the 26 letters may sit in any cells. The question becomes a
puzzle about the clue graph: letters are points, every clue pair with two different letters is an edge,
and the letters must be put on different cells so that every edge joins two cells a king move apart.
Letters outside the clues fill whatever cells are left, so only the clue letters matter.

Grids and wrap conventions are those of kryptos/idea123_compass.py (rows of width w, last row short;
flat / cwrap / twrap). With 27 cells one cell stays empty, and it may be any cell.

solve() decides the puzzle exactly by backtracking: the next letter is always the one with the fewest
cells left (cells next to all its placed neighbours and still free), tried on every such cell. A
budget on the number of different moves (distinct (drow, dcol), "stay" included, as D in idea 123)
turns the same search into "is there a grid that needs at most D directions"; min_dirs() raises the
budget from an exact lower bound until a grid appears. Searches stop at a node limit and then say
"undecided" instead of guessing.
"""
import random

from .ciphers.substitution import AZ
from .idea123_compass import CONVS, SIZES, WIDTHS, move

GRIDS = [(n, w, conv) for n in SIZES for w in WIDTHS for conv in CONVS]
STAY = (0, 0)
_GEO = {}


class Limit(Exception):
    pass


def geometry(n, w, conv):
    """(nb, code): nb[i] = bit mask of the cells one king move from cell i; code[i][j] = the move i -> j."""
    key = (n, w, conv)
    g = _GEO.get(key)
    if g is None:
        nb = [0] * n
        code = [[None] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                dr, dc = move(i, j, n, w, conv)
                code[i][j] = (dr, dc)
                if i != j and max(abs(dr), abs(dc)) <= 1:
                    nb[i] |= 1 << j
        g = _GEO[key] = (nb, code)
    return g


def clue_pairs(ct, cribs):
    return [(cribs[i], ct[i]) for i in sorted(cribs)]


def graph(pairs):
    """letters (most edges first), directed edges without repeats, and whether some letter stays."""
    edges = sorted({(p, c) for p, c in pairs if p != c})
    deg = {}
    for p, c in edges:
        deg[p] = deg.get(p, 0) + 1
        deg[c] = deg.get(c, 0) + 1
    letters = sorted(deg, key=lambda x: (-deg[x], x))
    return letters, edges, any(p == c for p, c in pairs)


def lower_bound(pairs):
    """Fewest different moves any grid needs: the moves out of one plain letter to different cipher
    letters are all different, and so are the moves into one cipher letter; plus "stay" if used."""
    _, edges, loop = graph(pairs)
    out, inn = {}, {}
    for p, c in edges:
        out[p] = out.get(p, 0) + 1
        inn[c] = inn.get(c, 0) + 1
    return max(list(out.values()) + list(inn.values()) + [0]) + (1 if loop else 0)


def rings(pairs):
    """Independent closed rings in the clue graph (lines - letters + pieces). A graph without rings
    is a tree: any proper choice of moves lays it out, only room and collisions can stop it."""
    letters, edges, _ = graph(pairs)
    par = {ch: ch for ch in letters}

    def find(x):
        while par[x] != x:
            x = par[x]
        return x
    for p, c in edges:
        par[find(p)] = find(c)
    return len(edges) - len(letters) + len({find(ch) for ch in letters})


def solve(pairs, n, w, conv, maxdirs=None, limit=2000000, want=1, pinned=None):
    """Exact search. Returns (verdict, solutions, nodes): verdict "SAT", "UNSAT" or "LIMIT";
    solutions = up to `want` placements {letter: cell} of the clue letters.
    pinned: {letter: cell} fixed in advance (the search then lists the grids that agree with it)."""
    letters, edges, loop = graph(pairs)
    if len(letters) > n:
        return "UNSAT", [], 0
    nb, code = geometry(n, w, conv)
    ix = {ch: k for k, ch in enumerate(letters)}
    m = len(letters)
    und = [[] for _ in range(m)]            # undirected neighbours
    outs = [[] for _ in range(m)]           # v -> u
    ins = [[] for _ in range(m)]            # u -> v
    for p, c in edges:
        a, b = ix[p], ix[c]
        und[a].append(b)
        und[b].append(a)
        outs[a].append(b)
        ins[b].append(a)
    budget = None if maxdirs is None else maxdirs - (1 if loop else 0)
    if budget is not None and budget < 0:
        return "UNSAT", [], 0
    full = (1 << n) - 1
    pos = [-1] * m
    used_dirs = {}
    sols = []
    nodes = [0]
    mask0 = 0
    for ch, x in (pinned or {}).items():
        if ch in ix:
            if (mask0 >> x) & 1:
                return "UNSAT", [], 0
            pos[ix[ch]] = x
            mask0 |= 1 << x
    for p, c in edges:
        a, b = pos[ix[p]], pos[ix[c]]
        if a >= 0 and b >= 0:
            if not (nb[a] >> b) & 1:
                return "UNSAT", [], 0
            used_dirs[code[a][b]] = 1
    if budget is not None and len(used_dirs) > budget:
        return "UNSAT", [], 0
    start = sum(1 for x in pos if x >= 0)

    def rec(placed, usedmask):
        if placed == m:
            sols.append({letters[k]: pos[k] for k in range(m)})
            return len(sols) >= want
        best, bdom, bcnt = -1, 0, 99
        for v in range(m):
            if pos[v] >= 0:
                continue
            dom = full & ~usedmask
            touched = False
            for u in und[v]:
                if pos[u] >= 0:
                    dom &= nb[pos[u]]
                    touched = True
            if not touched:
                continue
            if not dom:
                return False
            cnt = bin(dom).count("1")
            if cnt < bcnt:
                best, bdom, bcnt = v, dom, cnt
                if cnt == 1:
                    break
        if best < 0:                         # a new piece of the graph: its busiest letter, any free cell
            best = next(v for v in range(m) if pos[v] < 0)
            bdom = full & ~usedmask
        v = best
        while bdom:
            bit = bdom & -bdom
            bdom ^= bit
            x = bit.bit_length() - 1
            nodes[0] += 1
            if nodes[0] > limit:
                raise Limit()
            added = None
            if budget is not None:
                added = []
                ok = True
                for u in outs[v]:
                    if pos[u] >= 0:
                        d = code[x][pos[u]]
                        if d not in used_dirs:
                            if len(used_dirs) >= budget:
                                ok = False
                                break
                            used_dirs[d] = 1
                            added.append(d)
                if ok:
                    for u in ins[v]:
                        if pos[u] >= 0:
                            d = code[pos[u]][x]
                            if d not in used_dirs:
                                if len(used_dirs) >= budget:
                                    ok = False
                                    break
                                used_dirs[d] = 1
                                added.append(d)
                if not ok:
                    for d in added:
                        del used_dirs[d]
                    continue
            pos[v] = x
            done = rec(placed + 1, usedmask | bit)
            pos[v] = -1
            if added:
                for d in added:
                    del used_dirs[d]
            if done:
                return True
        return False

    try:
        rec(start, mask0)
    except Limit:
        return ("SAT" if sols else "LIMIT"), sols, nodes[0]
    return ("SAT" if sols else "UNSAT"), sols, nodes[0]


def min_dirs(pairs, n, w, conv, limit=300000, top=9):
    """Smallest number of different moves (stay included) over all grids.
    Returns (lo, hi, placement): lo == hi when exact; hi None when no grid was found up to `top`."""
    lo = lower_bound(pairs)
    exact = True
    for d in range(lo, top + 1):
        v, sols, _ = solve(pairs, n, w, conv, maxdirs=d, limit=limit)
        if v == "SAT":
            return (d if exact else lo), d, sols[0]
        if v == "LIMIT":
            exact = False
        elif exact:
            lo = d + 1
    return lo, None, None


def check(place, pairs, n, w, conv):
    """Independent check of a placement {letter: cell}: different cells, every clue pair a king move or
    a stay. Returns the number of different moves, or None if the placement is wrong."""
    cells = [place[ch] for ch in place]
    if len(set(cells)) != len(cells) or any(not 0 <= c < n for c in cells):
        return None
    moves = set()
    for p, c in pairs:
        if p == c:                           # a stay: fine wherever the letter sits
            moves.add(STAY)
            continue
        if p not in place or c not in place:
            return None
        dr, dc = move(place[p], place[c], n, w, conv)
        if max(abs(dr), abs(dc)) > 1 or (dr, dc) == STAY:
            return None
        moves.add((dr, dc))
    return len(moves)


def complete(place, n, rng=None):
    """A full grid (string of n cells, '.' for the empty one) holding the placement; the other letters
    go into the free cells (in A-Z order, or shuffled if rng is given)."""
    cellsfree = [i for i in range(n) if i not in set(place.values())]
    rest = [ch for ch in AZ if ch not in place]
    if rng is not None:
        rng.shuffle(cellsfree)
    grid = ["."] * n
    for ch, i in place.items():
        grid[i] = ch
    for ch, i in zip(rest, cellsfree):
        grid[i] = ch
    return "".join(grid)


def show(grid, w):
    return "\n".join(" ".join(grid[r:r + w]) for r in range(0, len(grid), w))


# ------------------------------------------------------------------ planted grids

def random_grid(n, rng):
    """The 26 letters in random cells of an n-cell grid ('.' = the empty cell when n = 27)."""
    g = list(AZ) + ["."] * (n - 26)
    rng.shuffle(g)
    return "".join(g)


def encrypt(text, grid, w, conv, rng, steps=None):
    """Every letter moved by a random king move (or stay) to a neighbouring letter of the hidden grid.
    steps: allowed moves (a list of (drow, dcol)); a letter that none of them can move stays."""
    n = len(grid)
    nb, code = geometry(n, w, conv)
    ix = {ch: i for i, ch in enumerate(grid) if ch != "."}
    out = []
    for ch in text:
        i = ix[ch]
        opts = [j for j in range(n) if (nb[i] >> j) & 1 and grid[j] != "."
                and (steps is None or code[i][j] in steps)]
        if steps is None or STAY in steps or not opts:
            opts.append(i)
        out.append(grid[rng.choice(opts)])
    return "".join(out)


def grid_place(grid, pairs):
    """The placement of the clue letters that a full grid gives."""
    need = {ch for p, c in pairs for ch in (p, c) if p != c}
    return {ch: i for i, ch in enumerate(grid) if ch in need}


def shuffled_pairs(ct, cribs, seed):
    s = list(ct)
    random.Random(seed).shuffle(s)
    return [(cribs[i], s[i]) for i in sorted(cribs)]
