"""Helpers for idea 139: four-square and two-square on 26/27-cell rectangles with ALL squares free.

No alphabet list. Every clue letter pair says where letters sit relative to each other:

  four-square, plain squares P1 (top left), P2 (bottom right), cipher squares Q1 (top right), Q2 (bottom
  left), plain pair (a, b), cipher (x, y) in order A (order B writes x, y the other way):
      row(x in Q1) = row(a in P1)     col(x in Q1) = col(b in P2)
      row(y in Q2) = row(b in P2)     col(y in Q2) = col(a in P1)
  two-square (side by side, idea 103's rule), squares S1, S2, a in S1, b in S2, order A:
      row(x in S2) = row(a in S1)     col(x in S2) = col(b in S2)
      row(y in S1) = row(b in S2)     col(y in S1) = col(a in S1)
  (order B swaps x and y; "one above the other" is the turned grid, which is in the grid list.)

A half-known pair (one plain letter known) still gives the two equalities that use that letter.

So the question is: can we give every (square, letter) a row and a column so that all the equalities hold
and no two letters of one square share a cell? If yes, the remaining letters fill the empty cells in any
order and the result is a real set of squares that encrypts every clue letter correctly. If no, the cipher
is impossible on that grid for EVERY choice of squares. This module decides it exactly by backtracking.

The labels split into independent "systems" (rows shared by P1 and Q1, rows shared by P2 and Q2, columns
shared by P1 and Q2, columns shared by P2 and Q1), and renaming the values inside one system changes nothing,
so values are handed out in first-use order (symmetry breaking).
"""
import random
from collections import defaultdict

from kryptos.idea103_matrix import GRIDS, pair_list, stream  # noqa: F401

# square -> (row system, column system); systems 0, 1 are rows (R values), 2, 3 are columns (C values)
FOUR = {"P1": (0, 2), "Q1": (0, 3), "P2": (1, 3), "Q2": (1, 2)}
TWO = {"S1": (0, 2), "S2": (0, 3)}


def conditions(ct, cribs, w, o, cipher, order, with_q=False):
    """[((square, letter, axis), (square, letter, axis))] equalities; axis 0 = row, 1 = column.

    ct is the 97-letter text (letter i = ct[i]); pairs with no clue letter say nothing. with_q (27-cell
    grids): the carved ? is letter -1 and pairs with letter w - 1 when a block starts on it."""
    eq = []
    st = stream(ct)
    for i, j in pair_list(w, o, with_q=with_q):
        a, b = cribs.get(i), cribs.get(j)
        x, y = (st[i + 1], st[j + 1]) if order == "A" else (st[j + 1], st[i + 1])
        if cipher == "four":
            if a:
                eq.append((("Q1", x, 0), ("P1", a, 0)))
                eq.append((("Q2", y, 1), ("P1", a, 1)))
            if b:
                eq.append((("Q1", x, 1), ("P2", b, 1)))
                eq.append((("Q2", y, 0), ("P2", b, 0)))
        else:
            if a:
                eq.append((("S2", x, 0), ("S1", a, 0)))
                eq.append((("S1", y, 1), ("S1", a, 1)))
            if b:
                eq.append((("S2", x, 1), ("S2", b, 1)))
                eq.append((("S1", y, 0), ("S2", b, 0)))
    return eq


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
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb


def feasible(eq, grid, cipher, limit=2_000_000):
    """Exact decision. Returns (True, assignment) / (False, None) / (None, None) when the node limit is hit.

    assignment: {(square, letter): (row, col)} for every letter the clues touch."""
    R, C = grid
    squares = FOUR if cipher == "four" else TWO
    uf = _UF()
    for u, v in eq:
        uf.union(u, v)
    letters = defaultdict(set)                     # square -> letters touched
    for u, v in eq:
        for s, ch, _ in (u, v):
            letters[s].add(ch)
    # classes
    cls_id = {}
    nodes = []                                     # (square, letter, row class, col class)
    for s in sorted(letters):
        for ch in sorted(letters[s]):
            ids = []
            for ax in (0, 1):
                root = uf.find((s, ch, ax))
                if root not in cls_id:
                    cls_id[root] = (len(cls_id), squares[s][ax])
                ids.append(cls_id[root][0])
            nodes.append((s, ch, ids[0], ids[1]))
    ncls = len(cls_id)
    system = [0] * ncls
    for root, (k, sy) in cls_id.items():
        system[k] = sy
    dom = [R if system[k] < 2 else C for k in range(ncls)]
    # quick test: two letters of one square in the same row class and the same column class
    seen = set()
    for s, ch, r, c in nodes:
        if (s, r, c) in seen:
            return False, None
        seen.add((s, r, c))
    sq_index = {s: n for n, s in enumerate(sorted(letters))}
    # per-class list of nodes; per square occupancy and row / column counts
    touch = [[] for _ in range(ncls)]
    for n, (s, ch, r, c) in enumerate(nodes):
        touch[r].append(n)
        if c != r:
            touch[c].append(n)
    # quick capacity test: a row class holding more than C letters of one square, a column class more than R
    cnt = defaultdict(int)
    for s, ch, r, c in nodes:
        cnt[s, r] += 1
        cnt[s, c] += 1
    for (s, k), m in cnt.items():
        if m > (C if system[k] < 2 else R):
            return False, None
    # variable order: most-constrained classes first (by number of letters), grouped greedily by adjacency
    # static order: start from the biggest class, then always take the class that completes the most letters
    # (both coordinates known), so cell clashes show up as early as possible
    partner = [[] for _ in range(ncls)]
    for s, ch, r, c in nodes:
        partner[r].append(c)
        partner[c].append(r)
    order, chosen = [], [False] * ncls
    score = [0] * ncls
    while len(order) < ncls:
        k = max((x for x in range(ncls) if not chosen[x]), key=lambda x: (score[x], len(touch[x])))
        chosen[k] = True
        order.append(k)
        for p in partner[k]:
            score[p] += 1
    val = [-1] * ncls
    nsq = len(sq_index)
    occ = [dict() for _ in range(nsq)]
    rowcnt = [[0] * R for _ in range(nsq)]
    colcnt = [[0] * C for _ in range(nsq)]
    used = [0, 0, 0, 0]                            # values handed out so far in each system
    nodes_si = [(sq_index[s], r, c) for s, ch, r, c in nodes]
    budget = [limit]

    def assign(k, v):
        """Set class k = v; returns the list of undo actions, or None on a clash (already undone)."""
        val[k] = v
        done = []
        for n in touch[k]:
            si, r, c = nodes_si[n]
            if k == r:
                rowcnt[si][v] += 1
                done.append(("r", si, v))
                if rowcnt[si][v] > C:
                    undo(done)
                    val[k] = -1
                    return None
            if k == c:
                colcnt[si][v] += 1
                done.append(("c", si, v))
                if colcnt[si][v] > R:
                    undo(done)
                    val[k] = -1
                    return None
            if val[r] >= 0 and val[c] >= 0:
                cell = (val[r], val[c])
                if cell in occ[si]:
                    undo(done)
                    val[k] = -1
                    return None
                occ[si][cell] = n
                done.append(("o", si, cell))
        return done

    def undo(done):
        for kind, si, x in reversed(done):
            if kind == "r":
                rowcnt[si][x] -= 1
            elif kind == "c":
                colcnt[si][x] -= 1
            else:
                del occ[si][x]

    def dfs(d):
        if d == ncls:
            return True
        budget[0] -= 1
        if budget[0] < 0:
            raise _Limit
        k = order[d]
        sy = system[k]
        top = min(dom[k], used[sy] + 1)
        for v in range(top):
            done = assign(k, v)
            if done is None:
                continue
            fresh = v == used[sy]
            if fresh:
                used[sy] += 1
            if dfs(d + 1):
                return True
            if fresh:
                used[sy] -= 1
            undo(done)
            val[k] = -1
        return False

    try:
        ok = dfs(0)
    except _Limit:
        return None, None
    if not ok:
        return False, None
    return True, {(s, ch): (val[r], val[c]) for s, ch, r, c in nodes}


class _Limit(Exception):
    pass


def build_squares(assign, grid, cipher, rng=None):
    """Fill the free cells: {square: cell string} that satisfies the assignment (other letters at random)."""
    R, C = grid
    rng = rng or random.Random(0)
    names = FOUR if cipher == "four" else TWO
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + ("?" if R * C == 27 else "")
    out = {}
    for s in names:
        cells = [None] * (R * C)
        placed = set()
        for (ss, ch), (r, c) in assign.items():
            if ss == s:
                cells[r * C + c] = ch
                placed.add(ch)
        rest = [ch for ch in alpha if ch not in placed]
        rng.shuffle(rest)
        for k in range(R * C):
            if cells[k] is None:
                cells[k] = rest.pop()
        out[s] = "".join(cells)
    return out


# ---------------------------------------------------------------- encryption (for planted answers and checks)

def _rc(sq, C):
    return {ch: divmod(k, C) for k, ch in enumerate(sq)}


def four_square(text, w, o, grid, sq, order="A", decrypt=False):
    """text: 97 letters. Returns the 97-letter result (unpaired letters pass through)."""
    R, C = grid
    p1, p2, q1, q2 = sq["P1"], sq["P2"], sq["Q1"], sq["Q2"]
    s = list(text)
    if not decrypt:
        a1, a2 = _rc(p1, C), _rc(p2, C)
        for i, j in pair_list(w, o):
            (ra, ca), (rb, cb) = a1[s[i]], a2[s[j]]
            x, y = q1[ra * C + cb], q2[rb * C + ca]
            s[i], s[j] = (x, y) if order == "A" else (y, x)
    else:
        b1, b2 = _rc(q1, C), _rc(q2, C)
        for i, j in pair_list(w, o):
            x, y = (s[i], s[j]) if order == "A" else (s[j], s[i])
            (ra, cb), (rb, ca) = b1[x], b2[y]
            s[i], s[j] = p1[ra * C + ca], p2[rb * C + cb]
    return "".join(s)


def two_square(text, w, o, grid, sq, order="A", decrypt=False):
    R, C = grid
    s1, s2 = sq["S1"], sq["S2"]
    a1, a2 = _rc(s1, C), _rc(s2, C)
    s = list(text)
    for i, j in pair_list(w, o):
        if not decrypt:
            (ra, ca), (rb, cb) = a1[s[i]], a2[s[j]]
            x, y = s2[ra * C + cb], s1[rb * C + ca]
            s[i], s[j] = (x, y) if order == "A" else (y, x)
        else:
            x, y = (s[i], s[j]) if order == "A" else (s[j], s[i])
            (ra, cb), (rb, ca) = a2[x], a1[y]
            s[i], s[j] = s1[ra * C + ca], s2[rb * C + cb]
    return "".join(s)


def random_squares(grid, cipher, rng):
    alpha = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ" + ("?" if grid[0] * grid[1] == 27 else ""))
    out = {}
    for s in (FOUR if cipher == "four" else TWO):
        a = alpha[:]
        rng.shuffle(a)
        out[s] = "".join(a)
    return out


def decide(ct, cribs, w, o, grid, cipher, order, limit=2_000_000):
    """(verdict, assignment): verdict True feasible, False impossible for every square, None undecided."""
    return feasible(conditions(ct, cribs, w, o, cipher, order, grid[0] * grid[1] == 27), grid, cipher, limit)


def check_assignment(ct, cribs, w, o, grid, cipher, order, assign, rng=None):
    """Build real squares from an assignment and confirm they encrypt every clue letter (an independent check)."""
    sq = build_squares(assign, grid, cipher, rng)
    if "?" in "".join(sq.values()) and grid[0] * grid[1] != 27:
        return False
    f = four_square if cipher == "four" else two_square
    # decrypt the cipher: every clue letter in a pair must come back. A "?" cell would decrypt to "?",
    # which can only happen for an unknown letter, never for a clue letter.
    try:
        pt = f(ct, w, o, grid, sq, order, decrypt=True)
    except KeyError:
        return False
    paired = {k for p in pair_list(w, o) for k in p}
    return all(pt[i] == ch for i, ch in cribs.items() if i in paired)
