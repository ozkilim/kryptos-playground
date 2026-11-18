"""Idea 123 helpers: compass steps on a letter grid.

An alphabet (26 letters, or 27 cells with '?' as the last cell) is written in rows of width w,
last row short. A plain letter sits in cell (r, c); the key gives a compass move (dr, dc) and the
cipher letter is the letter in cell (r + dr, c + dc). Three conventions:

  flat   no wrap: the move must stay inside the grid (and off the empty cells of the last row)
  cwrap  columns wrap: c + dc is taken mod w (the target must still be a filled cell)
  twrap  both wrap: rows are also taken mod the number of rows (target must be filled)

For the clue letters the move from each plain letter to its cipher letter is read off the grid
as the shortest such move. Statistics per grid:
  R = largest king distance max(|dr|, |dc|) of the 24 moves (R = 1: every move is a compass step)
  D = number of different moves
  Q = number of moves on one of the 8 compass lines (dr = 0, dc = 0 or |dr| = |dc|)

Everything is done with precomputed 27x27 tables per (cells, width, convention).
"""
import math

from .ciphers.substitution import AZ

CONVS = ("flat", "cwrap", "twrap")
WIDTHS = tuple(range(3, 14))
SIZES = (26, 27)
STEPS = [(dr, dc) for dr in (-1, 0, 1) for dc in (-1, 0, 1)]
NB = 13                                  # first block has 13 clue pairs, second 11


def _signed(d, m):
    d %= m
    return d - m if d > m // 2 else d


def move(i, j, n, w, conv):
    """Shortest move from cell i to cell j (row-major, n cells, width w) under a convention."""
    ri, ci, rj, cj = i // w, i % w, j // w, j % w
    dr, dc = rj - ri, cj - ci
    if conv in ("cwrap", "twrap"):
        alts = [dc, dc - w, dc + w]
        dc = min(alts, key=lambda x: (abs(x), x))
    if conv == "twrap":
        rows = -(-n // w)
        alts = [dr, dr - rows, dr + rows]
        dr = min(alts, key=lambda x: (abs(x), x))
    return dr, dc


def target(i, step, n, w, conv):
    """Cell reached from cell i by step (dr, dc), or None if it is off the grid / empty."""
    rows = -(-n // w)
    r, c = i // w + step[0], i % w + step[1]
    if conv in ("cwrap", "twrap"):
        c %= w
    elif not 0 <= c < w:
        return None
    if conv == "twrap":
        r %= rows
    elif not 0 <= r < rows:
        return None
    j = r * w + c
    if conv == "twrap" and j >= n:
        # a short last row: wrapping rows lands in an empty cell; step over the empty cells
        return None
    return j if 0 <= j < n else None


_TABLES = {}


def tables(n, w, conv):
    """(dist, code, line) as flat lists indexed i*27+j."""
    key = (n, w, conv)
    t = _TABLES.get(key)
    if t is None:
        dist, code, line = [99] * 729, [-1] * 729, [0] * 729
        for i in range(n):
            for j in range(n):
                dr, dc = move(i, j, n, w, conv)
                k = i * 27 + j
                dist[k] = max(abs(dr), abs(dc))
                code[k] = (dr + 20) * 64 + dc + 20
                line[k] = 1 if (dr == 0 or dc == 0 or abs(dr) == abs(dc)) else 0
        t = _TABLES[key] = (dist, code, line)
    return t


GRIDS = [(n, w, conv) for n in SIZES for w in WIDTHS for conv in CONVS]


def cells(alpha, n):
    """letter -> cell index; '?' is the 27th cell."""
    a = alpha + ("?" if n == 27 else "")
    return {ch: i for i, ch in enumerate(a)}


def keys(alpha, n, pl, cl):
    ix = cells(alpha, n)
    return [ix[p] * 27 + ix[c] for p, c in zip(pl, cl)]


def stats(ks, tab):
    """Per part (all, b1, b2): (R, D, Q)."""
    dist, code, line = tab
    d = [dist[k] for k in ks]
    m = [code[k] for k in ks]
    q = [line[k] for k in ks]
    a = (max(d), len(set(m)), sum(q))
    b1 = (max(d[:NB]), len(set(m[:NB])), sum(q[:NB]))
    b2 = (max(d[NB:]), len(set(m[NB:])), sum(q[NB:]))
    return a, b1, b2


def chance_r1(alpha, n, w, conv, pl):
    """Chance that random cipher letters give R = 1: product over pairs of |neighbourhood| / n."""
    ix = cells(alpha, n)
    dist = tables(n, w, conv)[0]
    lp = 0.0
    for p in pl:
        i = ix[p]
        nb = sum(1 for j in range(n) if dist[i * 27 + j] <= 1 and (n == 26 or j < 26))
        lp += math.log(nb / 26.0)
    return math.exp(lp)


# ------------------------------------------------------------------ encrypt / decode

def encrypt(text, alpha, n, w, conv, rng):
    """Every letter moved by a random compass step (or stay) that lands on a letter cell."""
    a = alpha + ("?" if n == 27 else "")
    ix = cells(alpha, n)
    out = []
    for ch in text:
        i = ix[ch]
        opts = []
        for s in STEPS:
            j = target(i, s, n, w, conv)
            if j is not None and a[j] != "?":
                opts.append(j)
        out.append(a[rng.choice(opts)])
    return "".join(out)


def candidates(alpha, n, w, conv):
    """cipher letter -> plain letters one compass step (or stay) away."""
    ix = cells(alpha, n)
    dist = tables(n, w, conv)[0]
    out = {}
    for c in AZ:
        j = ix[c]
        out[c] = [p for p in AZ if dist[ix[p] * 27 + j] <= 1]
    return out


class Model:
    """Big quadgram model as a dict and a small-gram backoff for the beam start."""

    def __init__(self, path):
        from .score import Quadgrams
        q = Quadgrams(path)
        self.q, self.floor = q.logp, q.floor
        tri = {}
        for g, lp in q.logp.items():
            tri[g[:3]] = tri.get(g[:3], 0.0) + 10 ** lp
        self.tri = {g: math.log10(v) for g, v in tri.items()}


def beam_decode(ct, cribs, cand, model, width=3000):
    """Beam search: each cipher letter becomes one of its candidates; clue letters fixed."""
    q, fl, tri = model.q, model.floor, model.tri
    beam = [(0.0, "")]
    for i, c in enumerate(ct):
        opts = [cribs[i]] if i in cribs else cand[c]
        nxt = {}
        for s, t in beam:
            for p in opts:
                u = t + p
                if len(u) >= 4:
                    v = s + q.get(u[-4:], fl)
                elif len(u) == 3:
                    v = s + tri.get(u, fl)
                else:
                    v = s
                key = u[-3:]
                old = nxt.get(key)
                if old is None or v > old[0]:
                    nxt[key] = (v, u)
        beam = sorted(nxt.values(), reverse=True)[:width]
    return beam[0][1]


class Words:
    """Unigram word model (data/english/words_big.txt) as a trie, for a segmentation decode."""

    def __init__(self, path, junk=-6.0):
        cnt = {}
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2 and parts[0].isalpha():
                    w = parts[0].upper()
                    if len(w) == 1 and w not in "AI":
                        continue
                    cnt[w] = cnt.get(w, 0) + int(parts[1])
        tot = float(sum(cnt.values()))
        self.trie = {}
        for w, c in cnt.items():
            node = self.trie
            for ch in w:
                node = node.setdefault(ch, {})
            node["$"] = math.log10(c / tot)
        self.junk = junk


def word_decode(ct, cribs, cand, words):
    """Best split into dictionary words (unigram) with a per-letter penalty for junk letters."""
    n = len(ct)
    opts = [[cribs[i]] if i in cribs else cand[c] for i, c in enumerate(ct)]
    best = [(-1e18, "")] * (n + 1)
    best[0] = (0.0, "")
    for i in range(n):
        s0, t0 = best[i]
        if s0 < -1e17:
            continue
        # junk letter: take the first candidate (cipher-letter itself if allowed) - cheap filler
        for p in opts[i][:1] if False else opts[i]:
            v = s0 + words.junk
            if v > best[i + 1][0]:
                best[i + 1] = (v, t0 + p)
            break
        stack = [(words.trie, i, "")]
        while stack:
            node, j, pre = stack.pop()
            if "$" in node and j > i:
                v = s0 + node["$"]
                if v > best[j][0]:
                    best[j] = (v, t0 + pre)
            if j < n:
                for p in opts[j]:
                    nx = node.get(p)
                    if nx is not None:
                        stack.append((nx, j + 1, pre + p))
    return best[n][1]


def polish(start, ct, cribs, cand, model, beta=1.5, sweeps=4):
    """Coordinate ascent on big-model quadgram mean + beta * word coverage."""
    from .score import word_coverage
    q, fl = model.q, model.floor

    def f(t):
        return sum(q.get(t[i:i + 4], fl) for i in range(len(t) - 3)) / (len(t) - 3) + beta * word_coverage(t)

    cur = list(start)
    best = f(start)
    for _ in range(sweeps):
        moved = False
        for i, c in enumerate(ct):
            if i in cribs:
                continue
            keep = cur[i]
            for p in cand[c]:
                if p == keep:
                    continue
                cur[i] = p
                v = f("".join(cur))
                if v > best + 1e-12:
                    best, keep, moved = v, p, True
            cur[i] = keep
        if not moved:
            break
    return "".join(cur), best


def decode(ct, cribs, cand, model, words):
    """Viterbi on quadgrams and the word split, each polished; the better objective wins."""
    outs = [polish(beam_decode(ct, cribs, cand, model), ct, cribs, cand, model),
            polish(word_decode(ct, cribs, cand, words), ct, cribs, cand, model)]
    return max(outs, key=lambda x: x[1])[0]
