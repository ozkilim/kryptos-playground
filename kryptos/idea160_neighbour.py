"""Idea 160: find the letter on the copper, write its neighbour.

A reference text is a set of cells (a carved panel, or K1-K3's plaintext written into the cells its
ciphertext is carved in) plus a reading order through them. A pointer sits on one cell.

  forward role   (the decoder searches)  go on to the next cell holding the K4 letter; the plain letter
                 is the cell at a fixed offset from it. One start cell gives one 97-letter reading.
  reverse role   (the encoder searches)  go on to the next cell holding the PLAIN letter and write the
                 letter at the offset. Easy to encode, but the decoder must guess; on the clue words the
                 walk is fixed by the plain letters, so they can be tested exactly from every pointer.

Pointer rules: 'same' (the found cell may be used again at once), 'next' (search strictly after it),
'one-on' (skip one more cell), 'row-reset' (as 'next', back to the start cell at every carved K4 row),
'jump' (the finger moves to the neighbour that was written).
"""
import json

from . import K4, load
from .ciphers import AZ
from .data import DATA_DIR, letters

N = 97
ROWSTARTS = (0, 4, 35, 66)         # K4 as carved: OBKR, then three rows of 31
MORSE = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUSHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ"
RULES = ("same", "next", "one-on", "row-reset", "jump")
STEP = {"same": 0, "next": 1, "one-on": 2, "row-reset": 1}
A2I = {c: i for i, c in enumerate(AZ)}

GRID_OFFS = ([(0, d) for d in (1, 2, 3, -1, -2, -3)] + [(d, 0) for d in (1, 2, 3, -1, -2, -3)]
             + [(-1, 2), (-2, 1), (1, 2), (-1, -2), (-2, -1), (1, -2), (2, 1), (2, -1)]
             + [(-1, 1), (-1, -1), (1, 1), (1, -1)])
PATH_OFFS = (1, 2, 3, -1, -2, -3)


def off_name(o):
    if isinstance(o, int):
        return "%+d along the reading order" % o
    return "(%+d rows, %+d cells)" % o


def panels(k4=K4):
    """{name: rows}. '?' is a carved cell that matches no letter. k4 fills the K4 cells (a control
    ciphertext must sit in the panel itself, or K4 and the controls would not get the same test)."""
    lay = json.load(open(DATA_DIR / "sculpture_layout.json"))
    cp, tp = lay["cipher_panel"], lay["tableau_panel"]
    k1, k2, k3 = load("k1"), load("k2"), load("k3")
    ct = k1["ciphertext"] + k2["ciphertext"] + k3["ciphertext"] + "?"
    assert "".join(cp) == ct + K4, "cipher panel does not match K1-K4"
    pt = k1["plaintext"] + k2["plaintext"] + k3["plaintext"] + "?"
    assert len(pt) == len(ct)

    def lay_out(text):
        rows, o = [], 0
        for row in cp:
            rows.append("".join(ch if ch.isalpha() else "?" for ch in text[o:o + len(row)]))
            o += len(row)
        return rows
    cc, pp = lay_out(ct + k4), lay_out(pt + k4)      # K1-K3 plaintext in the cells of its ciphertext
    cut = cp[24].index("?") + 1                      # K4 starts after the '?' in row 24
    return {
        "cipher panel, K1-K3 cells only": cc[:24] + [cc[24][:cut]],
        "cipher panel, all 28 rows": cc,
        "K1-K3 plaintext in the carved cells": pp[:24] + [pp[24][:cut]],
        "K1-K3 plaintext in the carved cells, then K4": pp,
        "tableau panel, all 28 rows": tp,
        "tableau body (26 rows, no label column)": [r[1:] for r in tp[1:-1]],
        "Morse text": [MORSE],
    }


def _next_table(T):
    """nxt[q][letter] = first place j >= q (going round) holding the letter, or -1."""
    n = len(T)
    last, nxt = [-1] * 26, [None] * n
    for j in range(2 * n - 1, -1, -1):
        x = T[j % n]
        if x != "?":
            last[A2I[x]] = j % n
        if j < n:
            nxt[j] = last[:]
    return nxt


class Text:
    """One panel with one alignment and one reading order.

    self.offs holds one entry per offset and edge convention: (offset, edge, E, J, nxt), where E[j] is
    the letter written when the cell at place j is found, J[j] the place of that neighbour, and nxt the
    search table. edge = 'skip': a cell whose neighbour is missing (off the panel, or a '?') does not
    count as an occurrence. edge = 'hole': it counts, and the reading gets a '?' there."""

    def __init__(self, name, rows, align="left", order="rows"):
        self.name = "%s, %s-aligned, %s" % (name, align, order)
        w = max(len(r) for r in rows)
        cells, ch = [], []
        for r, row in enumerate(rows):
            sh = 0 if align == "left" else w - len(row)
            for c, x in enumerate(row):
                cells.append((r, c + sh))
                ch.append(x if x.isalpha() else "?")
        at = {rc: i for i, rc in enumerate(cells)}
        ids = list(range(len(cells)))
        if order.startswith("columns"):
            ids.sort(key=lambda i: (cells[i][1], cells[i][0]))
        if order.endswith("backwards"):
            ids.reverse()
        self.n = n = len(ids)
        self.T = T = "".join(ch[i] for i in ids)
        where = {cid: j for j, cid in enumerate(ids)}
        self.cell = [cells[i] for i in ids]
        base = _next_table(T)
        self.offs, self._cand = [], {}
        todo = [o for o in GRID_OFFS if len(rows) > 1 or not o[0]] + list(PATH_OFFS)
        for o in todo:
            if isinstance(o, int):
                J = [(j + o) % n for j in range(n)]
            else:
                J = [where[at[(cells[i][0] + o[0], cells[i][1] + o[1])]]
                     if (cells[i][0] + o[0], cells[i][1] + o[1]) in at else -1 for i in ids]
            E = "".join(T[j] if j >= 0 else "?" for j in J)
            masked = "".join(t if e != "?" else "?" for t, e in zip(T, E))
            self.offs.append((o, "skip", E, J, base if masked == T else _next_table(masked)))
            if masked != T:
                self.offs.append((o, "hole", E, J, base))

    def off(self, o, edge="skip"):
        return next(i for i, t in enumerate(self.offs) if t[0] == o and t[1] == edge)

    def off_label(self, oi):
        o, edge = self.offs[oi][:2]
        return off_name(o) + ("" if edge == "skip" else ", edge cells leave a hole")

    # ------------------------------------------------------------------ walking
    def walk(self, seq, rule, s, oi, base=0):
        """Places found when searching the letters of seq in turn from pointer s (-1: letter absent)."""
        o, edge, E, J, nxt = self.offs[oi]
        n, q, out = self.n, s, []
        if rule == "jump":
            for ch in seq:
                x = nxt[q][A2I[ch]]
                out.append(x)
                if x >= 0:
                    q = (J[x] + 1) % n if J[x] >= 0 else (x + 1) % n
            return out
        g = STEP[rule]
        reset = rule == "row-reset"
        for i, ch in enumerate(seq):
            if reset and (base + i) in ROWSTARTS:
                q = s
            x = nxt[q][A2I[ch]]
            out.append(x)
            if x >= 0:
                q = (x + g) % n
        return out

    def _groups(self, seq, rule, oi, base=0):
        """Start cells grouped by the walk they give: [(one start, how many starts)]."""
        nxt = self.offs[oi][4]
        firsts = [i for i in range(len(seq)) if i == 0 or (rule == "row-reset" and (base + i) in ROWSTARTS)]
        idx = [A2I[seq[i]] for i in firsts]
        groups = {}
        for s in range(self.n):
            row = nxt[s]
            key = tuple(row[a] for a in idx)
            if -1 in key:
                key = ("s", s)
            g = groups.get(key)
            if g is None:
                groups[key] = [s, 1]
            else:
                g[1] += 1
        return list(groups.values())

    def readings(self, ct, rules=RULES):
        """Forward role: yields (rule, offset index, reading, start, number of starts giving it)."""
        for oi in range(len(self.offs)):
            E = self.offs[oi][2]
            for rule in rules:
                for s, m in self._groups(ct, rule, oi):
                    yield rule, oi, "".join([E[x] if x >= 0 else "?" for x in self.walk(ct, rule, s, oi)]), s, m

    def read(self, ct, rule, oi, s):
        E = self.offs[oi][2]
        return "".join(E[x] if x >= 0 else "?" for x in self.walk(ct, rule, s, oi))

    # ------------------------------------------------------------- reverse role
    def write(self, pt, rule, oi, s):
        """Reverse-role encoder: search the plain letter, write the neighbour. None if it cannot."""
        E = self.offs[oi][2]
        xs = self.walk(pt, rule, s, oi)
        if any(x < 0 or E[x] == "?" for x in xs):
            return None
        return "".join(E[x] for x in xs)

    def segment_fit(self, search, emit, rule, oi, base):
        """Most places where searching `search` from some pointer emits `emit`.

        With 'row-reset' the segment is cut at the carved rows and each piece gets its own free pointer,
        which can only make the count larger (an upper bound)."""
        E = self.offs[oi][2]
        cuts = [0] + [i for i in range(1, len(search)) if rule == "row-reset" and (base + i) in ROWSTARTS] + [len(search)]
        r, tot = ("next" if rule == "row-reset" else rule), 0
        for a, b in zip(cuts, cuts[1:]):
            seq, want, best = search[a:b], emit[a:b], 0
            for s, m in self._groups(seq, r, oi):
                c = sum(1 for x, w in zip(self.walk(seq, r, s, oi), want) if x >= 0 and E[x] == w)
                if c > best:
                    best = c
            tot += best
        return tot

    # --------------------------------------------- choosing letters (encode forwards / decode reverse)
    def cand(self, rule, oi):
        """cand[q][target] = [(letter to search, place found, pointer afterwards)]."""
        key = (rule, oi)
        if key not in self._cand:
            o, edge, E, J, nxt = self.offs[oi]
            n, out = self.n, []
            g = STEP.get(rule, 1)
            for q in range(n):
                d = {}
                for a, x in enumerate(nxt[q]):
                    if x >= 0 and E[x] != "?":
                        nq = (J[x] + 1) % n if rule == "jump" else (x + g) % n
                        d.setdefault(E[x], []).append((AZ[a], x, nq))
                out.append(d)
            self._cand[key] = out
        return self._cand[key]

    def feasible(self, target, rule, oi, forced=None, s=None):
        """feas[i] = pointers from which target[i:] can be produced (forced: {i: searched letter}).

        'row-reset' needs the start s: the pointer returns to s at every carved row."""
        cand, forced = self.cand(rule, oi), forced or {}
        feas = [None] * (len(target) + 1)
        feas[len(target)] = nx = set(range(self.n))
        for i in range(len(target) - 1, -1, -1):
            t, f = target[i], forced.get(i)
            if rule == "row-reset" and (i + 1) in ROWSTARTS:
                ok = {q for q in range(self.n) if any(f is None or L == f for L, x, nq in cand[q].get(t, ()))} \
                    if s in nx else set()
            else:
                ok = {q for q in range(self.n)
                      if any(nq in nx and (f is None or L == f) for L, x, nq in cand[q].get(t, ()))}
            feas[i] = nx = ok
        return feas

    def encode(self, pt, rule, oi, s, rng):
        """Forward-role encoder: choose cipher letters so that the decoder's walk from s reads pt.
        Looks ahead, so it never walks into a dead end; None if pt cannot be written from s."""
        cand = self.cand(rule, oi)
        feas = self.feasible(pt, rule, oi, s=s)
        if s not in feas[0]:
            return None
        q, out = s, []
        for i, p in enumerate(pt):
            if rule == "row-reset" and i in ROWSTARTS:
                q = s
            back = rule == "row-reset" and (i + 1) in ROWSTARTS
            L, x, nq = rng.choice([c for c in cand[q].get(p, ()) if (s if back else c[2]) in feas[i + 1]])
            out.append(L)
            q = nq
        return "".join(out)

    def decode_reverse(self, ct, cribs, rule, oi, model, beam=400):
        """Reverse role, whole message: plaintexts whose encoding is ct and that hold the clue letters,
        searched with a beam ranked on English. Returns (start pointers that can finish,
        [(score per quadgram, text)]). Not for 'row-reset'."""
        cand = self.cand(rule, oi)
        feas = self.feasible(ct, rule, oi, forced=cribs)
        get, floor = model.logp.get, model.floor
        states = {(q, ""): 0.0 for q in feas[0]}
        for i, c in enumerate(ct):
            new, f, nx = {}, cribs.get(i), feas[i + 1]
            for (q, text), sc in states.items():
                for L, x, nq in cand[q].get(c, ()):
                    if nq in nx and (f is None or L == f):
                        t = text + L
                        v = sc + (get(t[-4:], floor) if len(t) >= 4 else 0.0)
                        if v > new.get((nq, t), -1e9):
                            new[(nq, t)] = v
            if len(new) > beam:
                new = dict(sorted(new.items(), key=lambda kv: -kv[1])[:beam])
            states = new
            if not states:
                break
        best = {}
        for (q, text), sc in states.items():
            if len(text) == len(ct) and sc > best.get(text, -1e9):
                best[text] = sc
        return len(feas[0]), sorted(((sc / (len(ct) - 3), t) for t, sc in best.items()), reverse=True)

    def reach(self, pt, rule, oi):
        """Forward role: how many letters of pt can be encoded from the best start before every walk dies."""
        cand = self.cand(rule, oi)
        cur = set(range(self.n))
        for i, p in enumerate(pt):
            cur = {nq for q in cur for L, x, nq in cand[q].get(p, ())}
            if not cur:
                return i
        return len(pt)


def all_texts(k4=K4, smoke=False):
    out = []
    for name, rows in panels(k4).items():
        if len(rows) == 1:
            out += [Text(name, rows, "left", o) for o in ("rows", "rows backwards")]
            continue
        if smoke and name not in ("cipher panel, K1-K3 cells only", "K1-K3 plaintext in the carved cells",
                                  "tableau panel, all 28 rows"):
            continue
        for align in ("left", "right"):
            for order in ("rows", "rows backwards", "columns", "columns backwards"):
                out.append(Text(name, rows, align, order))
    return out


def clue_count(reading, cribs):
    return sum(1 for i, p in cribs.items() if reading[i] == p)


def english_message(rng, n=N):
    """English that is not on the sculpture (Python's help pages)."""
    from . import fingerprint as FP
    eng = english_message.__dict__.setdefault("eng", FP.english_windows())
    o = rng.randrange(len(eng) - n)
    return eng[o:o + n]


def word_message(T, rule, oi, s, rng, n=N, tries=400):
    """Common English words strung together so that the forward-role encoder can write every letter
    from start s (ordinary prose almost never can: see Text.reach). None if it gets stuck."""
    from . import wordkeys
    words = word_message.__dict__.setdefault("w", [w for w in wordkeys.common_words(4000) if 3 <= len(w) <= 9])
    cand, text, cur = T.cand(rule, oi), "", {s}
    while len(text) < n:
        for _ in range(tries):
            w, c, ok = rng.choice(words)[:n - len(text)], cur, True
            for k, p in enumerate(w):
                if rule == "row-reset" and (len(text) + k) in ROWSTARTS:
                    c = {s}
                c = {nq for q in c for L, x, nq in cand[q].get(p, ())}
                if not c:
                    ok = False
                    break
            if ok:
                text, cur = text + w, c
                break
        else:
            return None
    return text


__all__ = ["Text", "all_texts", "panels", "clue_count", "english_message", "letters", "RULES", "N", "ROWSTARTS"]
