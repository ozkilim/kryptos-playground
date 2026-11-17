"""Idea 82: exact test for two rotors in series when both wirings are hidden.

    Y = R1[P + s] - e1*s          first rotor, turned s
    C = R2[Y + t] - e2*t          second rotor, turned t        (e1, e2 = +1 or -1)

Y is never seen. Writing q for R2 backwards, every clue letter gives one equation between a
contact of R1 and a contact of R2:

    R1[u] - q[v] = e1*s - t       with  u = P + s,  v = C + e2*t          (mod 26)

So the clue letters draw a graph: 26 input contacts on one side, 26 output contacts on the other,
one weighted edge per clue letter. Two things can go wrong for a wrong setting:

  * a closed loop of edges whose weights do not add up        (chance 1/26 to pass by luck)
  * inside one connected piece, two different contacts of the same rotor forced onto the same
    letter (a wiring is one-to-one)                           (chance 25/26 to pass: weak)

Only loops are strong. 24 edges on up to 52 contacts make few loops, which is the whole story
of this idea: see attacks/82_two_paper_rotors.py for the honest count.
"""


def loops(us, vs, ws):
    """Edges R1[u] - q[v] = w (mod 26). Returns -1 if no pair of real wirings fits, else the
    number of closed loops (each one a forced coincidence that came out right)."""
    comp, off, members = {}, {}, {}
    n = 0
    for u, v, w in zip(us, vs, ws):
        v += 26
        cu, cv = comp.get(u), comp.get(v)
        if cu is None:
            if cv is None:
                comp[u] = comp[v] = u
                off[u], off[v] = w % 26, 0
                members[u] = [u, v]
            else:
                comp[u] = cv
                off[u] = (off[v] + w) % 26
                members[cv].append(u)
        elif cv is None:
            comp[v] = cu
            off[v] = (off[u] - w) % 26
            members[cu].append(v)
        elif cu == cv:
            if (off[u] - off[v] - w) % 26:
                return -1
            n += 1
        else:
            d = (off[u] - w - off[v]) % 26        # add d to every offset in v's piece
            mu = members[cu]
            for x in members.pop(cv):
                comp[x] = cu
                off[x] = (off[x] + d) % 26
                mu.append(x)
    for m in members.values():
        if len(m) > 2:
            seen = set()
            for x in m:
                key = off[x] if x < 26 else off[x] + 26
                if key in seen:
                    return -1
                seen.add(key)
    return n


def edges(pv, cv, s, t, e1=1, e2=1):
    """The graph for clue plain values pv, cipher values cv, rotor turns s (first) and t (second)."""
    us = [(p + a) % 26 for p, a in zip(pv, s)]
    vs = [(c + e2 * b) % 26 for c, b in zip(cv, t)]
    ws = [(e1 * a - b) % 26 for a, b in zip(s, t)]
    return us, vs, ws


def test(pv, cv, s, t, e1=1, e2=1):
    us, vs, ws = edges(pv, cv, s, t, e1, e2)
    return loops(us, vs, ws)


def encrypt(pt_vals, r1, r2, s, t, e1=1, e2=1):
    out = []
    for p, a, b in zip(pt_vals, s, t):
        y = (r1[(p + a) % 26] - e1 * a) % 26
        out.append((r2[(y + b) % 26] - e2 * b) % 26)
    return out


def back_pieces(us, vs, ws):
    """One strip there and back: R[u] - R[v] = w, both contacts on the same strip.
    Returns None if no real wiring fits, else (loops, pieces): each piece is a list of
    (contact, value) known up to one constant per piece."""
    comp, off, members = {}, {}, {}
    n = 0
    for u, v, w in zip(us, vs, ws):
        if u == v:
            if w % 26:
                return None
            n += 1
            continue
        cu, cv = comp.get(u), comp.get(v)
        if cu is None:
            if cv is None:
                comp[u] = comp[v] = u
                off[u], off[v] = w % 26, 0
                members[u] = [u, v]
            else:
                comp[u] = cv
                off[u] = (off[v] + w) % 26
                members[cv].append(u)
        elif cv is None:
            comp[v] = cu
            off[v] = (off[u] - w) % 26
            members[cu].append(v)
        elif cu == cv:
            if (off[u] - off[v] - w) % 26:
                return None
            n += 1
        else:
            d = (off[u] - w - off[v]) % 26
            mu = members[cu]
            for x in members.pop(cv):
                comp[x] = cu
                off[x] = (off[x] + d) % 26
                mu.append(x)
    for m in members.values():
        if len(set(off[x] for x in m)) != len(m):
            return None
    return n, [[(x, off[x]) for x in m] for m in members.values()]


def loops_back(us, vs, ws):
    """The same test when the second rotor is the first one read backwards (one strip, there and
    back). Returns -1 or the number of loops."""
    r = back_pieces(us, vs, ws)
    return -1 if r is None else r[0]


def back_wirings(pieces, limit=3000):
    """Every way to put the pieces on one strip (the biggest piece is pinned: adding a constant
    to the whole wiring changes nothing). Contacts no clue letter touches stay None. An empty
    list means the pieces cannot share a strip at all: the setting is dead."""
    pieces = sorted(pieces, key=len, reverse=True)
    wiring, used, out = [None] * 26, set(), []

    def place(k):
        if len(out) >= limit:
            return
        if k == len(pieces):
            out.append(list(wiring))
            return
        for sh in (range(26) if k else (0,)):
            vals = [(o + sh) % 26 for _, o in pieces[k]]
            if any(v in used for v in vals):
                continue
            for (x, _), v in zip(pieces[k], vals):
                wiring[x] = v
            used.update(vals)
            place(k + 1)
            used.difference_update(vals)
    place(0)
    return out


def back_decrypt(wiring, cv, s, t, e1=1, e2=1):
    """Plain values for cipher values cv under one strip there and back (None where the strip
    is not known)."""
    inv = {v: x for x, v in enumerate(wiring) if v is not None}
    out = []
    for c, a, b in zip(cv, s, t):
        y = wiring[(c + e2 * b) % 26]
        u = None if y is None else inv.get((y + e1 * a - b) % 26)
        out.append(None if u is None else (u - a) % 26)
    return out
