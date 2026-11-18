"""Idea 134: one hidden strip R used twice in the same direction.

    C = R[ R[P + s] - s + t ] - t          (mod 26)

Write x = P + s (the contact the letter enters), u = t - s and z = C + t. Then every clue letter
says: R sends x to some a, and R sends a + u to z. Equivalently  Rinv[z] = R[x] + u.

`solve` is an exact backtracking search over R for one setting: forced contacts are propagated,
the clue with fewest choices is branched on, and two contacts on one letter kill a branch.
It returns the list of partial wirings (contacts the clues force; others None) or [] if none fits.

`prefilter` is a fast necessary test used before the backtracking: clues that share an entry
contact x share a; clues that share an exit letter z share a + u. These give exact equations
a_x - a_x' = const between entry contacts (weighted union-find); a loop that does not add up, or
two entry contacts forced onto one letter, kills the setting.
"""


def encrypt(pv, r, s, t):
    return [(r[(r[(p + a) % 26] - a + b) % 26] - b) % 26 for p, a, b in zip(pv, s, t)]


def decrypt(cv, r, s, t):
    """Letters where the partial wiring r (None = unknown) decides them, else None."""
    ri = [None] * 26
    for i, y in enumerate(r):
        if y is not None:
            ri[y] = i
    out = []
    for c, a, b in zip(cv, s, t):
        w = ri[(c + b) % 26]
        if w is None:
            out.append(None)
            continue
        v = ri[(w + a - b) % 26]
        out.append(None if v is None else (v - a) % 26)
    return out


def prefilter(xs, us, zs):
    """Necessary condition. Returns False if no wiring can fit."""
    # same x: same a. same z: a_x + u = a_x' + u'.
    par, off = {}, {}

    def find(v):
        o = 0
        while par[v] != v:
            o += off[v]
            v = par[v]
        return v, o % 26

    seen_z = {}
    for x, u, z in zip(xs, us, zs):
        if x not in par:
            par[x], off[x] = x, 0
        if z in seen_z:
            x2, u2 = seen_z[z]
            # a_x + u = a_x2 + u2  ->  a_x - a_x2 = u2 - u
            w = (u2 - u) % 26
            r1, o1 = find(x)       # a_x = a_r1 + o1
            r2, o2 = find(x2)
            if r1 == r2:
                if (o1 - o2 - w) % 26:
                    return False
            else:                  # a_r1 = a_r2 + o2 + w - o1
                par[r1], off[r1] = r2, (o2 + w - o1) % 26
        else:
            seen_z[z] = (x, u)
    # same x, different u must go to different z  (already implied by z-equations for same z);
    # one piece: different x need different a; the same (x, u) pair needs the same z.
    groups = {}
    for x in par:
        r, o = find(x)
        g = groups.setdefault(r, set())
        if o in g:
            return False
        g.add(o)
    xu = {}
    for x, u, z in zip(xs, us, zs):
        if xu.setdefault((x, u), z) != z:
            return False
    return True


def solve(xs, us, zs, limit=1, node_cap=200000):
    """All (up to `limit`) partial wirings that satisfy every clue. Returns (solutions, nodes,
    complete) where complete is False if the node cap stopped the search."""
    cons = sorted(set(zip(xs, us, zs)))
    n = len(cons)
    byx = [[] for _ in range(26)]
    byz = [[] for _ in range(26)]
    for k, (x, u, z) in enumerate(cons):
        byx[x].append(k)
        byz[z].append(k)
    sols = []
    nodes = [0]

    def assign(R, Ri, d, r, stack):
        if R[d] == r:
            return True
        if R[d] >= 0 or Ri[r] >= 0:
            return False
        R[d] = r
        Ri[r] = d
        stack.append((d, r))
        return True

    def propagate(R, Ri, done, stack):
        i = 0
        while i < len(stack):
            d, r = stack[i]
            i += 1
            for k in byx[d]:
                if not done[k]:
                    x, u, z = cons[k]
                    done[k] = True
                    if not assign(R, Ri, (r + u) % 26, z, stack):
                        return False
            for k in byz[r]:
                if not done[k]:
                    x, u, z = cons[k]
                    done[k] = True
                    if not assign(R, Ri, x, (d - u) % 26, stack):
                        return False
            # a newly set contact can also be the hidden middle of a resolved clue: covered,
            # since every resolved clue has both its contacts set.
        return True

    def rec(R, Ri, done):
        nodes[0] += 1
        if nodes[0] > node_cap or len(sols) >= limit:
            return
        best, bopts = -1, None
        for k in range(n):
            if done[k]:
                continue
            x, u, z = cons[k]
            opts = []
            for a in range(26):
                if Ri[a] >= 0:
                    continue
                m = (a + u) % 26
                if m == x:
                    if a == z:
                        opts.append(a)
                    continue
                if a == z or R[m] >= 0:
                    continue
                opts.append(a)
            if best < 0 or len(opts) < len(bopts):
                best, bopts = k, opts
                if not opts:
                    return
        if best < 0:
            sols.append(list(R))
            return
        x, u, z = cons[best]
        for a in bopts:
            R2, Ri2, done2 = list(R), list(Ri), list(done)
            stack = []
            done2[best] = True
            if assign(R2, Ri2, x, a, stack) and assign(R2, Ri2, (a + u) % 26, z, stack) and \
                    propagate(R2, Ri2, done2, stack):
                rec(R2, Ri2, done2)
            if len(sols) >= limit or nodes[0] > node_cap:
                return

    rec([-1] * 26, [-1] * 26, [False] * n)
    return [[None if v < 0 else v for v in s] for s in sols], nodes[0], nodes[0] <= node_cap


def test(pv, cv, s, t):
    """pv, cv, s, t over the clue places. Returns (status, solutions, nodes):
    status 'dead' (prefilter or search), 'alive', or 'cap'."""
    xs = [(p + a) % 26 for p, a in zip(pv, s)]
    us = [(b - a) % 26 for a, b in zip(s, t)]
    zs = [(c + b) % 26 for c, b in zip(cv, t)]
    if not prefilter(xs, us, zs):
        return "dead", [], 0
    sols, nodes, complete = solve_fast(xs, us, zs)
    if sols:
        return "alive", sols, nodes
    return ("dead" if complete else "cap"), [], nodes


def _pieces(xs, us, zs):
    """Union-find of entry contacts through shared exit letters. Returns None (dead) or
    (X, K): X[ci] = [(x, offset)], K[ci] = {w: z} with the middle contact a_x + u = v + w."""
    cons = sorted(set(zip(xs, us, zs)))
    par, off = {}, {}

    def find(v):
        o = 0
        while par[v] != v:
            o += off[v]
            v = par[v]
        return v, o % 26
    seen_z = {}
    for x, u, z in cons:
        if x not in par:
            par[x], off[x] = x, 0
        if z in seen_z:
            x2, u2 = seen_z[z]
            w = (u2 - u) % 26
            r1, o1 = find(x)
            r2, o2 = find(x2)
            if r1 == r2:
                if (o1 - o2 - w) % 26:
                    return None
            else:
                par[r1], off[r1] = r2, (o2 + w - o1) % 26
        else:
            seen_z[z] = (x, u)
    roots, xinfo = {}, {}
    for x in par:
        r, o = find(x)
        roots.setdefault(r, len(roots))
        xinfo[x] = (roots[r], o)
    nc = len(roots)
    X = [[] for _ in range(nc)]
    K = [{} for _ in range(nc)]
    for x, (ci, o) in xinfo.items():
        X[ci].append((x, o))
    for x, u, z in cons:
        ci, o = xinfo[x]
        if K[ci].setdefault((o + u) % 26, z) != z:
            return None
    for ci in range(nc):
        if len(set(o for _, o in X[ci])) != len(X[ci]):
            return None
    return X, K


def _search(X, K, limit, node_cap):
    nc = len(X)
    xinfo, zinfo = {}, {}
    for ci in range(nc):
        for x, o in X[ci]:
            xinfo[x] = (ci, o)
        for w, z in K[ci].items():
            zinfo[z] = (ci, w)
    allowed = []
    for ci in range(nc):
        ok = [True] * 26
        for x, o in X[ci]:
            for w, z in K[ci].items():
                v = (x - w) % 26
                if (v + o - z) % 26:
                    ok[v] = False
                v = (z - o) % 26
                if (v + w - x) % 26:
                    ok[v] = False
        al = [v for v in range(26) if ok[v]]
        if not al:
            return [], 0, True
        allowed.append((al, ok))
    order = sorted(range(nc), key=lambda c: (len(allowed[c][0]), -len(K[c])))
    sols = []
    nodes = [0]

    def place(R, Ri, val, ci, v):
        """Set piece ci to v and propagate. Returns False on a clash."""
        queue = [(ci, v)]
        while queue:
            ci, v = queue.pop()
            if val[ci] >= 0:
                if val[ci] != v:
                    return False
                continue
            if not allowed[ci][1][v]:
                return False
            val[ci] = v
            pairs = [(x, (v + o) % 26) for x, o in X[ci]] + [((v + w) % 26, z) for w, z in K[ci].items()]
            for d, r in pairs:
                if R[d] == r:
                    continue
                if R[d] >= 0 or Ri[r] >= 0:
                    return False
                R[d] = r
                Ri[r] = d
                xi = xinfo.get(d)
                if xi is not None:
                    queue.append((xi[0], (r - xi[1]) % 26))
                zi = zinfo.get(r)
                if zi is not None:
                    queue.append((zi[0], (d - zi[1]) % 26))
        return True

    def rec(R, Ri, val, k):
        nodes[0] += 1
        if nodes[0] > node_cap or len(sols) >= limit:
            return
        while k < nc and val[order[k]] >= 0:
            k += 1
        if k == nc:
            sols.append([None if y < 0 else y for y in R])
            return
        ci = order[k]
        for v in allowed[ci][0]:
            R2, Ri2, val2 = list(R), list(Ri), list(val)
            if place(R2, Ri2, val2, ci, v):
                rec(R2, Ri2, val2, k + 1)
            if len(sols) >= limit or nodes[0] > node_cap:
                return

    rec([-1] * 26, [-1] * 26, [-1] * nc, 0)
    return sols, nodes[0], nodes[0] <= node_cap


def solve_fast(xs, us, zs, limit=1, node_cap=200000):
    """The same exact search as `solve`, organised by pieces: clues that share an exit letter tie
    their entry contacts together (a_x = v + offset), so each piece has one unknown v. A piece's
    allowed values are worked out once, then the pieces are placed one by one with forced values
    propagated (a contact a piece sets may be another piece's entry or exit). Returns
    (solutions, nodes, complete) like `solve`."""
    pc = _pieces(xs, us, zs)
    if pc is None:
        return [], 0, True
    return _search(pc[0], pc[1], limit, node_cap)


def solve_shifts(xs, us, zs, dx, du, dz, limit=1, node_cap=200000):
    """solve_fast for x + dx*c, u + du*c, z + dz*c at every c = 0..25 (the slow offset's start).
    The pieces do not depend on c, so they are built once. Returns [(c, solutions, complete)]."""
    pc = _pieces(xs, us, zs)
    if pc is None:
        return []
    X, K = pc
    out = []
    for c in range(26):
        ax, aw, az = dx * c, du * c, dz * c
        Xc = [[((x + ax) % 26, o) for x, o in xs_] for xs_ in X]
        Kc = [{(w + aw) % 26: (z + az) % 26 for w, z in k.items()} for k in K]
        sols, nodes, complete = _search(Xc, Kc, limit, node_cap)
        out.append((c, sols, complete))
    return out
