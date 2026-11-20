"""Idea 143: two-step plain-autokey chains on one hidden alphabet, decided exactly.

Model. One hidden alphabet numbers plain, cipher and fed letter: X[C_i] = a X[P_i] + b X[K_i] + E, with
a, b = +-1 and K_i the plaintext letter d places back (or ahead). Take three positions j, i = j + d,
h = j + 2d with j and h inside the clues and i outside. The unknown middle plaintext letter drops out:

    back:   X[C_h] - a X[P_h] - ab X[C_i] + a X[P_j] + (ab - 1) E = 0
    ahead:  X[C_i] - ab X[C_j] + b X[P_j] - b X[P_h] + (ab - 1) E = 0

When ab = 1 the constant is gone (the worker of idea 100 saw this). When ab = -1 it stays as -2E, but
moving every letter E places along the alphabet (X -> X - E) removes it, and a moved alphabet is still an
alphabet. So for all four sign forms the question is the same: do the 26 letters have DISTINCT places mod 26
that satisfy 9-11 equations with no constant?

That is decided here in three steps.
  1. Linear proofs of "no": a pair of letters forced into the same place (mod 13 and mod 2), or three
     letters forced equal mod 13 (only two places share a residue mod 13).
  2. A backtracking search for a witness alphabet, checked against the equations before it is believed.
  3. If no witness turns up, the same search run exhaustively inside a node limit. Over the limit the
     cell is 'undecided' and is reported as such.
"""
import random

from .ciphers.substitution import AZ
from .round9 import solve_mod_p
from .round11 import B1, B2

PT1, PT2 = "EASTNORTHEAST", "BERLINCLOCK"
CLUE = dict(zip(B1 + B2, PT1 + PT2))
IZ = {c: i for i, c in enumerate(AZ)}
# (name, a, b): X[C] = a X[P] + b X[K] + E
FORMS = (("C = P + K", 1, 1), ("C = P - K", 1, -1), ("C = K - P", -1, 1), ("C = -P - K", -1, -1))
LAGS = (19, 20, 21, 22)
DIRS = ("back", "ahead")


def chains(d, clue=CLUE):
    """(j, i, h) with j, h clue positions and i = j + d not a clue position."""
    return [(j, j + d, j + 2 * d) for j in sorted(clue) if j + 2 * d in clue and j + d not in clue]


def chain_rows(ct, d, a, b, direction, clue=CLUE):
    """One row of 26 coefficients per chain; the system is rows * X = 0 after the shift X -> X - E."""
    rows = []
    for j, i, h in chains(d, clue):
        r = [0] * 26
        if direction == "back":
            r[IZ[ct[h]]] += 1
            r[IZ[clue[h]]] -= a
            r[IZ[ct[i]]] -= a * b
            r[IZ[clue[j]]] += a
        else:
            r[IZ[ct[i]]] += 1
            r[IZ[ct[j]]] -= a * b
            r[IZ[clue[j]]] += b
            r[IZ[clue[h]]] -= b
        rows.append([v % 26 for v in r])
    return rows


def satisfies(rows, alpha, a=1, b=1, E=0):
    """Does the alphabet (a 26-letter string, place = index) with constant E satisfy every chain?"""
    if sorted(alpha) != list(AZ):
        return False
    X = [alpha.index(c) for c in AZ]
    return all((sum(c * x for c, x in zip(r, X)) + (a * b - 1) * E) % 26 == 0 for r in rows)


def _rank(rows, p):
    if not rows:
        return 0
    sol = solve_mod_p(rows, [0] * len(rows), p)
    return len(rows[0]) - len(sol[1])


def linear_no(rows):
    """A reason no alphabet with distinct places exists, found by linear algebra alone, or None."""
    cols = [j for j in range(26) if any(r[j] for r in rows)]
    if not cols:
        return None
    sub = [[r[j] for j in cols] for r in rows]
    zero = [0] * len(sub)
    n = len(cols)
    same13 = list(range(n))                                # union-find over 'forced equal mod 13'

    def find(x):
        while same13[x] != x:
            x = same13[x]
        return x

    for x in range(n):
        for y in range(x + 1, n):
            row = [0] * n
            row[x], row[y] = 1, -1
            if solve_mod_p(sub + [row], zero + [1], 13) is None:
                if solve_mod_p(sub + [row], zero + [1], 2) is None:
                    return "%s and %s forced into the same place" % (AZ[cols[x]], AZ[cols[y]])
                same13[find(x)] = find(y)
    groups = {}
    for x in range(n):
        groups.setdefault(find(x), []).append(AZ[cols[x]])
    for g in groups.values():
        if len(g) >= 3:
            return "%s forced equal mod 13 (only two places share a residue)" % "".join(g)
    return None


class _Budget(Exception):
    pass


def _search(eqs, nvar, order_seed, limit, fix_first):
    """Backtracking over the letters that occur. eqs: list of {var: coef}. Returns a list of values, None
    (proved: no assignment with distinct values), or raises _Budget."""
    rng = random.Random(order_seed) if order_seed is not None else None
    val = [None] * nvar
    used = [False] * 26
    byvar = [[] for _ in range(nvar)]
    for k, e in enumerate(eqs):
        for v in e:
            byvar[v].append(k)
    nodes = [0]

    def pick():
        best, bc = None, None
        for e in eqs:
            un = [v for v in e if val[v] is None]
            if len(un) == 1:
                v = un[0]
                rest = sum(c * val[w] for w, c in e.items() if w != v)
                cand = [x for x in range(26) if not used[x] and (e[v] * x + rest) % 26 == 0]
                if bc is None or len(cand) < len(bc):
                    best, bc = v, cand
                    if not cand:
                        return v, cand
        if best is not None:
            return best, bc
        open_vars = [u for u in range(nvar) if val[u] is None]
        v = max(open_vars, key=lambda u: (sum(1 for k in byvar[u]
                                              if sum(1 for w in eqs[k] if val[w] is None) == 2),
                                          len(byvar[u]), -u))
        cand = [x for x in range(26) if not used[x]]
        if rng:
            rng.shuffle(cand)
        return v, cand

    def ok(v):
        for k in byvar[v]:
            e = eqs[k]
            if all(val[w] is not None for w in e) and sum(c * val[w] for w, c in e.items()) % 26:
                return False
        return True

    def rec(left, first):
        if left == 0:
            return True
        nodes[0] += 1
        if nodes[0] > limit:
            raise _Budget()
        v, cand = pick()
        if first and fix_first:
            cand = [0]
        for x in cand:
            val[v] = x
            used[x] = True
            if ok(v) and rec(left - 1, False):
                return True
            val[v] = None
            used[x] = False
        return False

    return list(val) if rec(nvar, True) else None


def decide(rows, tries=30, try_nodes=20000, proof_nodes=3000000):
    """('none', reason) | ('ok', alphabet) | ('undecided', note). The alphabet is a witness with constant 0:
    place of letter c = alphabet.index(c); it is verified against the rows before it is returned."""
    rows = [r for r in rows if any(r)]
    why = linear_no(rows)
    if why:
        return "none", why
    cols = [j for j in range(26) if any(r[j] for r in rows)]
    idx = {j: n for n, j in enumerate(cols)}
    eqs = [{idx[j]: (r[j] if r[j] <= 13 else r[j] - 26) for j in cols if r[j]} for r in rows]
    # moving the whole alphabet is a symmetry when every row's coefficients sum to 0 (the ab = 1 forms)
    fix = all(sum(r) % 26 == 0 for r in rows)
    found = None
    for t in range(tries):
        try:
            found = _search(eqs, len(cols), t, try_nodes, fix)
        except _Budget:
            continue
        if found is None:
            return "none", "exhaustive search: no distinct places"
        break
    if found is None:
        try:
            found = _search(eqs, len(cols), None, proof_nodes, fix)
        except _Budget:
            return "undecided", "no witness and no proof inside the node limit"
        if found is None:
            return "none", "exhaustive search: no distinct places"
    place = {cols[n]: x for n, x in enumerate(found)}
    spare = [x for x in range(26) if x not in set(found)]
    for j in range(26):
        if j not in place:
            place[j] = spare.pop()
    alpha = [None] * 26
    for j, x in place.items():
        alpha[x] = AZ[j]
    alpha = "".join(alpha)
    assert satisfies(rows, alpha), "witness fails its own equations"
    return "ok", alpha


def cells(ct, lags=LAGS, clue=CLUE):
    """Every (lag, direction, form) cell for one ciphertext: {(d, dir, form name): (status, detail, info)}."""
    out = {}
    for d in lags:
        for dn in DIRS:
            for fn, a, b in FORMS:
                rows = chain_rows(ct, d, a, b, dn, clue)
                st, detail = decide(rows)
                live = [r for r in rows if any(r)]
                out[d, dn, fn] = (st, detail, {"chains": len(rows), "rank13": _rank(live, 13),
                                               "rank2": _rank(live, 2),
                                               "letters": sum(1 for j in range(26) if any(r[j] for r in rows))})
    return out


# ---------------------------------------------------------------- the cipher itself (for planted answers)

def encrypt(pt, alpha, d, a, b, E, direction, primer):
    """Plain autokey at lag d on one hidden alphabet. primer supplies the fed letter where the text has none."""
    X = {c: i for i, c in enumerate(alpha)}
    n = len(pt)
    out = []
    for i, p in enumerate(pt):
        q = i - d if direction == "back" else i + d
        k = pt[q] if 0 <= q < n else primer[i]
        out.append(alpha[(a * X[p] + b * X[k] + E) % 26])
    return "".join(out)


def decrypt(ct, alpha, d, a, b, E, direction, primer):
    X = {c: i for i, c in enumerate(alpha)}
    n = len(ct)
    pt = [None] * n
    for i in (range(n) if direction == "back" else range(n - 1, -1, -1)):
        q = i - d if direction == "back" else i + d
        k = pt[q] if 0 <= q < n else primer[i]
        pt[i] = alpha[(a * (X[ct[i]] - b * X[k] - E)) % 26]
    return "".join(pt)


def plant(rng, d, form, direction, clue=CLUE):
    """A 97-letter English text with the clue words in place, enciphered on a random hidden alphabet."""
    from .round11 import english97
    pt = list(english97(rng))
    for p, ch in clue.items():
        pt[p] = ch
    pt = "".join(pt)
    alpha = "".join(rng.sample(AZ, 26))
    primer = "".join(rng.choice(AZ) for _ in range(len(pt)))
    fn, a, b = form
    E = rng.randrange(26)
    return {"pt": pt, "alpha": alpha, "E": E, "primer": primer, "d": d, "form": form, "dir": direction,
            "ct": encrypt(pt, alpha, d, a, b, E, direction, primer)}


def witness_ok(ct, alpha, d, a, b, direction, E=0, clue=CLUE):
    """An independent check of a witness: run the cipher itself through every chain. The first step gives
    the middle plaintext letter, the second step must then give the cipher letter K4 really has."""
    if sorted(alpha) != list(AZ):
        return False
    X = {c: i for i, c in enumerate(alpha)}
    for j, i, h in chains(d, clue):
        if direction == "back":
            mid = alpha[(a * (X[ct[i]] - b * X[clue[j]] - E)) % 26]          # P_i from C_i and K_i = P_j
            if alpha[(a * X[clue[h]] + b * X[mid] + E) % 26] != ct[h]:      # C_h from P_h and K_h = P_i
                return False
        else:
            mid = alpha[(b * (X[ct[j]] - a * X[clue[j]] - E)) % 26]          # K_j = P_i from C_j and P_j
            if alpha[(a * X[mid] + b * X[clue[h]] + E) % 26] != ct[i]:      # C_i from P_i and K_i = P_h
                return False
    return True


def anchored(d, n=97, clue=CLUE):
    """Positions whose plaintext a full alphabet would fix: those a whole number of lags from a clue letter."""
    res = {p % d for p in clue}
    return [i for i in range(n) if i % d in res]
