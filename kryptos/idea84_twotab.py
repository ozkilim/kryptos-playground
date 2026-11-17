"""Idea 84: two repeating-key layers on two DIFFERENT tableaux, tested exactly on the clue letters.

    Y_i = A[e1 * A^-1(P_i) + a_(i mod p)]        layer one, on alphabet A
    C_i = B[e2 * B^-1(Y_i) + b_(i mod q)]        layer two, on alphabet B

e = +1 is Vigenere (variant Beaufort is the same thing with the key negated, and the key letters
are free here), e = -1 is Beaufort. When A and B differ the two keys do not add up, so the test
cannot be a linear system. Instead: every clue letter i ties key letter a_(i mod p) to key
letter b_(i mod q) by a known one-to-one table (F[i]: a -> b, G[i]: b -> a). The clue letters
draw a graph on the key letters. In each connected piece, guess one key letter (26 values) and
follow the edges; every edge that closes a loop is a check.

    checks of a setting = sum over pieces of (edges - key letters), pieces without a loop count 0

which is the power of 26 by which chance is expected to fail. The 26 guesses are run by code
that is written out once per (p, q) (plain Python source, early exit on the first wrong check),
because that is several times faster than walking a step list.
"""
from .ciphers.substitution import AZ

R26 = tuple(range(26))


def components(p, q, pos):
    """Connected pieces of the key-letter graph: [(nodes, edges)] with nodes ('a', r) / ('b', t)
    and edges (index into pos, r, t)."""
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    edges = [(j, i % p, i % q) for j, i in enumerate(pos)]
    for j, r, t in edges:
        parent[find(("a", r))] = find(("b", t))
    out = {}
    for j, r, t in edges:
        root = find(("a", r))
        nodes, es = out.setdefault(root, (set(), []))
        nodes.update((("a", r), ("b", t)))
        es.append((j, r, t))
    return [out[k] for k in sorted(out)]


def _order(nodes, edges, start):
    """Steps from a start node: ('root', node), ('ab', j, r, t) derive b from a, ('ba', j, r, t)
    derive a from b, ('chk', j, r, t). Checks are made as early as possible. Returns (cost, steps)."""
    known, left, steps, checks, cost = {start}, list(edges), [("root", start)], 0, 1.0
    while left:
        done = [e for e in left if ("a", e[1]) in known and ("b", e[2]) in known]
        if done:
            for e in done:
                steps.append(("chk",) + e)
                cost += 26.0 ** -checks
                checks += 1
                left.remove(e)
            continue
        best = None
        for e in left:
            a_in, b_in = ("a", e[1]) in known, ("b", e[2]) in known
            if a_in == b_in:
                continue
            new = ("b", e[2]) if a_in else ("a", e[1])
            gain = sum(1 for f in left if f is not e and
                       ((("a", f[1]) == new and ("b", f[2]) in known) or
                        (("b", f[2]) == new and ("a", f[1]) in known) or
                        (f[1] == e[1] and f[2] == e[2])))
            if best is None or gain > best[0]:
                best = (gain, e, a_in, new)
        _, e, a_in, new = best
        steps.append(("ab" if a_in else "ba",) + e)
        cost += 26.0 ** -checks
        known.add(new)
        left.remove(e)
    return cost, steps


def plan(p, q, pos):
    """The test plan for key lengths p, q: {'p', 'q', 'checks', 'comps': [steps], 'free': n}.
    Pieces without a loop test nothing and are left out ('free' counts them)."""
    comps, checks, free = [], 0, 0
    for nodes, edges in components(p, q, pos):
        if len(edges) < len(nodes):          # a tree: always solvable, 26 ways
            free += 1
            continue
        checks += len(edges) - len(nodes)
        comps.append(min((_order(nodes, edges, s) for s in sorted(nodes)), key=lambda x: x[0])[1])
    return {"p": p, "q": q, "checks": checks, "comps": comps, "free": free}


def plans(pos, min_checks=7, max_len=26):
    out = []
    for p in range(1, max_len + 1):
        for q in range(1, max_len + 1):
            pl = plan(p, q, pos)
            if pl["checks"] >= min_checks:
                out.append(pl)
    return out


def source(pls, n):
    """Python source of scan(F, G) -> [(plan index, number of key solutions)] for the plans."""
    src = ["def scan(F, G):", "    out = []"]
    src.append("    " + ", ".join("F%d" % j for j in range(n)) + " = F")
    src.append("    " + ", ".join("G%d" % j for j in range(n)) + " = G")
    for k, pl in enumerate(pls):
        src.append("    tot = 1")
        for ci, steps in enumerate(pl["comps"]):
            ind = "    " if ci == 0 else "        "
            if ci:
                src.append("    if tot:")
            src.append(ind + "n = 0")
            kind, node = steps[0]
            src.append(ind + "for %s%d in R:" % (node[0].upper(), node[1]))
            for st in steps[1:]:
                kind, j, r, t = st
                if kind == "ab":
                    src.append(ind + "    B%d = F%d[A%d]" % (t, j, r))
                elif kind == "ba":
                    src.append(ind + "    A%d = G%d[B%d]" % (r, j, t))
                else:
                    src.append(ind + "    if F%d[A%d] != B%d: continue" % (j, r, t))
            src.append(ind + "    n += 1")
            src.append(ind + "tot *= n")
        src.append("    if tot: out.append((%d, tot))" % k)
    src.append("    return out")
    return "\n".join(src)


def compile_scan(pls, n):
    ns = {"R": R26}
    exec(source(pls, n), ns)
    return ns["scan"]


def tables(alpha_a, alpha_b, e1, e2, pl, cl):
    """F[j][a] = b and G[j][b] = a for each clue letter j (plain letters pl, cipher letters cl)."""
    ia = {c: i for i, c in enumerate(alpha_a)}
    ib = {c: i for i, c in enumerate(alpha_b)}
    pi = [ib[c] for c in alpha_a]                    # place in A -> place in B of the same letter
    inv = [ia[c] for c in alpha_b]
    F, G = [], []
    for p, c in zip(pl, cl):
        x, z = e1 * ia[p], ib[c]
        F.append([(z - e2 * pi[(x + a) % 26]) % 26 for a in R26])
        G.append([(inv[(e2 * (z - b)) % 26] - x) % 26 for b in R26])
    return F, G


def solve(pl, F, G):
    """Slow reference solver: every key that fits, as [(a dict, b dict)] over the tested pieces."""
    sols = [({}, {})]
    for steps in pl["comps"]:
        part = []
        for g in R26:
            a, b = {}, {}
            (a if steps[0][1][0] == "a" else b)[steps[0][1][1]] = g
            for kind, j, r, t in steps[1:]:
                if kind == "ab":
                    b[t] = F[j][a[r]]
                elif kind == "ba":
                    a[r] = G[j][b[t]]
                elif F[j][a[r]] != b[t]:
                    break
            else:
                part.append((a, b))
        sols = [({**sa, **a}, {**sb, **b}) for sa, sb in sols for a, b in part]
        if not sols:
            return []
    return sols


def encrypt(pt, alpha_a, alpha_b, a, b, e1=1, e2=1):
    """a, b: key values (lists of 0-25, places in A and in B)."""
    out = []
    for i, ch in enumerate(pt):
        y = alpha_a[(e1 * alpha_a.index(ch) + a[i % len(a)]) % 26]
        out.append(alpha_b[(e2 * alpha_b.index(y) + b[i % len(b)]) % 26])
    return "".join(out)


def decrypt(ct, alpha_a, alpha_b, a, b, p, q, e1=1, e2=1):
    """a, b: dicts residue -> key value (may be partial). Unknown letters come back as '?'."""
    out = []
    for i, ch in enumerate(ct):
        ka, kb = a.get(i % p), b.get(i % q)
        if ka is None or kb is None:
            out.append("?")
            continue
        y = alpha_b[(e2 * (alpha_b.index(ch) - kb)) % 26]
        out.append(alpha_a[(e1 * (alpha_a.index(y) - ka)) % 26])
    return "".join(out)


def key_text(vals, n, alpha):
    """A key as letters of its own alphabet and of A-Z ('?' where the clues do not reach)."""
    return ("".join(alpha[vals[r]] if r in vals else "?" for r in range(n)) + "/" +
            "".join(AZ[vals[r]] if r in vals else "?" for r in range(n)))
