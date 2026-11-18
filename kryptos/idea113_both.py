"""Idea 113 helpers: Quagmire IV with BOTH alphabets hidden and a key of length 8 (repeating or sliding).

One equation per clue letter i (plain letter p, cipher letter c, key slot r = i mod 8, q = i div 8):

    Y[c] - S[r] = X[p] + q * W        (mod 26)

X = places of the plain letters in the hidden plain alphabet, Y = places of the cipher letters in the hidden
cipher alphabet, S = the 8 key numbers, W = 0 for a repeating key, else the sum of the sliding word.
Beaufort form is the same system with X turned back to front, so it is tested with the Vigenere form.

Idea 99's Plan (kryptos/idea99_half.py) gives the loop structure with the cipher letters and key slots as
nodes and the clue letters as edges. With both alphabets hidden, every node value and every loop check is a
linear form in the 13 clue plain places X. So the search runs over X itself:

* gauge: one plain letter is put at place 0 (shifting X and S together changes nothing);
* scale: multiplying everything by a unit u mod 26 changes nothing either (W goes to u*W), so for W = 0 and
  W = 13 a second letter is put at 1, 2 or 13 (and if 13, a third at 1 or 2). For a sliding key the word sums
  W = 1 and W = 2 stand for all odd and all even sums;
* the loop checks are solved for 4 of the letters, the rest are enumerated in nested loops, generated as
  straight Python code, with every plain place and every cipher place checked for collisions as soon as
  it is known.

Every survivor fixes ("forces") the plaintext at each position whose cipher letter is a clue cipher letter and
whose key slot sits in the same piece: the place X = Y[c] - S[r] - q*W. If that place holds one of the 13
clue plain letters the letter is known; otherwise it is known to be one of the other 13 letters ('?').
Survivors are scored by an order-3 Markov chain over these classes (13 letters, '?', unknown '*'), whose
probabilities are marginals of the big quadgram model. The best are then completed by annealing.
"""
import heapq
import math
import random
from collections import Counter

from .ciphers import AZ
from .data import CRIBS
from .idea99_half import Plan, clue_letters

L = 8
NCLS = 15            # 13 clue plain letters, '?' = one of the other letters, '*' = unknown
OTHER, ANY = 13, 14


# ---------------------------------------------------------------- the linear structure

class System:
    """The clue equations of one text at key length 8 and word sum W, as linear forms in the plain places."""

    def __init__(self, ct, cribs=CRIBS, W=0, Lk=L):
        self.ct, self.cribs, self.W, self.L = ct, dict(cribs), W % 26, Lk
        pos = sorted(cribs)
        pl, cl = clue_letters(ct, cribs)
        self.pos, self.pl, self.cl = pos, pl, cl
        self.plan = p = Plan(cl, Lk, pos, None)
        self.letters = sorted(set(pl))                 # the clue plain letters (variables)
        self.vi = {c: i for i, c in enumerate(self.letters)}
        n = len(self.letters)
        q = [i // Lk for i in pos]
        self.nchecks, self.sizes, self.ncomp = p.nchecks, p.sizes, p.ncomp

        def edge_form(expr):
            f, k = [0] * (n + 1), 0
            for e, c in expr.items():
                f[self.vi[pl[e]]] += c
                k += c * q[e] * self.W
            f[n] = k
            return [x % 26 for x in f]

        # node forms: value of node = form . (X, 1), relative to its piece root
        self.nodes = {node: edge_form(expr) for node, expr in p.pot.items()}
        self.checks = []
        for plus, minus, qc in p.checks:
            f = [0] * (n + 1)
            for e in plus:
                f[self.vi[pl[e]]] += 1
            for e in minus:
                f[self.vi[pl[e]]] -= 1
            f[n] = qc * self.W
            self.checks.append([x % 26 for x in f])
        self.comp = {node: c for node, c in p.comp.items()}
        self.cipher_pieces = [sorted(nd[1] for nd, c in self.comp.items() if c == j and nd[0] == "h")
                              for j in range(self.ncomp)]
        self.slot_piece = {nd[1]: c for nd, c in self.comp.items() if nd[0] == "k"}
        self.letter_piece = {nd[1]: c for nd, c in self.comp.items() if nd[0] == "h"}
        # forced positions: cipher letter in a piece and key slot in the same piece
        self.forced = [j for j in range(len(ct)) if ct[j] in self.letter_piece
                       and self.slot_piece.get(j % Lk) == self.letter_piece[ct[j]]]

    def shape(self):
        return (self.nchecks, tuple(self.sizes), len(self.letters))

    def open_checks(self):
        """True if every loop is a real test of the plain places (none is 0 = 0 or 'two letters on one place')."""
        k = Plan(self.cl, self.L, self.pos, self.pl).kinds
        return all(x == "open" for x in k)

    def evaluate(self, X):
        """X = list of places for self.letters. Returns (Y {cipher letter: place}, S {slot: value}) per piece
        root, or None if a check fails."""
        n = len(self.letters)
        v = list(X) + [1]
        for f in self.checks:
            if sum(a * b for a, b in zip(f, v)) % 26:
                return None
        Y, S = {}, {}
        for node, f in self.nodes.items():
            val = sum(a * b for a, b in zip(f, v)) % 26
            (Y if node[0] == "h" else S)[node[1]] = val
        return Y, S


def canonical(X, scale):
    """The representative of X (places of the letters, in order) under shifts and, if scale, unit multiples."""
    n = len(X)
    best = None
    for a0 in [0]:
        sh = [(x - X[a0]) % 26 for x in X]
        cands = [sh]
        if scale:
            cands = [[(u * x) % 26 for x in sh] for u in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)]
        for c in cands:
            if best is None or c < best:
                best = c
    return best


# ---------------------------------------------------------------- elimination and code generation

class Enumerator:
    """Builds the generated search function for one System."""

    def __init__(self, sysm, scale):
        self.s, self.scale = sysm, scale
        n = len(sysm.letters)
        self.n = n
        # the gauge letter (place 0) and the scale letter: the two most used in the checks
        use = Counter()
        for f in sysm.checks:
            for i in range(n):
                if f[i]:
                    use[i] += 1
        order = sorted(range(n), key=lambda i: (-use[i], i))
        self.a0, self.s0 = order[0], order[1]
        # solve the checks for dependents (coefficient a unit), substituting as we go
        dep = {}                                     # var -> form over vars (+const)
        resid = []
        for f in sysm.checks:
            f = self._subst(list(f), dep)
            piv = None
            for pref in ((1, 25), (3, 5, 7, 9, 11, 15, 17, 19, 21, 23)):
                for i in order[::-1]:
                    if i in (self.a0, self.s0) or i in dep:
                        continue
                    if f[i] in pref:
                        piv = i
                        break
                if piv is not None:
                    break
            if piv is None:
                if any(f[:n]):
                    resid.append(f)
                elif f[n] % 26:
                    resid.append(f)               # impossible check (const != 0)
                continue
            inv = next(u for u in range(26) if (u * f[piv]) % 26 == 1)
            g = [(-inv * x) % 26 for x in f]
            g[piv] = 0
            for d in list(dep):
                dep[d] = self._subst(dep[d], {piv: g})
            dep[piv] = g
        self.dep, self.resid = dep, [self._subst(f, dep) for f in resid]
        self.free = [i for i in range(n) if i != self.a0 and i not in dep]   # includes s0
        assert self.s0 in self.free

    def regular(self):
        """Like K4: every loop solved for its own letter, nothing left over, and no two plain letters (or the
        cipher letters of one piece) tied to the same place by the loops."""
        if self.resid or len(self.dep) != len(self.s.checks):
            return False
        q = self.quantities()
        for grp in {g for _, _, g in q if g == "P" or isinstance(g, tuple)}:
            forms = [tuple(f) for _, f, g in q if g == grp]
            if len(set(forms)) != len(forms):
                return False
        return True

    def _subst(self, f, dep):
        f = list(f)
        n = self.n
        for d, g in dep.items():
            c = f[d]
            if c:
                f[d] = 0
                for i in range(n + 1):
                    f[i] = (f[i] + c * g[i]) % 26
        f[self.a0] = 0                               # a0 = 0
        return f

    def form(self, f):
        """A form over all letters (+const) as a form over the free vars (+const)."""
        return self._subst(f, self.dep)

    def plan_order(self):
        """Free vars in an order that checks collisions early (greedy on expected node count)."""
        s = self.s
        quants = self.quantities()
        free = [v for v in self.free if v != self.s0]
        chosen = [self.s0]
        while free:
            best = None
            for v in free:
                trial = chosen + [v]
                ready = sum(1 for _, f, _ in quants if all(not f[i] or i in trial for i in range(self.n))
                            and any(f[i] and i == v for i in range(self.n)))
                key = (-ready, v)
                if best is None or key < best[0]:
                    best = (key, v)
            chosen.append(best[1])
            free.remove(best[1])
        return chosen

    def quantities(self):
        """[(name, form over free vars, group)] - group 'P' plain places, ('Y', piece), 'S' key, 'R' residual."""
        s, n = self.s, self.n
        out = []
        for i in range(n):
            if i == self.a0:
                f = [0] * (n + 1)
            elif i in self.dep:
                f = self.dep[i]
            else:
                f = [0] * (n + 1)
                f[i] = 1
            out.append(("x%d" % i, f, "P"))
        for node, f in sorted(s.nodes.items()):
            g = self.form(f)
            if node[0] == "h":
                out.append(("y_%s" % node[1], g, ("Y", s.comp[node])))
            else:
                out.append(("s_%d" % node[1], g, "S"))
        for k, f in enumerate(self.resid):
            out.append(("r%d" % k, f, "R"))
        return out

    def source(self, order, table_name="T"):
        """Python source of search(doms, T, T0, C, keep, thresh_true) -> (count, n_above_true, top list, sum, sum of squares).
        doms[d] = the values tried for free var d (in `order`)."""
        s, n = self.s, self.n
        quants = self.quantities()
        depth = {}
        for name, f, grp in quants:
            used = [order.index(i) for i in range(n) if f[i]]
            depth[name] = max(used) if used else -1
        groups = sorted({g for _, _, g in quants if g in ("P",) or isinstance(g, tuple)}, key=str)
        mask = {g: "m%s" % (g if isinstance(g, str) else "Y%d" % g[1]) for g in groups}

        def expr(f):
            terms = []
            for i in range(n):
                c = f[i] % 26
                if c:
                    v = "v%d" % order.index(i)
                    terms.append(v if c == 1 else "%d*%s" % (c, v))
            if f[n] % 26:
                terms.append(str(f[n] % 26))
            return "(" + "+".join(terms) + ")%26" if terms else "0"

        lines = ["def search(doms, T, T0, C, keep, thresh_true):",
                 "    import heapq",
                 "    count = 0; above = 0; top = []; thr = -1e300; push = heapq.heappush; rep = heapq.heapreplace",
                 "    s1 = 0.0; s2 = 0.0"]
        ind = "    "
        # depth -1 quantities (constants)
        init = {mask[g]: 0 for g in groups}
        for name, f, grp in quants:
            if depth[name] == -1:
                val = f[n] % 26
                if grp == "R":
                    if val:
                        lines.append(ind + "return 0, 0, [], 0.0, 0.0")
                    continue
                if grp == "S":
                    lines.append(ind + "%s = %d" % (name, val))
                    continue
                m = mask[grp]
                if init[m] >> val & 1:
                    lines.append(ind + "return 0, 0, [], 0.0, 0.0")
                init[m] |= 1 << val
                lines.append(ind + "%s = %d" % (name, val))
        for m, v in init.items():
            lines.append(ind + "%s_0 = %d" % (m, v))
        cur = {m: "%s_0" % m for m in init}
        for d in range(len(order)):
            dom = "doms[%d]" % d
            lines.append(ind + "for v%d in %s:" % (d, dom))
            ind += "    "
            for name, f, grp in quants:
                if depth[name] != d:
                    continue
                if grp == "R":
                    lines.append(ind + "if %s: continue" % expr(f))
                    continue
                lines.append(ind + "%s = %s" % (name, expr(f)))
                if grp == "S":
                    continue
                m = mask[grp]
                lines.append(ind + "b = 1 << %s" % name)
                lines.append(ind + "if %s & b: continue" % cur[m])
                nm = "%s_%d" % (m, d + 1)
                lines.append(ind + "%s = %s | b" % (nm, cur[m]))
                cur[m] = nm
        # leaf: score
        lines.append(ind + "count += 1")
        lines += [ind + l for l in self.leaf_lines(table_name)]
        lines.append(ind + "s1 += sc; s2 += sc * sc")
        lines.append(ind + "if sc > thresh_true: above += 1")
        lines.append(ind + "if sc > thr:")
        tup = "(sc, (%s))" % ",".join("v%d" % d for d in range(len(order)))
        lines.append(ind + "    if len(top) < keep:")
        lines.append(ind + "        push(top, %s)" % tup)
        lines.append(ind + "        if len(top) == keep: thr = top[0][0]")
        lines.append(ind + "    else:")
        lines.append(ind + "        rep(top, %s); thr = top[0][0]" % tup)
        lines.append("    return count, above, top, s1, s2")
        return "\n".join(lines)

    def leaf_lines(self, T):
        """Straight-line scoring of the forced classes (an order-3 Markov chain)."""
        s, n = self.s, self.n
        ct, Lk, W = s.ct, s.L, s.W
        out = ["inv = [13]*26"]
        for i in range(n):
            out.append("inv[x%d] = %d" % (i, i))
        cls = {}
        crib = s.cribs
        places, weight = {}, Counter()
        for j in range(len(ct)):
            if j in crib:
                cls[j] = str(s.vi[crib[j]])
            elif j in s.forced:
                key = (ct[j], j % Lk, (j // Lk) * W % 26)
                if key not in places:
                    nm = "p%d" % len(places)
                    places[key] = nm
                    out.append("z%s = (y_%s - s_%d - %d) %% 26" % (nm[1:], key[0], key[1], key[2]))
                    out.append("%s = inv[z%s]" % (nm, nm[1:]))
                weight[places[key]] += 1
                cls[j] = places[key]
            else:
                cls[j] = str(ANY)
        # positions whose place holds none of the clue letters hold ONE other letter per place: the chain
        # scores them as 'some other letter', so add the cost of naming it (table C by group size)
        out.append("g = [0]*26")
        for nm, w in sorted(weight.items()):
            out.append("if %s == 13: g[z%s] += %d" % (nm, nm[1:], w))
        terms = []
        for i in range(len(ct) - 3):
            win = [cls[i + k] for k in range(4)]
            if all(w.isdigit() for w in win):
                continue                       # constant across survivors
            # index = ((a*15+b)*15+c)*15+d
            parts, const = [], 0
            for k, w in enumerate(win):
                mult = NCLS ** (3 - k)
                if w.isdigit():
                    const += int(w) * mult
                else:
                    parts.append("%s*%d" % (w, mult) if mult != 1 else w)
            idx = "+".join(parts + ([str(const)] if const else []))
            terms.append("%s[%s]" % (T if i else T + "0", idx))
        out.append("sc = " + ("+".join(terms) if terms else "0.0"))
        out.append("for m in g: sc += C[m]")
        return out


# ---------------------------------------------------------------- class tables from the big model

def class_tables(big_path, letters):
    """Returns (T0, T, C). C[m] = log10 cost of m positions sharing one place that holds an unnamed other letter.
    T0[pattern] = log10 P(pattern) for the first window, T[pattern] = log10 P(last | first three).
    Pattern = 4 classes: index in `letters`, OTHER = a letter not in `letters`, ANY = unknown."""
    cmap = {c: (letters.index(c) if c in letters else OTHER) for c in AZ}
    counts = {}
    with open(big_path) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            q, c = line.split()
            counts[q] = int(c)
    total = float(sum(counts.values()))
    P = [0.0] * NCLS ** 4
    # smoothing: every one of the 26^4 quadgrams gets eps counts (added per pattern below)
    eps = 0.01
    for q, w in counts.items():
        cl = (cmap[q[0]], cmap[q[1]], cmap[q[2]], cmap[q[3]])
        for m in range(16):
            k = [cl[t] if not (m >> t) & 1 else ANY for t in range(4)]
            P[((k[0] * NCLS + k[1]) * NCLS + k[2]) * NCLS + k[3]] += w
    size = [1] * len(letters) + [26 - len(letters), 26]
    for idx in range(NCLS ** 4):
        a, b, c, d = idx // NCLS ** 3, idx // NCLS ** 2 % NCLS, idx // NCLS % NCLS, idx % NCLS
        if max(a, b, c, d) < NCLS:
            P[idx] += eps * size[a] * size[b] * size[c] * size[d]
    tot = total + eps * 26 ** 4
    uni = Counter()
    for q, c in counts.items():
        uni[q[0]] += c
    po = [uni[c] / total for c in AZ if c not in letters]
    so = sum(po)
    C = [0.0] + [math.log10(sum(p ** m for p in po) / len(po)) - m * math.log10(so) for m in range(1, 98)]
    T0, T = [0.0] * NCLS ** 4, [0.0] * NCLS ** 4
    for idx in range(NCLS ** 4):
        if P[idx] <= 0:
            T0[idx] = T[idx] = -99.0
            continue
        T0[idx] = math.log10(P[idx] / tot)
        prefix = idx - idx % NCLS + ANY            # last class -> '*'
        T[idx] = math.log10(P[idx] / P[prefix])
    return T0, T, C


# ---------------------------------------------------------------- driver pieces (used by the attack and test)

def domains(nfree, scale):
    """Tasks [doms] covering the canonical search (first var = the scale letter)."""
    R = list(range(26))
    if scale:
        heads = [([1], [v]) for v in range(26)] + [([2], [v]) for v in range(26)] + [([13], [1, 2])]
    else:
        heads = [([u], [v]) for u in range(1, 26) for v in range(26)]
    return [[a, b] + [R] * (nfree - 2) for a, b in heads]


def single(vals):
    return [[v] for v in vals]


def build(ct, cribs, W, scale):
    sysm = System(ct, cribs, W)
    en = Enumerator(sysm, scale)
    order = en.plan_order()
    src = en.source(order)
    ns = {}
    exec(compile(src, "<idea113 W=%d>" % W, "exec"), ns)
    return sysm, en, order, ns["search"], src


def leaf_to_X(en, order, vals):
    """Free var values (in `order`) -> places of all clue plain letters."""
    n = en.n
    v = [0] * n
    for d, i in enumerate(order):
        v[i] = vals[d]
    X = [0] * n
    for i in range(n):
        if i == en.a0:
            X[i] = 0
        elif i in en.dep:
            f = en.dep[i]
            X[i] = (sum(f[k] * v[k] for k in range(n)) + f[n]) % 26
        else:
            X[i] = v[i]
    return X


def true_vals(en, order, X):
    """Canonical free-var values of a true X (for the planted rank), or None if not canonical-reachable."""
    n = en.n
    sh = [(x - X[en.a0]) % 26 for x in X]
    units = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25) if en.scale else (1,)
    for u in units:
        c = [(u * x) % 26 for x in sh]
        if en.scale:
            s0 = c[en.s0]
            if s0 not in (1, 2, 13):
                continue
            if s0 == 13 and c[order[1]] not in (1, 2):
                continue
        return tuple(c[i] for i in order), u
    return None, None


def forced_reading(sysm, X):
    """The forced reading of a setting: letters where the place holds a clue letter, '?' other letter, '.'."""
    ev = sysm.evaluate(X)
    if ev is None:
        return None
    Y, S = ev
    at = {x: c for c, x in zip(sysm.letters, X)}
    out = []
    for j, c in enumerate(sysm.ct):
        if j in sysm.forced:
            x = (Y[c] - S[j % sysm.L] - (j // sysm.L) * sysm.W) % 26
            out.append(at.get(x, "?"))
        else:
            out.append(".")
    return "".join(out)


# ---------------------------------------------------------------- completing a survivor

class Completer:
    """Fills in the 13 other plain letters, the other cipher letters and the offset between the pieces by
    simulated annealing on the big model. The clue letters stay right throughout."""

    def __init__(self, sysm, X, big):
        self.s, self.big = sysm, big
        Y, S = sysm.evaluate(X)
        self.X = dict(zip(sysm.letters, X))
        self.Y, self.S = Y, S
        self.pfree = [c for c in AZ if c not in self.X]
        self.pplaces = [x for x in range(26) if x not in self.X.values()]
        self.cin = set(Y)
        self.cfree = [c for c in AZ if c not in self.cin]
        ct = sysm.ct
        self.slot = [j % sysm.L for j in range(len(ct))]
        self.qw = [(j // sysm.L) * sysm.W % 26 for j in range(len(ct))]
        self.root_piece = 0
        self.pl = sysm.letter_piece
        self.sp = sysm.slot_piece

    def offsets_ok(self):
        """Offsets d for the other pieces (piece j >= 1 shifted by d) keeping cipher places distinct."""
        p0 = {self.Y[c] for c in self.Y if self.pl[c] == 0}
        res = []
        for j in range(1, self.s.ncomp):
            pj = [self.Y[c] for c in self.Y if self.pl[c] == j]
            res.append([d for d in range(26) if all((v + d) % 26 not in p0 for v in pj)])
        return res

    def build(self, offs, pperm, cperm):
        Yf, Sf = {}, {}
        for c, v in self.Y.items():
            pc = self.pl[c]
            Yf[c] = (v + (offs[pc - 1] if pc else 0)) % 26
        for r, v in self.S.items():
            pc = self.sp[r]
            Sf[r] = (v + (offs[pc - 1] if pc else 0)) % 26
        for r in range(self.s.L):
            Sf.setdefault(r, 0)
        used = set(Yf.values())
        if len(used) != len(Yf):
            return None
        cpl = [x for x in range(26) if x not in used]
        for c, x in zip(cperm, cpl):
            Yf[c] = x
        at = [None] * 26
        for c, x in self.X.items():
            at[x] = c
        for c, x in zip(pperm, self.pplaces):
            at[x] = c
        return Yf, Sf, at

    def decrypt(self, b):
        Yf, Sf, at = b
        return "".join(at[(Yf[c] - Sf[r] - k) % 26] for c, r, k in zip(self.s.ct, self.slot, self.qw))

    def score(self, pt):
        get, fl = self.big.logp.get, self.big.floor
        return sum(get(pt[i:i + 4], fl) for i in range(len(pt) - 3))

    def anneal(self, rng, iters=5000, restarts=2, t0=3.0, t1=0.05):
        okd = self.offsets_ok()
        if any(not o for o in okd):
            return -99.0, None            # the pieces cannot sit side by side: not a real setting
        best = (-math.inf, None)
        nq = len(self.s.ct) - 3
        for _ in range(restarts):
            offs = [rng.choice(o) for o in okd]
            pperm = rng.sample(self.pfree, len(self.pfree))
            cperm = rng.sample(self.cfree, len(self.cfree))
            b = self.build(offs, pperm, cperm)
            cur = self.score(self.decrypt(b))
            if cur > best[0]:
                best = (cur, (list(offs), list(pperm), list(cperm)))
            for it in range(iters):
                t = t0 * (t1 / t0) ** (it / iters)
                no, npp, ncp = offs, pperm, cperm
                r = rng.random()
                if okd and r < 0.1:
                    j = rng.randrange(len(okd))
                    no = list(offs)
                    no[j] = rng.choice(okd[j])
                elif r < 0.55 and len(pperm) > 1:
                    a, c = rng.sample(range(len(pperm)), 2)
                    npp = list(pperm)
                    npp[a], npp[c] = npp[c], npp[a]
                elif len(cperm) > 1:
                    a, c = rng.sample(range(len(cperm)), 2)
                    ncp = list(cperm)
                    ncp[a], ncp[c] = ncp[c], ncp[a]
                else:
                    continue
                b = self.build(no, npp, ncp)
                if b is None:
                    continue
                sc = self.score(self.decrypt(b))
                if sc >= cur or rng.random() < math.exp((sc - cur) / t):
                    offs, pperm, cperm, cur = no, npp, ncp, sc
                    if cur > best[0]:
                        best = (cur, (list(offs), list(pperm), list(cperm)))
        sc, (offs, pperm, cperm) = best
        return sc / nq, self.decrypt(self.build(offs, pperm, cperm))


# ---------------------------------------------------------------- a textbook encryptor (planting)

def quagmire4(pt, plain_alpha, cipher_alpha, key, beaufort=False):
    out = []
    for p, k in zip(pt, key):
        a = plain_alpha.index(p)
        out.append(cipher_alpha[(k - a) % 26 if beaufort else (a + k) % 26])
    return "".join(out)


def key_stream(nums, sliding=False, n=97):
    out, t = [], 0
    for i in range(n):
        v = nums[i % len(nums)]
        t = (t + v) % 26
        out.append(t if sliding else v)
    return out


def encrypt(pt, rng, sliding=False):
    """Draws both alphabets and 8 key numbers from rng (for the clue pre-filter and planting)."""
    pa = "".join(rng.sample(AZ, 26))
    ca = "".join(rng.sample(AZ, 26))
    nums = [rng.randrange(26) for _ in range(L)]
    return quagmire4(pt, pa, ca, key_stream(nums, sliding))
