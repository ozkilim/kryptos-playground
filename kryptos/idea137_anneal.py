"""Idea 137: search over full alphabets for Quagmire III (one unknown alphabet on both sides), repeating key.

Beaufort form: key[i mod L] = x[C_i] + x[P_i] (mod 26), so P_i = alpha[(key - x[C_i]) mod 26].
Vigenere form: key = x[C] - x[P], so P = alpha[(x[C] - key) mod 26].

State: the full alphabet (a permutation) plus one key value for every residue class that holds no
clue position ("free" residues). The key of a residue that holds a clue position comes from the
alphabet (k_r = x[C] +/- x[P] at its clue letters). The clue equations are hard: after each swap,
Problem.repair puts every letter an equation forces back on its forced place, and the move is
dropped if any equation still fails. So every state visited decrypts all 24 clue letters exactly.

Searchers: anneal() (simulated annealing), tempering() (parallel tempering, used by the attack),
polish() (greedy finish), near_truth() (mechanics check from a planted truth).
Score: sum of log10 quadgram probabilities of the full 97-letter decrypt, with a flat 26^4 table.
"""
import math
import random

from .round9 import POS

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def load_table(path):
    counts = {}
    with open(path) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            q, c = line.split()
            counts[q] = int(c)
    total = sum(counts.values())
    floor = math.log10(0.01 / total)
    t = [floor] * (26 ** 4)
    for q, c in counts.items():
        a, b, cc, d = (ord(ch) - 65 for ch in q)
        t[((a * 26 + b) * 26 + cc) * 26 + d] = math.log10(c / total)
    return t


def qsum(table, p):
    s = 0.0
    for i in range(len(p) - 3):
        s += table[((p[i] * 26 + p[i + 1]) * 26 + p[i + 2]) * 26 + p[i + 3]]
    return s


class Problem:
    def __init__(self, ct, cribs, L, form="beau", pos=POS):
        self.c = [ord(ch) - 65 for ch in ct]
        self.n = len(ct)
        self.L = L
        self.s = 1 if form == "beau" else -1
        self.form = form
        self.res = [i % L for i in range(self.n)]
        self.clue = [(i, ord(ct[i]) - 65, ord(cribs[i]) - 65) for i in pos]
        byres = {}
        for i, c, p in self.clue:
            byres.setdefault(i % L, []).append((c, p))
        self.byres = byres
        self.free = [r for r in range(L) if r not in byres]
        self.rep = [(r, lst[0][0], lst[0][1]) for r, lst in byres.items()]
        self.k0 = [0] * L
        self.cribs, self.pos = cribs, pos
        self.setup_repair()

    def setup_repair(self):
        """Rows of the clue equations as (letter, coef) lists, each with one 'forced' letter whose
        coefficient is a unit mod 26, so its place follows from the others."""
        from .idea130_exact import equations, order
        rows = equations("".join(chr(65 + v) for v in self.c), self.cribs, self.L, self.form, self.pos)
        self.rows = [[(ord(ch) - 65, c) for ch, c in r.items()] for r in rows]
        seq = [ord(ch) - 65 for ch in order(rows)] if rows else []
        rank = {ch: i for i, ch in enumerate(seq)}
        forced, used = [], set()
        for r in self.rows:
            cand = sorted((rank[ch] for ch, c in r if c % 2 and c % 13 and ch not in used), reverse=True)
            if not cand:
                forced.append(None)
                continue
            d = seq[cand[0]]
            used.add(d)
            c = dict(r)[d]
            forced.append((d, pow(c, -1, 26), [(ch, cc) for ch, cc in r if ch != d]))
        self.forced = forced

    def repair(self, alpha, x):
        """Move each forced letter to its forced place (swapping with the occupant), a few passes,
        then report whether every clue equation holds."""
        rows, forced = self.rows, self.forced
        for _ in range(4):
            changed = False
            for f in forced:
                if f is None:
                    continue
                d, inv, rest = f
                s = 0
                for ch, cc in rest:
                    s += cc * x[ch]
                v = (-s * inv) % 26
                if x[d] != v:
                    o, pd = alpha[v], x[d]
                    alpha[v], alpha[pd] = d, o
                    x[d], x[o] = v, pd
                    changed = True
            if not changed:
                break
        for r in rows:
            s = 0
            for ch, cc in r:
                s += cc * x[ch]
            if s % 26:
                return False
        return True

    def fast_keys(self, x, kfree):
        k = self.k0
        s = self.s
        for r, c, p in self.rep:
            k[r] = (x[c] + s * x[p]) % 26
        for r, v in zip(self.free, kfree):
            k[r] = v
        return k

    def keys(self, x, kfree):
        """Key per residue from alphabet places x (letter -> place) and the free key values;
        returns (key list, broken clue equations)."""
        k = [0] * self.L
        broken = 0
        s = self.s
        for r, lst in self.byres.items():
            if len(lst) == 1:
                c, p = lst[0]
                k[r] = (x[c] + s * x[p]) % 26
            else:
                cnt = {}
                for c, p in lst:
                    v = (x[c] + s * x[p]) % 26
                    cnt[v] = cnt.get(v, 0) + 1
                v, m = max(cnt.items(), key=lambda t: t[1])
                k[r] = v
                broken += len(lst) - m
        for r, v in zip(self.free, kfree):
            k[r] = v
        return k, broken

    def decrypt(self, alpha, x, k):
        res, c = self.res, self.c
        if self.s == 1:
            return [alpha[(k[res[i]] - x[c[i]]) % 26] for i in range(self.n)]
        return [alpha[(x[c[i]] - k[res[i]]) % 26] for i in range(self.n)]

    def text(self, alpha, kfree):
        x = [0] * 26
        for i, a in enumerate(alpha):
            x[a] = i
        k, broken = self.keys(x, kfree)
        return "".join(chr(65 + v) for v in self.decrypt(alpha, x, k)), broken


def anneal(prob, table, rng, iters, t0=3.0, t1=0.2, alpha=None, kfree=None):
    """One annealing run on states where every clue equation holds. A move swaps two letters (or
    changes one free key value), then the letters the equations force are put back on their forced
    places (prob.repair); if the equations still fail, the move is dropped. Returns
    (best quadgram sum, alpha, kfree), or (None, ...) if no valid start was found."""
    nf = len(prob.free)
    kfree = list(kfree) if kfree is not None else [rng.randrange(26) for _ in range(nf)]
    for _ in range(10000):
        al = list(alpha) if alpha is not None else rng.sample(range(26), 26)
        x = [0] * 26
        for i, a in enumerate(al):
            x[a] = i
        if prob.repair(al, x):
            break
        alpha = None
    else:
        return None, None, None
    alpha = al

    def evaluate():
        k = prob.fast_keys(x, kfree)
        return qsum(table, prob.decrypt(alpha, x, k))

    cur = evaluate()
    best = (cur, list(alpha), list(kfree))
    pfree = 0.0 if nf == 0 else min(0.3, 1.5 * nf / (nf + 26))
    lr = math.log(t1 / t0)
    rand, rr = rng.random, rng.randrange
    repair = prob.repair
    for it in range(iters):
        T = t0 * math.exp(lr * it / iters)
        if nf and rand() < pfree:
            j = rr(nf)
            old = kfree[j]
            kfree[j] = rr(26)
            new = evaluate()
            if new >= cur or rand() < math.exp((new - cur) / T):
                cur = new
                if cur > best[0]:
                    best = (cur, list(alpha), list(kfree))
            else:
                kfree[j] = old
        else:
            save = alpha[:]
            i, j = rr(26), rr(25)
            if j >= i:
                j += 1
            a, b = alpha[i], alpha[j]
            alpha[i], alpha[j] = b, a
            x[a], x[b] = j, i
            if repair(alpha, x):
                new = evaluate()
                if new >= cur or rand() < math.exp((new - cur) / T):
                    cur = new
                    if cur > best[0]:
                        best = (cur, list(alpha), list(kfree))
                    continue
            alpha[:] = save
            for i2, a2 in enumerate(save):
                x[a2] = i2
    return best


def polish(prob, table, alpha, kfree):
    """Greedy finish from a zero-broken state: best-improving swaps / free-key changes that keep
    every clue equation exact, until no move helps."""
    alpha, kfree = list(alpha), list(kfree)
    x = [0] * 26
    for i, a in enumerate(alpha):
        x[a] = i

    def ev():
        k, broken = prob.keys(x, kfree)
        return qsum(table, prob.decrypt(alpha, x, k)), broken

    cur, br = ev()
    assert br == 0
    improved = True
    while improved:
        improved = False
        for i in range(26):
            for j in range(i + 1, 26):
                a, b = alpha[i], alpha[j]
                alpha[i], alpha[j] = b, a
                x[a], x[b] = j, i
                q, br = ev()
                if br == 0 and q > cur + 1e-9:
                    cur, improved = q, True
                else:
                    alpha[i], alpha[j] = a, b
                    x[a], x[b] = i, j
        for f in range(len(kfree)):
            old = kfree[f]
            for v in range(26):
                kfree[f] = v
                q, br = ev()
                if q > cur + 1e-9:
                    cur, old, improved = q, v, True
            kfree[f] = old
        if not improved:      # pairs of neighbouring free key values together
            for f in range(len(kfree) - 1):
                if prob.free[f + 1] != prob.free[f] + 1:
                    continue
                o1, o2 = kfree[f], kfree[f + 1]
                for v1 in range(26):
                    kfree[f] = v1
                    for v2 in range(26):
                        kfree[f + 1] = v2
                        q, br = ev()
                        if q > cur + 1e-9:
                            cur, o1, o2, improved = q, v1, v2, True
                kfree[f], kfree[f + 1] = o1, o2
    return cur, alpha, kfree


def near_truth(prob, table, rng, alpha, key, swaps=1, iters=20000):
    """Mechanics check: start from the planted alphabet with `swaps` random swaps of letters that
    occur at no clue position and random free key values, anneal briefly at low temperature and polish.
    Returns (score per quadgram, text)."""
    al = [ord(ch) - 65 for ch in alpha]
    inside = {v for _, c, p in prob.clue for v in (c, p)}
    out = [i for i, a in enumerate(al) if a not in inside]
    for _ in range(swaps if len(out) > 1 else 0):
        i, j = rng.sample(out, 2)
        al[i], al[j] = al[j], al[i]
    kf = [rng.randrange(26) for _ in prob.free]
    q0, al, kf = polish(prob, table, al, kf)
    q, al2, kf2 = anneal(prob, table, rng, iters, t0=0.5, t1=0.05, alpha=al, kfree=kf)
    q, al2, kf2 = polish(prob, table, al2, kf2)
    if q < q0:
        q = q0
    else:
        al, kf = al2, kf2
    txt, br = prob.text(al, kf)
    assert br == 0
    return q / (prob.n - 3), txt


def witness_alpha(prob, max_nodes=10 ** 7):
    """A valid alphabet (list of letter numbers by place) from the exact solver, or None."""
    from .idea130_exact import Budget, decide, equations
    rows = equations("".join(chr(65 + v) for v in prob.c), prob.cribs, prob.L, prob.form, prob.pos)
    try:
        verdict, wit, _ = decide(rows, max_nodes)
    except Budget:
        return None
    if verdict != "SAT":
        return None
    a = [None] * 26
    for ch, v in wit.items():
        a[v] = ord(ch) - 65
    rest = iter(v for v in range(26) if v not in a)
    return [v if v is not None else next(rest) for v in a]


def search(prob, table, rng, restarts, iters, out_all=None, **kw):
    """Several restarts; returns the best (score per quadgram, text, alphabet string, kfree) found
    with every clue equation exact, plus how many restarts reached such a state."""
    best, reached = None, 0
    for _ in range(restarts):
        q, al, kf = anneal(prob, table, rng, iters, **kw)
        if q is None:
            continue
        reached += 1
        if out_all is not None:
            out_all.append(q / (prob.n - 3))
        q, al, kf = polish(prob, table, al, kf)
        if best is None or q > best[0]:
            best = (q, al, kf)
    if best is None:
        return None, reached
    q, al, kf = best
    txt, br = prob.text(al, kf)
    assert br == 0
    return {"score": q / (prob.n - 3), "text": txt, "alphabet": "".join(chr(65 + a) for a in al),
            "kfree": kf}, reached


def encrypt(pt, alpha, key, form="beau"):
    """alpha: alphabet string, key: list of L ints."""
    x = {ch: i for i, ch in enumerate(alpha)}
    L = len(key)
    out = []
    for i, ch in enumerate(pt):
        k = key[i % L]
        v = (k - x[ch]) % 26 if form == "beau" else (x[ch] + k) % 26
        out.append(alpha[v])
    return "".join(out)


def truth_score(prob, table, alpha, key):
    """Score of the planted truth under the same model (per quadgram)."""
    al = [ord(ch) - 65 for ch in alpha]
    kfree = [key[r] for r in prob.free]
    txt, br = prob.text(al, kfree)
    p = [ord(ch) - 65 for ch in txt]
    return qsum(table, p) / (prob.n - 3), txt, br


class _Replica:
    def __init__(self, prob, table, rng, start=None):
        self.prob, self.table, self.rng = prob, table, rng
        nf = len(prob.free)
        self.kfree = [rng.randrange(26) for _ in range(nf)]
        for _ in range(3000):
            al = rng.sample(range(26), 26)
            x = [0] * 26
            for i, a in enumerate(al):
                x[a] = i
            if prob.repair(al, x):
                break
        else:
            if start is None:
                raise ValueError("no valid random start")
            al = list(start)
            x = [0] * 26
            for i, a in enumerate(al):
                x[a] = i
            assert prob.repair(al, x)
        self.alpha, self.x = al, x
        self.cur = self.evaluate()

    def evaluate(self):
        p = self.prob
        return qsum(self.table, p.decrypt(self.alpha, self.x, p.fast_keys(self.x, self.kfree)))

    def steps(self, n, T, pfree):
        rng, alpha, x, kfree, prob = self.rng, self.alpha, self.x, self.kfree, self.prob
        rand, rr, nf = rng.random, rng.randrange, len(kfree)
        cur = self.cur
        best = None
        for _ in range(n):
            if nf and rand() < pfree:
                j = rr(nf)
                old = kfree[j]
                kfree[j] = rr(26)
                new = self.evaluate()
                if new >= cur or rand() < math.exp((new - cur) / T):
                    cur = new
                    if best is None or cur > best[0]:
                        best = (cur, alpha[:], kfree[:])
                else:
                    kfree[j] = old
                continue
            save = alpha[:]
            i, j = rr(26), rr(25)
            if j >= i:
                j += 1
            a, b = alpha[i], alpha[j]
            alpha[i], alpha[j] = b, a
            x[a], x[b] = j, i
            if prob.repair(alpha, x):
                new = self.evaluate()
                if new >= cur or rand() < math.exp((new - cur) / T):
                    cur = new
                    if best is None or cur > best[0]:
                        best = (cur, alpha[:], kfree[:])
                    continue
            alpha[:] = save
            for i2, a2 in enumerate(save):
                x[a2] = i2
        self.cur = cur
        return best


def tempering(prob, table, rng, sweeps, temps=(0.6, 1.0, 1.6, 2.5, 4.0, 6.5, 10.0, 16.0), per=200, start=None):
    """Parallel tempering: one replica per temperature, `per` moves each between exchange attempts,
    `sweeps` exchange rounds. Returns the best (quadgram sum, alpha, kfree) seen at any temperature."""
    nf = len(prob.free)
    pfree = 0.0 if nf == 0 else min(0.3, 1.5 * nf / (nf + 26))
    reps = [_Replica(prob, table, rng, start) for _ in temps]
    best = (reps[0].cur, reps[0].alpha[:], reps[0].kfree[:])
    for _ in range(sweeps):
        for r, T in zip(reps, temps):
            b = r.steps(per, T, pfree)
            if b and b[0] > best[0]:
                best = b
        for i in range(len(temps) - 1):
            a, b = reps[i], reps[i + 1]
            d = (b.cur - a.cur) * (1 / temps[i] - 1 / temps[i + 1])
            if d >= 0 or rng.random() < math.exp(d):
                reps[i], reps[i + 1] = b, a
    return best
