"""Helpers for idea 92: short key formulas when the tableau alphabet is hidden.

The key stream is KNOWN once a formula is chosen (k_i = b1*f1(i) + b2*f2(i) + b3*f3(i) + c mod 26),
the alphabet X is not. Six layouts:

  V      X[C] = X[P] + k        one hidden alphabet on both sides, Vigenere form
  B      X[C] = k - X[P]        one hidden alphabet on both sides, Beaufort form
  hpAZ   A[C] = X[P] + k        hidden plain side, cipher side A-Z      (hpKR: cipher side KRYPTOS)
  hcAZ   X[C] = A[P] + k        hidden cipher side, plain side A-Z      (hcKR: plain side KRYPTOS)

(Variant Beaufort is V with -k, and Beaufort in the half-hidden layouts is the same test with X or the
coefficients negated, so all b = 1..25 cover them.)

For a given ciphertext the clue letters give a fixed set of linear tests on the key values:

  * every closed loop in the graph "cipher letter - plain letter" gives one equation on the k_i alone
    (K4, layouts V and B: 24 clue letters, 21 different letters in one piece, so 4 loops);
  * what is left places the letters of each piece relative to each other, and no two letters may share
    a position.

plan() works the tests out once per ciphertext as integer vectors over the 24 clue positions, so a formula
is tested by dot products. Because the tests are linear in the formula, a hash join over single
ingredients finds every fitting formula of up to three ingredients without listing them all.
"""
import itertools
from multiprocessing import Pool

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import CRIBS

N = 97
LAYOUTS = ("V", "B", "hpAZ", "hpKR", "hcAZ", "hcKR")
KEY = 5                      # tests used as the join key (padded with empty ones)
CAP = 60_000_000             # most raw join matches we are willing to check for one search
_FIXED = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}


# ------------------------------------------------------------------ ingredients

def carved(i):
    """(row, column) of K4 letter i on the copper: 4 letters end the K3 row, then rows of 31."""
    if i < 4:
        return 0, 27 + i
    return 1 + (i - 4) // 31, (i - 4) % 31


def library(small=False, n=N):
    """{name: [value at 0..n-1]}: idea 54's position and grid ingredients (no neighbour letters)."""
    lib = {}
    pos = range(n)
    lib["i"] = [i for i in pos]
    lib["i^2"] = [i * i for i in pos]
    lib["i^3"] = [i ** 3 for i in pos]
    lib["tri(i)"] = [i * (i + 1) // 2 for i in pos]
    pi = "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821"
    e = "27182818284590452353602874713526624977572470936999595749669676277240766303535475945713821785251664274274"
    primes = [m for m in range(2, 700) if all(m % d for d in range(2, int(m ** 0.5) + 1))]
    fib = [0, 1]
    while len(fib) < n + 3:
        fib.append(fib[-1] + fib[-2])
    for off in (0, 1):
        lib["pi_digit+%d" % off] = [int(pi[i + off]) for i in pos]
        lib["e_digit+%d" % off] = [int(e[i + off]) for i in pos]
        lib["prime+%d" % off] = [primes[i + off] for i in pos]
        lib["fib+%d" % off] = [fib[i + off] for i in pos]
    lib["2^i"] = [pow(2, i, 26 * 13) for i in pos]
    lib["3^i"] = [pow(3, i, 26 * 13) for i in pos]
    for w in ((7, 31) if small else range(2, 41)):
        lib["col%d" % w] = [i % w for i in pos]
        lib["row%d" % w] = [i // w for i in pos]
        lib["row*col%d" % w] = [(i % w) * (i // w) for i in pos]
    lib["carved_row"] = [carved(i)[0] for i in pos]
    lib["carved_col"] = [carved(i)[1] for i in pos]
    lib["carved_row*col"] = [carved(i)[0] * carved(i)[1] for i in pos]
    return {k: [x % 26 for x in v] for k, v in lib.items()}


def classes(lib, pos):
    """Ingredients grouped by their values at the clue positions: [(values, [names])]."""
    seen = {}
    for name in sorted(lib):
        sig = tuple(lib[name][i] for i in pos)
        if any(sig):
            seen.setdefault(sig, []).append(name)
    return sorted(seen.items(), key=lambda kv: kv[1][0])


# ------------------------------------------------------------------ the tests the clues give

def _vec(m, j=None, const=0):
    v = [0] * (m + 1)
    if j is not None:
        v[j] = 1
    v[m] = const
    return v


def plan(layout, ct, cribs):
    """Work out the tests for one layout and one ciphertext.

    Linear forms are integer lists: one coefficient per clue position (in sorted order) plus a constant.
    Returns {"c26": forms that must be 0 mod 26, "c2": forms that must be even,
             "comps": pieces [{"letters", "signs", "forms", "mode", "anchor"}], "cvals": constants to try}.
    A letter's position is sign * root + form. mode: "rel" (root free, only differences matter), "abs"
    (root 0), "anchored" (2 * root = anchor form, two roots), "free" (any root, Beaufort piece without an
    odd loop)."""
    pos = sorted(cribs)
    m = len(pos)
    c26, c2, comps = [], [], []
    if layout in ("V", "B"):
        sg = 1 if layout == "V" else -1
        adj = {}
        for j, i in enumerate(pos):
            u, v = ct[i], cribs[i]                    # X[u] = sg * X[v] + k_j
            adj.setdefault(u, []).append((j, v, True))
            adj.setdefault(v, []).append((j, u, False))
        info, used = {}, set()
        for start in sorted(adj):
            if start in info:
                continue
            info[start] = (1, _vec(m))
            order, queue = [start], [start]
            while queue:
                a = queue.pop(0)
                sa, fa = info[a]
                for j, b, a_is_cipher in adj[a]:
                    if b in info or j in used:
                        continue
                    used.add(j)
                    if a_is_cipher:                   # X[b] = sg * (X[a] - k_j)
                        fb = [sg * x for x in fa]
                        fb[j] -= sg
                    else:                             # X[b] = sg * X[a] + k_j
                        fb = [sg * x for x in fa]
                        fb[j] += 1
                    info[b] = (sg * sa, fb)
                    order.append(b)
                    queue.append(b)
            comp = {"letters": order, "signs": [info[x][0] for x in order], "forms": [info[x][1] for x in order],
                    "anchor": None, "mode": "rel" if layout == "V" else "free"}
            members = set(order)
            for j, i in enumerate(pos):
                u, v = ct[i], cribs[i]
                if j in used or u not in members:
                    continue
                (su, fu), (sv, fv) = info[u], info[v]
                lin = [a - sg * b for a, b in zip(fu, fv)]
                lin[j] -= 1                           # (su - sg*sv) * root + lin = 0
                f = su - sg * sv
                if f == 0:
                    c26.append(lin)
                    continue
                w = [-x * (f // 2) for x in lin]      # 2 * root = w
                if comp["anchor"] is None:
                    comp["anchor"], comp["mode"] = w, "anchored"
                    c2.append(w)
                else:
                    c26.append([a - b for a, b in zip(w, comp["anchor"])])
            comps.append(comp)
        cvals = tuple(range(26)) if layout == "V" else (0, 1)
    else:
        idx = {ch: k for k, ch in enumerate(_FIXED[layout[2:]])}
        first, comp = {}, {"letters": [], "signs": [], "forms": [], "anchor": None, "mode": "abs"}
        for j, i in enumerate(pos):
            if layout.startswith("hp"):               # X[P] = A[C] - k
                letter, form = cribs[i], _vec(m, const=idx[ct[i]])
                form[j] = -1
            else:                                     # X[C] = A[P] + k
                letter, form = ct[i], _vec(m, j, idx[cribs[i]])
            if letter in first:
                c26.append([a - b for a, b in zip(first[letter], form)])
            else:
                first[letter] = form
                comp["letters"].append(letter)
                comp["signs"].append(0)
                comp["forms"].append(form)
        comps.append(comp)
        cvals = (0,)                                  # a constant only rotates the hidden alphabet
    # make the tests free of the constant c where possible, and put those first (they filter best)
    s = [sum(f[:m]) % 26 for f in c26]
    piv = next((j for j in range(len(c26)) if s[j] % 2 and s[j] % 13), None)
    if piv is not None:
        inv = next(x for x in range(26) if x * s[piv] % 26 == 1)
        for j in range(len(c26)):
            if j != piv and s[j]:
                t = s[j] * inv % 26
                c26[j] = [a - t * b for a, b in zip(c26[j], c26[piv])]
        c26 = [f for j, f in enumerate(c26) if j != piv] + [c26[piv]]
    return {"layout": layout, "pos": pos, "c26": c26, "c2": c2, "comps": comps, "cvals": cvals}


def loops(pl):
    """(number of exact tests mod 26, parity tests, letters placed, pieces)."""
    return len(pl["c26"]), len(pl["c2"]), sum(len(c["letters"]) for c in pl["comps"]), len(pl["comps"])


def _choose(n, k):
    out = 1.0
    for j in range(k):
        out *= (n - j) / (k - j)
    return out if 0 <= k <= n else 0.0


def distinct_chance(pl):
    """Rough chance that random key values let all placed letters sit on different positions of one
    alphabet: each piece must not clash with itself, and the pieces must fit side by side."""
    p, placed = 1.0, 0
    for j, c in enumerate(sorted(pl["comps"], key=lambda c: -len(c["letters"]))):
        n = len(c["letters"])
        q = 1.0
        for x in range(1, n):
            q *= (26 - x) / 26.0
        roots = {"anchored": 2, "free": 26, "rel": 26 if j else 1}.get(c["mode"], 1)
        room = _choose(26 - placed, n) / _choose(26, n)
        p *= q * min(1.0, roots * room)
        placed += n
    return p


def pass_chance(pl):
    """Chance per (formula, constant) of passing the loop tests, and of passing everything."""
    lp = 26.0 ** -len(pl["c26"]) * 0.5 ** len(pl["c2"])
    return lp, lp * distinct_chance(pl)


def n_formulas(ncls, size):
    return {0: 1, 1: ncls * 25, 2: ncls * (ncls - 1) // 2 * 625,
            3: ncls * (ncls - 1) * (ncls - 2) // 6 * 15625}[size]


# ------------------------------------------------------------------ tables and the join

class Tables:
    """Everything a search needs for one (layout, ciphertext): tests applied to every single ingredient."""

    def __init__(self, layout, ct, cribs, small=False, lib=None):
        self.layout, self.ct, self.cribs = layout, ct, cribs
        self.lib = lib or library(small)
        self.pl = pl = plan(layout, ct, cribs)
        pos = pl["pos"]
        m = len(pos)
        self.cls = classes(self.lib, pos)
        self.ncls = len(self.cls)
        zero = [0] * (m + 1)
        keyf = (pl["c26"] + [zero] * KEY)[:KEY]
        rest = pl["c26"][KEY:]
        self.n26 = len(rest)
        rest = rest + pl["c2"]
        potf, self.comps = [], []
        for c in pl["comps"]:
            slots = list(range(len(potf), len(potf) + len(c["forms"])))
            potf += c["forms"]
            anchor = None
            if c["anchor"] is not None:
                anchor = len(potf)
                potf.append(c["anchor"])
            self.comps.append((tuple(slots), tuple(c["signs"]), c["mode"], anchor, len(slots)))
        self.big = max(range(len(self.comps)), key=lambda j: self.comps[j][4])
        allf = keyf + rest + potf
        nk, nr = KEY, len(rest)
        self.S = [sum(f[:m]) % 26 for f in allf]
        self.D = [f[m] % 26 for f in allf]
        self.ck, self.rest, self.pot = [], [], []
        for sig, _ in self.cls:
            d = [sum(a * b for a, b in zip(f, sig)) % 26 for f in allf]
            for b in range(1, 26):
                v = [(b * x) % 26 for x in d]
                self.ck.append(tuple(v[:nk]))
                self.rest.append(tuple(v[nk:nk + nr]))
                self.pot.append(tuple(v[nk + nr:]))
        self.nE = len(self.ck)
        self.Sk, self.Dk = self.S[:nk], self.D[:nk]
        self.Sr, self.Dr = self.S[nk:nk + nr], self.D[nk:nk + nr]
        self.Sp, self.Dp = self.S[nk + nr:], self.D[nk + nr:]
        # R: what the rest of the formula must add up to, for every (single ingredient or none, constant)
        self.R = {}
        for e in range(-1, self.nE):
            v = self.ck[e] if e >= 0 else (0,) * nk
            for c in pl["cvals"]:
                key = tuple((-(v[j] + c * self.Sk[j] + self.Dk[j])) % 26 for j in range(nk))
                self.R.setdefault(key, []).append((e, c))

    def raw_matches(self, size):
        """Expected number of join matches to check for formulas of this size."""
        left = {0: 1, 1: 1, 2: self.nE, 3: self.nE * (self.nE - 25) // 2}[size]
        return left * sum(len(v) for v in self.R.values()) / 26.0 ** min(KEY, len(self.pl["c26"]))

    def check(self, es, c):
        """None: a loop test fails. False: two letters share a position. Else the good roots per piece."""
        rest, pot = self.rest, self.pot
        for j in range(len(self.Sr)):
            v = c * self.Sr[j] + self.Dr[j]
            for e in es:
                v += rest[e][j]
            if v % (26 if j < self.n26 else 2):
                return None
        vals = []
        for t in range(len(self.Sp)):
            v = c * self.Sp[t] + self.Dp[t]
            for e in es:
                v += pot[e][t]
            vals.append(v % 26)
        out = []
        for slots, signs, mode, anchor, n in self.comps:
            if mode == "anchored":
                cand = (vals[anchor] // 2, vals[anchor] // 2 + 13)
            elif mode == "free":
                cand = range(26)
            else:
                if len({vals[t] for t in slots}) != n:
                    return False
                out.append([0])
                continue
            good = [r for r in cand if len({(s * r + vals[t]) % 26 for t, s in zip(slots, signs)}) == n]
            if not good:
                return False
            out.append(good)
        return out

    def values(self, es, c):
        vals = []
        for t in range(len(self.Sp)):
            vals.append((c * self.Sp[t] + self.Dp[t] + sum(self.pot[e][t] for e in es)) % 26)
        return vals

    def spread(self, es, c):
        """How many letters of the biggest piece land on different positions (the near-miss gauge)."""
        vals = self.values(es, c)
        slots, signs, mode, anchor, n = self.comps[self.big]
        if mode == "anchored":
            cand = (vals[anchor] // 2, vals[anchor] // 2 + 13)
        else:
            cand = range(26) if mode == "free" else (0,)
        return max(len({(s * r + vals[t]) % 26 for t, s in zip(slots, signs)}) for r in cand)

    def clue_stream(self, es, c):
        """Key values at the clue positions (to tell equal streams apart from equal formulas)."""
        out = []
        for j in range(len(self.pl["pos"])):
            v = c
            for e in es:
                v += (e % 25 + 1) * self.cls[e // 25][0][j]
            out.append(v % 26)
        return tuple(out)

    def small_search(self):
        """Formulas of 0, 1 and 2 ingredients.

        Returns (loop passes, of those with a flat key, distinct streams passing, hits, most letters on
        different positions). A flat key takes at most two values on the clue positions (0 and 13, say): it
        passes loop tests for free and can never put the letters apart."""
        passes, flat, hits, seen, near = 0, 0, [], set(), 0
        cand = [((), e, c) for e, c in self.R.get((0,) * KEY, ())]
        for e1 in range(self.nE):
            for e2, c in self.R.get(self.ck[e1], ()):
                if e2 >= 0 and e2 // 25 > e1 // 25:
                    cand.append(((e1,), e2, c))
        for head, e, c in cand:
            es = head + ((e,) if e >= 0 else ())
            r = self.check(es, c)
            if r is None:
                continue
            passes += 1
            ks = self.clue_stream(es, c)
            seen.add(ks)
            flat += len(set(ks)) <= 2
            if r:
                hits.append((es, c, r))
            else:
                near = max(near, self.spread(es, c))
        return passes, flat, len(seen), hits, near

    def triple_chunk(self, firsts):
        """Three-ingredient formulas whose first ingredient is in `firsts`."""
        ck, get, check = self.ck, self.R.get, self.check
        passes, flat, hits, near = 0, 0, [], 0
        for e1 in firsts:
            a0, a1, a2, a3, a4 = ck[e1]
            for e2 in range((e1 // 25 + 1) * 25, self.nE):
                b = ck[e2]
                h = get(((a0 + b[0]) % 26, (a1 + b[1]) % 26, (a2 + b[2]) % 26, (a3 + b[3]) % 26, (a4 + b[4]) % 26))
                if h:
                    lim = e2 // 25
                    for e3, c in h:
                        if e3 // 25 > lim:
                            r = check((e1, e2, e3), c)
                            if r is not None:
                                passes += 1
                                if r:
                                    hits.append(((e1, e2, e3), c, r))
                                else:
                                    sp = self.spread((e1, e2, e3), c)
                                    near = max(near, sp)
                                    flat += sp <= 3 and len(set(self.clue_stream((e1, e2, e3), c))) <= 2
        return passes, flat, hits, near

    def name(self, es, c, pick=None):
        parts = ["%d*%s" % (e % 25 + 1, (pick[j] if pick else self.cls[e // 25][1][0])) for j, e in enumerate(es)]
        return " + ".join(parts + ["%d" % c])


_T = {}


def _init(layout, ct, cribs, small):
    _T["t"] = Tables(layout, ct, cribs, small)


def _work(firsts):
    return _T["t"].triple_chunk(firsts)


def search(layout, ct, cribs, small=False, sizes=(0, 1, 2, 3), procs=None, cap=CAP):
    """Every formula of the given sizes for one layout. Returns a dict with counts, hits and what was skipped."""
    t = Tables(layout, ct, cribs, small)
    pl = t.pl
    lp, fp = pass_chance(pl)
    out = {"layout": layout, "tables": t, "loops": loops(pl), "hits": [], "skipped": [], "tested": 0,
           "passes": 0, "pred_passes": 0.0, "pred_hits": 0.0, "streams": 0, "near": 0, "flat": 0,
           "letters": t.comps[t.big][4]}
    nc = len(pl["cvals"])
    if 2 in sizes or 1 in sizes or 0 in sizes:
        if t.raw_matches(2) > cap:
            out["skipped"].append("0-2")
        else:
            p, fl, s, h, near = t.small_search()
            out["flat"] += fl
            out["near"] = max(out["near"], near)
            n = sum(n_formulas(t.ncls, k) for k in (0, 1, 2)) * nc
            out["tested"] += n
            out["passes"] += p
            out["streams"] += s
            out["pred_passes"] += n * lp
            out["pred_hits"] += n * fp
            out["hits"] += h
    if 3 in sizes:
        if t.raw_matches(3) > cap:
            out["skipped"].append("3")
        else:
            firsts = list(range(t.nE))
            chunks = [firsts[i:i + 50] for i in range(0, len(firsts), 50)]
            n = n_formulas(t.ncls, 3) * nc
            out["tested"] += n
            out["pred_passes"] += n * lp
            out["pred_hits"] += n * fp
            if procs == 1:
                res = [t.triple_chunk(ch) for ch in chunks]
            else:
                with Pool(procs, initializer=_init, initargs=(layout, ct, cribs, small)) as pool:
                    res = list(pool.imap_unordered(_work, chunks))
            for p, fl, h, near in res:
                out["passes"] += p
                out["flat"] += fl
                out["hits"] += h
                out["near"] = max(out["near"], near)
    return out


# ------------------------------------------------------------------ reading a survivor

class Scorer:
    def __init__(self, qg):
        self.get, self.floor = qg.logp.get, qg.floor

    def __call__(self, text):
        get, fl = self.get, self.floor
        return sum(get(text[i:i + 4], fl) for i in range(len(text) - 3)) / (len(text) - 3)


def full_streams(t, es, c):
    """Every full-length key stream the hit stands for (ingredients equal on the clues may differ elsewhere)."""
    seen = {}
    for pick in itertools.product(*[t.cls[e // 25][1] for e in es]):
        k = [c] * N
        for e, name in zip(es, pick):
            b, f = e % 25 + 1, t.lib[name]
            k = [(x + b * y) % 26 for x, y in zip(k, f)]
        seen.setdefault(tuple(k), t.name(es, c, pick))
    return [(name, list(k)) for k, name in seen.items()]


def arrangements(t, es, c, roots, cap=2000):
    """Every way to lay the pieces on one alphabet without a clash: yields {letter: position}."""
    vals = t.values(es, c)
    pieces = []
    for j, ((slots, signs, mode, anchor, n), good) in enumerate(zip(t.comps, roots)):
        letters = t.pl["comps"][j]["letters"]
        cand = range(26) if (mode == "rel" and j > 0) else good
        pieces.append((letters, slots, signs, list(cand)))
    count = [0]

    def rec(j, placed, taken):
        if count[0] >= cap:
            return
        if j == len(pieces):
            count[0] += 1
            yield dict(placed)
            return
        letters, slots, signs, cand = pieces[j]
        for r in cand:
            ps = [(s * r + vals[x]) % 26 for x, s in zip(slots, signs)]
            if len(set(ps)) != len(ps) or taken & set(ps):
                continue
            new = dict(placed)
            new.update(zip(letters, ps))
            for x in rec(j + 1, new, taken | set(ps)):
                yield x

    return rec(0, {}, set())


def fill(layout, ct, k, placed, score, rng, restarts=6):
    """Complete the hidden alphabet (free letters on free positions) for the best English reading.

    Returns (score, plaintext, alphabet as a 26-letter string)."""
    free_l = [ch for ch in AZ if ch not in placed]
    free_p = [p for p in range(26) if p not in set(placed.values())]
    fixed = _FIXED.get(layout[2:])
    sign = -1 if layout == "B" else 1

    def decrypt(x):
        at = [None] * 26
        for ch, p in x.items():
            at[p] = ch
        if layout in ("V", "B"):
            return "".join(at[(sign * (x[ch] - kk)) % 26] for ch, kk in zip(ct, k))
        if layout.startswith("hp"):
            return "".join(at[(fixed.index(ch) - kk) % 26] for ch, kk in zip(ct, k))
        return "".join(fixed[(x[ch] - kk) % 26] for ch, kk in zip(ct, k))

    def build(perm):
        x = dict(placed)
        x.update(zip(free_l, perm))
        return x

    best = (-99.0, None, None)
    if len(free_l) <= 6:
        tries = itertools.permutations(free_p)
    else:
        tries = None
    if tries is not None:
        for perm in tries:
            x = build(perm)
            pt = decrypt(x)
            sc = score(pt)
            if sc > best[0]:
                best = (sc, pt, x)
    else:
        for _ in range(restarts):
            perm = free_p[:]
            rng.shuffle(perm)
            cur = score(decrypt(build(perm)))
            improved = True
            while improved:
                improved = False
                for a in range(len(perm)):
                    for b in range(a + 1, len(perm)):
                        perm[a], perm[b] = perm[b], perm[a]
                        sc = score(decrypt(build(perm)))
                        if sc > cur + 1e-12:
                            cur, improved = sc, True
                        else:
                            perm[a], perm[b] = perm[b], perm[a]
            if cur > best[0]:
                x = build(perm)
                best = (cur, decrypt(x), x)
    x = best[2]
    at = [None] * 26
    for ch, p in x.items():
        at[p] = ch
    return best[0], best[1], "".join(at)


UNITS = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)


def canon(layout, k):
    """One name for every key that reads the same. V: u*k with the alphabet stretched by a unit u.
    B: the same, and k + 2t with the alphabet moved t places. Half-hidden: k + t (the alphabet turned)."""
    if layout == "V":
        return min(tuple([u * x % 26 for x in k]) for u in UNITS)
    if layout == "B":
        out = []
        for u in UNITS:
            v = [u * x % 26 for x in k]
            t = v[0] - v[0] % 2
            out.append(tuple([(x - t) % 26 for x in v]))
        return min(out)
    return tuple([(x - k[0]) % 26 for x in k])


def partial(layout, ct, k, placed):
    """Decrypt with only the letters the clues place; '.' where the letter is not known yet."""
    at = {p: ch for ch, p in placed.items()}
    fixed = _FIXED.get(layout[2:])
    if layout in ("V", "B"):
        sign = -1 if layout == "B" else 1
        return "".join(at.get((sign * (placed[ch] - kk)) % 26, ".") if ch in placed else "."
                       for ch, kk in zip(ct, k))
    if layout.startswith("hp"):
        return "".join(at.get((fixed.index(ch) - kk) % 26, ".") for ch, kk in zip(ct, k))
    return "".join(fixed[(placed[ch] - kk) % 26] if ch in placed else "." for ch, kk in zip(ct, k))


def partial_score(text, score):
    """Mean score of the four-letter windows that are fully known (very low when fewer than 10 are)."""
    get, fl = score.get, score.floor
    t, n = 0.0, 0
    for i in range(len(text) - 3):
        q = text[i:i + 4]
        if "." not in q:
            t += get(q, fl)
            n += 1
    return t / n if n >= 10 else -20.0 + n


def read_hits(res, ct, score, rng, limit=300, max_streams=200000):
    """Read the fits. Step 1: every different key stream is laid out on one alphabet (pieces side by side)
    and its forced letters are scored. Step 2: the `limit` best are completed on English.

    Returns (rows, different key streams, streams that can be laid out); rows are (score, plaintext,
    formula, alphabet, key stream), best first."""
    t, lay = res["tables"], res["layout"]
    todo = {}
    for es, c, roots in res["hits"]:
        for name, k in full_streams(t, es, c):
            todo.setdefault(canon(lay, k), (name, k, es, c, roots))
    items = sorted(todo.values(), key=lambda x: x[0])
    total = len(items)
    if total > max_streams:
        items = rng.sample(items, max_streams)
    ranked = []
    for name, k, es, c, roots in items:
        best = None
        for placed in arrangements(t, es, c, roots, cap=200):
            sc = partial_score(partial(lay, ct, k, placed), score)
            if best is None or sc > best:
                best = sc
        if best is not None:
            ranked.append((best, name, k, es, c, roots))
    ranked.sort(key=lambda x: (-x[0], x[1]))
    rows = []
    for _, name, k, es, c, roots in ranked[:limit]:
        best = None
        for placed in arrangements(t, es, c, roots, cap=200):
            r = fill(lay, ct, k, placed, score, rng)
            if best is None or r[0] > best[0]:
                best = r
        rows.append((best[0], best[1], name, best[2], k))
    rows.sort(key=lambda r: (-r[0], r[2]))
    return rows, total, len(ranked)


def distinct_streams(t):
    """How many different key streams the 0-2 ingredient formulas (constant 0) give on the clue positions:
    (formulas, different streams). In layouts V and B a stream and its 11 other unit multiples are one test."""
    sig = []
    for s, _ in t.cls:
        for b in range(1, 26):
            sig.append(tuple(b * x % 26 for x in s))
    seen = {hash((0,) * len(sig[0]))}
    seen.update(hash(x) for x in sig)
    n = 1 + len(sig)
    for e1 in range(len(sig)):
        a = sig[e1]
        rest = sig[(e1 // 25 + 1) * 25:]
        seen.update([hash(tuple([(x + y) % 26 for x, y in zip(a, b)])) for b in rest])
        n += len(rest)
    return n, len(seen)


# ------------------------------------------------------------------ planting

def encrypt(layout, pt, k, x):
    """Encrypt pt with key values k and hidden alphabet x (a 26-letter string)."""
    ix = {ch: p for p, ch in enumerate(x)}
    fixed = _FIXED.get(layout[2:])
    out = []
    for ch, kk in zip(pt, k):
        if layout == "V":
            out.append(x[(ix[ch] + kk) % 26])
        elif layout == "B":
            out.append(x[(kk - ix[ch]) % 26])
        elif layout.startswith("hp"):
            out.append(fixed[(ix[ch] + kk) % 26])
        else:
            out.append(x[(fixed.index(ch) + kk) % 26])
    return "".join(out)


def formula_stream(lib, terms, c):
    """terms = [(b, ingredient name)]."""
    k = [c] * N
    for b, name in terms:
        k = [(x + b * y) % 26 for x, y in zip(k, lib[name])]
    return k


def plant(layout, terms, rng, text, lib, min_tests=4, tries=5000):
    """A planted message: random hidden alphabet, key from the formula. The text is redrawn until the
    clue letters give at least `min_tests` loop tests in one piece (K4 itself has 4 in one piece);
    min_tests=None takes the first text as it comes. Returns (ct, cribs, pt, alphabet, key stream, draws)."""
    c = rng.randrange(26)
    k = formula_stream(lib, terms, c)
    for draw in range(1, tries + 1):
        o = rng.randrange(len(text) - N)
        pt = text[o:o + N]
        x = "".join(rng.sample(AZ, 26))
        ct = encrypt(layout, pt, k, x)
        cribs = {i: pt[i] for i in CRIBS}
        pl = plan(layout, ct, cribs)
        if min_tests is None or (len(pl["c26"]) >= min_tests and len(pl["comps"]) == 1):
            return ct, cribs, pt, x, k, draw
    raise RuntimeError("no planted text with enough loop tests")


def same_reading(a, b):
    return sum(x == y for x, y in zip(a, b))
