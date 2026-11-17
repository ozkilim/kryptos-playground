"""Idea 83: what the repeated cipher letters inside the clues say about ANY state machine.

The devices: a hidden state in Z_m that moves on after every letter by a hidden table g of that
letter, and a hidden table F that turns a value into a cipher letter.

  moore          C_i = F(s_i),              s_i = s_(i-1) + g(P_i)
  mealy          C_i = F(s_(i-1) + h(P_i)),  s_i = s_(i-1) + g(P_i)      (h: a second hidden table)
  cipher-fed     the same, but the state moves by g(C_i)

Tools here, all working only from the 24 clue letters:

  digram_rule    the one-line test that needs no modulus (see the attack's docstring)
  solve_linear   a small exact solver over Z_m: equations (== 0) and "must differ" conditions
                 (!= 0), depth-first with forced values
  additive       the constraints for moore / mealy in the unknowns g, h (works for a many-to-one F)
  tables         the mealy and cipher-fed devices with a one-to-one F, in the unknowns that make
                 them easy: u(cipher letter) and h(plain letter)
  moduli         which moduli m allow any tables at all: "yes" (tables found and re-checked by
                 running the device), "no" (proved none) or "cap" (node budget ran out: undecided)
  drift_checks   the same devices on KNOWN alphabets, where only g is hidden
"""
import random
from math import gcd

B1, B2 = list(range(21, 34)), list(range(63, 74))
WORD_STARTS = (25, 69)          # NORTHEAST and CLOCK: a space comes before them


# ------------------------------------------------------------------ the rule that needs no modulus

def digram_rule(ct, known):
    """known: {position: plain letter}. In these devices the step from one F-input to the next
    depends only on the two plain letters. So a plain pair that gives a doubled cipher letter once
    must give a doubled letter every time (F one-to-one). Returns the pairs that break this:
    [(plain pair, positions doubled, positions not doubled)]."""
    seen = {}
    for i in sorted(known):
        if i + 1 in known:
            seen.setdefault(known[i] + known[i + 1], ([], []))[ct[i] != ct[i + 1]].append(i)
    return [(d, a, b) for d, (a, b) in sorted(seen.items()) if a and b]


# ------------------------------------------------------------------ linear constraints mod m

def solve_linear(m, cons, fixed=None, cap=2000000, seed=None):
    """cons: [(terms {var: coef}, const, is_equation)] meaning sum(coef * x) + const == 0 (or != 0)
    mod m. Returns (status, {var: value}); status "yes", "no" (search exhausted) or "cap"."""
    fixed = dict(fixed or {})
    clean, names = [], set(fixed)
    for terms, const, eq in cons:
        t = {v: c % m for v, c in terms.items() if c % m}
        if not t:
            if (const % m == 0) != eq:
                return "no", None
            continue
        clean.append((t, const % m, eq))
        names.update(t)
    # order: fixed first, then the variable that closes the most equations (then conditions)
    order, left = list(fixed), set(names) - set(fixed)
    placed = set(order)
    while left:
        def gain(v):
            e = sum(1 for t, _, eq in clean if eq and v in t and all(x in placed or x == v for x in t))
            c = sum(1 for t, _, eq in clean if not eq and v in t and all(x in placed or x == v for x in t))
            near = sum(1 for t, _, eq in clean if eq and v in t)
            return (e, near, c, str(v))
        v = max(sorted(left, key=str), key=gain)
        order.append(v)
        placed.add(v)
        left.discard(v)
    depth_of = {v: i for i, v in enumerate(order)}
    close_eq = [[] for _ in order]
    close_ne = [[] for _ in order]
    for t, const, eq in clean:
        d = max(depth_of[v] for v in t)
        v = order[d]
        rest = [(depth_of[x], c) for x, c in t.items() if x != v]
        (close_eq if eq else close_ne)[d].append((rest, t[v], const))
    values = list(range(m))
    if seed is not None:
        random.Random(seed).shuffle(values)
    val = [0] * len(order)
    nodes = [0]

    def candidates(d):
        if order[d] in fixed:
            return [fixed[order[d]] % m]
        if close_eq[d]:
            rest, a, const = close_eq[d][0]
            b = (-const - sum(val[i] * c for i, c in rest)) % m
            g = gcd(a, m)
            if b % g:
                return []
            mm = m // g
            x0 = (b // g) * pow(a // g, -1, mm) % mm if mm > 1 else 0
            return [x0 + k * mm for k in range(g)]
        return values

    def rec(d):
        if d == len(order):
            return True
        for x in candidates(d):
            nodes[0] += 1
            if nodes[0] > cap:
                raise OverflowError
            ok = True
            for rest, a, const in close_eq[d]:
                if (a * x + const + sum(val[i] * c for i, c in rest)) % m:
                    ok = False
                    break
            if ok:
                for rest, a, const in close_ne[d]:
                    if (a * x + const + sum(val[i] * c for i, c in rest)) % m == 0:
                        ok = False
                        break
            if ok:
                val[d] = x
                if rec(d + 1):
                    return True
        return False

    try:
        found = rec(0)
    except OverflowError:
        return "cap", None
    return ("yes", {v: val[i] for i, v in enumerate(order)}) if found else ("no", None)


# ------------------------------------------------------------------ the devices as constraints

def additive(ct, cribs, kind="moore", same_state=True, differ=True, decipherable=True):
    """Constraints for moore / mealy in the unknowns g (and h), from the clue letters only.

    same_state    the same cipher letter means the same value under F (F is one-to-one)
    differ        different cipher letters mean different values (F is a function at all)
    decipherable  different plain letters move/read differently (g one-to-one for moore, h for mealy)

    Each clue starts from its own unknown state ("D"). Returns (constraints, fixed)."""
    vals = []                                   # per clue position: linear form of the value fed to F
    for b, blk in enumerate((B1, B2)):
        acc = {("D", b): 1}
        for n, i in enumerate(blk):
            p = cribs[i]
            if kind == "moore":
                if n:
                    acc = dict(acc)
                    acc[("g", p)] = acc.get(("g", p), 0) + 1
                vals.append((i, dict(acc)))
            else:
                t = dict(acc)
                t[("h", p)] = t.get(("h", p), 0) + 1
                vals.append((i, t))
                acc = dict(acc)
                acc[("g", p)] = acc.get(("g", p), 0) + 1
    cons = []
    for x in range(len(vals)):
        for y in range(x + 1, len(vals)):
            (i, a), (j, b) = vals[x], vals[y]
            same = ct[i] == ct[j]
            if (same and not same_state) or (not same and not differ):
                continue
            t = dict(b)
            for v, c in a.items():
                t[v] = t.get(v, 0) - c
            cons.append((t, 0, same))
    if decipherable:
        tag = "g" if kind == "moore" else "h"
        ls = sorted(set(cribs[i] for i in B1 + B2))
        for x in range(len(ls)):
            for y in range(x + 1, len(ls)):
                cons.append(({(tag, ls[x]): 1, (tag, ls[y]): -1}, 0, False))
    fixed = {("D", 0): 0}
    if kind == "mealy":
        fixed[("h", cribs[B1[0]])] = 0
    return cons, fixed


def additive_check(m, sol, ct, cribs, kind):
    """Independent check of an `additive` solution: run the device, rebuild F, see it is one-to-one."""
    f, back = {}, {}
    for b, blk in enumerate((B1, B2)):
        s = sol.get(("D", b), 0)
        for n, i in enumerate(blk):
            p = cribs[i]
            if kind == "moore":
                if n:
                    s = (s + sol[("g", p)]) % m
                v = s
            else:
                v = (s + sol[("h", p)]) % m
                s = (s + sol.get(("g", p), 0)) % m
            if f.setdefault(v, ct[i]) != ct[i] or back.setdefault(ct[i], v) != v:
                return False
    return True


def tables(ct, cribs, feed="plain"):
    """The mealy device with a one-to-one F. Unknowns: u(cipher letter) = the value F turns into
    that letter, and h(plain letter). u(C_i) - h(P_i) is the state before letter i, so the step
    taken after letter i is the difference of two neighbours. A feed letter (the plain letter, or
    with feed="cipher" the cipher letter) seen twice inside the clues must give the same step both
    times. u and h must each put different letters on different values."""
    step = {}
    for blk in (B1, B2):
        for i in blk[:-1]:
            t = {}
            for v, c in ((("u", ct[i + 1]), 1), (("h", cribs[i + 1]), -1), (("u", ct[i]), -1), (("h", cribs[i]), 1)):
                t[v] = t.get(v, 0) + c
            step.setdefault(cribs[i] if feed == "plain" else ct[i], []).append(t)
    cons = []
    for forms in step.values():
        for t in forms[1:]:
            d = dict(t)
            for v, c in forms[0].items():
                d[v] = d.get(v, 0) - c
            cons.append((d, 0, True))
    for tag, ls in (("u", sorted(set(ct[i] for i in B1 + B2))), ("h", sorted(set(cribs[i] for i in B1 + B2)))):
        for x in range(len(ls)):
            for y in range(x + 1, len(ls)):
                cons.append(({(tag, ls[x]): 1, (tag, ls[y]): -1}, 0, False))
    return cons, {("u", ct[B1[0]]): 0, ("h", cribs[B1[0]]): 0}


def tables_check(m, sol, ct, cribs, feed="plain"):
    """Independent check of a `tables` solution: derive g, run the device over each clue, compare."""
    g = {}
    for blk in (B1, B2):
        for i in blk[:-1]:
            s0 = (sol[("u", ct[i])] - sol[("h", cribs[i])]) % m
            s1 = (sol[("u", ct[i + 1])] - sol[("h", cribs[i + 1])]) % m
            key = cribs[i] if feed == "plain" else ct[i]
            if g.setdefault(key, (s1 - s0) % m) != (s1 - s0) % m:
                return False
    f = {}
    for c in set(ct[i] for i in B1 + B2):
        if f.setdefault(sol[("u", c)], c) != c:
            return False
    if len(set(sol[("h", cribs[i])] for i in B1 + B2)) != len(set(cribs[i] for i in B1 + B2)):
        return False
    for blk in (B1, B2):
        s = (sol[("u", ct[blk[0]])] - sol[("h", cribs[blk[0]])]) % m
        for i in blk:
            if f.get((s + sol[("h", cribs[i])]) % m) != ct[i]:
                return False
            s = (s + g.get(cribs[i] if feed == "plain" else ct[i], 0)) % m
    return True


def moduli(ct, cribs, ms, kind="moore", cap=200000, tries=4, **flags):
    """{m: status} over a list of moduli.

    kind: "moore" or "mealy" (general form, flags as in `additive`), or "tables" / "tables-cipher"
    (one-to-one F, plain-fed / cipher-fed). Each modulus gets `tries` searches of `cap` nodes with
    different value orders (a "no" from any of them is a proof). Every "yes" is re-checked."""
    fast = kind.startswith("tables")
    feed = "cipher" if kind == "tables-cipher" else "plain"
    one_to_one = fast or (flags.get("same_state", True) and flags.get("differ", True))
    cons, fixed = tables(ct, cribs, feed) if fast else additive(ct, cribs, kind, **flags)
    distinct = len(set(ct[i] for i in B1 + B2))
    out = {}
    for m in ms:
        if one_to_one and m < distinct:          # more cipher letters than values: impossible
            out[m] = "no"
            continue
        for k in range(tries):
            st, sol = solve_linear(m, cons, fixed, cap, seed=1000 * k + m)
            if st != "cap":
                break
        if st == "yes" and one_to_one:
            good = tables_check(m, sol, ct, cribs, feed) if fast else additive_check(m, sol, ct, cribs, kind)
            assert good, "solver returned tables that do not reproduce the clue letters"
        out[m] = st
    return out


def additive_encrypt(pt, m, g, f, h=None, start=0, feed="plain"):
    """The device itself. g, h: {letter: number}; f: list of m cipher symbols.
    h None = moore; feed="cipher" moves the state by g(cipher letter)."""
    s, out = start, []
    for ch in pt:
        if h is None:
            s = (s + g[ch]) % m
            out.append(f[s])
        else:
            c = f[(s + h[ch]) % m]
            out.append(c)
            s = (s + g[c if feed == "cipher" else ch]) % m
    return "".join(out)


# ------------------------------------------------------------------ letter-fed drift on known alphabets

FEEDS = ("plain before", "plain incl.", "cipher before", "cipher incl.")


def drift_checks(k, pl, cl, n=26):
    """Key values k at the clue positions (B1 then B2), for known alphabets. Model: the key moves
    on after each letter by a hidden amount that depends only on that letter: g(plain) or
    g(cipher); 'incl.' means the letter being enciphered has already moved the key.
    Returns {feed: number of checks passed, or -1 if any check fails}."""
    out = {}
    for name, letters, off in ((FEEDS[0], pl, 0), (FEEDS[1], pl, 1), (FEEDS[2], cl, 0), (FEEDS[3], cl, 1)):
        seen, n_pairs, ok = {}, 0, True
        for a, b in ((0, len(B1)), (len(B1), len(B1) + len(B2))):
            for x in range(a, b - 1):
                d = (k[x + 1] - k[x]) % n
                n_pairs += 1
                if seen.setdefault(letters[x + off], d) != d:
                    ok = False
                    break
            if not ok:
                break
        out[name] = n_pairs - len(seen) if ok else -1
    return out


def drift_encrypt(pt, pa, ca, g, feed, beaufort=False, start=0):
    """Known plain alphabet pa and cipher alphabet ca; the key starts at `start` and drifts by g.
    For "cipher incl." the cipher letter c must satisfy index(c) - g(c) = key +- index(p), so g
    has to make c -> index(c) - g(c) one-to-one (see drift_table)."""
    ip = {c: i for i, c in enumerate(pa)}
    inv = {(i - g[c]) % 26: c for i, c in enumerate(ca)} if feed == "cipher incl." else None
    s, out = start, []
    for ch in pt:
        if feed == "plain incl.":
            s = (s + g[ch]) % 26
        v = (s + (-1 if beaufort else 1) * ip[ch]) % 26
        c = inv[v] if inv else ca[v]
        out.append(c)
        if feed == "plain before":
            s = (s + g[ch]) % 26
        elif feed != "plain incl.":
            s = (s + g[c]) % 26
    return "".join(out)


def drift_table(rng, ca, feed):
    """A random step table g that gives a decipherable cipher for this feed."""
    if feed == "cipher incl.":
        perm = list(range(26))
        rng.shuffle(perm)
        return {c: (i - perm[i]) % 26 for i, c in enumerate(ca)}
    return {c: rng.randrange(26) for c in ca}


# ------------------------------------------------------------------ the clock with any outer ring

def ring_encrypt(pt, outer_pos, n, inner, spaces=False, blank=None):
    """Wheatstone-type device: outer_pos {letter: cell} on a ring of n cells, inner = list of m
    cipher symbols. The hand turns forward 1..n cells to each next letter."""
    m, t, out = len(inner), 0, []
    for i, ch in enumerate(pt):
        if i:
            a, b = outer_pos[pt[i - 1]], outer_pos[ch]
            if spaces and i in WORD_STARTS:
                t += ((blank - a) % n or n) + ((b - blank) % n or n)
            else:
                t += (b - a) % n or n
        out.append(inner[t % m])
    return "".join(out)
