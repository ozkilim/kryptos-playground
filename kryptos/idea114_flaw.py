"""Idea 114 helpers: a tableau with one flaw (one extra or missing letter in a header, a row or the strip).

The usual tableau cipher: the cell index in the strip is v = a + k (Vigenere) or v = k - a (Beaufort),
where a is the plaintext letter's place in the header and k the key's row; the cipher letter is the
strip letter at v. One flaw means one of three places is off by one past some cell t:

  col   the header has a letter too many (d=+1) or too few (d=-1) at cell t: a -> g(a)
  row   the row labels are off past row t:                                    k -> g(k)
  body  the strip itself is off past cell t:                                  v -> g(v)

with g(u) = u + d for u >= t, u otherwise (mod 26), t = 1..25, d = +1 / -1. A fourth, narrower
flaw models the carved tableau literally: only ONE row (rho) is off, and only past header column t
(row N of the carved tableau has 31 letters where the others have 30, so a reader going by
physical column drifts one letter late somewhere along it):

  cell  if k == rho and a >= t: v -> v + d

For each flaw the clue letters give a corrected key stream (the key values the rule must explain).
Column flaws give one stream per (t, d); the others can give two candidate key values at a clue
letter (g is not one-to-one), so every combination is tried. The corrected streams then go through
the round-11 key-rule battery unchanged (repeating, sliding, progressive, autokey), with a fast
generated pre-check that only calls the battery when a rule passes its first three equations.
"""
import itertools

from .round11 import POS, _plan, battery

N = 26
MIN_CHECKS = 7
FAMILIES = ("repeating", "sliding", "progressive", "autokey")
NEVER = ("stacked", "chain")
MAX_COMBOS = 256


def g_table(t, d):
    return [(u + d) % N if u >= t else u for u in range(N)]


def g_inverse(t, d):
    inv = [[] for _ in range(N)]
    for u, v in enumerate(g_table(t, d)):
        inv[v].append(u)
    return [tuple(x) for x in inv]


GT = {(t, d): g_table(t, d) for t in range(1, N) for d in (1, -1)}
GI = {(t, d): g_inverse(t, d) for t in range(1, N) for d in (1, -1)}


# ------------------------------------------------------------------ the rules as equations

def _tree(groups):
    first, pairs = {}, []
    for g, idx in groups:
        f = first.setdefault(g, idx)
        if f != idx:
            pairs.append((f, idx))
    return pairs


def rules(pos=POS, min_checks=MIN_CHECKS):
    """[(family, label, checks, [equation strings])]. Each equation is a Python expression that is
    0 mod 26 when it holds, in k0..k23 (key values), p0..p23 / c0..c23 (plain / cipher places)."""
    pl = _plan(pos)
    n = len(pos)
    out = []
    for p in range(1, 18):
        pr = _tree(zip(pl["res"][p], range(n)))
        if len(pr) >= min_checks:
            out.append(("repeating", "repeating p=%d" % p, len(pr), ["k%d-k%d" % (b, a) for a, b in pr]))
    lag1 = pl["lag"][1]
    for p in range(1, 16):
        pr = _tree(zip(pl["lagres"][1, p], range(len(lag1))))
        if len(pr) >= min_checks:
            eq = ["(k%d-k%d)-(k%d-k%d)" % (lag1[b][1], lag1[b][0], lag1[a][1], lag1[a][0]) for a, b in pr]
            out.append(("sliding", "sliding p=%d" % p, len(pr), eq))
    for p in range(1, 13):
        lp = pl["lag"][p]
        if not lp:
            continue
        a0, b0 = lp[0]
        s = "(k%d-k%d)" % (b0, a0)
        pr = _tree(zip(pl["res"][p], range(n)))
        if len(pr) - 1 < min_checks:
            continue
        div = pl["div"][p]
        eq = ["k%d-k%d-%s*%d" % (b, a, s, div[b] - div[a]) for a, b in pr if (a, b) != (a0, b0)]
        out.append(("progressive", "progressive p=%d" % p, len(pr) - 1, eq, s))
    for name, x in (("plain", "p"), ("cipher", "c")):
        for L in range(1, 7):
            pairs = pl["lag"][L]
            if len(pairs) - 1 < min_checks:
                break
            a0, b0 = pairs[0]
            for sg in (1, -1):
                op = "-" if sg == 1 else "+"
                eq = ["(k%d%s%s%d)-(k%d%s%s%d)" % (b, op, x, a, b0, op, x, a0) for a, b in pairs[1:]]
                out.append(("autokey", "autokey %s lag=%d sign=%+d" % (name, L, sg), len(pairs) - 1, eq))
    return [r if len(r) == 5 else r + (None,) for r in out]


def _compile(families, depth=3):
    rs = [r for r in rules() if r[0] in families]
    terms = []
    for fam, _, _, eq, s in rs:
        parts = ["(%s)%%26==0" % e for e in eq[:depth]]
        if s:
            parts.insert(0, "%s%%26" % s)
        terms.append("(" + " and ".join(parts) + ")")
    src = ("def f(k, xp, xc):\n"
           "    %s = k\n    %s = xp\n    %s = xc\n"
           "    return %s\n" % (",".join("k%d" % i for i in range(24)), ",".join("p%d" % i for i in range(24)),
                                ",".join("c%d" % i for i in range(24)), " or\\\n        ".join(terms)))
    ns = {}
    exec(compile(src, "<idea114 pre-check>", "exec"), ns)
    return ns["f"]


PRE_ALL = _compile(FAMILIES)
PRE_NOREP = _compile(("sliding", "progressive", "autokey"))


def check(k, xp, xc, rep=True):
    """Exact battery hits [(checks, rule)] for one corrected stream (fast path first)."""
    if not (PRE_ALL if rep else PRE_NOREP)(k, xp, xc):
        return []
    skip = NEVER if rep else NEVER + ("repeating",)
    return battery(k, POS, xp=xp, xc=xc, min_checks=MIN_CHECKS, skip=skip)


def chance_per_stream(families=FAMILIES):
    """Expected passes per uniformly random 24-value stream, summed over the rules."""
    return sum(26.0 ** -r[2] for r in rules() if r[0] in families)


# ------------------------------------------------------------------ flawed key streams

def _expand(cands):
    """All combinations of per-letter candidate lists (None if any list is empty or too many)."""
    amb = [j for j, c in enumerate(cands) if len(c) != 1]
    if not amb:
        return [[c[0] for c in cands]]
    if any(not cands[j] for j in amb):
        return []
    tot = 1
    for j in amb:
        tot *= len(cands[j])
    if tot > MAX_COMBOS:
        return None
    base = [c[0] for c in cands]
    out = []
    for combo in itertools.product(*(cands[j] for j in amb)):
        v = list(base)
        for j, x in zip(amb, combo):
            v[j] = x
        out.append(v)
    return out


def variants(k, a, b, form, kinds=("col", "row", "body")):
    """Yield (flaw, corrected stream) for one key stream.

    k: key values at the clue letters (vig: b - a, beau: b + a); a: the plaintext letters' places in
    the header; b: the cipher letters' places in the strip. flaw = (kind, lo, hi, d): every t in
    lo..hi gives this same stream. Streams that would need more than MAX_COMBOS combinations are
    yielded as (flaw, None) so the caller can count them."""
    sgn = -1 if form == "vig" else 1
    if "col" in kinds:
        vals = sorted(set(x for x in a if x > 0))
        lo = 1
        for t in vals:
            for d in (1, -1):
                yield ("col", lo, t, d), [(kj + sgn * d) % N if aj >= t else kj for kj, aj in zip(k, a)]
            lo = t + 1
    for kind in ("row", "body"):
        if kind not in kinds:
            continue
        seen = {}
        for d in (1, -1):
            for t in range(1, N):
                gi = GI[t, d]
                if kind == "row":
                    cands = tuple(gi[kj] for kj in k)
                else:
                    cands = tuple(tuple((kj - bj + v) % N for v in gi[bj]) for kj, bj in zip(k, b))
                key = (d, cands)
                if key in seen:
                    seen[key][1] = t
                    continue
                seen[key] = [t, t]
        for (d, cands), (lo, hi) in seen.items():
            ex = _expand(cands)
            if ex is None:
                yield (kind, lo, hi, d), None
                continue
            for v in ex:
                yield (kind, lo, hi, d), v


def cell_variants(k, a, rho_range=range(N)):
    """The single-row flaw (Vigenere form only): row rho is off by d past header column t."""
    for rho in rho_range:
        for d in (1, -1):
            seen = {}
            for t in range(1, N):
                cands = []
                for kj, aj in zip(k, a):
                    if aj >= t:
                        if kj == rho:
                            cands.append(())
                        elif kj == (rho + d) % N:
                            cands.append((rho, kj))
                        else:
                            cands.append((kj,))
                    else:
                        cands.append((kj,))
                cands = tuple(cands)
                if cands in seen:
                    seen[cands][1] = t
                else:
                    seen[cands] = [t, t]
            for cands, (lo, hi) in seen.items():
                ex = _expand(cands)
                if ex is None:
                    yield ("cell", lo, hi, d, rho), None
                    continue
                for v in ex:
                    yield ("cell", lo, hi, d, rho), v


# ------------------------------------------------------------------ encryption and decryption

def enc_index(a, kv, form, flaw):
    """Strip index of the cipher letter for header place a and key value kv under one flaw.
    flaw: None, ("col", t, d), ("row", t, d), ("body", t, d) or ("cell", t, d, rho)."""
    kind = flaw[0] if flaw else None
    if kind == "col":
        a = GT[flaw[1], flaw[2]][a]
    elif kind == "row":
        kv = GT[flaw[1], flaw[2]][kv]
    v = (a + kv) % N if form == "vig" else (kv - a) % N
    if kind == "body":
        v = GT[flaw[1], flaw[2]][v]
    elif kind == "cell" and kv == flaw[3] and a >= flaw[1]:
        v = (v + flaw[2]) % N
    return v


def dec_index(b, kv, form, flaw):
    """Header place(s) a with enc_index(a, kv) == b (first one, or None)."""
    for a in range(N):
        if enc_index(a, kv, form, flaw) == b:
            return a
    return None


def kv_of(a, b, form, flaw):
    for kv in range(N):
        if enc_index(a, kv, form, flaw) == b:
            return kv
    return None


def rule_key(rule, kclue, n=97, pos=POS):
    """Key values at all n positions from a battery rule and the corrected clue values (None where
    the clues do not fix them). Autokey rules return ('autokey', name, lag, sign, c0)."""
    kc = dict(zip(pos, kclue))
    parts = rule.split()
    fam = parts[0]
    if fam == "repeating":
        p = int(parts[1].split("=")[1])
        w = {i % p: v for i, v in kc.items()}
        return [w.get(i % p) for i in range(n)]
    if fam == "sliding":
        p = int(parts[1].split("=")[1])
        w = {}
        for i, v in kc.items():
            if i + 1 in kc:
                w[i % p] = (kc[i + 1] - v) % N
        out = [None] * n
        i0 = pos[0]
        out[i0] = kc[i0]
        for i in range(i0 + 1, n):
            s = w.get((i - 1) % p)
            out[i] = None if s is None or out[i - 1] is None else (out[i - 1] + s) % N
        for i in range(i0 - 1, -1, -1):
            s = w.get(i % p)
            out[i] = None if s is None or out[i + 1] is None else (out[i + 1] - s) % N
        return out
    if fam == "progressive":
        p = int(parts[1].split("=")[1])
        s = int(parts[2].split("=")[1])
        base = {i % p: (v - s * (i // p)) % N for i, v in kc.items()}
        return [None if i % p not in base else (base[i % p] + s * (i // p)) % N for i in range(n)]
    if fam == "autokey":
        name, lag, sg = parts[1], int(parts[2].split("=")[1]), int(parts[3].split("=")[1])
        j = next(i for i in pos if i - lag in kc)
        return ("autokey", name, lag, sg, j)
    raise ValueError(rule)


def decrypt(ct, cribs, m, a_alpha, b_alpha, form, flaw, rule, kclue):
    """Decrypt all of ct with the flaw applied ('?' where the key is not fixed). a_alpha / b_alpha:
    header and strip alphabets of the layout; m: the tableau alphabet (autokey feeds use it)."""
    ia = {c: i for i, c in enumerate(a_alpha)}
    ib = {c: i for i, c in enumerate(b_alpha)}
    im = {c: i for i, c in enumerate(m)}
    n = len(ct)
    key = rule_key(rule, kclue, n)
    out = [None] * n
    if isinstance(key, tuple):
        _, name, lag, sg, j = key
        kc = dict(zip(POS, kclue))
        c0 = (kc[j] - sg * im[(cribs if name == "plain" else ct)[j - lag]]) % N
        if name == "cipher":
            for i in range(lag, n):
                kv = (c0 + sg * im[ct[i - lag]]) % N
                x = dec_index(ib[ct[i]], kv, form, flaw)
                out[i] = None if x is None else a_alpha[x]
        else:
            for i, ch in cribs.items():
                out[i] = ch
            for i in range(n):                   # forward
                if out[i] is None and i >= lag and out[i - lag] is not None:
                    x = dec_index(ib[ct[i]], (c0 + sg * im[out[i - lag]]) % N, form, flaw)
                    out[i] = None if x is None else a_alpha[x]
            for i in range(n - 1, lag - 1, -1):  # backward: the key at i gives the letter at i - lag
                if out[i] is not None and out[i - lag] is None:
                    kv = kv_of(ia[out[i]], ib[ct[i]], form, flaw)
                    if kv is not None:
                        out[i - lag] = m[(sg * (kv - c0)) % N]
        for i, ch in cribs.items():
            out[i] = ch
    else:
        for i in range(n):
            if key[i] is not None:
                x = dec_index(ib[ct[i]], key[i], form, flaw)
                out[i] = None if x is None else a_alpha[x]
    return "".join(c or "?" for c in out)
