"""Shared tools for round 11: dictionary alphabets, key streams in any modulus, and a battery of
exact key-rule tests that works on any set of positions (one clue block alone, or both blocks
with the gap between them changed).
"""
import os
from multiprocessing import Pool

from . import wordkeys
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import load, letters
from .round9 import keyword_alphabet, solve_mod_p

B1, B2 = list(range(21, 34)), list(range(63, 74))
POS = B1 + B2
SMOKE = os.environ.get("KRYPTOS_SMOKE")


def english97(rng, n=97):
    text = letters(load("k2")["plaintext"] + load("k3")["plaintext"] + load("k1")["plaintext"])
    o = rng.randrange(len(text) - n)
    return text[o:o + n]


def mixes(word):
    """The keyword alphabet and its two transposition-mixed forms."""
    m = keyword_alphabet(word)
    yield "", m
    u = []
    for ch in word:
        if ch not in u:
            u.append(ch)
    w = len(u)
    if w < 3:
        return
    cols = [m[c::w] for c in range(w)]
    yield "~cols", "".join(cols)
    yield "~keyed", "".join(cols[c] for c in sorted(range(w), key=lambda c: u[c]))


def vocabulary():
    return ["KRYPTOS"] + wordkeys.theme_words() + wordkeys.common_words() + wordkeys.big_dictionary()


def dictionary_alphabets(mixed=False, smoke_limit=6000):
    """[(name, alphabet)]: A-Z, then every distinct keyword alphabet (optionally the mixed forms)."""
    seen, out = {AZ}, [("(A-Z)", AZ)]
    for w in vocabulary():
        if 3 <= len(w) <= 22:
            for tag, m in (mixes(w) if mixed else (("", keyword_alphabet(w)),)):
                if m not in seen:
                    seen.add(m)
                    out.append((w + tag, m))
        if SMOKE and len(out) >= smoke_limit:
            break
    return out


def streams(m, pl, cl, n=26):
    """Key values the clue letters force, for a keyword alphabet M in five layouts, two forms.

    pl / cl: clue plaintext / ciphertext letters. Yields (layout, form, k, xp, xc); xp, xc are
    the letters' positions in M (for autokey feeds)."""
    iz = {c: i for i, c in enumerate(AZ)}
    ik = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    im = {c: i for i, c in enumerate(m)}
    xp, xc = [im[c] for c in pl], [im[c] for c in cl]
    lays = (("M/M", im, im), ("M/AZ", im, iz), ("AZ/M", iz, im), ("M/KR", im, ik), ("KR/M", ik, im))
    if m == AZ:
        lays = (("AZ/AZ", iz, iz), ("AZ/KR", iz, ik), ("KR/AZ", ik, iz), ("KR/KR", ik, ik))
    for lay, ia, ib in lays:
        a, b = [ia[c] for c in pl], [ib[c] for c in cl]
        yield lay, "vig", [(y - x) % n for x, y in zip(a, b)], xp, xc
        yield lay, "beau", [(y + x) % n for x, y in zip(a, b)], xp, xc


def _runs(pos):
    out, s = [], 0
    for j in range(1, len(pos) + 1):
        if j == len(pos) or pos[j] != pos[j - 1] + 1:
            out.append((s, j))
            s = j
    return out


_PLANS = {}


def _plan(pos):
    """Index lists for a set of positions, computed once: residues per period and same-block pairs per lag."""
    key = tuple(pos)
    pl = _PLANS.get(key)
    if pl is None:
        runs = _runs(pos)
        pl = {"res": {p: [i % p for i in pos] for p in range(1, 18)},
              "div": {p: [i // p for i in pos] for p in range(1, 13)},
              "lag": {L: [(j, j + L) for a, b in runs for j in range(a, b - L)] for L in range(1, 14)}}
        pl["lagres"] = {(L, q): [pos[j] % q for j, _ in pl["lag"][L]] for L in range(1, 14) for q in range(1, 16)}
        _PLANS[key] = pl
    return pl


def battery(k, pos, n=26, xp=None, xc=None, min_checks=7, skip=()):
    """Exact key-rule tests on key values k at positions pos (arithmetic mod n).

    Returns [(checks, rule)] for every rule the values satisfy with at least min_checks
    independent coincidences. Rules: repeating, sliding (running sum of a repeating word),
    progressive, autokey (needs xp/xc), two stacked repeating keys, chain addition."""
    out, cnt = [], len(k)
    pl = _plan(pos)
    res, lag, lagres = pl["res"], pl["lag"], pl["lagres"]
    if "repeating" not in skip:
        for p in range(1, 18):
            seen = {}
            for v, r in zip(k, res[p]):
                if seen.setdefault(r, v) != v:
                    break
            else:
                if cnt - len(seen) >= min_checks:
                    out.append((cnt - len(seen), "repeating p=%d" % p))
    diff = {}
    for L in range(1, 14):
        diff[L] = [(k[b] - k[a]) % n for a, b in lag[L]]
    if "sliding" not in skip:
        d = diff[1]
        for p in range(1, 16):
            seen = {}
            for v, r in zip(d, lagres[1, p]):
                if seen.setdefault(r, v) != v:
                    break
            else:
                if len(d) - len(seen) >= min_checks:
                    out.append((len(d) - len(seen), "sliding p=%d" % p))
    if "progressive" not in skip:
        for p in range(1, 13):
            if not diff[p] or not diff[p][0]:
                continue
            s = diff[p][0]
            seen = {}
            for v, r, q in zip(k, res[p], pl["div"][p]):
                base = (v - s * q) % n
                if seen.setdefault(r, base) != base:
                    break
            else:
                if cnt - len(seen) - 1 >= min_checks:
                    out.append((cnt - len(seen) - 1, "progressive p=%d step=%d" % (p, s)))
    if "autokey" not in skip and xp is not None:
        for name, x in (("plain", xp), ("cipher", xc)):
            for L in range(1, 7):
                pairs = lag[L]
                if len(pairs) - 1 < min_checks:
                    break
                a0, b0 = pairs[0]
                for sg in (1, -1):
                    c0 = (k[b0] - sg * x[a0]) % n
                    for a, b in pairs:
                        if (k[b] - sg * x[a]) % n != c0:
                            break
                    else:
                        out.append((len(pairs) - 1, "autokey %s lag=%d sign=%+d" % (name, L, sg)))
    if "stacked" not in skip:
        for p in range(2, 13):
            dp = diff[p]
            for q in range(p + 1, 14):
                if q % p == 0:
                    continue
                seen = {}
                for v, r in zip(dp, lagres[p, q]):
                    if seen.setdefault(r, v) != v:
                        break
                else:
                    c1 = len(dp) - len(seen)
                    seen = {}
                    for v, r in zip(diff[q], lagres[q, p]):
                        if seen.setdefault(r, v) != v:
                            break
                    else:
                        c2 = len(diff[q]) - len(seen)
                        if c1 + c2 < min_checks + 1:
                            continue
                        if n == 26:
                            rows = []
                            for i in pos:
                                v = [0] * (p + q)
                                v[i % p] = 1
                                v[p + i % q] = 1
                                rows.append(v)
                            s13, s2 = solve_mod_p(rows, k, 13), solve_mod_p(rows, k, 2)
                            if s13 is None or s2 is None:
                                continue
                            ck = cnt - (p + q - len(s13[1]))
                            if ck >= min_checks:
                                out.append((ck, "two stacked keys p=%d q=%d" % (p, q)))
                        else:
                            out.append((c1 + c2, "two stacked keys p=%d q=%d (necessary test)" % (p, q)))
    if "chain" not in skip:
        for m in range(2, 7):
            pairs = lag[m]
            if len(pairs) < min_checks:
                break
            for t in range(1, m):
                for a, b in pairs:
                    if (k[b - t] + k[a] - k[b]) % n:
                        break
                else:
                    out.append((len(pairs), "chain taps %d,%d" % (t, m)))
    return out


def _residues(d, q):
    seen = {}
    for i, v in d:
        if seen.setdefault(i % q, v) != v:
            return -1
    return len(d) - len(seen)


def pmap(work, items, init, initargs, chunk=1500, procs=None):
    """Run work(chunk) over chunks of items in a pool; yields each chunk's result."""
    chunks = [items[i:i + chunk] for i in range(0, len(items), chunk)]
    with Pool(procs, initializer=init, initargs=initargs) as pool:
        for r in pool.imap_unordered(work, chunks):
            yield r
