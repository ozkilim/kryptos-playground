"""Double columnar transposition + periodic substitution, tested with only the
24 clue letters (no decryption). Used by attacks/07_double_columnar.py.

Lives in the package (not the attack script) so multiprocessing workers can
import it.
"""
from itertools import permutations
from multiprocessing import Pool, cpu_count

from ..ciphers import AZ, KRYPTOS_ALPHABET, KEY_FROM, PLAIN_FROM, columnar_decrypt
from ..data import K4

N = len(K4)
MAX_PERIOD = 26
MIN_CONSTRAINTS = 6  # a fit with fewer equalities than this is too easy to get by chance
ALPHABETS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort")  # variant Beaufort is Vigenere with the key negated
PLACEMENTS = ("before", "middle", "after")


def posmap(order):
    """m[i] = where letter i lands after one columnar layer with this order."""
    return columnar_decrypt(list(range(N)), list(order))


def all_orders(wmin, wmax):
    return [o for w in range(wmin, wmax + 1) for o in permutations(range(w))]


def keyword_order(word):
    word = word.upper()
    return tuple(sorted(range(len(word)), key=lambda i: (word[i], i)))


# ---- per-worker state -------------------------------------------------------
_S = {}


def _init(ct, cribs, orders2):
    crib_pos = sorted(cribs)
    _S["crib_pos"] = crib_pos
    _S["maps2"] = [posmap(o) for o in orders2]
    _S["orders2"] = orders2
    tables = []
    for aname, alpha in ALPHABETS.items():
        idx = {c: i for i, c in enumerate(alpha)}
        cv = [idx[c] for c in ct]
        pv = {i: idx[cribs[i]] for i in crib_pos}
        for variant in VARIANTS:
            tables.append((aname, variant, cv, pv, KEY_FROM[variant]))
    _S["tables"] = tables
    _S["ct"], _S["cribs"] = ct, cribs


def _consistent_periods(slots, ks):
    """Periods 1..MAX_PERIOD where one repeating key fits, with #constraints."""
    out = []
    n = len(slots)
    for p in range(1, MAX_PERIOD + 1):
        seen = {}
        con = 0
        ok = True
        for t in range(n):
            r = slots[t] % p
            k = ks[t]
            prev = seen.get(r)
            if prev is None:
                seen[r] = k
            else:
                con += 1
                if prev != k:
                    ok = False
                    break
        if ok and con >= MIN_CONSTRAINTS:
            out.append((p, con))
    return out


def _work(args):
    """Test one first-layer order against every second-layer order."""
    o1, start, stop = args
    m1 = posmap(o1)
    crib_pos = _S["crib_pos"]
    mids = [m1[i] for i in crib_pos]
    hits, tested = [], 0
    for k2 in range(start, stop):
        m2 = _S["maps2"][k2]
        js = [m2[a] for a in mids]
        for aname, variant, cv, pv, f in _S["tables"]:
            ks = [f(cv[j], pv[i]) for j, i in zip(js, crib_pos)]
            for place, slots in (("before", crib_pos), ("middle", mids), ("after", js)):
                tested += MAX_PERIOD
                for p, con in _consistent_periods(slots, ks):
                    hits.append((o1, _S["orders2"][k2], aname, variant, place, p, con))
    return tested, hits


def decrypt(ct, cribs, o1, o2, aname, variant, place, p):
    """Best-effort decrypt of a survivor: key slots fixed by the cribs, others 'A'."""
    alpha = ALPHABETS[aname]
    idx = {c: i for i, c in enumerate(alpha)}
    m1, m2 = posmap(o1), posmap(o2)
    f, dec = KEY_FROM[variant], PLAIN_FROM[variant]
    key = {}
    for i in cribs:
        a = m1[i]
        j = m2[a]
        slot = {"before": i, "middle": a, "after": j}[place] % p
        key[slot] = f(idx[ct[j]], idx[cribs[i]])
    out = []
    for i in range(len(ct)):
        a = m1[i]
        j = m2[a]
        slot = {"before": i, "middle": a, "after": j}[place] % p
        out.append(alpha[dec(idx[ct[j]], key.get(slot, 0))])
    return "".join(out)


def scan(ct, cribs, orders1, orders2, procs=None, chunk=400):
    """Run every (T1, T2) pair. Returns (hypotheses tested, survivors)."""
    jobs = [(o1, s, min(s + chunk, len(orders2))) for o1 in orders1 for s in range(0, len(orders2), chunk)]
    tested, hits = 0, []
    with Pool(procs or cpu_count(), initializer=_init, initargs=(ct, cribs, orders2)) as pool:
        for t, h in pool.imap_unordered(_work, jobs, chunksize=4):
            tested += t
            hits += h
    return tested, hits


