"""Helpers for idea 79: re-run formula mining (attack 54) and the three-keyword hash join (attack 63)
with the gap between the two clues off by a few letters.

The trick that lets both attacks run unchanged: instead of teaching them about a shifted second clue,
we hand them the text the encipherer would have had. If g letters were dropped between the clues when
the sculpture was cut (g > 0) we put g unknown letters back; if g letters were added (g < 0) we take
them out. The second clue then sits at positions 63+g .. 73+g and every position, grid and neighbour
ingredient is computed where the encipherer computed it.

The unknown letters go in (or come out) at CUT = 48. Neither attack ever reads a ciphertext letter
further than 5 places from a clue letter, so any cut between observed positions 39 and 57 gives the
same answer; the planted tests cut at a random place in that range to show it.
"""
import importlib.util
import itertools
from pathlib import Path

from .ciphers.substitution import AZ
from .round11 import B1, B2

ROOT = Path(__file__).resolve().parent.parent
GAPS = (-3, -2, -1, 1, 2, 3)
CUT = 48
CUT_RANGE = (39, 57)
HOLE = "?"
_MODS = {}
_S = {}


def attack(name):
    """Load an attack script as a module (once per process)."""
    if name not in _MODS:
        spec = importlib.util.spec_from_file_location("idea79_" + name[:2], ROOT / "attacks" / name)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MODS[name] = mod
    return _MODS[name]


def m54():
    return attack("54_formula_mining.py")


def m63():
    return attack("63_three_keywords.py")


def regap(ct, cribs, g, cut=CUT):
    """The text as the encipherer had it, if the carved gap is off by g, and the clues at their true places.

    g > 0: g letters are missing from the carved text (put g unknown letters back at `cut`).
    g < 0: -g letters were added to the carved text (take them out at `cut`)."""
    if g >= 0:
        text = ct[:cut] + HOLE * g + ct[cut:]
    else:
        text = ct[:cut] + ct[cut - g:]
    out = {i: cribs[i] for i in B1}
    out.update({i + g: cribs[i] for i in B2})
    return text, out


def damage(ct, pt, g, rng):
    """The opposite of regap, for planted answers: lose g letters (g > 0) or add -g random letters (g < 0)
    at a random place between the clues. Returns the carved ciphertext and the plaintext lined up with it."""
    cut = rng.randrange(CUT_RANGE[0], CUT_RANGE[1] + 1 - abs(g))
    if g >= 0:
        return ct[:cut] + ct[cut + g:], pt[:cut] + pt[cut + g:]
    junk = "".join(rng.choice(AZ) for _ in range(-g))
    return ct[:cut] + junk + ct[cut:], pt[:cut] + HOLE * (-g) + pt[cut:]


# ---------------------------------------------------------------- formula mining (attack 54)

def _use(rid):
    """Point attack 54's globals at one run (a ciphertext with its gap already put right)."""
    m = m54()
    st = _S["cache"].get(rid)
    if st is None:
        text, cribs = _S["runs"][rid]
        st = {"lib": m.library(text, cribs, _S["small"]), "ct": text, "cribs": cribs, "pos": sorted(cribs)}
        _S["cache"][rid] = st
    m.POS = st["pos"]
    m._S.update(lib=st["lib"], ct=st["ct"], cribs=st["cribs"])
    return m, st


def formula_init(runs, small):
    _S.update(runs=runs, small=small, cache={})


def formula_work(job):
    rid, first, names, size = job
    m, st = _use(rid)
    if size == 0:
        hits = []
        for an, a in m.ALPH.items():
            for bn, b in m.ALPH.items():
                res = m.test_combo((), st["lib"], {i: b.index(st["ct"][i]) for i in st["pos"]},
                                   {i: a.index(st["cribs"][i]) for i in st["pos"]})
                if res:
                    hits.append(("pt%s/ct%s" % (an, bn), (), res[0], res[1]))
        return rid, 4, hits
    n, hits = m.work((first, names, size))
    return rid, n, hits


def formula_jobs(runs, small, sizes=(0, 1, 2, 3), names=None):
    """Jobs for every run; `names` limits the library (used by the fast test)."""
    m = m54()
    jobs = []
    for rid, (text, cribs) in runs.items():
        lib_names = sorted(m.library(text, cribs, small))
        if names is not None:
            lib_names = [n for n in lib_names if n in names]
        for size in sizes:
            if size == 0:
                jobs.append((rid, None, lib_names, 0))
            else:
                jobs += [(rid, f, lib_names, size) for f in lib_names[:len(lib_names) - size + 1]]
    return jobs


def formula_mine(runs, small=False, sizes=(0, 1, 2, 3), names=None, pool=None):
    """{run id: (formulas tried, hits)}. Runs in this process unless a pool (started with formula_init) is given."""
    jobs = formula_jobs(runs, small, sizes, names)
    out = {rid: [0, []] for rid in runs}
    if pool is None:
        formula_init(runs, small)
        results = map(formula_work, jobs)
    else:
        jobs.sort(key=lambda j: -j[3])
        results = pool.imap_unordered(formula_work, jobs, chunksize=2)
    for rid, n, hits in results:
        out[rid][0] += n
        out[rid][1] += hits
    return out


def formula_plant(pt, rng, widths=(7, 31)):
    """Encrypt with a hidden 3-ingredient formula key: grid column + grid row + previous plaintext letter."""
    w = rng.choice(widths)
    b1, b2, b3, c = rng.randrange(1, 26), rng.randrange(1, 26), rng.randrange(1, 26), rng.randrange(26)
    ct = []
    for i, p in enumerate(pt):
        prev = AZ.index(pt[i - 1]) if i else 0
        ct.append(AZ[(AZ.index(p) + b1 * (i % w) + b2 * (i // w) + b3 * prev + c) % 26])
    return "".join(ct), ("col%d" % w, "row%d" % w, "P[i-1]AZ")


# ---------------------------------------------------------------- three-keyword join (attack 63)

_INDEX = {}


def _word_index(p, slots):
    """Dictionary words of length p, cut down to the key slots the clues fix."""
    key = (p, slots)
    if key not in _INDEX:
        _INDEX[key] = {"".join(w[j] for j in slots): w for w in m63().words_by_length().get(p, [])}
    return _INDEX[key]


def key_word(shift, p, m1, m2):
    """A dictionary word the implied key could be (named on A-Z at any offset, or on either alphabet)."""
    slots = tuple(sorted(shift))
    idx = _word_index(p, slots)
    if not idx:
        return None
    for alpha in itertools.chain((AZ[c:] + AZ[:c] for c in range(26)), (m1, m2)):
        w = idx.get("".join(alpha[shift[j]] for j in slots))
        if w:
            return w
    return None


def join_analyse(ct, cribs, g, alphas=None, max_p=20, keep=40, want=None):
    """Attack 63's hash join on the re-gapped text. Every match is decrypted and scored.

    want = (form, plain alphabet name, cipher alphabet name, key length): a planted setting to look for."""
    m = m63()
    m.MAX_P = max_p
    alphas = alphas or m.alphabets()
    text, tc = regap(ct, cribs, g)
    hits = m.search(text, tc, alphas)
    # between observed 39 and 57 we do not know where the slip is, so those letters are left out of the decrypt
    holes = range(CUT_RANGE[0], CUT_RANGE[1] + 1 + g)
    filled = text.replace(HOLE, "A")
    by_p, worded, top, found = {}, [], [], False
    for p, form, a, b in hits:
        by_p[p] = by_p.get(p, 0) + 1
        if want and (form, alphas[a][0], alphas[b][0], p) == tuple(want):
            found = True
        m1, m2 = alphas[a][1], alphas[b][1]
        pt, shift = m.decrypt(filled, tc, p, form, m1, m2)
        pt = pt[:holes[0]] + "." * len(holes) + pt[holes[-1] + 1:]
        sc = round(m.known_score(pt), 2)
        row = (sc, p, form, alphas[a][0], alphas[b][0], pt)
        top.append(row)
        if len(top) > 4 * keep:
            top = sorted(top, reverse=True)[:keep]
        if p >= 5:
            w = key_word(shift, p, m1, m2)
            if w:
                worded.append(row + (w,))
    top = sorted(top, reverse=True)[:keep]
    return {"n": len(hits), "by_p": by_p, "top": top, "worded": sorted(worded, reverse=True)[:keep],
            "n_worded": len(worded), "found": found}


def join_plant(pt, alpha1, alpha2, key):
    """Quagmire IV: plain alphabet alpha1, cipher alphabet alpha2, repeating key word."""
    return "".join(alpha2[(alpha1.index(ch) + alpha2.index(key[i % len(key)])) % 26] for i, ch in enumerate(pt))
