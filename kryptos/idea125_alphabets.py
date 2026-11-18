"""Idea 125: keyword alphabets that no dictionary test could list.

Part 1 (misspellings). For every theme word and every one of the 22,000 common words, every single
spelling change: one letter replaced by any other, one letter dropped, one letter doubled, two
neighbours swapped. Each changed word gives its keyword alphabet (keyword, then the rest in A-Z
order) and the two transposition-mixed forms (round11.mixes). Alphabets already in the dictionary
list (round11.dictionary_alphabets(mixed=True)) are dropped, and so are duplicates.

Part 2 (other ways to finish the alphabet), for every word of the vocabulary (KRYPTOS, theme,
common, big dictionary):
  rev    keyword, then the rest of the alphabet in reverse (Z to A) order
  wrap   keyword, then the rest in A-Z order starting after the keyword's last letter and wrapping
  last   repeated letters kept at their LAST place in the word instead of the first
  end    the rest in A-Z order first, the keyword at the end
  swap   the plain keyword alphabet with one K1-K3 misspelling swap applied to the finished alphabet:
         Q<->L (IQLUSION), U<->O (UNDERGRUUND), A<->E (DESPARATLY), C<->S (PALIMPCEST)
Duplicates, dictionary-list alphabets and part-1 alphabets are dropped.

The battery is kryptos.idea120_layer.test_alphabet (round-11 battery plus idea 104's two hole
fixes), on the plain clue letters (an identity "known layer").

Part 3 is attack 63's exact hash join (Quagmire IV: plain alphabet from one list, cipher alphabet
from another, repeating key of length p) with the part-2 alphabets added to the dictionary list on
both sides; only pairs with at least one new alphabet are kept (dictionary x dictionary was attack 63).
"""
import os

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET as KR
from .round9 import keyword_alphabet
from .round11 import POS, dictionary_alphabets, mixes, pmap, vocabulary
from . import wordkeys
from . import idea104_holes as H
from . import idea120_layer as L

SMOKE = os.environ.get("KRYPTOS_SMOKE")
SWAPS = (("Q", "L"), ("U", "O"), ("A", "E"), ("C", "S"))
IDENTITY = dict(tname="AZ", tab=AZ, word="A", e=1, phase=0, order="last", label="no known layer")
MAX_P = 20


# ------------------------------------------------------------------ part 1: one spelling change

def edits(word):
    """Every word one spelling change away (replace, drop, double, swap neighbours), 3+ letters."""
    out = set()
    n = len(word)
    for i in range(n):
        for c in AZ:
            if c != word[i]:
                out.add(word[:i] + c + word[i + 1:])
        out.add(word[:i] + word[i + 1:])
        out.add(word[:i] + word[i] + word[i:])
        if i < n - 1 and word[i] != word[i + 1]:
            out.add(word[:i] + word[i + 1] + word[i] + word[i + 2:])
    out.discard(word)
    return sorted(w for w in out if len(w) >= 3)


def part1_words():
    return list(dict.fromkeys(["KRYPTOS"] + wordkeys.theme_words() + wordkeys.common_words()))


def part1(known, limit=None):
    """[(name, alphabet)]: the new misspelling alphabets. known: set of alphabets to leave out
    (updated in place). name = 'MISSPELT<-WORD' plus the mix tag."""
    out = []
    for w in part1_words():
        for e in edits(w):
            for tag, m in mixes(e):
                if m not in known:
                    known.add(m)
                    out.append(("%s<-%s%s" % (e, w, tag), m))
        if limit and len(out) >= limit:
            break
    return out


# ------------------------------------------------------------------ part 2: other constructions

def distinct(word):
    u = []
    for ch in word:
        if ch not in u:
            u.append(ch)
    return u


def construct(word, how):
    """One part-2 alphabet from word (letters A-Z only)."""
    if how == "rev":
        u = distinct(word)
        return "".join(u) + "".join(c for c in AZ[::-1] if c not in u)
    if how == "wrap":
        u = distinct(word)
        s = AZ.index(u[-1]) + 1
        return "".join(u) + "".join(c for c in AZ[s:] + AZ[:s] if c not in u)
    if how == "last":
        u = distinct(word[::-1])[::-1]
        return "".join(u) + "".join(c for c in AZ if c not in u)
    if how == "end":
        u = distinct(word)
        return "".join(c for c in AZ if c not in u) + "".join(u)
    if how.startswith("swap"):
        a, b = how[4], how[5]
        m = keyword_alphabet(word)
        return m.translate(str.maketrans(a + b, b + a))
    raise ValueError(how)


HOWS = ("rev", "wrap", "last", "end") + tuple("swap%s%s" % s for s in SWAPS)


def part2(known, limit=None):
    out = []
    for w in vocabulary():
        if not (3 <= len(w) <= 22 and w.isalpha()):
            continue
        for how in HOWS:
            m = construct(w, how)
            assert sorted(m) == list(AZ)
            if m not in known:
                known.add(m)
                out.append(("%s@%s" % (w, how), m))
        if limit and len(out) >= limit:
            break
    return out


def all_lists(smoke=None):
    """(dictionary list, part 1, part 2). smoke: limit each new part to about this many."""
    dic = dictionary_alphabets(mixed=True)
    known = {m for _, m in dic} | {KR}
    p1 = part1(known, smoke)
    p2 = part2(known, smoke)
    return dic, p1, p2


# ------------------------------------------------------------------ the battery on a list

_S = {}


def init(pl, cl):
    _S["pl"], _S["cl"] = pl, cl
    _S["feeds"] = H.make_feeds(pl, cl)


def work(chunk):
    hits = []
    for name, m in chunk:
        hits += L.test_alphabet(name, m, _S["pl"], _S["cl"], _S["feeds"])
    return len(chunk), hits


def battery_search(ct, cribs, alphas, chunk=1000, procs=None, progress=None):
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    hits, done = [], 0
    for n, h in pmap(work, alphas, init, (pl, cl), chunk=chunk, procs=procs):
        hits += h
        done += n
        if progress and done % (chunk * 500) < chunk:
            progress(done)
    return hits


def read(hit, m, ct, cribs):
    return L.read(hit, IDENTITY, m, ct, cribs)


# ------------------------------------------------------------------ part 3: Quagmire IV hash join

def groups(pos, p):
    g = {}
    for k, i in enumerate(pos):
        g.setdefault(i % p, []).append(k)
    return [(v[0], k) for v in g.values() for k in v[1:]]


_J = {}


def join_init(alphas, n_dic):
    _J["alphas"], _J["n_dic"] = alphas, n_dic


def join_one(args):
    """args: (p, cribs, [(label, ct)]). Returns (p, {label: [(form, plain index, cipher index)]}, counts)."""
    p, cribs, cts = args
    alphas, nd = _J["alphas"], _J["n_dic"]
    pos = sorted(cribs)
    pairs = groups(pos, p)
    table = {}
    for a, m in enumerate(alphas):
        idx = {c: i for i, c in enumerate(m)}
        v = [idx[cribs[i]] for i in pos]
        table.setdefault(bytes((v[k] - v[r]) % 26 for r, k in pairs), []).append(a)
    out, counts = {}, {}
    for label, ct in cts:
        got, n = [], 0
        for b, m in enumerate(alphas):
            idx = {c: i for i, c in enumerate(m)}
            v = [idx[ct[i]] for i in pos]
            sig = bytes((v[k] - v[r]) % 26 for r, k in pairs)
            neg = bytes((v[r] - v[k]) % 26 for r, k in pairs)
            for form, s in (("vig", sig), ("beau", neg)):
                for a in table.get(s, ()):
                    if a < nd and b < nd:
                        continue                  # dictionary x dictionary: attack 63
                    n += 1
                    if len(got) < 20000:
                        got.append((form, a, b))
        out[label], counts[label] = got, n
    return p, out, counts


def join_search(cribs, cts, alphas, n_dic, procs=None, max_p=MAX_P):
    """alphas: [alphabet], the first n_dic of them the dictionary list.
    Returns {label: {p: (count, [(form, plain index, cipher index)] up to 20,000)}}."""
    from multiprocessing import Pool
    res = {label: {} for label, _ in cts}
    with Pool(procs, initializer=join_init, initargs=(alphas, n_dic)) as pool:
        for p, out, counts in pool.imap_unordered(join_one, [(p, cribs, cts) for p in range(1, max_p + 1)]):
            for label in out:
                res[label][p] = (counts[label], out[label])
    return res


def join_decrypt(ct, cribs, p, form, m1, m2):
    """Quagmire IV reading ('?' where the key slot is not fixed by a clue)."""
    shift = {}
    for i, pl in cribs.items():
        c, x = m2.index(ct[i]), m1.index(pl)
        shift[i % p] = (c - x) % 26 if form == "vig" else (c + x) % 26
    out = []
    for i, ch in enumerate(ct):
        s = shift.get(i % p)
        if s is None:
            out.append("?")
        else:
            c = m2.index(ch)
            out.append(m1[(c - s) % 26] if form == "vig" else m1[(s - c) % 26])
    return "".join(out)


def quag4_encrypt(pt, m1, m2, key, form="vig"):
    return "".join(m2[(m1.index(ch) + key[i % len(key)]) % 26] if form == "vig" else
                   m2[(key[i % len(key)] - m1.index(ch)) % 26] for i, ch in enumerate(pt))
