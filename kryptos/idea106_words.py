"""Idea 106: K4 letters count WORDS through the solved K1-K3 text (a prisoner letter code).

A text is a list of words. A "pick" turns it into one letter per word (first letter, second, ...,
last; '?' if the word is too short). After that the two main rules are plain index rules on that
line of letters T:

  B (window)  P_i = T[s + a*i + sgn*d(C_i)]            word number = start + a*i + value
  W (walk)    P_i = T[s + a*i + sgn*(d(C_0)+..+d(C_i))]  move on d words from the last word used

d = place of the K4 letter in A-Z or in the KRYPTOS alphabet (0..25). Numbering from 1 instead of
0 is a = sgn in rule W and a shifted start in rule B. A text read backwards is a negative a. So
a = -30..30 with both signs covers "from 0 or 1, counted forwards or backwards, text forwards or
backwards" in one sweep.

  C (pairs)   word number from one K4 letter, letter number inside the word from its neighbour.
"""
from collections import Counter

from . import CRIBS, K4
from . import load
from .ciphers import AZ, KRYPTOS_ALPHABET
from .data import letters
from .round11 import SMOKE, pmap

N = 97
A_MAX = 30
KEEP = 9                      # settings with this many clue letters are kept for a full reading
ALPHAS = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
PICKS = ("1", "2", "3", "4", "last")      # letter number 1..4 of the word, or its last letter
_S = {}

K1_WORDS = "BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION"
K2_WORDS = ("IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS "
            "GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD "
            "ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY "
            "EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY "
            "FOUR SECONDS WEST")
K2_ENDS = {"ID BY ROWS": "ID BY ROWS", "LAYER TWO": "X LAYER TWO"}
K3_WORDS = ("SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS "
            "REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE "
            "A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO "
            "FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q")
MORSE_WORDS = "VIRTUALLY INVISIBLE DIGETAL INTERPRETATIU SHADOW FORCES LUCID MEMORY T IS YOUR POSITION SOS RQ"
FIXES = {"IQLUSION": "ILLUSION", "UNDERGRUUND": "UNDERGROUND", "DESPARATLY": "DESPERATELY",
         "DIGETAL": "DIGITAL", "INTERPRETATIU": "INTERPRETATION"}
MARKS = ("X", "Q")


def check_transcription():
    """The word lists must spell exactly the plaintexts stored in data/sculpture."""
    k1, k2, k3 = load("k1"), load("k2"), load("k3")
    assert letters(K1_WORDS) == letters(k1["plaintext"])
    assert letters(K2_WORDS + K2_ENDS["ID BY ROWS"]) == letters(k2["plaintext"])
    assert letters(K2_WORDS + K2_ENDS["LAYER TWO"]) == letters(k2["plaintext_corrected"])
    assert letters(K3_WORDS) == letters(k3["plaintext"])
    return True


def _style(words, corrected, marks):
    out = [FIXES.get(w, w) if corrected else w for w in words.split()]
    return [w for w in out if marks or w not in MARKS]


def word_texts(full=None):
    """[(name, [words])]: K1, K2, K3 alone and joined in order, and the Morse text, in every style.

    Styles: spelling as carved or corrected; the X (and K3's closing Q) kept as words or dropped;
    K2 ending ID BY ROWS or (X) LAYER TWO. Duplicates are dropped.
    """
    full = (not SMOKE) if full is None else full
    check_transcription()
    out, seen = [], set()

    def add(name, words):
        if tuple(words) not in seen:
            seen.add(tuple(words))
            out.append((name, words))

    for corrected in (False, True):
        for marks in (True, False):
            for end in K2_ENDS:
                st = "%s, X %s, %s" % ("corrected" if corrected else "as carved", "kept" if marks else "dropped", end)
                k1 = _style(K1_WORDS, corrected, marks)
                k2 = _style(K2_WORDS + " " + K2_ENDS[end], corrected, marks)
                k3 = _style(K3_WORDS, corrected, marks)
                mo = _style(MORSE_WORDS, corrected, True)
                add("K1-K3 (%s)" % st, k1 + k2 + k3)
                add("K2 (%s)" % st, k2)
                add("K1 (%s)" % st, k1)
                add("K3 (%s)" % st, k3)
                add("Morse (%s)" % st, mo)
                if full:
                    add("K1-K2 (%s)" % st, k1 + k2)
                    add("K2-K3 (%s)" % st, k2 + k3)
                    add("K1-K3 then Morse (%s)" % st, k1 + k2 + k3 + mo)
                    add("Morse then K1-K3 (%s)" % st, mo + k1 + k2 + k3)
    return out


def line(words, pick):
    """One letter per word: letter number 1..4, or the last letter; '?' if the word is too short."""
    if pick == "last":
        return "".join(w[-1] for w in words)
    k = int(pick) - 1
    return "".join(w[k] if k < len(w) else "?" for w in words)


def _where(text):
    w = {}
    for j, ch in enumerate(text):
        w.setdefault(ch, []).append(j)
    return w


def values(ct, rule, alpha):
    d = [alpha.index(c) for c in ct]
    if rule == "B":
        return d
    out, t = [], 0
    for x in d:
        t += x
        out.append(t)
    return out


def read(ct, text, rule, an, sgn, a, s, ring=True):
    """The full reading for one setting ('?' off the line, or where the word is too short)."""
    v, L, out = values(ct, rule, ALPHAS[an]), len(text), []
    for i in range(len(ct)):
        j = s + a * i + sgn * v[i]
        out.append(text[j % L] if ring or 0 <= j < L else "?")
    return "".join(out)


# ---------------------------------------------------------------- rules B and W: the search

def canon(tlist):
    """{(text index, pick): index of the first text with the same line of letters}. Many styles
    differ only in letters the pick never looks at; each distinct line is searched once."""
    first, out = {}, {}
    for ti, (_, words) in enumerate(tlist):
        for pick in PICKS:
            out[ti, pick] = first.setdefault((pick, line(words, pick)), ti)
    return out


def init(ct, cribs, tlist):
    _S["ct"], _S["cribs"], _S["texts"] = ct, cribs, tlist
    _S["canon"] = canon(tlist)
    _S["v"] = {(r, an): values(ct, r, al) for r in "BW" for an, al in ALPHAS.items()}


def _new_best():
    return {(r, m): (0, None) for r in "BW" for m in ("ring", "line", "plain")}


def work(jobs):
    """Rules B and W on the given texts: (settings, histogram of clue counts, best, kept)."""
    cribs = sorted(_S["cribs"].items())
    n, hist, tops, best = 0, {"B": Counter(), "W": Counter()}, [], _new_best()
    for ti in jobs:
        name, words = _S["texts"][ti]
        L = len(words)
        for pick in PICKS:
            if _S["canon"][ti, pick] != ti:
                continue
            where = _where(line(words, pick))
            for (rule, an), v in sorted(_S["v"].items()):
                for sgn in (1, -1):
                    for a in range(-A_MAX, A_MAX + 1):
                        offs = [a * i + sgn * v[i] for i in range(N)]
                        cnt = [0] * L
                        for i, p in cribs:
                            o = offs[i]
                            for j in where.get(p, ()):
                                cnt[(j - o) % L] += 1
                        n += L
                        hist[rule].update(cnt)
                        m = max(cnt)
                        tag = (ti, pick, an, sgn, a)
                        if m > best[rule, "ring"][0]:
                            best[rule, "ring"] = (m, tag + (cnt.index(m),))
                        if a in (0, sgn) and m > best[rule, "plain"][0]:     # no extra advance: count from 0 or from 1
                            best[rule, "plain"] = (m, tag + (cnt.index(m),))
                        lo, hi = max(0, -min(offs)), min(L - 1, L - 1 - max(offs))   # starts that keep all 97 on the line
                        if hi >= lo:
                            ml = max(cnt[lo:hi + 1])
                            if ml > best[rule, "line"][0]:
                                best[rule, "line"] = (ml, tag + (lo + cnt[lo:hi + 1].index(ml),))
                        if m >= KEEP:
                            tops += [(c, rule, ti, pick, an, sgn, a, s) for s, c in enumerate(cnt) if c >= KEEP]
    return n, hist, best, tops


def search(ct, cribs, tlist, procs=None, serial=False):
    jobs = list(range(len(tlist)))
    res = {"n": 0, "hist": {"B": Counter(), "W": Counter()}, "tops": [], "best": _new_best()}
    if serial:
        init(ct, cribs, tlist)
        parts = [work(jobs)]
    else:
        parts = pmap(work, jobs, init, (ct, cribs, tlist), chunk=1, procs=procs)
    for n, hist, best, tops in parts:
        res["n"] += n
        res["tops"] += tops
        for r in "BW":
            res["hist"][r].update(hist[r])
        for k, b in best.items():
            if (b[0], str(b[1])) > (res["best"][k][0], str(res["best"][k][1])):
                res["best"][k] = b
    res["tops"].sort(reverse=True)
    res["top"] = max(b[0] for b in res["best"].values())
    return res


def mean(hist):
    tot = sum(hist.values())
    return sum(m * c for m, c in hist.items()) / tot if tot else 0.0


def tail(res, k, rules="BW"):
    return sum(c for r in rules for m, c in res["hist"][r].items() if m >= k)


def producible(words, cribs=CRIBS):
    """{pick: how many of the 24 clue letters occur at all as that letter of some word}."""
    return {pick: sum(p in set(line(words, pick)) for p in cribs.values()) for pick in PICKS}


# ---------------------------------------------------------------- rules B and W: encoding

def feasible(pt, text, rule, a, sgn=1, ring=True):
    """F[i] = pointers on letter i from which the rest of pt can still be encoded (rule W),
    or None if the message cannot be walked at all. For rule B use starts_b()."""
    L, n = len(text), len(pt)
    where = _where(text)
    F = [None] * n
    for i in range(n - 1, -1, -1):
        c = set(where.get(pt[i], ()))
        if i < n - 1:
            nxt = F[i + 1]
            c = {q for q in c if any(((q + a + sgn * d) % L if ring else q + a + sgn * d) in nxt for d in range(26))}
        if not c:
            return None
        F[i] = c
    return F


def starts_b(pt, text, a, sgn=1, ring=True):
    """Every start from which rule B can encode pt (each letter must lie in its 26-word window)."""
    L, ok = len(text), None
    where = _where(text)
    for i, p in enumerate(pt):
        g = {(j - sgn * d - a * i) % L if ring else j - sgn * d - a * i for j in where.get(p, ()) for d in range(26)}
        ok = g if ok is None else ok & g
        if not ok:
            return []
    return sorted(x for x in ok if 0 <= x < L)


def starts_w(pt, text, a, sgn=1, ring=True):
    F = feasible(pt, text, "W", a, sgn, ring)
    if not F:
        return []
    L = len(text)
    out = {(q - sgn * d) % L if ring else q - sgn * d for q in F[0] for d in range(26)}
    return sorted(s for s in out if 0 <= s < L)


def encode(pt, text, rule, alpha, a, s, rng, sgn=1, ring=True, choice="random"):
    """Encode pt by counting words; None if some letter cannot be reached. The encoder chooses
    among the reachable words that carry the letter ('nearest' or 'random')."""
    L = len(text)
    pick = (lambda c: c[0]) if choice == "nearest" else rng.choice

    def at(j):
        return text[j % L] if ring else (text[j] if 0 <= j < L else None)

    out = []
    if rule == "B":
        for i, p in enumerate(pt):
            c = [d for d in range(26) if at(s + a * i + sgn * d) == p]
            if not c:
                return None
            out.append(alpha[pick(c)])
        return "".join(out)
    F = feasible(pt, text, rule, a, sgn, ring)
    if not F:
        return None
    q = s - a                                   # so that q_0 = s + sgn*d_0
    for i in range(len(pt)):
        c = [d for d in range(26) if ((q + a + sgn * d) % L if ring else q + a + sgn * d) in F[i]]
        if not c:
            return None
        d = pick(c)
        q = (q + a + sgn * d) % L if ring else q + a + sgn * d
        out.append(alpha[d])
    return "".join(out)


def reach(pt, text, a, sgn=1):
    """How many letters of pt rule W can walk (ring, best start) before no pointer is left."""
    L = len(text)
    where = _where(text)
    cur = set(where.get(pt[0], ()))
    for i in range(1, len(pt)):
        if not cur:
            return i - 1
        cur = {q for q in where.get(pt[i], ()) if any((q - a - sgn * d) % L in cur for d in range(26))}
    return len(pt) if cur else len(pt) - 1


def compose(rng, text, rule, a, s, vocab, sgn=1, ring=True, n=N, tries=400):
    """Write a message of exactly n letters, made of English words, that the rule can encode from
    start s: each next word is drawn at random among words whose letters are all reachable.
    Returns the message without spaces, or None."""
    L = len(text)
    where = _where(text)

    def step(cur, i, ch):
        if rule == "B":
            ok = any((text[(s + a * i + sgn * d) % L] if ring else
                      (text[s + a * i + sgn * d] if 0 <= s + a * i + sgn * d < L else None)) == ch for d in range(26))
            return cur if ok else None
        nxt = set()
        for q in where.get(ch, ()):
            for d in range(26):
                p = q - a - sgn * d
                if (p % L if ring else p) in cur:
                    nxt.add(q)
                    break
        return nxt or None

    for _ in range(tries):
        msg, cur = "", ({(s - a) % L if ring else s - a} if rule == "W" else True)
        fails = 0
        while len(msg) < n and fails < 300:
            w = rng.choice(vocab)
            left = n - len(msg) - len(w)
            if left < 0 or left in (1, 2):
                fails += 1
                continue
            c = cur
            for k, ch in enumerate(w):
                c = step(c, len(msg) + k, ch)
                if c is None:
                    break
            if c is None:
                fails += 1
                continue
            msg, cur = msg + w, c
        if len(msg) == n:
            return msg
    return None


# ---------------------------------------------------------------- rule C: two letters, word and letter number

C_MODES = [(an2, base, wrap, end) for an2 in ("AZ", "KR") for base in (1, 0) for wrap in (False, True)
           for end in (False, True)]


def c_letter(word, d2, base, wrap, end):
    """Letter number d2 (0..25, numbered from `base`) of a word, from its start or its end."""
    k = d2 if base == 1 else d2 - 1
    if wrap:
        k %= len(word)
    elif not 0 <= k < len(word):
        return "?"
    return word[-1 - k] if end else word[k]


def c_read(ct, words, e, an, sgn, a, s, mode, ring=True):
    """Overlapping pairs: P_i = letter number d2(C_(i+e)) of word number s + a*i + sgn*d(C_i)."""
    an2, base, wrap, end = mode
    L, out = len(words), []
    for i in range(len(ct)):
        j, k = s + a * i + sgn * ALPHAS[an].index(ct[i]), i + e
        if not 0 <= k < len(ct) or not (ring or 0 <= j < L):
            out.append("?")
        else:
            out.append(c_letter(words[j % L], ALPHAS[an2].index(ct[k]), base, wrap, end))
    return "".join(out)


def c_halved(ct, words, phase, an, sgn, s, mode):
    """Pairs that do not overlap: letters (phase+2k, phase+2k+1) give word and letter number."""
    an2, base, wrap, end = mode
    L = len(words)
    return "".join(c_letter(words[(s + sgn * ALPHAS[an].index(ct[i])) % L], ALPHAS[an2].index(ct[i + 1]), base, wrap, end)
                   for i in range(phase, len(ct) - 1, 2))


HALF_WORDS = ("BERLIN", "CLOCK", "NORTH", "EAST")


def work_c(jobs):
    """Rule C on the given texts. Returns (settings, histogram, best strict, best wrap, kept,
    reachable: {(ti, wrap): most clue letters any letter-numbering can reach at all},
    halved: Counter of clue words seen in the non-overlapping readings, and their number)."""
    ct, cribs = _S["ct"], sorted(_S["cribs"].items())
    d = {an: [al.index(c) for c in ct] for an, al in ALPHAS.items()}
    n, hist, tops = 0, Counter(), []
    best = {False: (0, None), True: (0, None)}
    can, half, nhalf = {}, Counter(), 0
    for ti in jobs:
        name, words = _S["texts"][ti]
        L = len(words)
        for mode in C_MODES:
            an2, base, wrap, end = mode
            for e in (1, -1):
                match = []                      # per clue letter: the words that give it for this neighbour letter
                for i, p in cribs:
                    d2 = d[an2][i + e]
                    match.append((i, [j for j, w in enumerate(words) if c_letter(w, d2, base, wrap, end) == p]))
                k = (ti, wrap)
                can[k] = max(can.get(k, 0), sum(bool(m) for _, m in match))
                for an in ALPHAS:
                    for sgn in (1, -1):
                        for a in range(-A_MAX, A_MAX + 1):
                            cnt = [0] * L
                            for i, m in match:
                                o = a * i + sgn * d[an][i]
                                for j in m:
                                    cnt[(j - o) % L] += 1
                            n += L
                            hist.update(cnt)
                            mx = max(cnt)
                            if mx > best[wrap][0]:
                                best[wrap] = (mx, (ti, e, an, sgn, a, cnt.index(mx), mode))
                            if mx >= KEEP:
                                tops += [(c, ti, e, an, sgn, a, s, mode) for s, c in enumerate(cnt) if c >= KEEP]
            for phase in (0, 1):                # the halved message: no clue position applies, look for clue words
                for an in ALPHAS:
                    for sgn in (1, -1):
                        for s in range(L):
                            r = c_halved(ct, words, phase, an, sgn, s, mode)
                            nhalf += 1
                            for w in HALF_WORDS:
                                if w in r:
                                    half[w] += 1
    return n, hist, best, tops, can, half, nhalf


def search_c(ct, cribs, tlist, procs=None, serial=False):
    jobs = list(range(len(tlist)))
    res = {"n": 0, "hist": Counter(), "tops": [], "best": {False: (0, None), True: (0, None)}, "can": {},
           "half": Counter(), "nhalf": 0}
    if serial:
        init(ct, cribs, tlist)
        parts = [work_c(jobs)]
    else:
        parts = pmap(work_c, jobs, init, (ct, cribs, tlist), chunk=1, procs=procs)
    for n, hist, best, tops, can, half, nhalf in parts:
        res["n"] += n
        res["nhalf"] += nhalf
        res["hist"].update(hist)
        res["half"].update(half)
        res["tops"] += tops
        res["can"].update(can)
        for k, b in best.items():
            if (b[0], str(b[1])) > (res["best"][k][0], str(res["best"][k][1])):
                res["best"][k] = b
    res["tops"].sort(reverse=True)
    res["top"] = max(b[0] for b in res["best"].values())
    return res


def encode_c(pt, words, e, alpha, a, s, mode, rng, sgn=1):
    """Encode pt with overlapping pairs (ring); returns a 97-letter ciphertext or None.
    Each cipher letter is a word number for its own place and a letter number for its neighbour's,
    so the choice is a chain; solved backwards, then drawn forwards."""
    an2, base, wrap, end = mode
    L, n = len(words), len(pt)
    a2 = ALPHAS[an2]

    def ok(i, c, c2):        # does (C_i = c, C_(i+e) = c2) give pt[i]?
        return c_letter(words[(s + a * i + sgn * c) % L], a2.index(alpha[c2]), base, wrap, end) == pt[i]

    # chain order: with e = +1 place i needs C_i and C_(i+1); with e = -1 it needs C_i and C_(i-1)
    order = list(range(n)) if e == 1 else list(range(n - 1, -1, -1))
    good = {}                # good[k][c]: C at chain place k can be c and the rest of the chain completes
    last = order[-1]
    good[last] = set(range(26))                 # the last place has no neighbour: its letter is not defined
    for idx in range(n - 2, -1, -1):
        i, nx = order[idx], order[idx + 1]
        good[i] = {c for c in range(26) if any(ok(i, c, c2) for c2 in good[nx])}
        if not good[i]:
            return None
    out = [None] * n
    c = rng.choice(sorted(good[order[0]]))
    out[order[0]] = c
    for idx in range(n - 1):
        i, nx = order[idx], order[idx + 1]
        c = rng.choice([c2 for c2 in sorted(good[nx]) if ok(i, c, c2)])
        out[nx] = c
    return "".join(alpha[x] for x in out)


def reach_c(pt, words, a, s, mode, alpha=AZ, sgn=1):
    """How many letters of pt the overlapping-pair rule (neighbour +1) can encode from start s."""
    an2, base, wrap, end = mode
    L, a2 = len(words), ALPHAS[an2]
    slot = [a2.index(alpha[c]) for c in range(26)]
    cur = set(range(26))
    for i, p in enumerate(pt[:-1]):
        ws = [words[(s + a * i + sgn * c) % L] for c in cur]
        cur = {c2 for c2 in range(26) if any(c_letter(w, slot[c2], base, wrap, end) == p for w in ws)}
        if not cur:
            return i
    return len(pt)


def compose_c(rng, words, a, s, mode, vocab, alpha=AZ, sgn=1, n=N, tries=200):
    """A message of n letters made of English words that the overlapping-pair rule can encode."""
    for _ in range(tries):
        msg, fails = "", 0
        while len(msg) < n and fails < 300:
            w = rng.choice(vocab)
            left = n - len(msg) - len(w)
            if left < 0 or left in (1, 2) or reach_c(msg + w + "?", words, a, s, mode, alpha, sgn) < len(msg + w) + 1:
                fails += 1
                continue
            msg += w
        if len(msg) == n:
            return msg
    return None


__all__ = [n for n in dir() if not n.startswith("_")] + ["_S"]
_ = (K4,)
