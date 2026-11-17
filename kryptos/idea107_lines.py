"""Helpers for idea 107: one word per worksheet line.

The plaintext is written one word per line. The key letter of a plaintext letter depends on its
place inside the word (its column) and on the line:

  add       K = a[line] + b[column]            a column key plus a free letter for each line
  speed     K = a[line] * column + b0          one start letter, each word has its own speed
  ownspeed  K = a[line] * column + s[line]     each word has its own speed and its own start
  slide     K_i = K_(i-1) + d[column]          the strip is moved on by the column key and is never
                                               put back (no line letter at all)

The column is counted from the start of the word or from its end. Every line is Vigenere, every
line is Beaufort, or the lines take turns.

Inside the clue words everything is known but the few key letters, so each model is a small
linear system mod 26 with coefficients that let it be solved by plain substitution: each test is a
list of sums of clue key values that must be 0 mod 26 ("checks"). tests() builds the lists,
Scanner runs them on a key stream, solve() gives the key letters back, Reader fills in the rest
of the text with a search over word breaks.
"""
import math
from collections import Counter

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET

N = 26
B1_SPLITS = (("EAST|NORTH|EAST", (4, 5, 4)), ("EAST|NORTHEAST", (4, 9)), ("EASTNORTHEAST", (13,)))
B2_SPLITS = (("BERLIN|CLOCK", (6, 5)), ("BERLINCLOCK", (11,)))
MODELS = ("add", "speed", "ownspeed", "slide")
LEAD = 3                     # checks tested in line before the slow path
NEAR = 5                     # failed tests that held this many checks are kept by name
WORD_COST = 1.0              # evidence every word must pay (keeps chance four-letter words out)


def parsings():
    """[(name, lines)], lines = [(block, [clue index, ...])] with clue indices 0..23."""
    out = []
    for n1, s1 in B1_SPLITS:
        for n2, s2 in B2_SPLITS:
            lines, j = [], 0
            for blk, split in ((0, s1), (1, s2)):
                for ln in split:
                    lines.append((blk, list(range(j, j + ln))))
                    j += ln
            out.append((n1 + " + " + n2, lines))
    return out


def form_patterns(lines):
    """Every way the lines can be Vigenere (0) / Beaufort (1): all one form, or taking turns.
    The number of words between the two clue blocks is unknown, so block 2 starts on either."""
    out, seen = [], set()
    n1 = sum(1 for b, _ in lines if b == 0)
    n2 = len(lines) - n1
    cands = [("V", (0,) * len(lines)), ("B", (1,) * len(lines))]
    for f in (0, 1):
        for g in (0, 1):
            cands.append(("turns%d%d" % (f, g),
                          tuple((f + t) % 2 for t in range(n1)) + tuple((g + t) % 2 for t in range(n2))))
    for name, pat in cands:
        if pat not in seen:
            seen.add(pat)
            out.append((name, pat))
    return out


class Test(object):
    __slots__ = ("id", "parsing", "lines", "model", "align", "base", "pattern", "forms", "checks")

    def name(self):
        return "%s | %s%s%s | %s" % (self.parsing, self.model,
                                     "" if self.model == "ownspeed" else " col-from-" + self.align,
                                     " base%d" % self.base if self.model == "speed" else "", self.pattern)

    def var(self, li, j):
        """Index of clue letter j's key value in x = Vigenere values (0..23) + Beaufort values (24..47)."""
        return j + 24 * self.forms[li]

    def col(self, li, t):
        n = len(self.lines[li][1])
        return t if self.align == "start" else n - 1 - t

    def const_form(self):
        return self.pattern in ("V", "B")


def _add(e, idx, coef):
    v = e.get(idx, 0) + coef
    if v:
        e[idx] = v
    else:
        e.pop(idx, None)


def _comb(*terms):
    """Sum of coef * expression (an expression is {x index: coefficient})."""
    e = {}
    for coef, ex in terms:
        for i, c in ex.items():
            _add(e, i, coef * c)
    return e


def _checks(t):
    lines, out = t.lines, []
    X = lambda li, tt: {t.var(li, lines[li][1][tt]): 1}  # noqa: E731
    if t.model == "add":
        a, b, done = {}, {}, set()
        by_col = {}
        for li, (_, js) in enumerate(lines):
            for tt in range(len(js)):
                by_col.setdefault(t.col(li, tt), []).append((li, tt))
        for root in range(len(lines)):
            if root in a:
                continue
            a[root] = {}
            queue = [root]
            while queue:
                li = queue.pop(0)
                for tt in range(len(lines[li][1])):
                    if (li, tt) in done:
                        continue
                    done.add((li, tt))
                    c = t.col(li, tt)
                    if c in b:
                        out.append(_comb((1, X(li, tt)), (-1, a[li]), (-1, b[c])))
                        continue
                    b[c] = _comb((1, X(li, tt)), (-1, a[li]))
                    for l2, t2 in by_col[c]:
                        if l2 not in a:
                            a[l2] = _comb((1, X(l2, t2)), (-1, b[c]))
                            done.add((l2, t2))
                            queue.append(l2)
    elif t.model in ("speed", "ownspeed"):
        b0 = None
        for li, (_, js) in enumerate(lines):
            order = sorted(range(len(js)), key=lambda tt: t.col(li, tt))
            u = [X(li, tt) for tt in order]
            for q in range(2, len(u)):
                out.append(_comb((1, u[q]), (q - 1, u[0]), (-q, u[1])))
            if t.model == "speed":
                mine = _comb((1 + t.base, u[0]), (-t.base, u[1]))
                if b0 is None:
                    b0 = mine
                else:
                    out.append(_comb((1, mine), (-1, b0)))
    elif t.model == "slide":
        d = {}
        prev = None
        for li, (blk, js) in enumerate(lines):
            for tt in range(len(js)):
                cur = (blk, X(li, tt))
                if prev is not None and prev[0] == blk:
                    e = _comb((1, cur[1]), (-1, prev[1]))
                    c = t.col(li, tt)
                    if c in d:
                        out.append(_comb((1, e), (-1, d[c])))
                    else:
                        d[c] = e
                prev = cur
    return [c for c in out]


def tests():
    out = []
    for pname, lines in parsings():
        for model in MODELS:
            for align in ("start", "end"):
                if model == "ownspeed" and align == "end":
                    continue           # a word with its own speed and start reads the same from either end
                for base in ((0, 1) if model == "speed" else (0,)):
                    for fname, forms in form_patterns(lines):
                        if model == "slide" and fname not in ("V", "B"):
                            continue
                        t = Test()
                        t.id, t.parsing, t.lines, t.model, t.align = len(out), pname, lines, model, align
                        t.base, t.pattern, t.forms = base, fname, forms
                        t.checks = _checks(t)
                        out.append(t)
    return out


def _src(e):
    parts = []
    for i in sorted(e):
        c = e[i]
        parts.append(("+" if c > 0 else "-") + ("x[%d]" % i if abs(c) == 1 else "%d*x[%d]" % (abs(c), i)))
    s = "".join(parts)
    return s[1:] if s.startswith("+") else s


class Scanner(object):
    """Runs every test on x = Vigenere key values + Beaufort key values (48 numbers).

    scan(x) returns the ids of the tests whose checks ALL hold. hist counts, for the tests that
    pass their first LEAD checks, how many checks hold before the first one fails (a gauge that can
    be compared with chance: 26^-d)."""

    def __init__(self, ts=None):
        self.tests = ts if ts is not None else tests()
        self.hist = Counter()
        self._rest = []
        src = ["def scan(x, deep):"]
        for t in self.tests:
            assert len(t.checks) >= 7, t.name()
            lead = " and ".join("not (%s) %% 26" % _src(c) for c in t.checks[:LEAD])
            src.append("    if %s: deep(%d, x)" % (lead, t.id))
            self._rest.append([eval("lambda x: (%s) %% 26" % _src(c)) for c in t.checks[LEAD:]])
        ns = {}
        exec("\n".join(src), ns)
        self._scan = ns["scan"]
        self._hits = []
        self.near, self.cur = [], None       # (cur, test id, checks held) for the near misses

    def _deep(self, tid, x):
        d = LEAD
        for f in self._rest[tid]:
            if f(x):
                self.hist[d] += 1
                if d >= NEAR:
                    self.near.append((self.cur, tid, d))
                return
            d += 1
        self._hits.append(tid)

    def scan(self, x):
        self._hits = []
        self._scan(x, self._deep)
        return self._hits

    def chance(self, n_streams):
        """Expected counts by chance over n_streams key streams: ({d: tests failing exactly at check d+1},
        full passes)."""
        lead, full = Counter(), 0.0
        for t in self.tests:
            n = len(t.checks)
            for d in range(LEAD, n):
                lead[d] += n_streams * 26.0 ** -d * 25 / 26
            full += n_streams * 26.0 ** -n
        return lead, full


def slow_pass(t, x):
    return all(sum(c * x[i] for i, c in e.items()) % N == 0 for e in t.checks)


# ---------------------------------------------------------------- solving a passed test

def solve(t, x):
    """Key letters of a test that passed. Raises AssertionError if they do not give x back."""
    lines = t.lines
    val = lambda li, tt: x[t.var(li, lines[li][1][tt])]  # noqa: E731
    p = {"a": {}, "b": {}, "s": {}, "d": {}, "b0": None}
    if t.model == "add":
        a, b = p["a"], p["b"]
        left = set(range(len(lines)))
        while left:
            a[min(left)] = 0
            grew = True
            while grew:
                grew = False
                for li in sorted(left):
                    if li in a:
                        for tt in range(len(lines[li][1])):
                            b.setdefault(t.col(li, tt), (val(li, tt) - a[li]) % N)
                        left.discard(li)
                        grew = True
                    else:
                        for tt in range(len(lines[li][1])):
                            c = t.col(li, tt)
                            if c in b:
                                a[li] = (val(li, tt) - b[c]) % N
                                grew = True
                                break
    elif t.model in ("speed", "ownspeed"):
        for li, (_, js) in enumerate(lines):
            order = sorted(range(len(js)), key=lambda tt: t.col(li, tt))
            u0, u1 = val(li, order[0]), val(li, order[1])
            p["a"][li] = (u1 - u0) % N
            if t.model == "ownspeed":
                p["s"][li] = u0
            elif p["b0"] is None:
                p["b0"] = (u0 - t.base * (u1 - u0)) % N
    else:
        prev = None
        for li, (blk, js) in enumerate(lines):
            for tt in range(len(js)):
                if prev is not None and prev[0] == blk:
                    p["d"].setdefault(t.col(li, tt), (val(li, tt) - prev[1]) % N)
                prev = (blk, val(li, tt))
    # the key letters must give every clue key value back
    prev = None
    for li, (blk, js) in enumerate(lines):
        for tt in range(len(js)):
            c = t.col(li, tt)
            if t.model == "add":
                k = p["a"][li] + p["b"][c]
            elif t.model == "speed":
                k = p["a"][li] * (c + t.base) + p["b0"]
            elif t.model == "ownspeed":
                k = p["a"][li] * c + p["s"][li]
            else:
                k = val(li, tt) if prev is None or prev[0] != blk else prev[1] + p["d"][c]
                prev = (blk, k % N)
            assert k % N == val(li, tt), (t.name(), li, tt)
    return p


def letters_of(vals):
    return "".join(AZ[v % N] for v in vals)


# ---------------------------------------------------------------- the cipher itself (planted texts)

def layout(lay, m):
    """Plain and cipher alphabets of a layout name from kryptos.round11.streams ('M/AZ', 'KR/M', ...)."""
    pick = {"M": m, "AZ": AZ, "KR": KRYPTOS_ALPHABET}
    a, b = lay.split("/")
    return pick[a], pick[b]


def encrypt_words(words, pa, ca, model, align, base, forms, key):
    """One word per line. forms: 0/1 per line (Vigenere C = P + K, Beaufort C = K - P), numbers taken in
    the plain alphabet pa and the cipher alphabet ca.
    key: add {'a': per line, 'b': column key}; speed {'a': per line, 'b0'}; ownspeed {'a', 's'};
    slide {'d': column key, 'start': K before the first letter}."""
    ip = {c: i for i, c in enumerate(pa)}
    out = []
    K = key.get("start", 0)
    for li, w in enumerate(words):
        n = len(w)
        for tt, ch in enumerate(w):
            c = tt if align == "start" else n - 1 - tt
            if model == "add":
                k = key["a"][li] + key["b"][c]
            elif model == "speed":
                k = key["a"][li] * (c + base) + key["b0"]
            elif model == "ownspeed":
                k = key["a"][li] * c + key["s"][li]
            else:
                K = k = (K + key["d"][c]) % N
            x = ip[ch]
            out.append(ca[(k + x) % N] if forms[li] == 0 else ca[(k - x) % N])
    return "".join(out)


# ---------------------------------------------------------------- reading a survivor

class Vocab(object):
    """Words by length, with a lazily built index for words seen through a mask of known letters."""

    def __init__(self, words):
        self.by_len = {}
        for w in set(words):
            self.by_len.setdefault(len(w), []).append(w)
        self._proj = {}

    def proj(self, n, mask):
        key = (n, mask)
        s = self._proj.get(key)
        if s is None:
            ws = self.by_len.get(n, ())
            s = set(ws) if len(mask) == n else set("".join(w[i] for i in mask) for w in ws)
            self._proj[key] = s
        return s


def reading_vocab():
    """Words for the reader: the system dictionary (6+ letters, or shorter if also a common word), the
    6,000 most common words, and the plain endings -S, -ED, -ING of common dictionary words."""
    from . import wordkeys
    common = wordkeys.common_words()
    big = set(w for w in wordkeys.big_dictionary() if len(w) >= 3)
    cs = set(common)
    out = set(w for w in big if len(w) >= 6 or w in cs) | set(common[:6000])
    for w in cs & big:
        if len(w) >= 4:
            out.add(w + "S")
            out.add(w + "D" if w.endswith("E") else w + "ED")
            out.add((w[:-1] if w.endswith("E") else w) + "ING")
    return Vocab(out)


LN26 = math.log(26.0)
CLUE_SPANS = ((21, 34), (63, 74))
REGIONS = ((0, 21), (34, 63), (74, 97))


class Reader(object):
    """Fills in the text outside the clue words for a test that passed.

    The word breaks, the line letter of every word (and whatever else the model leaves free) are
    unknown, so each stretch of text is cut into dictionary words by dynamic programming. A word
    earns its evidence: ln(26^known letters / (free choices x words that fit the mask)), the log
    of how much less often chance gives a word there; only words with positive evidence are used
    and everything else stays '?'. Returns (reading, evidence, words)."""

    def __init__(self, t, params, pa, ca, ct, vocab, nmax=12):
        self.t, self.p, self.pa, self.ct, self.vocab, self.nmax = t, params, pa, ct, vocab, nmax
        ic = {c: i for i, c in enumerate(ca)}
        self.y = [ic[c] for c in ct]
        self.alt = not t.const_form()
        self._masks = {}

    # -- states: the form of the next word (form models) or the last key value (slide); None = unknown
    def expand(self, s):
        if self.t.model == "slide":
            return [s]
        if s is not None:
            return [s]
        return [0, 1] if self.alt else [self.t.forms[0]]

    def cands(self, i, n, s):
        """[(text with ? for unknown letters, next state)], number of free choices."""
        t, p, y, pa = self.t, self.p, self.y, self.pa
        cols = [tt if t.align == "start" else n - 1 - tt for tt in range(n)]
        out = []
        if t.model == "slide":
            f, d = t.forms[0], p["d"]
            br, branched = [(s, "")], False
            for tt in range(n):
                dd = d.get(cols[tt])
                new = []
                for k, txt in br:
                    if dd is None:
                        new.append((None, txt + "?"))
                    elif k is None:
                        if branched and len(br) == 1:
                            new.append((None, txt + "?"))
                        else:
                            yy = y[i + tt]
                            for kk in range(N):
                                new.append((kk, txt + pa[(yy - kk) % N if f == 0 else (kk - yy) % N]))
                    else:
                        kk = (k + dd) % N
                        yy = y[i + tt]
                        new.append((kk, txt + pa[(yy - kk) % N if f == 0 else (kk - yy) % N]))
                if len(new) > len(br):
                    branched = True
                br = new
            return [(txt, k) for k, txt in br], len(br)
        f = s
        nxt = 1 - f if self.alt else f
        if t.model == "add":
            b = p["b"]
            kc = [b.get(c) for c in cols]
            for a in range(N):
                out.append(("".join("?" if k is None else
                                    pa[(y[i + tt] - a - k) % N if f == 0 else (a + k - y[i + tt]) % N]
                                    for tt, k in enumerate(kc)), nxt))
            return out, N
        if t.model == "speed":
            b0, base = p["b0"], t.base
            for a in range(N):
                out.append(("".join(pa[(y[i + tt] - a * (c + base) - b0) % N if f == 0
                                       else (a * (c + base) + b0 - y[i + tt]) % N]
                                    for tt, c in enumerate(cols)), nxt))
            return out, N
        for a in range(N):
            for st in range(N):
                out.append(("".join(pa[(y[i + tt] - a * c - st) % N if f == 0 else (a * c + st - y[i + tt]) % N]
                                    for tt, c in enumerate(cols)), nxt))
        return out, N * N

    def weight(self, txt, ncand):
        n = len(txt)
        if "?" in txt:
            mask = tuple(i for i, ch in enumerate(txt) if ch != "?")
            if len(mask) < 3:
                return 0.0
            key = "".join(txt[i] for i in mask)
        else:
            if n < 3:
                return 0.0
            mask = self._masks.get(n)
            if mask is None:
                mask = self._masks[n] = tuple(range(n))
            key = txt
        s = self.vocab.proj(n, mask)
        if key not in s:
            return 0.0
        return len(mask) * LN26 - math.log(ncand) - math.log(len(s)) - WORD_COST

    def region(self, lo, hi, start, term):
        best = [dict() for _ in range(hi - lo + 1)]
        best[0][start] = (0.0, None)
        for off in range(hi - lo):
            i = lo + off
            for s, (sc, _) in list(best[off].items()):
                cur = best[off + 1].get(None)
                if cur is None or sc > cur[0]:
                    best[off + 1][None] = (sc, (off, s, "?", 0.0))
                for r in self.expand(s):
                    for n in range(3, min(self.nmax, hi - i) + 1):
                        cl, ncand = self.cands(i, n, r)
                        for txt, nxt in cl:
                            w = self.weight(txt, ncand)
                            if w > 0:
                                cur = best[off + n].get(nxt)
                                if cur is None or sc + w > cur[0]:
                                    best[off + n][nxt] = (sc + w, (off, s, txt, w))
        ends = [(v[0], s) for s, v in best[-1].items() if term is None or s is None or s == term]
        if not ends:
            return "?" * (hi - lo), 0.0, []
        sc, s = max(ends, key=lambda e: e[0])
        off, parts, words = hi - lo, [], []
        while off > 0:
            _, (poff, ps, txt, w) = best[off][s]
            parts.append(txt)
            if w > 0:
                words.append(txt)
            off, s = poff, ps
        return "".join(reversed(parts)), sc, list(reversed(words))

    def ends(self):
        """(start state, end state) for the three stretches outside the clues."""
        t, lines = t_lines = self.t, self.t.lines
        del t_lines
        first2 = next(li for li, (blk, _) in enumerate(lines) if blk == 1)
        if t.model == "slide":
            x = self.kv
            d0 = self.p["d"].get(0 if t.align == "start" else len(lines[0][1]) - 1)
            d1 = self.p["d"].get(0 if t.align == "start" else len(lines[first2][1]) - 1)
            return [(None, None if d0 is None else (x[0] - d0) % N),
                    (x[12], None if d1 is None else (x[13] - d1) % N),
                    (x[23], None)]
        if not self.alt:
            return [(None, None)] * 3
        return [(None, t.forms[0]), (1 - t.forms[first2 - 1], t.forms[first2]), (1 - t.forms[-1], None)]

    def read(self, cribs, kv=None):
        """kv: the 24 clue key values in the test's own form (needed for the slide model)."""
        self.kv = kv
        out, total, words = [], 0.0, []
        clue = "".join(cribs[i] for i in sorted(cribs))
        pieces = [clue[:13], clue[13:], ""]
        for (lo, hi), (start, term), piece in zip(REGIONS, self.ends(), pieces):
            txt, sc, ws = self.region(lo, hi, start, term)
            out.append(txt + piece)
            total += sc
            words.extend(ws)
        return "".join(out), total, words


def known_score(reading, big):
    """(big-model score per quadgram, count) over quadgrams with no '?' that are not wholly inside the clues."""
    q = []
    for i in range(len(reading) - 3):
        g = reading[i:i + 4]
        if "?" in g or any(lo <= i and i + 4 <= hi for lo, hi in CLUE_SPANS):
            continue
        q.append(big.logp.get(g, big.floor))
    return (sum(q) / len(q) if q else -99.0), len(q)


# ---------------------------------------------------------------- a fact about K4's own letters

def east_clash(ct):
    """EAST is enciphered twice (letters 22-25 and 31-34). If both stand in the same columns of their
    lines and both lines have the same form, a line letter moves all four cipher letters by the same
    amount in the cipher alphabet. Returns the two cipher words and whether that is possible at all
    (no cipher letter may have to sit in two places)."""
    w1, w2 = ct[21:25], ct[30:34]
    # same shift for every pair means: w1[i] == w1[j]  <=>  w2[i] == w2[j]
    ok = all((w1[i] == w1[j]) == (w2[i] == w2[j]) for i in range(4) for j in range(4))
    return w1, w2, ok


def clash_dead(t):
    """True if the test needs the two EASTs to differ by one line letter (see east_clash)."""
    b1 = t.parsing.split(" + ")[0]
    if b1 == "EASTNORTHEAST":
        return False
    same_cols = b1 == "EAST|NORTH|EAST" or t.align == "end"
    li2 = 2 if b1 == "EAST|NORTH|EAST" else 1
    same_form = t.forms[0] == t.forms[li2]
    if not (same_cols and same_form):
        return False
    return t.model in ("add", "slide") or (t.model == "speed" and t.base == 0)
