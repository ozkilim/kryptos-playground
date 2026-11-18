"""Idea 126: is there a message hidden in the solved K1-K3 text itself (acrostics, skip readings)?

No K4 and no cipher model here. A "reading" is a rule that picks letters out of the solved text:
first / second / third / last letter of each word, every k-th word or letter from any start, the
K2 coordinate digits used as repeating step counts, the first / last letter and the columns of the
plaintext laid under the carved cipher rows, sentence initials, doubled letters. Each reading is read
forwards and backwards and scored six ways (higher = more English): quadgram mean (big model),
best 20-letter quadgram window, word coverage, longest dictionary word of 5+, method-word count,
and the longest stretch that splits wholly into common English words ("wordrun").

Readings fall into three families: letters taken from words (acrostics), letters of the running
text (skips), and the carved-row layout. For each family and score the statistic is the largest
value over the family's readings (quadgram scores also as z-scores against reference controls).
Controls are the same text with word order shuffled inside each section (K1, K2, K3 and the Morse
text separately), which keeps every word and every letter count. Test controls give the null
distribution of every maximum, and a combined statistic (the largest of all 21 maxima, each
standardised by the controls) gives one p-value that pays for every reading, score and family.
"""
import math
import random
from array import array

from .data import DATA_DIR
from .idea106_words import FIXES, K1_WORDS, K2_WORDS, K3_WORDS, MORSE_WORDS
from .round11 import SMOKE, pmap

STATS = ("qmean", "qwin", "cover", "longest", "method", "wordrun")
NS = len(STATS)
SD_FLOOR = (0.01, 0.02)
MIN_LEN = 12          # readings shorter than this are not scored (printed only)
KMAX = 40
WIN = 20
D1 = (3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4)          # 38 57 6.5 / 77 8 44 as single digits
D2 = (38, 57, 6, 5, 77, 8, 44)                  # ... as the numbers
N_COMMON = 2000
TWO = frozenset("OF TO IN IS IT AN AS AT BE BY ON OR WE HE IF NO SO UP US DO GO ME MY".split())
COMPASS = ("EASTWARD", "WESTWARD", "NORTHWARD", "SOUTHWARD", "NORTHEAST", "NORTHWEST", "SOUTHEAST", "SOUTHWEST",
           "BACKWARD", "BACKWARDS", "FORWARD", "FORWARDS", "UPWARD", "DOWNWARD", "DIAGONAL", "CIPHER", "ALPHABET")
METHOD = ("ROW", "ROWS", "COLUMN", "KEY", "SHIFT", "ADD", "READ", "LAYER", "CLOCK", "EAST", "WEST",
          "NORTH", "SOUTH", "LEFT", "RIGHT", "TURN", "ROTATE", "GRID", "TABLE", "SQUARE", "MINUS", "PLUS",
          "SUBTRACT", "BERLIN", "KRYPTOS", "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT",
          "NINE", "TEN", "ELEVEN", "TWELVE", "FIRST", "SECOND", "THIRD", "LAST", "EVERY", "SKIP", "COUNT")

SEP = {"K1": K1_WORDS, "K2": K2_WORDS + " ID BY ROWS", "K3": K3_WORDS, "MO": MORSE_WORDS}
SECTIONS = ("K1", "K2", "K3", "MO")
LAYER = {"ID": "X", "BY": "LAYER", "ROWS": "TWO"}
MARKS = ("X", "Q")

# Sentence starts in the carved K1-K3 text (X kept, ID BY ROWS), for the sentence-initial readings.
SENTENCES = (
    "BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION ."
    " IT WAS TOTALLY INVISIBLE . HOWS THAT POSSIBLE . THEY USED THE EARTHS MAGNETIC FIELD . X THE INFORMATION WAS"
    " GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION . X DOES LANGLEY KNOW ABOUT THIS . THEY SHOULD ."
    " ITS BURIED OUT THERE SOMEWHERE . X WHO KNOWS THE EXACT LOCATION . ONLY WW . THIS WAS HIS LAST MESSAGE . X THIRTY"
    " EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY"
    " FOUR SECONDS WEST . ID BY ROWS ."
    " SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS"
    " REMOVED . WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER . AND THEN WIDENING THE HOLE"
    " A LITTLE I INSERTED THE CANDLE AND PEERED IN . THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO"
    " FLICKER . BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST . X CAN YOU SEE ANYTHING Q .")


def sentence_bounds():
    """(start word indices, end word indices) of the sentences, X counted as a word."""
    starts, ends, i, new = [], [], 0, True
    for tok in SENTENCES.split():
        if tok == ".":
            ends.append(i - 1)
            new = True
            continue
        if new:
            starts.append(i)
            new = False
        i += 1
    return starts, ends


def real_sections():
    return {s: SEP[s].split() for s in SECTIONS}


def shuffled_sections(sections, seed):
    rng = random.Random(seed)
    out = {}
    for s in SECTIONS:
        w = list(sections[s])
        rng.shuffle(w)
        out[s] = w
    return out


def _style(words, sec, spell, marks, end):
    out = list(words)
    if sec == "K2" and end == "LAYER":
        out = [LAYER.get(w, w) for w in out]
    if spell:
        out = [FIXES.get(w, w) for w in out]
    if not marks and sec != "MO":
        out = [w for w in out if w not in MARKS]
    return out


def units(sections):
    """[(name, [words])] in a fixed order: each section and K1-K3 joined, in every style that differs."""
    out = []
    for spell in (0, 1):
        for marks in (1, 0):
            for end in ("ROWS", "LAYER"):
                st = "%s,X%s,%s" % ("corr" if spell else "carved", "kept" if marks else "drop", end)
                parts = {s: _style(sections[s], s, spell, marks, end) for s in SECTIONS}
                if marks and end == "ROWS":
                    out.append(("K1[%s]" % ("corr" if spell else "carved"), parts["K1"]))
                    out.append(("MO[%s]" % ("corr" if spell else "carved"), parts["MO"]))
                if end == "ROWS":
                    out.append(("K3[%s]" % st.rsplit(",", 1)[0], parts["K3"]))
                out.append(("K2[%s]" % st, parts["K2"]))
                out.append(("K1-K3[%s]" % st, parts["K1"] + parts["K2"] + parts["K3"]))
    return out


PICKS = ("letters", "w1", "w2", "w3", "wlast")


def base_strings(sections):
    """[(name, string)]: per unit, the letter string and the four word-letter lines ('?' = too short)."""
    out = []
    for name, words in units(sections):
        out.append((name + ":letters", "".join(words)))
        for p in (1, 2, 3):
            out.append((name + ":w%d" % p, "".join(w[p - 1] if len(w) >= p else "?" for w in words)))
        out.append((name + ":wlast", "".join(w[-1] for w in words)))
    return out


# --------------------------------------------------------------------------- the carved rows

def panel_cells(nletters=None):
    """For each carved row 0..24 of the cipher panel, the list of plaintext letter indices (0..767,
    '?' cells skipped) that lie under it, up to the '?' before K4. A text with a different letter
    count (a planted text) is laid into the same cells and cut at its length."""
    import json
    lay = json.load(open(DATA_DIR / "sculpture_layout.json"))["cipher_panel"]
    from . import load
    pt = load("k1")["plaintext"] + load("k2")["plaintext"] + load("k3")["plaintext"]
    rows, pos, li = [], 0, 0
    for r in lay:
        row = []
        for ch in r:
            if pos >= len(pt):
                break
            assert (ch == "?") == (pt[pos] == "?"), (pos, ch, pt[pos])
            if ch != "?":
                row.append(li)
                li += 1
            pos += 1
        if row:
            rows.append(row)
        if pos >= len(pt):
            break
    if nletters is not None:
        cells = [c for r in rows for c in r]
        while len(cells) < nletters:          # a longer text runs on past the last row
            cells.append(cells[-1] + 1)
        rows = [[c for c in r if c < nletters] for r in rows]
        rows = [r for r in rows if r]
    return rows


# --------------------------------------------------------------------------- the reading rules

def _steps(n, steps, s):
    out, p, j = [], s, 0
    while p < n:
        out.append(p)
        p += steps[j % len(steps)]
        j += 1
    return out


def build_specs(sections, min_len=MIN_LEN, only=None):
    """Every reading rule, as (label, base index, kind, arg). kind 'slice' -> arg (s, k);
    kind 'idx' -> arg = tuple of positions. The rules depend only on lengths, so one list serves the
    real text and all its shuffles. `only` limits the units (for the fast test)."""
    bases = base_strings(sections)
    specs = []
    carved_join = None
    for bi, (name, b) in enumerate(bases):
        unit, kind = name.split(":")
        if only and not any(unit.startswith(o) for o in only):
            continue
        n = len(b)
        k0 = 2 if kind == "letters" else 1
        for k in range(k0, KMAX + 1):
            for s in range(k):
                if len(range(s, n, k)) >= min_len:
                    specs.append(("%s every %d from %d" % (name, k, s), bi, "slice", (s, k)))
        for dn, steps in (("digits", D1), ("numbers", D2)):
            for s in range(sum(steps)):
                ix = _steps(n, steps, s)
                if len(ix) >= min_len:
                    specs.append(("%s %s-steps from %d" % (name, dn, s), bi, "idx", tuple(ix)))
        if unit == "K1-K3[carved,Xkept,ROWS]":
            if kind == "letters":
                carved_join = bi
                # doubled letters: rule depends on content, so it is a 'dbl' kind
                specs.append(("%s doubled letters" % name, bi, "dbl", 0))
                specs.append(("%s letter after each double" % name, bi, "dbl", 1))
            if kind in ("w1", "wlast"):
                st, en = sentence_bounds()
                ix = st if kind == "w1" else en
                specs.append(("%s sentence %s" % (name, "starts" if kind == "w1" else "ends"), bi, "idx", tuple(ix)))
    if carved_join is not None:
        rows = panel_cells(len(bases[carved_join][1]))
        specs.append(("carved rows: first letter of each row", carved_join, "idx", tuple(r[0] for r in rows)))
        specs.append(("carved rows: last letter of each row", carved_join, "idx", tuple(r[-1] for r in rows)))
        width = max(len(r) for r in rows)
        for c in range(width):
            ix = tuple(r[c] for r in rows if c < len(r))
            if len(ix) >= min_len:
                specs.append(("carved rows: column %d" % c, carved_join, "idx", ix))
    return specs


def reading(b, kind, arg):
    if kind == "slice":
        s, k = arg
        r = b[s::k]
    elif kind == "idx":
        r = "".join(b[i] for i in arg)
    else:
        r = "".join(b[i + 1 + arg] for i in range(len(b) - 1 - arg) if b[i] == b[i + 1])
    return r.replace("?", "")


# --------------------------------------------------------------------------- scoring

class Scorer:
    def __init__(self):
        logp, total = {}, 0
        with open(DATA_DIR / "english" / "quadgrams_big.txt") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                q, c = line.split()
                logp[q] = int(c)
                total += int(c)
        self.q = {k: math.log10(v / total) for k, v in logp.items()}
        # an unseen quadgram counts as a little rarer than the rarest one listed (-7.05). The usual
        # floor (0.01 counts, -9.35) makes the score of a short reading swing with the number of
        # unseen quadgrams and buries a short English stretch in noise.
        self.floor = min(self.q.values()) - 0.05
        words = set()
        for path in ("/usr/share/dict/words", str(DATA_DIR / "keys.txt")):
            try:
                with open(path) as f:
                    for w in f:
                        w = w.strip()
                        if w.isalpha() and 4 <= len(w) <= 15:
                            words.add(w.upper())
            except OSError:
                pass
        self.words = words
        pre = set()
        for w in words:
            for L in range(4, len(w) + 1):
                pre.add(w[:L])
        self.pre = pre
        # common words: the 2,000 most frequent of data/english/words_big.txt (2-letter words only
        # from a fixed everyday list, no 1-letter words) plus the method words and compass words
        common = set(METHOD) | set(COMPASS)
        with open(DATA_DIR / "english" / "words_big.txt") as f:
            for k, line in enumerate(f):
                if k >= N_COMMON:
                    break
                w = line.split()[0].upper()
                if w.isalpha() and (len(w) >= 3 or w in TWO):
                    common.add(w)
        self.common = common
        cpre = set()
        for w in common:
            for L in range(2, len(w) + 1):
                cpre.add(w[:L])
        self.cpre = cpre

    def stats(self, s):
        n = len(s)
        get, fl = self.q.get, self.floor
        if n >= 4:
            v = [get(s[i:i + 4], fl) for i in range(n - 3)]
            tot = sum(v)
            qmean = tot / len(v)
            m = WIN - 3
            if len(v) > m:
                cur = sum(v[:m])
                best = cur
                for i in range(m, len(v)):
                    cur += v[i] - v[i - m]
                    if cur > best:
                        best = cur
                qwin = best / m
            else:
                qwin = qmean
        else:
            qmean = qwin = fl
        pre, words = self.pre, self.words
        best = [0] * (n + 1)
        longest = 0
        for i in range(n - 4, -1, -1):
            b = best[i + 1]
            L = 4
            while i + L <= n:
                w = s[i:i + L]
                if w not in pre:
                    break
                if w in words:
                    if L + best[i + L] > b:
                        b = L + best[i + L]
                    if L > longest:
                        longest = L
                L += 1
            best[i] = b
        if n - 4 < 0:
            pass
        else:
            for i in range(n - 3, n):
                if best[i] < best[i + 1]:
                    best[i] = best[i + 1]
        cover = best[0] / n if n else 0.0
        if longest < 5:
            longest = 0
        method = 0
        for m in METHOD:
            if m in s:
                method += s.count(m)
        # longest stretch made entirely of common words
        cpre, common = self.cpre, self.common
        f = [0] * (n + 1)
        run = 0
        for i in range(n - 2, -1, -1):
            b = 0
            L = 2
            while i + L <= n:
                w = s[i:i + L]
                if w not in cpre:
                    break
                if w in common and L + f[i + L] > b:
                    b = L + f[i + L]
                L += 1
            f[i] = b
            if b > run:
                run = b
        return qmean, qwin, cover, longest, method, run


def all_stats(scorer, sections, specs):
    """array of len(specs) * 2 * NS: forwards then backwards for each spec."""
    bases = [b for _, b in base_strings(sections)]
    out = array("d")
    st = scorer.stats
    for _, bi, kind, arg in specs:
        r = reading(bases[bi], kind, arg)
        out.extend(st(r))
        out.extend(st(r[::-1]))
    return out


def readings_text(sections, specs):
    bases = [b for _, b in base_strings(sections)]
    out = []
    for label, bi, kind, arg in specs:
        r = reading(bases[bi], kind, arg)
        out.append((label, r))
        out.append((label + " (backwards)", r[::-1]))
    return out


# --------------------------------------------------------------------------- workers
#
# Each text gets six "channels", each the largest value over all readings:
#   0 qmean-z   the whole reading's quadgram mean as a z-score against the reference controls
#   1 qwin-z    the best 20-letter window as a z-score
#   2 qwin      the best 20-letter window, raw (readings of 20+ letters): is there an English
#               stretch anywhere, in any reading?
#   3 cover     word coverage, raw (readings of 20+ letters)
#   4 longest   longest dictionary word of 5+ letters, raw
#   5 method    method-word count, raw
#   6 wordrun   longest stretch that splits wholly into common English words (2,000 most frequent
#               plus the method and compass words), raw
# z-scores need the reference controls; the raw channels do not.

CHANNELS = ("qmean-z", "qwin-z", "qwin", "cover", "longest", "method", "wordrun")
NC = len(CHANNELS)
LONG = 20


FAMILIES = ("word", "letter", "rows")


def eligible(sections, specs):
    """Per reading: does it have LONG+ letters in this text (for the raw qwin and cover channels)."""
    return [len(r) >= LONG for _, r in readings_text(sections, specs)]


def families(specs):
    """Per reading: 0 = letters picked from words (acrostics), 1 = letters of the running text,
    2 = the plaintext laid under the carved rows."""
    out = []
    for label, bi, kind, arg in specs:
        if label.startswith("carved rows"):
            f = 2
        elif ":letters" in label:
            f = 1
        else:
            f = 0
        out += [f, f]
    return out


_W = {}


def _init(sections, specs, norm, track, elig):
    _W["sc"] = Scorer()
    _W["sections"], _W["specs"] = sections, specs
    _W["norm"], _W["track"], _W["elig"] = norm, track, elig
    _W["fam"] = families(specs)


def _pass1(seeds):
    sc, sec, specs = _W["sc"], _W["sections"], _W["specs"]
    R = len(specs) * 2 * NS
    s1, s2 = array("d", [0.0]) * R, array("d", [0.0]) * R
    for seed in seeds:
        v = all_stats(sc, shuffled_sections(sec, seed), specs)
        for i in range(0, R, NS):
            a, b = v[i], v[i + 1]
            s1[i] += a
            s2[i] += a * a
            s1[i + 1] += b
            s2[i + 1] += b * b
    return len(seeds), s1, s2


def make_norm(s1, s2, m):
    R = len(s1)
    mean, sd = array("d", [0.0]) * R, array("d", [1.0]) * R
    for i in range(R):
        if i % NS < 2:
            mean[i] = s1[i] / m
            var = max(0.0, s2[i] / m - mean[i] ** 2)
            sd[i] = max(math.sqrt(var), SD_FLOOR[i % NS])
    return mean, sd


def chan(norm, elig, r, v):
    """The six channel values of reading r (flat stats v[r*NS:(r+1)*NS])."""
    mean, sd = norm
    i = r * NS
    big = elig[r]
    return ((v[i] - mean[i]) / sd[i], (v[i + 1] - mean[i + 1]) / sd[i + 1],
            v[i + 1] if big else -99.0, v[i + 2] if big else -99.0, v[i + 3], v[i + 4], v[i + 5])


def maxz(v, norm, elig, fam):
    """Per (family, channel), flat index f*NC + k: (largest value over the family's readings, reading)."""
    best = [(-1e9, -1)] * (NC * len(FAMILIES))
    for r in range(len(v) // NS):
        c = chan(norm, elig, r, v)
        o = fam[r] * NC
        for k in range(NC):
            if c[k] > best[o + k][0]:
                best[o + k] = (c[k], r)
    return best


def _pass2(seeds):
    sc, sec, specs = _W["sc"], _W["sections"], _W["specs"]
    out = []
    for seed in seeds:
        v = all_stats(sc, shuffled_sections(sec, seed), specs)
        out.append((seed, maxz(v, _W["norm"], _W["elig"], _W["fam"]),
                    [chan(_W["norm"], _W["elig"], r, v)[k] for r, k in _W["track"]]))
    return out


def run_test(sections, n_ref, n_test, seed0=1, only=None, procs=None, track_per_chan=8, log=print):
    """The whole test on one text. Returns a dict with the text's largest value per channel, the
    controls' largest values, p-values, and the top readings."""
    specs = build_specs(sections, only=only)
    R = len(specs) * 2 * NS
    log("  %d reading rules x 2 directions = %d readings" % (len(specs), len(specs) * 2))
    elig = eligible(sections, specs)
    ref = list(range(seed0, seed0 + n_ref))
    test = list(range(seed0 + n_ref, seed0 + n_ref + n_test))
    np_ = procs or 12
    s1, s2, m = array("d", [0.0]) * R, array("d", [0.0]) * R, 0
    for k, a, b in pmap(_pass1, ref, _init, (sections, specs, None, [], elig), chunk=max(1, n_ref // (np_ * 2)),
                        procs=procs):
        m += k
        for i in range(R):
            s1[i] += a[i]
            s2[i] += b[i]
    norm = make_norm(s1, s2, m)
    sc = Scorer()
    real = all_stats(sc, sections, specs)
    fam = families(specs)
    real_max = maxz(real, norm, elig, fam)
    nr = R // NS
    real_ch = [chan(norm, elig, r, real) for r in range(nr)]
    track = []
    for f in range(len(FAMILIES)):
        for k in range(NC):
            best = sorted(((real_ch[r][k], r) for r in range(nr) if fam[r] == f), reverse=True)[:track_per_chan]
            track += [(r, k) for _, r in best]
    ctrl = []
    for res in pmap(_pass2, test, _init, (sections, specs, norm, track, elig), chunk=max(1, n_test // (np_ * 3)),
                    procs=procs):
        ctrl.extend(res)
    ctrl.sort()
    N = len(ctrl)
    NK = NC * len(FAMILIES)
    per = []
    for k in range(NK):
        cz = sorted(c[1][k][0] for c in ctrl)
        ge = sum(1 for z in cz if z >= real_max[k][0] - 1e-12)
        per.append({"channel": "%s:%s" % (FAMILIES[k // NC], CHANNELS[k % NC]), "real": real_max[k][0],
                    "reading": real_max[k][1], "ctrl_min": cz[0], "ctrl_median": cz[N // 2], "ctrl_max": cz[-1],
                    "ge": ge, "p": (1 + ge) / (N + 1)})
    # one combined statistic. A maximum over many readings follows a Gumbel law, so each
    # (family, channel)'s maximum is turned into a tail probability under a Gumbel fitted (by
    # moments) to the controls' maxima; the statistic is -log10 of the smallest of the 21 tail
    # probabilities. (A first version standardised by mean and sd; heavy-tailed channels then let
    # one control in 1,000 beat planted 3.) The p-value still comes from the test controls' ranks.
    mean_ = [sum(c[1][k][0] for c in ctrl) / N for k in range(NK)]
    sdv = [math.sqrt(sum((c[1][k][0] - mean_[k]) ** 2 for c in ctrl) / N) for k in range(NK)]
    use = [k for k in range(NK) if sdv[k] > 1e-6]
    beta = [sdv[k] * math.sqrt(6) / math.pi for k in range(NK)]
    mu = [mean_[k] - 0.5772156649 * beta[k] for k in range(NK)]

    def tail(k, x):
        if k not in use:
            return 0.0
        e = -(x - mu[k]) / beta[k]
        if e > 50:
            return 0.0
        t = math.exp(e)
        p = -math.expm1(-t) if t > 1e-12 else t
        return -math.log10(max(p, 1e-300))

    sdv = beta

    def comb(mz):
        return max(tail(k, mz[k][0]) for k in use)

    real_comb = comb(real_max)
    ctrl_comb = sorted(comb(c[1]) for c in ctrl)
    ge = sum(1 for z in ctrl_comb if z >= real_comb - 1e-12)
    tracked = []
    for j, (r, k) in enumerate(track):
        cv = [c[2][j] for c in ctrl]
        val = real_ch[r][k]
        g = sum(1 for x in cv if x >= val - 1e-12)
        kk = fam[r] * NC + k
        std = tail(kk, val) if kk in use else -1e9
        tracked.append({"reading": r, "channel": "%s:%s" % (FAMILIES[fam[r]], CHANNELS[k]), "value": val,
                        "std": std, "ctrl_ge": g,
                        "p_single": (1 + g) / (N + 1)})
    tracked.sort(key=lambda t: -t["std"])
    return {"specs": specs, "n_readings": nr, "n_channels": NK, "n_ref": m, "n_test": N,
            "per_channel": per, "real_comb": real_comb, "ctrl_comb_max": ctrl_comb[-1],
            "ctrl_comb_median": ctrl_comb[N // 2], "comb_ge": ge, "p_comb": (1 + ge) / (N + 1),
            "top": tracked, "real": real,
            "ctrl_maxima": [[round(c[1][k][0], 4) for k in range(NK)] for c in ctrl],
            "real_maxima": [round(real_max[k][0], 4) for k in range(NK)],
            "gumbel": [(round(mu[k], 4), round(beta[k], 4)) for k in range(NK)]}


def describe(sections, specs, r):
    """(label, reading text) for reading number r (2 per spec: forwards, backwards)."""
    sp, back = divmod(r, 2)
    label, bi, kind, arg = specs[sp]
    bases = [b for _, b in base_strings(sections)]
    t = reading(bases[bi], kind, arg)
    if back:
        t, label = t[::-1], label + " (backwards)"
    return label, t


# --------------------------------------------------------------------------- planted texts

PLANTS = (
    # (message, section, pick, skip, first word index inside the section)
    ("SHIFTEACHROWBYTHEKEY", "K2", 1, 1, 30),
    ("ADDTHECLOCKTIMETOROW", "K3", 1, 3, 10),
    ("READLAYERTWOEASTWARD", "K2", 2, 1, 40),
)
FILLER = ("SOME ZONE ZERO QUIET QUITE JUST JOIN VERY VAST YEAR YOUNG KEEP KIND EVEN EVER UNTIL UPON OVER "
          "OPEN NEXT NONE MUCH MOST LONG LATE GOOD GREAT FIND FULL BEST BOTH CAME COME DOWN DAYS HERE HIGH "
          "AWAY ALSO ZEAL EXIT EXTRA AXLE OXEN SWEPT TWIN OWED AWED EWER IZAR AZURE OZONE EYED DYED EDGE IDLE ODDS").split()


def plant(sections, msg, sec, pick, skip, start, rng):
    """A copy of the sections with words of section `sec` replaced so that letter `pick` of every
    `skip`-th word from `start` spells msg. Words come from the K1-K3 vocabulary when one fits."""
    vocab = sorted({w for s in ("K1", "K2", "K3") for w in sections[s]} - set(MARKS) - set(LAYER))
    pool = vocab + FILLER
    out = {s: list(sections[s]) for s in SECTIONS}
    words = out[sec]
    for j, ch in enumerate(msg):
        pos = start + j * skip
        assert pos < len(words), (msg, pos, len(words))
        fit = [w for w in vocab if len(w) >= pick and w[pick - 1] == ch]
        if not fit:
            fit = [w for w in pool if len(w) >= pick and w[pick - 1] == ch]
        words[pos] = rng.choice(fit)
    return out


def plant_rule_hit(sections, specs, i, msg):
    """Does reading i contain the planted message (forwards)?"""
    label, t = describe(sections, specs, i)
    return msg in t
