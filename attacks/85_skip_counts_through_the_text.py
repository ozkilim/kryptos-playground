"""Idea 85: each K4 letter is a distance to count on through the sculpture's own text.

Sanborn: no particular book is needed, "just to be able to read"; "who says it is even a math
solution?"; the earlier passages hold clues for the fourth. A reading method fits all three. The
solver holds a text T that is already on the sculpture and a pointer into it. Each K4 letter is a
number (A=1 .. Z=26). Count that many letters on, and the letter you land on is the plaintext.
The encoder may choose which occurrence of a letter to use, which flattens the letter counts and
lets a letter stand for itself. Every earlier test added the cipher letter to a key; none used it
as a distance.

Two rules, both read every one of the 97 letters once the text and the start are fixed:

  A (moving window)  P_i = T[s + a*i + d(C_i)]            the window moves on a letters each time
  B (walk)           q_i = q_(i-1) + a + d(C_i), P_i = T[q_i]   the pointer walks; a = 1 is A=1..Z=26

  texts      K1, K2 (as carved / corrected), K3 plaintext, K1-K3 joined, K1-K3 ciphertext, the whole
             cipher panel (with and without the '?' cells), the tableau panel (with and without its
             header rows and label column), the Morse text, both panels joined; plus the two panels
             read by columns, back-and-forth and along diagonals. Each forwards and backwards, as a
             ring and as a line.
  numbering  d = place of the letter in A-Z or in the KRYPTOS alphabet, counted forwards or
             backwards. Numbering from 0 or from 1 is the same as moving the start (rule A) or as
             a = 0 or 1 (rule B).
  settings   every start s, every advance a = 0..31 (the backwards texts give a = -31..-1)

For every setting we count how many of the 24 clue letters come out right. A hit is 24 of 24, and
then the other 73 letters must read as English. Chance is about 1.6 of 24 per setting.

Also here: can a message be encoded this way at all (often not, on prose with rule A), and what
index of coincidence the method gives when the encoder takes the nearest occurrence or a random one
(K4 has 0.0361).

  python attacks/85_skip_counts_through_the_text.py
"""
import json
import random
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, load  # noqa: E402
from kryptos import fingerprint as FP  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR, letters  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, pmap  # noqa: E402
from kryptos.score import ioc, quadgram_score, word_coverage  # noqa: E402

MORSE = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUSHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ"
ALPHAS = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
A_MAX = 31
KEEP = 9                      # settings with this many clue letters are kept for a full reading
N = 97
_S = {}


def _walks(rows):
    """The grid read by columns, back-and-forth and along diagonals ('?' cells and gaps skipped)."""
    h, w = len(rows), max(len(r) for r in rows)
    for align in ("left", "right"):
        g = [r.ljust(w) if align == "left" else r.rjust(w) for r in rows]
        walks = {
            "rows back-and-forth": [(r, c if r % 2 == 0 else w - 1 - c) for r in range(h) for c in range(w)],
            "columns": [(r, c) for c in range(w) for r in range(h)],
            "columns back-and-forth": [(r if c % 2 == 0 else h - 1 - r, c) for c in range(w) for r in range(h)],
            "columns right-to-left": [(r, c) for c in range(w - 1, -1, -1) for r in range(h)],
            "diagonals down-right": [(r, d - r) for d in range(h + w - 1) for r in range(h) if 0 <= d - r < w],
            "diagonals down-left": [(r, w - 1 - (d - r)) for d in range(h + w - 1) for r in range(h) if 0 <= d - r < w],
        }
        for name, walk in walks.items():
            yield "%s, %s-aligned" % (name, align), "".join(g[r][c] for r, c in walk if g[r][c].isalpha())


def texts(extra=None):
    """[(name, text)]. A '?' in a text is a cell the pointer can land on; it matches no letter."""
    extra = (not SMOKE) if extra is None else extra
    lay = json.load(open(DATA_DIR / "sculpture_layout.json"))
    cp, tp = lay["cipher_panel"], lay["tableau_panel"]
    k1, k2, k3 = load("k1"), load("k2"), load("k3")
    p1, p2, p2c, p3 = (letters(x) for x in (k1["plaintext"], k2["plaintext"], k2["plaintext_corrected"], k3["plaintext"]))
    c123 = letters(k1["ciphertext"] + k2["ciphertext"] + k3["ciphertext"])
    panel, tab = letters("".join(cp)), "".join(tp)
    out = [("K1 plaintext", p1), ("K2 plaintext as carved", p2), ("K2 plaintext corrected", p2c),
           ("K3 plaintext", p3), ("K1-K3 plaintext as carved", p1 + p2 + p3),
           ("K1-K3 plaintext corrected", p1 + p2c + p3),
           ("K1-K3 plaintext with ? kept", "".join(ch for ch in k1["plaintext"] + k2["plaintext"] + k3["plaintext"] + "?"
                                                   if ch.isalpha() or ch == "?")),
           ("K1-K3 ciphertext", c123), ("cipher panel", panel), ("cipher panel with ? cells", "".join(cp)),
           ("tableau panel by rows", tab), ("tableau body (26 rows, no labels)", "".join(r[1:] for r in tp[1:-1])),
           ("tableau body with labels", "".join(tp[1:-1])), ("Morse text", MORSE),
           ("cipher panel then tableau panel", panel + tab), ("tableau panel then cipher panel", tab + panel),
           ("K1-K3 plaintext then K4", p1 + p2 + p3 + K4)]
    if extra:
        for gname, rows in (("cipher panel", cp), ("tableau panel", tp)):
            out += [("%s: %s" % (gname, n), s) for n, s in _walks(rows)]
    seen, uniq = set(), []
    for name, s in out:
        if s not in seen and s[::-1] not in seen:
            seen.add(s)
            uniq.append((name, s))
    return uniq


def values(ct, rule, alpha):
    d = [alpha.index(c) for c in ct]
    if rule == "A":
        return d
    out, t = [], 0
    for x in d:
        t += x
        out.append(t)
    return out


def read(ct, text, rule, an, sgn, a, s, ring=True):
    """The full reading for one setting ('?' where the pointer leaves a line text or hits a '?')."""
    v, L, out = values(ct, rule, ALPHAS[an]), len(text), []
    for i in range(len(ct)):
        j = s + a * i + sgn * v[i]
        out.append(text[j % L] if ring or 0 <= j < L else "?")
    return "".join(out)


def init(ct, cribs, tlist):
    _S["ct"], _S["cribs"], _S["texts"] = ct, cribs, tlist
    _S["v"] = {(r, an): values(ct, r, al) for r in "AB" for an, al in ALPHAS.items()}


def work(jobs):
    cribs = sorted(_S["cribs"].items())
    n, hist, tops = 0, {"A": Counter(), "B": Counter()}, []
    best = {(r, m): (0, None) for r in "AB" for m in ("ring", "line")}
    for ti, rev in jobs:
        name, text = _S["texts"][ti]
        if rev:
            text = text[::-1]
        L = len(text)
        where = {}
        for j, ch in enumerate(text):
            where.setdefault(ch, []).append(j)
        for (rule, an), v in sorted(_S["v"].items()):
            for sgn in (1, -1):
                for a in range(1 if rev else 0, A_MAX + 1):     # backwards with a = 0 repeats forwards
                    offs = [a * i + sgn * v[i] for i in range(N)]
                    cnt = [0] * L
                    for i, p in cribs:
                        o = offs[i]
                        for j in where.get(p, ()):
                            cnt[(j - o) % L] += 1
                    n += L
                    hist[rule].update(cnt)
                    m = max(cnt)
                    tag = (name + (" backwards" if rev else ""), an, sgn, a)
                    if m > best[rule, "ring"][0]:
                        best[rule, "ring"] = (m, tag + (cnt.index(m),))
                    lo, hi = max(0, -min(offs)), min(L - 1, L - 1 - max(offs))       # starts that keep all 97 pointers on the line
                    if hi >= lo:
                        ml = max(cnt[lo:hi + 1])
                        if ml > best[rule, "line"][0]:
                            best[rule, "line"] = (ml, tag + (lo + cnt[lo:hi + 1].index(ml),))
                    if m >= KEEP:
                        tops += [(c, rule, ti, rev, an, sgn, a, s) for s, c in enumerate(cnt) if c >= KEEP]
    return n, hist, best, tops


def search(ct, cribs, tlist=None, procs=None, serial=False):
    tlist = tlist or texts()
    jobs = [(ti, rev) for ti in range(len(tlist)) for rev in (False, True)]
    res = {"n": 0, "hist": {"A": Counter(), "B": Counter()}, "tops": [],
           "best": {(r, m): (0, None) for r in "AB" for m in ("ring", "line")}}
    if serial:
        init(ct, cribs, tlist)
        parts = [work(jobs)]
    else:
        parts = pmap(work, jobs, init, (ct, cribs, tlist), chunk=1, procs=procs)
    for n, hist, best, tops in parts:
        res["n"] += n
        res["tops"] += tops
        for r in "AB":
            res["hist"][r].update(hist[r])
        for k, b in best.items():
            if (b[0], str(b[1])) > (res["best"][k][0], str(res["best"][k][1])):
                res["best"][k] = b
    res["tops"].sort(reverse=True)
    res["top"] = max(b[0] for b in res["best"].values())
    return res


def encode(pt, text, rule, alpha, a, s, rng, choice="random", ring=True):
    """Encode pt by counting through text; None if some letter cannot be reached.

    choice = 'nearest' takes the first occurrence ahead, 'random' any occurrence within 26.
    Rule B looks ahead so that it never walks into a dead end if a way through exists.
    """
    L, n = len(text), len(pt)

    def at(j):
        return text[j % L] if ring else (text[j] if 0 <= j < L else None)

    pick = (lambda c: c[0]) if choice == "nearest" else rng.choice
    if rule == "A":
        out = []
        for i, p in enumerate(pt):
            c = [d for d in range(26) if at(s + a * i + d) == p]
            if not c:
                return None
            out.append(alpha[pick(c)])
        return "".join(out)
    where = {}
    for j, ch in enumerate(text):
        where.setdefault(ch, []).append(j)
    feas = [None] * n                       # feas[i]: walk totals u (pointer = u + a*i) that can still finish
    for i in range(n - 1, -1, -1):
        c = {(j - a * i) % L if ring else j - a * i for j in where.get(pt[i], ())}
        if i < n - 1:
            nxt = feas[i + 1]
            c = {u for u in c if any(((u + d) % L if ring else u + d) in nxt for d in range(26))}
        feas[i] = c
    u, out = s, []
    for i in range(n):
        c = [d for d in range(26) if ((u + d) % L if ring else u + d) in feas[i]]
        if not c:
            return None
        d = pick(c)
        u = (u + d) % L if ring else u + d
        out.append(alpha[d])
    return "".join(out)


def message(rng, n=N):
    """English that is NOT on the sculpture (Python's own help pages), so nothing lines up by itself."""
    if "eng" not in _S:
        _S["eng"] = FP.english_windows()
    o = rng.randrange(len(_S["eng"]) - n)
    return _S["eng"][o:o + n]


def starts_a(pt, text, a, ring=True):
    """Every start from which rule A can encode pt (each letter must lie in its 26-letter window)."""
    L, ok = len(text), None
    where = {}
    for j, ch in enumerate(text):
        where.setdefault(ch, []).append(j)
    for i, p in enumerate(pt):
        g = {(j - d - a * i) % L if ring else j - d - a * i for j in where.get(p, ()) for d in range(26)}
        ok = g if ok is None else ok & g
        if not ok:
            return []
    return sorted(x for x in ok if 0 <= x < L)


def starts_b(pt, text, a, ring=True):
    """Every start from which rule B can walk the whole of pt."""
    L, n = len(text), len(pt)
    where = {}
    for j, ch in enumerate(text):
        where.setdefault(ch, []).append(j)
    nxt = None
    for i in range(n - 1, -1, -1):
        c = {(j - a * i) % L if ring else j - a * i for j in where.get(pt[i], ())}
        if nxt is not None:
            c = {u for u in c if any(((u + d) % L if ring else u + d) in nxt for d in range(26))}
        if not c:
            return []
        nxt = c
    return sorted({(u - d) % L if ring else u - d for u in nxt for d in range(26) if ring or u - d >= 0})


def reach(pt, text, a):
    """How many letters of pt rule B can walk (ring, best start) before no pointer is left."""
    L = len(text)
    where = {}
    for j, ch in enumerate(text):
        where.setdefault(ch, []).append(j)
    cur = set(where.get(pt[0], ()))
    for i in range(1, len(pt)):
        if not cur:
            return i - 1
        cur = {q for q in where.get(pt[i], ()) if any((q - d - a) % L in cur for d in range(26))}
    return len(pt) if cur else len(pt) - 1


PLANTS = [  # rule, text, backwards, alphabet, advance, choice, ring, where the message comes from
    ("A", "tableau panel by rows", False, "AZ", 31, "random", True, "english"),
    ("A", "tableau body (26 rows, no labels)", True, "KR", 30, "nearest", True, "english"),
    ("A", "tableau panel by rows", False, "KR", 0, "random", False, "english"),
    ("B", "tableau body (26 rows, no labels)", False, "AZ", 10, "random", True, "english"),
    ("B", "tableau panel by rows", False, "KR", 10, "nearest", True, "english"),
    ("B", "K1-K3 plaintext corrected", False, "AZ", 1, "random", True, "the text itself"),
    ("B", "K1-K3 plaintext as carved", False, "KR", 0, "random", False, "the text itself"),
]


def plant(rng, spec, tlist, tries=20000):
    """Encode an English text by the given rule; returns (ct, clue letters, plaintext, start, draws).

    Ordinary English can almost never be walked through the prose texts (see the report), so the
    two K1-K3 plants take their message from K1-K3 itself, which the search does not know.
    """
    rule, tname, rev, an, a, choice, ring, source = spec
    text = dict(tlist)[tname]
    text = text[::-1] if rev else text
    for t in range(1, tries + 1):
        if source == "english":
            pt = message(rng)
        else:
            o = rng.randrange(len(text) - N)
            pt = text[o:o + N]
        if rule == "B" and reach(pt, text, a) < N:
            continue
        ss = (starts_a if rule == "A" else starts_b)(pt, text, a, ring)
        if not ss:
            continue
        s = rng.choice(ss)
        ct = encode(pt, text, rule, ALPHAS[an], a, s, rng, choice, ring)
        if ct:
            return ct, {i: pt[i] for i in CRIBS}, pt, s, t
    raise RuntimeError("could not plant %r" % (spec,))


def check_plant(spec, ct, cribs, pt, s, tlist, serial=False):
    """Search a planted ciphertext; True if 24/24 is found at the planted setting and reads back."""
    rule, tname, rev, an, a, choice, ring, source = spec
    r = search(ct, cribs, tlist, serial=serial)
    ti = [n for n, _ in tlist].index(tname)
    text = tlist[ti][1][::-1] if rev else tlist[ti][1]
    m = r["best"][rule, "ring" if ring else "line"][0]
    hit = (24, rule, ti, rev, an, 1, a, s) in r["tops"]
    return m, sum(t[0] == 24 for t in r["tops"]), m == 24 and hit and read(ct, text, rule, an, 1, a, s, ring) == pt


def encodable(rng, text, trials):
    """(rule A share of (message, start) pairs over a=0..A_MAX, best a and its share;
        rule B share of messages with a=1, median letters walked, best a and its share)."""
    msgs = [message(rng) for _ in range(trials)]
    ea = [sum(len(starts_a(p, text, a)) for p in msgs[:max(10, trials // 4)]) / (max(10, trials // 4) * len(text))
          for a in range(A_MAX + 1)]
    rb = [[reach(p, text, a) for p in msgs] for a in range(A_MAX + 1)]
    eb = [sum(x == N for x in r) / trials for r in rb]
    return (sum(ea) / len(ea), ea.index(max(ea)), max(ea),
            eb[1], sorted(rb[1])[trials // 2], eb.index(max(eb)), max(eb))


def ic_study(rng, text, rule, a, want=200, limit=40000):
    """Index of coincidence of up to `want` encodable English messages, nearest and random choice."""
    out, tries = {"nearest": [], "random": []}, 0
    while len(out["nearest"]) < want and tries < limit:
        tries += 1
        pt = message(rng)
        if rule == "B" and reach(pt, text, a) < N:
            continue
        ss = (starts_a if rule == "A" else starts_b)(pt, text, a)
        if ss:
            s = rng.choice(ss)
            for choice in out:
                out[choice].append(ioc(encode(pt, text, rule, AZ, a, s, rng, choice)))
    return out, tries


def summary(res):
    b = res["best"]
    return "rule A ring %d line %d; rule B ring %d line %d" % (b["A", "ring"][0], b["A", "line"][0],
                                                               b["B", "ring"][0], b["B", "line"][0])


def tail(res, k):
    return sum(c for r in "AB" for m, c in res["hist"][r].items() if m >= k)


if __name__ == "__main__":
    TL = texts()
    with Experiment("cipher letters as skip counts through the sculpture's text (moving window and walk)", puzzle="k4",
                    notes="%d texts x 2 directions x every start x advance 0..%d x A-Z/KRYPTOS numbering x count "
                          "forwards/backwards x rules A (window) and B (walk), ring and line" % (len(TL), A_MAX),
                    cribs_forced=True) as ex:
        print("texts: %d (%d letters in all)" % (len(TL), sum(len(t) for _, t in TL)))
        print("K4 as distances A=1..Z=26: %d letters in all, so a plain walk on a line needs a text that long"
              % sum(AZ.index(c) + 1 for c in K4))
        res = search(K4, CRIBS, TL)
        ex.count(res["n"])
        tot = sum(sum(h.values()) for h in res["hist"].values())
        mean = sum(m * c for h in res["hist"].values() for m, c in h.items()) / tot
        print("settings: %d   mean clue letters per setting: %.2f of 24" % (res["n"], mean))
        print("K4 best clue letters:", summary(res))
        for k, b in sorted(res["best"].items()):
            print("   rule %s %s: %d/24  %s" % (k[0], k[1], b[0], b[1]))
        print("K4 settings with >=9: %d, >=10: %d, >=11: %d, >=12: %d"
              % (tail(res, 9), tail(res, 10), tail(res, 11), tail(res, 12)))
        print("best full readings (clue letters, English score per quadgram, word coverage):")
        full = []
        for c, rule, ti, rev, an, sgn, a, s in res["tops"]:
            name, text = TL[ti]
            pt = read(K4, text[::-1] if rev else text, rule, an, sgn, a, s).replace("?", "X")
            full.append((c, quadgram_score(pt), pt, rule, name + (" backwards" if rev else ""), an, sgn, a, s))
        for c, q, pt, rule, name, an, sgn, a, s in sorted(full, reverse=True)[:6]:
            ex.add(pt, rule=rule, text=name, numbering=an, sign=sgn, advance=a, start=s)
            print("   %d/24  %.2f  %.2f  %s  [rule %s, %s, %s, %+d, a=%d, s=%d]"
                  % (c, q, word_coverage(pt), pt, rule, name, an, sgn, a, s))
        if full:
            c, q, pt = max(full, key=lambda x: x[1])[:3]
            print("   most English-looking of the %d kept (>=%d clue letters): %.2f (%d/24) %s"
                  % (len(full), KEEP, q, c, pt))
            print("   [on this scale English is about -3.7 and random letters about -7.3]")

        ctrl = []
        for seed in ((1, 2) if SMOKE else range(1, 21)):
            r = search(shuffled_control(seed), CRIBS, TL)
            ctrl.append(r)
            print("shuffled K4 #%d: %s; >=9: %d, >=10: %d, >=11: %d, >=12: %d"
                  % (seed, summary(r), tail(r, 9), tail(r, 10), tail(r, 11), tail(r, 12)))
        ctop = [r["top"] for r in ctrl]
        print("shuffled K4s best:", ctop)

        rng = random.Random(85)
        ok = 0
        for spec in PLANTS:
            ct, cribs, pt, s, draws = plant(rng, spec, TL)
            m, n24, good = check_plant(spec, ct, cribs, pt, s, TL)
            ok += good
            print("planted rule %s on %s%s (%s, %s choice, a=%d, message from %s, draw %d): best %d/24, "
                  "%d setting%s at 24, planted setting found and read back: %s"
                  % (spec[0], spec[1], " backwards" if spec[2] else "", "ring" if spec[6] else "line", spec[5], spec[4],
                     spec[7], draws, m, n24, "" if n24 == 1 else "s", "yes" if good else "NO"))
        print("planted recovered: %d/%d" % (ok, len(PLANTS)))

        print("can ordinary English (not from the sculpture) be encoded at all?")
        T = dict(TL)
        trials = 20 if SMOKE else 200
        for tname in ("K1-K3 plaintext corrected", "cipher panel", "tableau panel by rows",
                      "tableau body (26 rows, no labels)"):
            ea, ba, bav, eb, med, bb, bbv = encodable(rng, T[tname], trials)
            print("   %-34s rule A: %.5f of (message, start) pairs over a=0..%d, best a=%d %.3f" % (tname, ea, A_MAX, ba, bav))
            print("   %-34s rule B: a=1 %.3f of %d messages from any start (half die within %d letters), best a=%d %.3f"
                  % ("", eb, trials, med, bb, bbv))
        print("index of coincidence of the method (K4: %.4f; English about 0.066, flat 0.0385)" % ioc(K4))
        want = 20 if SMOKE else 200
        for tname, rule, a in (("tableau panel by rows", "A", 31), ("tableau panel by rows", "A", 0),
                               ("tableau body (26 rows, no labels)", "B", 10), ("tableau panel by rows", "B", 10)):
            v, tries = ic_study(rng, T[tname], rule, a, want)
            for choice in ("nearest", "random"):
                x = v[choice]
                if x:
                    print("   rule %s on %-34s a=%-2d %-7s choice: mean %.4f, lowest %.4f, at or below K4: %d of %d "
                          "(from %d messages)" % (rule, tname, a, choice, sum(x) / len(x), min(x),
                                                  sum(y <= ioc(K4) + 1e-9 for y in x), len(x), tries))
                else:
                    print("   rule %s on %-34s a=%-2d: none of %d messages could be encoded" % (rule, tname, a, tries))

        top = res["top"]
        print("VERDICT:", "FULL HIT - read it" if top == 24 else
              ("K4 beats controls - inspect" if top > max(ctop) + 2 else
               "no signal (K4 best %d/24; shuffled %d-%d; 24 needed; planted %d/%d)"
               % (top, min(ctop), max(ctop), ok, len(PLANTS))))
