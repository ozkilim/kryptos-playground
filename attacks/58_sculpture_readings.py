"""Idea 58: the key is the sculpture itself, read some other way ("visual", "ID BY ROWS").

Running keys from the sculpture's text have been tried reading straight along the rows. But
Sanborn's own step is "visual", K3 is a grid read in a different direction, and K2's ending
was once read as "ID BY ROWS". So the key could be the copper read by columns, backwards,
back and forth, along diagonals, or taking every n-th letter.

The clues force 13 + 11 key letters for each cipher type. A key stream that is right must
contain those exact letters, 42 places apart. So we generate every reading and simply look for
them: no scoring, no free settings.

  grids      the cipher panel and the tableau panel as carved (ragged rows, left- or right-aligned),
             both panels side by side, K1-K3 plaintext, the Morse text
  readings   rows, columns, back-and-forth (both), 4 diagonal directions, each also reversed
  skips      every d-th letter for d = 1..60 from every start
  ciphers    Vigenere / Beaufort / variant / reversed (DIANA) table, A-Z or KRYPTOS on each side, key letter named on A-Z
             or KRYPTOS, with any Caesar offset

A full hit is all 24 key letters in place. We also report the best partial count so K4 can be
compared with shuffled controls.

  python attacks/58_sculpture_readings.py
"""
import json
import os
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, load  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR, letters  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
MORSE = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUSHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ"
B1, B2 = list(range(21, 34)), list(range(63, 74))
MAX_SKIP = 6 if SMOKE else 60


def grids():
    lay = json.load(open(DATA_DIR / "sculpture_layout.json"))
    cp, tp = lay["cipher_panel"], lay["tableau_panel"]
    out = {"cipher panel": cp, "tableau panel": tp,
           "both panels side by side": [a + b for a, b in zip(cp, tp)],
           "tableau then cipher side by side": [b + a for a, b in zip(cp, tp)]}
    pts = letters(load("k1")["plaintext"] + load("k2")["plaintext"] + load("k3")["plaintext"])
    for w in (7, 8, 21, 24, 30, 31, 32):
        out["K1-K3 plaintext in rows of %d" % w] = [pts[i:i + w] for i in range(0, len(pts), w)]
    out["morse"] = [MORSE]
    return out


def readings(rows):
    """Yield (name, string) for every way of walking the grid. '?' and gaps are skipped."""
    h, w = len(rows), max(len(r) for r in rows)
    for align in ("left", "right"):
        g = [list(r.ljust(w)) if align == "left" else list(r.rjust(w)) for r in rows]
        if align == "right" and all(len(r) == w for r in rows):
            continue
        walks = {
            "rows": [(r, c) for r in range(h) for c in range(w)],
            "rows back-and-forth": [(r, c if r % 2 == 0 else w - 1 - c) for r in range(h) for c in range(w)],
            "columns": [(r, c) for c in range(w) for r in range(h)],
            "columns back-and-forth": [(r if c % 2 == 0 else h - 1 - r, c) for c in range(w) for r in range(h)],
            "columns right-to-left": [(r, c) for c in range(w - 1, -1, -1) for r in range(h)],
            "diagonals down-right": [(r, d - r) for d in range(h + w - 1) for r in range(h) if 0 <= d - r < w],
            "diagonals down-left": [(r, w - 1 - (d - r)) for d in range(h + w - 1) for r in range(h) if 0 <= d - r < w],
        }
        for name, walk in walks.items():
            s = "".join(g[r][c] for r, c in walk if g[r][c].isalpha())
            yield "%s, %s-aligned" % (name, align), s
            yield "%s, %s-aligned, reversed" % (name, align), s[::-1]


def needles(ct, cribs):
    """{4-gram: [(needle id, offset inside the 97-long key)]} for every cipher view, plus the views."""
    views = []
    for an, a in (("AZ", AZ), ("KR", KRYPTOS_ALPHABET)):
        ia = {c: i for i, c in enumerate(a)}
        for bn, b in (("AZ", AZ), ("KR", KRYPTOS_ALPHABET)):
            ib = {c: i for i, c in enumerate(b)}
            for cn, f in (("vig", lambda c, p: c - p), ("beau", lambda c, p: c + p), ("var", lambda c, p: p - c),
                           ("diana", lambda c, p: -c - p)):
                sh = {i: f(ib[ct[i]], ia[cribs[i]]) % 26 for i in cribs}
                for kn, k in (("AZ", AZ), ("KR", KRYPTOS_ALPHABET)):
                    for off in range(26):
                        views.append(("pt%s/ct%s/%s key on %s+%d" % (an, bn, cn, kn, off),
                                      {i: k[(sh[i] + off) % 26] for i in cribs}))
    index = {}
    for vid, (_, key) in enumerate(views):
        for blk in (B1, B2):
            for i in blk[:-3]:
                index.setdefault("".join(key[j] for j in range(i, i + 4)), []).append((vid, i))
    return views, index


def scan(ct, cribs):
    views, index = needles(ct, cribs)
    best, n_streams, n_letters = (0, None), 0, 0
    for gname, rows in grids().items():
        for rname, s in readings(rows):
            for d in range(1, MAX_SKIP + 1):
                if len(s) // d < 20:
                    break
                for a in range(d):
                    t = s[a::d]
                    n_streams += 1
                    n_letters += len(t)
                    for o in range(len(t) - 3):
                        hits = index.get(t[o:o + 4])
                        if not hits:
                            continue
                        for vid, i in hits:
                            start = o - i          # where key position 0 would sit in this stream
                            key = views[vid][1]
                            m = sum(1 for p, ch in key.items() if 0 <= start + p < len(t) and t[start + p] == ch)
                            if m > best[0]:
                                best = (m, (gname, rname, "every %d from %d" % (d, a), views[vid][0], start))
    return best, n_streams, n_letters, len(views)


def plant(rng):
    """Key = the cipher panel read down the columns, every 3rd letter; Beaufort on KRYPTOS."""
    rows = grids()["cipher panel"]
    s = dict(readings(rows))["columns, left-aligned"][1::3]
    start = rng.randrange(len(s) - 97)
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    a = KRYPTOS_ALPHABET
    ct = "".join(a[(a.index(s[start + i]) - a.index(p)) % 26] for i, p in enumerate(pt))
    return ct, {i: pt[i] for i in CRIBS}


if __name__ == "__main__":
    with Experiment("sculpture read other ways as the key (columns, diagonals, skips)", puzzle="k4",
                    notes="cipher/tableau panels, K1-K3 plaintext grids, Morse; 14-28 walks x skips 1-%d; "
                          "forced key letters searched exactly" % MAX_SKIP, cribs_forced=True) as ex:
        best, ns, nl, nv = scan(K4, CRIBS)
        ex.count(ns * nv)
        print("streams: %d (%d letters), cipher views: %d" % (ns, nl, nv))
        print("K4 best: %d/24 key letters in place  %s" % best)
        ctrl = [scan(shuffled_control(seed), CRIBS)[0][0] for seed in ((1, 2) if SMOKE else (1, 2, 3, 4, 5))]
        print("shuffled K4s best:", ctrl)
        rng = random.Random(2)
        ok = 0
        for _ in range(2):
            ct, cribs = plant(rng)
            b = scan(ct, cribs)[0]
            ok += b[0] == 24
            print("planted (columns, every 3rd, Beaufort KRYPTOS) -> %d/24  %s" % b)
        print("planted recovered: %d/2" % ok)
        print("VERDICT:", "FULL HIT" if best[0] == 24 else
              ("K4 beats controls - inspect" if best[0] > max(ctrl) + 2 else
               "no signal (K4 %d/24; shuffled %s; 24 needed)" % (best[0], ctrl)))
