"""Idea 77: the tableau seen through the pierced copper ("SHADOW FORCES", "it's visual").

Kryptos's letters are cut right through the plate. The cipher panel and the tableau panel are
the two halves of one S-shaped sheet, and light throws the letters as shadows. So a physical
key for K4 is the tableau letter that lies behind (or is shadowed onto) each K4 letter.

Round 9 read the panels as text in many directions. That does not cover a true overlay, where
each row of one panel is mirrored (you look at the back of the copper), the panels may be
turned over top to bottom, and a slanting light shifts each row a little further than the last.

For every overlay we read the 24 tableau letters behind the clue letters and count how many
agree with the key letters the clues force, for every cipher form.

  overlays   row offset (any), top-to-bottom flip, mirror, column offset -33..33,
             slant -4..4 cells per row, rows packed left or right on either panel,
             tableau rows wrapping round or not
  ciphers    Vigenere / Beaufort / variant / reversed table, A-Z or KRYPTOS on each side,
             key letter read on A-Z or KRYPTOS, any constant offset

A full hit is 24 of 24.

  python attacks/77_overlay_through_the_copper.py
"""
import json
import random
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, english97, pmap  # noqa: E402

LAY = json.load(open(DATA_DIR / "sculpture_layout.json"))
CP, TP = LAY["cipher_panel"], LAY["tableau_panel"]
WC, WT = max(len(r) for r in CP), max(len(r) for r in TP)
DCS = range(-8, 9) if SMOKE else range(-33, 34)
SLANTS = (-1, 0, 1) if SMOKE else range(-4, 5)
_S = {}


def k4_cells():
    cells = [(r, c) for r, row in enumerate(CP) for c, ch in enumerate(row) if ch.isalpha()][-97:]
    assert "".join(CP[r][c] for r, c in cells) == K4
    return cells


CELLS = k4_cells()
R0 = CELLS[0][0]


def overlay(dr, flip, mirror, dc, slant, ac, at, wrap, positions=POS):
    """Tableau letters behind the K4 letters at `positions`, or None if any falls off the panel."""
    out = []
    for i in positions:
        r, c = CELLS[i]
        x = c if ac == "left" else c + WC - len(CP[r])
        if mirror:
            x = WC - 1 - x
        rt = (len(CP) - 1 - r if flip else r) + dr
        if not 0 <= rt < len(TP):
            return None
        row = TP[rt]
        x = x + dc + slant * (r - R0)
        if at == "right":
            x -= WT - len(row)
        if wrap:
            x %= len(row)
        elif not 0 <= x < len(row):
            return None
        if not row[x].isalpha():
            return None
        out.append(row[x])
    return out


def views(ct, cribs):
    out = []
    for an, a in (("AZ", AZ), ("KR", KRYPTOS_ALPHABET)):
        for bn, b in (("AZ", AZ), ("KR", KRYPTOS_ALPHABET)):
            for fn, f in (("vig", lambda c, p: c - p), ("beau", lambda c, p: c + p), ("var", lambda c, p: p - c),
                          ("reversed", lambda c, p: -c - p)):
                out.append(("pt%s/ct%s %s" % (an, bn, fn), [f(b.index(ct[i]), a.index(cribs[i])) % 26 for i in POS]))
    return out


def row_offsets():
    lo, hi = CELLS[0][0], CELLS[-1][0]
    jobs = [(dr, False) for dr in range(-hi, len(TP) - lo)]
    jobs += [(dr, True) for dr in range(-(len(CP) - 1 - lo), len(TP) - (len(CP) - 1 - hi))]
    return jobs


def init(ct, cribs):
    _S["v"] = views(ct, cribs)


def work(chunk):
    iz = {c: i for i, c in enumerate(AZ)}
    ik = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    best, n = (0, None), 0
    for dr, flip in chunk:
        for mirror in (False, True):
            for dc in DCS:
                for slant in SLANTS:
                    for ac in ("left", "right"):
                        for at in ("left", "right"):
                            for wrap in (False, True):
                                t = overlay(dr, flip, mirror, dc, slant, ac, at, wrap)
                                if t is None:
                                    continue
                                for kn, kx in (("AZ", iz), ("KR", ik)):
                                    tv = [kx[ch] for ch in t]
                                    for vn, sh in _S["v"]:
                                        n += 1
                                        m = Counter((a - b) % 26 for a, b in zip(tv, sh)).most_common(1)[0][1]
                                        if m > best[0]:
                                            best = (m, ("rows %+d%s%s, columns %+d, slant %+d, cipher rows %s, tableau rows %s%s"
                                                        % (dr, " flipped" if flip else "", " mirrored" if mirror else "", dc, slant,
                                                           ac, at, " wrapping" if wrap else ""), vn + ", key on " + kn))
    return n, best


def search(ct, cribs):
    best, n = (0, None), 0
    for c, b in pmap(work, row_offsets(), init, (ct, cribs), chunk=2):
        n += c
        best = max(best, b, key=lambda x: x[0])
    return n, best


def plant(rng):
    """K1-style Vigenere on the KRYPTOS tableau, keyed by a mirrored, slanted overlay."""
    while True:
        dr, flip = rng.choice(row_offsets())
        args = (dr, flip, True, rng.choice(list(DCS)), rng.choice(list(SLANTS)), "left", "right", True)
        key = overlay(*args, positions=range(97))
        if key:
            break
    pt = english97(rng)
    a = KRYPTOS_ALPHABET
    ct = "".join(a[(a.index(p) + a.index(k)) % 26] for p, k in zip(pt, key))
    return ct, {i: pt[i] for i in CRIBS}


if __name__ == "__main__":
    with Experiment("tableau seen through the pierced copper: mirrored, flipped, slanted overlays as the key", puzzle="k4",
                    notes="row offsets x flip x mirror x %d column offsets x %d slants x packing x wrap; 16 cipher forms x "
                          "key on A-Z/KRYPTOS x any offset" % (len(DCS), len(SLANTS)), cribs_forced=True) as ex:
        n, best = search(K4, CRIBS)
        ex.count(n)
        print("overlay x cipher settings: %d" % n)
        print("K4 best: %d/24 key letters in place  %s" % best)
        ctrl = [search(shuffled_control(seed), CRIBS)[1][0] for seed in ((1, 2) if SMOKE else (1, 2, 3, 4, 5))]
        print("shuffled K4s best:", ctrl)
        rng = random.Random(77)
        ok = 0
        for _ in range(3):
            ct, cribs = plant(rng)
            b = search(ct, cribs)[1]
            ok += b[0] == 24
            print("planted overlay key -> %d/24  %s" % b)
        print("planted recovered: %d/3" % ok)
        print("VERDICT:", "FULL HIT" if best[0] == 24 else
              ("K4 beats controls - inspect" if best[0] > max(ctrl) + 2 else
               "no signal (K4 %d/24; shuffled %s; 24 needed)" % (best[0], ctrl)))
