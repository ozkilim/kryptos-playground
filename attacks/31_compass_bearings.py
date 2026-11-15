"""Idea 31: read the key off the sculpture along a compass bearing.

EAST NORTHEAST is literally in the clue, the site has a compass rose and a
lodestone, and Sanborn talks about physical/visual steps. Using the exact
carved layout (data/sculpture_layout.json), each K4 letter's key is the
letter found by stepping d places in direction (dx, dy) from it: on the
cipher panel itself, on the tableau panel at the same coordinates, or on the
tableau mirrored. All 48 directions with |dx|,|dy| <= 3 (ENE is about (2,-1)),
distances 1-12, edges either stopping or wrapping round; Vigenere/Beaufort/
variant, A-Z/KRYPTOS. Exact clue test; shuffled-K4 control.
"""
import json
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.cribtools import required_keys  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402


def layout():
    d = json.loads((DATA_DIR / "sculpture_layout.json").read_text())
    cipher = d["cipher_panel"]
    pos = [(r, c) for r, row in enumerate(cipher) for c, ch in enumerate(row)]
    k4_start = len("".join(cipher)) - 97
    k4_pos = pos[k4_start:]
    assert "".join(cipher[r][c] for r, c in k4_pos) == K4
    tab = d["tableau_panel"]
    return {"cipher": cipher, "tableau": tab, "tableau mirrored": [row[::-1] for row in tab]}, k4_pos


def keystreams(panels, k4_pos):
    dirs = [(dx, dy) for dx in range(-3, 4) for dy in range(-3, 4) if (dx, dy) != (0, 0)]
    for pname, grid in panels.items():
        H = len(grid)
        for dx, dy in dirs:
            for d in range(1, 13):
                for wrap in (False, True):
                    ks = []
                    for r, c in k4_pos:
                        rr, cc = r + dy * d, c + dx * d
                        if wrap:
                            rr %= H
                            cc %= len(grid[rr])
                        ok = 0 <= rr < H and 0 <= cc < len(grid[rr]) and grid[rr][cc] != "?"
                        ks.append(grid[rr][cc] if ok else None)
                    yield (pname, dx, dy, d, wrap), ks


def scan(ct, panels, k4_pos):
    best, tested, hits = (0, 0, None), 0, []
    alphas = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
    reqs = {(an, v): required_keys(ct, CRIBS, al, v) for an, al in alphas.items()
            for v in ("vigenere", "beaufort", "variant_beaufort")}
    for cfg, ks in keystreams(panels, k4_pos):
        for (an, v), req in reqs.items():
            idx = {ch: i for i, ch in enumerate(alphas[an])}
            tested += 1
            n = sat = 0
            for i, k in req.items():
                if ks[i] is None:
                    continue
                n += 1
                sat += idx[ks[i]] == k
            if n >= 18 and (sat, -n) > (best[0], -best[1]):
                best = (sat, n, cfg + (an, v))
            if n >= 18 and sat == n:
                hits.append(cfg + (an, v))
    return tested, best, hits


if __name__ == "__main__":
    t0 = time.time()
    panels, k4_pos = layout()
    if SMOKE:
        panels = {"cipher": panels["cipher"]}
    with Experiment("compass-bearing keys across the carved layout", puzzle="k4",
                    notes="key letter = letter d steps along bearing (dx,dy) from each K4 letter on the cipher panel, "
                          "tableau, or mirrored tableau; 48 directions, d 1-12, stop/wrap at edges; vig/beau/varbeau, "
                          "A-Z/KRYPTOS") as ex:
        tested, best, hits = scan(K4, panels, k4_pos)
        ex.count(tested)
        ctrl = [scan(shuffled(K4, 1700 + s), panels, k4_pos)[1][:2] for s in range(2)]
        verdict = (f"HIT: {len(hits)} bearings give every clue letter" if hits else
                   f"dead: best bearing matches {best[0]}/{best[1]} clue letters (shuffled best "
                   f"{max(c[0] for c in ctrl)}/{ctrl[0][1]}); all needed")
        ex.notes += f"; {verdict}"
    report("31", name="compass-bearing keys", hypotheses=tested, best=[best[0], best[1], str(best[2])],
           survivors=len(hits), hits=[str(h) for h in hits[:10]], control=ctrl, verdict=verdict,
           minutes=round((time.time() - t0) / 60, 1))
    print("[31]", verdict)
