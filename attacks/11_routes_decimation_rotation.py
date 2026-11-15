"""Idea 11: non-columnar transpositions x EVERY key model.

97 is prime, so "take every a-th letter" (decimation, j = a*i + b mod 97)
gives 9,312 clean scrambles. Plus routes on padded grids (columns, snakes,
spirals, diagonals, each also reversed) and K3's own double rotation on text
padded to 98-104 letters. Each with periodic, progressive, autokey and
digit/small-shift keys, before or after.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos.campaign import run_stack_idea  # noqa: E402

def jobs():
    out = [("decimation", a) for a in range(1, 97)]
    for rows in range(2, 53):
        for cols in range(2, 53):
            if 97 <= rows * cols <= 104:
                out.append(("route", rows, cols))
    for pad in range(98, 105):
        for w1 in range(2, pad):
            for w2 in range(2, pad):
                if pad % w1 == 0 and pad % w2 == 0:
                    out.append(("rotation", pad, w1, w2))
    return out

if __name__ == "__main__":
    run_stack_idea("11", "decimation+routes+rotations x all key models", jobs(),
                   {"periodic", "progressive", "ctauto", "ptauto", "shift"},
                   notes="decimation (all a,b mod 97), grid routes 97-104 cells (6 routes x flip), K3 double rotation padded 98-104; "
                         "periodic<=26, progressive, ct/pt autokey<=60, shifts; before/after; AZ+KRYPTOS",
                   n_controls=2)
