"""Idea 17: double columnar (every order, widths 2-6 on both layers) x the
key models nobody has stacked: progressive, autokey, digit/small-shift.
(Attack 07 did double columnar with periodic keys.)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from itertools import permutations  # noqa: E402
from math import factorial  # noqa: E402
from kryptos.campaign import run_stack_idea  # noqa: E402

def jobs(wmax=6):
    out = []
    for w1 in range(2, wmax + 1):
        for o1 in permutations(range(w1)):
            for w2 in range(2, wmax + 1):
                out.append(("double", o1, w2, 0, factorial(w2)))
    return out

if __name__ == "__main__":
    j = jobs()
    run_stack_idea("17", "double-columnar x progressive/autokey/shift", j,
                   {"progressive", "ctauto", "ptauto", "shift"},
                   notes="double columnar all orders w2-6 x w2-6 + progressive p1-13, ct/pt autokey<=60, shifts; "
                         "key before/after both layers; AZ+KRYPTOS",
                   control_jobs=j[::10])
