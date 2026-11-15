"""Idea 35: paper strips cut, reordered and flipped.

Kobek found the K4 plaintext in Sanborn's papers as strips "taped out of
order", and K4 is carved as 4 + 31 + 31 + 31 letters. Hand method: cut the
text into strips, shuffle and/or reverse strips, then encipher (or the
reverse). Strip sets: K4's carved rows (4/31/31/31) and equal-width strips
of every width 5-48. For every strip order (all orders up to 6 strips, plus
reversed and odd/even orders for more) and every flip pattern, x every key
model (periodic, progressive, autokey, small shifts), key before or after.
"""
import sys
import time
from itertools import permutations, product
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos.campaign import SMOKE, run_stack_idea  # noqa: E402

N = 97


def strip_maps(lengths):
    starts = [sum(lengths[:k]) for k in range(len(lengths))]
    m = len(lengths)
    orders = list(permutations(range(m))) if m <= 6 else [tuple(range(m)), tuple(reversed(range(m))),
                                                          tuple(list(range(0, m, 2)) + list(range(1, m, 2)))]
    flips = list(product((False, True), repeat=m)) if m <= 6 else [tuple([False] * m), tuple([True] * m),
                                                                   tuple(k % 2 == 1 for k in range(m))]
    for o in orders:
        for fl in flips:
            seq = []
            for k in o:
                idx = list(range(starts[k], starts[k] + lengths[k]))
                seq += idx[::-1] if fl[k] else idx
            if seq == list(range(N)):
                continue
            mp = [0] * N
            for j, i in enumerate(seq):
                mp[i] = j
            yield (("strips", tuple(lengths), o, fl), mp)


def jobs():
    sets = [[4, 31, 31, 31], [31, 31, 31, 4], [35, 31, 31]]
    for w in range(5, 49):
        q, r = divmod(N, w)
        sets.append([w] * q + ([r] if r else []))
    out = []
    for L in sets[: 3 if SMOKE else None]:
        items = list(strip_maps(L))
        for k in range(0, len(items), 400):
            out.append(("maps", items[k:k + 400]))
    return out


if __name__ == "__main__":
    j = jobs()
    run_stack_idea("35", "paper strips (carved rows, equal widths) x all key models", j,
                   {"periodic", "progressive", "ctauto", "ptauto", "shift"},
                   notes="strips = K4's carved rows (4/31/31/31) or equal widths 5-48; every order (<=6 strips) or "
                         "reversed/odd-even, every flip pattern; periodic<=26, progressive, ct/pt autokey<=60, shifts; "
                         "before/after; A-Z/KRYPTOS", n_controls=1)
