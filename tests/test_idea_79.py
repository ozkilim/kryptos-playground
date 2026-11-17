"""Planted tests for idea 79: formula mining and the three-keyword join with the gap between the clues off."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea79_gap as G
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import english97

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]
NAMES = {"i", "i^2", "col7", "row7", "col31", "row31", "carved_row", "carved_col", "P[i-1]AZ", "C[i-1]AZ",
         "P[i+1]AZ", "C[i+2]KR"}


def observed(pt, enc, g, rng):
    ct, seen = G.damage(enc, pt, g, rng)
    return ct, {i: seen[i] for i in CRIBS}


def test_regap_undoes_damage():
    rng = random.Random(1)
    for g in (-2, -1, 1, 3):
        pt = english97(rng, 97 + g)
        ct, cribs = observed(pt, pt, g, rng)          # "cipher" = plaintext, so letters can be compared
        assert len(ct) == 97
        text, tc = G.regap(ct, cribs, g)
        assert len(text) == 97 + g
        assert all(pt[i] == c == text[i] for i, c in tc.items())
        assert sorted(tc) == list(range(21, 34)) + list(range(63 + g, 74 + g))


def test_formula_found_only_at_the_right_gap():
    rng = random.Random(79)
    for g in (1, -1):
        pt = english97(rng, 97 + g)
        enc, truth = G.formula_plant(pt, rng)
        ct, cribs = observed(pt, enc, g, rng)
        runs = {t: G.regap(ct, cribs, t) for t in (0, g, -g)}
        res = G.formula_mine(runs, small=True, names=NAMES)
        at = [t for t in runs if any(set(h[1]) == set(truth) and h[3] for h in res[t][1])]
        assert at == [g], (g, at)


def test_formula_k4_clean_on_small_slice():
    runs = {g: G.regap(K4, CRIBS, g) for g in (-1, 1)}
    res = G.formula_mine(runs, small=True, sizes=(0, 1, 2), names=NAMES)
    assert all(n > 0 and not hits for n, hits in res.values())


def test_join_found_only_at_the_right_gap_and_k4_clean():
    rng = random.Random(63)
    for g, key in ((1, "PALIMPSEST"), (-2, "SHADOWS")):
        pt = english97(rng, 97 + g)
        (w1, a1), (w2, a2) = ALPHAS[1], ALPHAS[4]
        ct, cribs = observed(pt, G.join_plant(pt, a1, a2, key), g, rng)
        want = ("vig", w1, w2, len(key))
        hit = G.join_analyse(ct, cribs, g, alphas=ALPHAS, want=want)
        assert hit["found"]
        assert any(key == row[6] for row in hit["worded"])
        row = next(r for r in hit["top"] if r[1:5] == (len(key), "vig", w1, w2))
        # the stretch where the slip could be is left out of the decrypt; the rest must be exact
        safe = [i for i in range(len(pt)) if i < 39 or i > 57 + g]
        assert len(row[5]) == len(pt) and all(row[5][i] in (pt[i], ".") for i in safe)
        assert sum(row[5][i] == pt[i] for i in safe) >= 60
        assert set(row[5][39:58 + g]) == {"."}
        assert not G.join_analyse(ct, cribs, 0, alphas=ALPHAS, want=want)["found"]
    for g in G.GAPS:
        assert G.join_analyse(K4, CRIBS, g, alphas=ALPHAS)["n"] == 0


if __name__ == "__main__":
    _runner.run(globals())
