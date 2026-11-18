"""Planted tests for idea 135: cipher-fed state device with one or both sides a keyword alphabet."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea135_fed as D
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import english97
from kryptos.score import Quadgrams

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS", "KRYPTOS",
         "QUARTZ", "HIEROGLYPH", "SANBORN", "SCHEIDT", "WELTZEITUHR", "MAGNETIC", "LANGLEY"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]


def _plant_one_side(rng, m, hidden):
    while True:
        name, a = rng.choice(ALPHAS)
        pt = english97(rng)
        r = D.plant_hidden(rng, pt, m, a, hidden)
        if r is None:
            continue
        cribs = {i: pt[i] for i in CRIBS}
        if D.check_count(r[0], cribs, hidden)[0] >= 7:
            return r[0], cribs, a


def test_k4_check_counts():
    # 8 equations; one side known leaves 13 (A) or 12 (B) unknowns at full rank: no linear check is left
    assert D.check_count(K4, CRIBS, "u") == (8, 13, 8, 0)
    assert D.check_count(K4, CRIBS, "h") == (8, 12, 8, 0)
    assert D.check_count(K4, CRIBS, "") == (8, 0, 0, 8)


def test_one_side_known_planted_fits_and_agrees_with_reference():
    rng = random.Random(5)
    for m, hidden in ((26, "u"), (26, "h"), (29, "u")):
        ct, cribs, a = _plant_one_side(rng, m, hidden)
        fast, ref = D.Eliminated(ct, cribs, hidden), D.Compiled(ct, cribs, hidden)
        idx = {c: i for i, c in enumerate(a)}
        st, sol = fast.run(idx, m)
        assert st == "yes" and fast.check(idx, m, sol)
        for _, b in ALPHAS:                                  # the two exact solvers agree on other alphabets
            jb = {c: i for i, c in enumerate(b)}
            s1, s2 = fast.run(jb, m)[0], ref.run(jb, m)[0]
            assert s2 == "cap" or s1 == s2


def test_both_sides_known_join_finds_and_reads_planted():
    rng = random.Random(11)
    qg = Quadgrams()
    m = 26
    while True:
        (cn, ca), (pn, pa) = rng.sample(ALPHAS, 2)
        pt = english97(rng)
        ct, g, s0, u, h = D.plant(rng, pt, m, ca, pa, sign=-1)
        cribs = {i: pt[i] for i in CRIBS}
        if D.check_count(ct, cribs, "")[0] >= 7:
            break
    up, hp = D.side_vectors(ct, cribs)
    table = {}
    for n, (_, a) in enumerate(ALPHAS):
        table.setdefault(D.encode(D.vector(up, {c: i for i, c in enumerate(a)}, m), m), []).append(n)
    hits = []
    for n, (_, a) in enumerate(ALPHAS):
        hv = D.vector(hp, {c: i for i, c in enumerate(a)}, m)
        for sign in (1, -1):
            hits += [(sign, c, n) for c in table.get(D.encode([-sign * x for x in hv], m), ())]
    assert (-1, ALPHAS.index((cn, ca)), ALPHAS.index((pn, pa))) in hits
    r = D.complete(ct, cribs, m, u, h, qg.logp, qg.floor, width=300, polish=1, order="FAB")
    assert sum(a == b for a, b in zip(r[1], pt)) >= 85


if __name__ == "__main__":
    _runner.run(globals())
