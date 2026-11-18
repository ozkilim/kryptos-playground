"""Planted tests for idea 118: the fixed copies of the tests of attacks 90, 59, 88, 60C, 61, 69B and 57 must
find the idea-105 plants the old code missed, and K4 must stay clean on the cheap parts."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea118_holes as H
from kryptos import idea90_rowkey as R


def test_attack90_hole_is_exactly_the_eleven_settings():
    t = H.tests90(True)
    got = sorted((x["lag"], p) for x in t.tests for p in x["periods"])
    assert got == [(30, 2), (30, 4)] + [(L, p) for L in (31, 32, 33) for p in (2, 3, 4)], got
    assert all(x["src"] == "cipher" and x["shift"] == 0 for x in t.tests)


def test_attack90_fixed_order_finds_lag_31_word_3():
    from kryptos.round11 import dictionary_alphabets
    alphas = dictionary_alphabets(mixed=False)[:400]
    rng = random.Random(5)
    ct, cribs, want, pt, m = R.plant(rng, alphas[1:], "cipher", 31, 0, 3)
    hits = H.tests90(True).test_alphabet(want[0], m, ct, cribs)
    assert any(h[1:10] == want for h in hits)
    assert not any(h[1:10] == want for h in R.test_alphabet(want[0], m, ct, cribs))   # the old code misses it


def test_attack59_short_lags_and_k4_clean():
    rng = random.Random(9)
    pt = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97))
    pt = pt[:21] + "EASTNORTHEAST" + pt[34:63] + "BERLINCLOCK" + pt[74:]
    A, key, lag = H.ALPH59["AZ"], [3, 11], 44
    ct = []
    for i, ch in enumerate(pt):
        u = A.index(ct[i - lag]) if i >= lag else 0
        ct.append(A[(A.index(ch) + 25 * u + key[i % 2]) % 26])
    ct = "".join(ct)
    _, hits, _ = H.search59(ct, {i: pt[i] for i in CRIBS})
    assert any(h[1:] == ("ptAZ/ctAZ/uAZ", "C", lag, 1, 25, 2) for h in hits)
    assert H.decrypt59(ct, {i: pt[i] for i in CRIBS}, max(hits))[lag:] == pt[lag:]
    assert not H.search59(K4, CRIBS)[1]


def test_plants_of_the_holes_are_found():
    eng = H.english_filler()
    cells = H.plant_cells(full=False)
    names = {(c[0], c[1]) for c in cells}
    assert ("88", "progressive 2+1 6-12") in names and ("57", "KR/M key under A") in names
    for i, (att, name, call, hole) in enumerate(cells):
        if att == "59":                       # covered above (its plants take 2 s each)
            continue
        _, recs = H.run_plant_cell((i, 1, 118, eng, False))
        assert all(r["status"] != "HOLE" for r in recs), (att, name, recs)
        assert any(r["status"] == "found" for r in recs), (att, name, recs)


def test_slidefair_same_column_and_quarter_turn_clockwise():
    assert H.rotate(list(range(6)), 3, True) == [3, 0, 4, 1, 5, 2]
    assert H.rotate(list(range(6)), 3) == [2, 5, 1, 4, 0, 3]
    assert not H.slidefair_fixed(K4, CRIBS)[0]


if __name__ == "__main__":
    _runner.run(globals())
