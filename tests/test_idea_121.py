"""Planted tests for idea 121: linear cipher feedback with free coefficients (order 15, sparse
worksheet lags, plain feedback, a repeating word on top), found from the clue letters alone."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ
from kryptos.idea121_feedback import POS, Plan, all_shapes, encrypt, new_tally, resolve, scan
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import english97

WORDS = ["PALIMPSEST", "ABSCISSA", "SHADOW", "LANTERN", "COMPASS", "TUNNEL"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]


def run(ct, pt, tests, alphas=ALPHAS):
    plan = Plan(ct, {i: pt[i] for i in POS}, tests)
    res = new_tally()
    scan(plan, "(fixed)", AZ, tests, res, fixed_only=True)
    for name, alpha in alphas:
        scan(plan, name, alpha, tests, res)
    return res, plan


def check(rng, rule, setting, test, min_read):
    name, alpha = rng.choice(ALPHAS)
    pt = english97(rng)
    ct = encrypt(pt, rule, alpha, setting, rng)
    res, plan = run(ct, pt, test)
    mine = [h for h in res["hits"] if h[0] == test and h[2] == name and h[4] == setting]
    assert mine, (rule, setting, test)
    assert set((h[2], h[4]) for h in res["hits"]) == {(name, setting)}     # the only survivor
    sc, text, sol, nsol = resolve(plan, mine[0])
    assert all(c == "?" or c == p for c, p in zip(text, pt))
    assert sum(c != "?" for c in text) >= min_read, text


def test_shapes_and_checks():
    sh = all_shapes()
    assert [s.checks for s in sh["A"]] == [8] and sh["A"][0].gchecks == 4
    assert len(sh["B"]) == 126 and min(s.checks for s in sh["B"]) >= 7
    assert [s.checks for s in sh["C"]] == [13, 11, 9, 7, 7]
    assert min(s.checks for s in sh["D"]) == 7


def test_k4_has_no_order_15_feedback_on_a_few_tableaux():
    res, _ = run(K4, CRIBS, "A")
    assert res["hits"] == []


def test_planted_feedback_rules_are_found_and_read():
    rng = random.Random(121)
    check(rng, {"a": {1: 2, 2: 25}}, ("M", "M", "M", 1), "A", 95)                        # double running sum
    check(rng, {"a": {1: 1, 7: 1}, "c": 5}, ("M", "AZ", "M", 1), "A", 90)                # left plus above, 7
    check(rng, {"a": {3: 4, 8: 11, 13: 6}, "c": 2}, ("KR", "M", "AZ", -1), "A", 84)       # lags 3, 8, 13
    check(rng, {"a": {1: 1, 31: 1}}, ("M", "M", "KR", 1), "B", 66)                       # left plus above, 31
    check(rng, {"a": {1: 9, 2: 3}, "b": {1: 7}, "c": 4}, ("M", "M", "M", 1), "C", 95)     # plain and cipher


if __name__ == "__main__":
    _runner.run(globals())
