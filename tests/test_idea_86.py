"""Planted tests for idea 86: any keyword alphabet solved from its alphabetical tail."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.idea86_tail import (Budget, brute_count, climb, encrypt, equations, extra_score, keyword_alphabet,
                                 minimal_keyword, read, solve)
from kryptos.round11 import english97
from kryptos.score import Quadgrams

SMALL = Quadgrams()                      # the small table is enough to rank the readings here


def planted(rng, kw, layout, form, rule, n):
    al = keyword_alphabet(kw)
    pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(english97(rng)))
    return al, pt, encrypt(pt, al, layout, form, rule, [rng.randrange(26) for _ in range(n)])


def test_keyword_alphabet_shape():
    al = keyword_alphabet("PALIMPCEST")
    assert al == "PALIMCESTBDFGHJKNOQRUVWXYZ" and minimal_keyword(al) == "PALIMCEST"
    assert minimal_keyword(keyword_alphabet("ABC")) == "" and minimal_keyword(keyword_alphabet("KRYPTOS")) == "KRYPTOS"


def test_solver_counts_match_brute_force():
    # few equations, so there ARE solutions to count; every listed one must really decrypt the clues
    seen = 0
    for layout, form, rule, n in (("M/M", "beau", "rep", 26), ("M/AZ", "vig", "rep", 26), ("M/M", "vig", "slide", 25),
                                  ("AZ/M", "beau", "rep", 26), ("M/KR", "beau", "slide", 25)):
        eqs, imp = equations(K4, CRIBS, layout, form, rule, n)
        assert not imp
        for m in (1, 2, 3) if layout == "M/M" and rule == "rep" else (1, 2):
            r = solve(eqs, m, list_cap=10 ** 6)
            assert r["count"] == brute_count(eqs, m) == len(set(r["alphas"]))
            assert all(read(al, K4, CRIBS, layout, form, rule, n)[2] for al in r["alphas"][:200])
            seen += r["count"]
    assert seen > 200


def test_planted_keywords_are_listed_and_read_best():
    rng = random.Random(86)
    for kw, layout, form, rule, n in (("SANBORN", "M/M", "beau", "rep", 13), ("SCHEIDT", "M/M", "beau", "rep", 19),
                                      ("QXJMWE", "M/M", "beau", "rep", 23), ("CLOCK", "M/M", "vig", "slide", 7),
                                      ("SCHEIDT", "M/KR", "vig", "rep", 19)):
        al, pt, ct = planted(rng, kw, layout, form, rule, n)
        m = len(minimal_keyword(al))
        eqs, imp = equations(ct, CRIBS, layout, form, rule, n)
        r = solve(eqs, m, list_cap=5000)
        assert not imp and r["count"] <= 5000 and al in r["alphas"]
        best = max(r["alphas"], key=lambda a: extra_score(read(a, ct, CRIBS, layout, form, rule, n)[0], SMALL)[0])
        got = read(best, ct, CRIBS, layout, form, rule, n)[0]
        assert all(g in (".", p) for g, p in zip(got, pt)) and got.count(".") < 40


def test_levels_nest_and_budget_stops_the_climb():
    eqs, imp = equations(K4, CRIBS, "M/M", "beau", "rep", 23)
    rows, done, list_m, alphas = climb(eqs, imp, 9, 10 ** 6, 100)
    counts = [c for _, c, _ in rows]
    assert done == 9 and counts == sorted(counts) and counts[6] == 0 and counts[7] == 3 and counts[8] == 59
    assert list_m == 9 and len(alphas) == 59 and all(len(minimal_keyword(a)) <= 9 for a in alphas)
    try:
        solve(eqs, 9, max_nodes=100)
        assert False
    except Budget:
        pass


def test_k4_fixed_points_kill_the_vigenere_form():
    # K -> K at 73 and S -> S at 32: on one alphabet a key letter of zero cannot also turn E into F
    eqs, imp = equations(K4, CRIBS, "M/M", "vig", "rep", 26)
    assert imp or solve(eqs, 6)["count"] == 0


if __name__ == "__main__":
    _runner.run(globals())
