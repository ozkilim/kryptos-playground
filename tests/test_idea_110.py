"""Planted tests for idea 110: any linear key rule (order 5 with free coefficients, text-fed rules,
arbitrary tables), found from the clue letters without naming the rule."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.idea110_linear import (LAYS_M, Plan, bits, encrypt, in_span2, lay_alphabets, linear_keyfn,
                                    new_tally, poly_keyfn, resolve, scan, system, table_keyfn)
from kryptos.round9 import keyword_alphabet, solve_mod_p
from kryptos.round11 import POS, english97

MOVED = list(range(21, 34)) + list(range(65, 76))
WORDS = ["PALIMPSEST", "ABSCISSA", "BERLIN", "SHADOW", "LANTERN", "COMPASS", "TUNNEL", "ILLUSION"]
ALPHAS = [("(A-Z)", AZ)] + [(w, keyword_alphabet(w)) for w in ["KRYPTOS"] + WORDS]


def run(ct, pt, pos=POS):
    pl, cl = [pt[i] for i in pos], [ct[i] for i in pos]
    plan = Plan(pl, cl, POS)                     # the attack always believes the carved positions
    res = new_tally()
    for name, alpha in ALPHAS:
        scan(plan, name, alpha, res)
    return res, plan


def hit(res, test, name, lay, form):
    return [h for h in res["hits"] if h[0] == test and h[1] == name and h[3] == lay and h[4] == form]


def check(rng, keyfn_maker, test, lay, form, read=True, moved=True):
    name, alpha = rng.choice(ALPHAS[2:])
    pt = english97(rng)
    pa, cb = lay_alphabets(lay, alpha)
    ct, _ = encrypt(pt, pa, cb, form, keyfn_maker(alpha))
    res, plan = run(ct, pt)
    mine = hit(res, test, name, lay, form)
    assert mine, (test, name, lay, form)
    if read:
        r = resolve(mine[0], ct, {i: pt[i] for i in POS}, plan)
        best = max(r["readings"], key=lambda x: sum(c != "?" for c in x[0]))
        assert all(c == "?" or c == p for c, p in zip(best[0], pt)) and sum(c != "?" for c in best[0]) >= 76
        assert best[1] == best[2] == 11            # the run from block 1 reproduces block 2
    if moved:
        res2, _ = run(ct, pt, MOVED)
        assert hit(res2, test, name, lay, form)


def test_mod2_span():
    assert in_span2(0b110, [0b100, 0b010]) == (True, 2)
    assert in_span2(0b001, [0b100, 0b010, 0b110]) == (False, 2)
    assert bits([1, 2, 3, 4, 7]) == 0b10101


def test_k4_has_no_linear_rule_on_the_carved_tableaux():
    res, plan = run(K4, CRIBS)
    assert [h for h in res["hits"] if h[0] in ("A", "A2", "B", "C1", "C2")] == []
    assert plan.neq[5] - 6 == 8 and plan.neq[6] - 5 == 7
    judged = {(f, d): c for f, d, _, _, c in plan.c2}
    assert judged[("plain", 1)] == 10 and judged[("plain", 2)] == 8 and judged[("cipher", 1)] == 8


def test_planted_key_rules_are_found_wherever_the_second_clue_sits():
    rng = random.Random(110)
    nz = lambda: rng.randrange(1, 26)                                       # noqa: E731
    seeds = [rng.randrange(26) for _ in range(6)]
    check(rng, lambda m: poly_keyfn([3, nz(), nz(), 7]), "A", "M/M", "vig")
    check(rng, lambda m: linear_keyfn({"a": [nz(), 0, nz(), 0, 5], "c": 4}, seeds), "A", "M/AZ", "beau")
    check(rng, lambda m: linear_keyfn({"a": [11], "c": 9}, seeds), "A", "AZ/M", "vig")
    # order 4 with a drift is an order-5 rule after taking differences: test A finds it, gap or no gap
    check(rng, lambda m: linear_keyfn({"a": [nz(), 0, 0, 7], "c": 2, "e": 5}, seeds), "A", "KR/M", "beau")
    # order 5 with a drift needs the carved positions
    check(rng, lambda m: linear_keyfn({"a": [nz(), 0, nz(), 0, 3], "c": 2, "e": 5}, seeds), "A2", "M/KR", "vig",
          moved=False)


def test_planted_text_fed_rules():
    rng = random.Random(111)
    seeds = [rng.randrange(26) for _ in range(6)]
    for s, t, n_p, n_c, lay, form in ((3, 5, "M", "AZ", "M/M", "vig"), (1, 1, "KR", "M", "M/AZ", "beau"),
                                      (6, 2, "AZ", "KR", "AZ/M", "vig"), (2, 4, "M", "M", "KR/M", "beau")):
        def maker(m, s=s, t=t, n_p=n_p, n_c=n_c):
            num = {"M": m, "AZ": AZ, "KR": KRYPTOS_ALPHABET}
            return linear_keyfn({"a": [rng.randrange(1, 26), rng.randrange(1, 26)], "u": rng.randrange(1, 26),
                                 "v": rng.randrange(1, 26), "s": s, "t": t, "c": rng.randrange(26)}, seeds,
                                {c: i for i, c in enumerate(num[n_p])}, {c: i for i, c in enumerate(num[n_c])})
        check(rng, maker, "B", lay, form)


def test_text_fed_shortcut_agrees_with_the_plain_solve():
    """The bit-mask filter of test B must pass exactly the settings a direct mod 2 solve passes."""
    rng = random.Random(7)
    total = 0
    for _ in range(4):
        pt = english97(rng)
        ct = "".join(rng.choice(AZ) for _ in pt)
        pl, cl = [pt[i] for i in POS], [ct[i] for i in POS]
        plan = Plan(pl, cl, POS)
        for name, alpha in ALPHAS[2:5]:
            res = new_tally()
            scan(plan, name, alpha, res)
            im = {c: i for i, c in enumerate(alpha)}
            xp = [[im[c] for c in pl], plan.xp[1], plan.xp[2]]
            xc = [[im[c] for c in cl], plan.xc[1], plan.xc[2]]
            slow = 0
            for _, na, nb in LAYS_M:
                k = [(y - x) % 26 for x, y in zip(xp[na], xc[nb])]
                for s, n_p, t, n_c in plan.b_settings():
                    rows, rhs = system(plan, k, 2, xp[n_p], s, xc[n_c], t)
                    slow += solve_mod_p(rows, rhs, 2) is not None
            assert res["B_mod2"] == 2 * slow
            total += slow
    assert total > 0


def test_planted_tables():
    rng = random.Random(112)
    for kind, test, lay, form in (("key", "C1", "M/M", "beau"), ("plain", "C2", "M/AZ", "vig"),
                                  ("cipher", "C2", "KR/M", "vig")):
        for _ in range(200):                      # redraw until the clues hold 7 forced repeats
            name, alpha = rng.choice(ALPHAS[2:])
            pt = english97(rng)
            g = [rng.randrange(26) for _ in range(26)] if kind == "key" else {c: rng.randrange(26) for c in AZ}
            pa, cb = lay_alphabets(lay, alpha)
            ct, _ = encrypt(pt, pa, cb, form, table_keyfn(kind, 1, g, [rng.randrange(26)]))
            res, plan = run(ct, pt)
            mine = hit(res, test, name, lay, form)
            if mine:
                break
        assert mine
        r = resolve(mine[0], ct, {i: pt[i] for i in POS}, plan)
        assert all(c == "?" or c == p for c, p in zip(r["text"], pt))
        # a table of the plain letter may stop at once (the next letter's entry is not in the clues)
        assert kind == "plain" or sum(c != "?" for c in r["text"]) > 24


if __name__ == "__main__":
    _runner.run(globals())
