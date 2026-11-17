"""Planted test for idea 103: pair ciphers (two-square, four-square) on 26- and 27-cell rectangles."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea103_matrix as M
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import english97

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS", "ILLUSION",
         "KRYPTOS", "LANGLEY", "CHECKPOINT"]
ALPHAS = [keyword_alphabet(w) for w in WORDS] + [M.AZ]
ITEMS = list(enumerate(ALPHAS))


def _message(rng):
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


def _square(word, grid, cfg):
    return M.cells(keyword_alphabet(word), grid, cfg)


def _two_square_hits(ct, cribs):
    plan = M.Plan(ct[1:], cribs)
    h2, h4 = M.scan(plan, ITEMS)
    out = []
    for gi, lid, a, b in M.join2(h2):
        g = M.GRIDS[gi]
        w, o, order, _ = plan.ts[lid]
        s1, s2 = M.cells(ALPHAS[a[4]], g, plan.cfgs[g][a[5]]), M.cells(ALPHAS[b[4]], g, plan.cfgs[g][b[5]])
        out.append((g, w, o, order, s1, s2, M.two_square(ct, w, o, g, s1, s2, order, decrypt=True)[0]))
    return out


def test_two_square_side_by_side_2x13_found_and_read():
    g = (2, 13)
    s1, s2 = _square("PALIMPSEST", g, ("rows", "")), _square("SHADOW", g, ("cols", ""))
    pt = _message(random.Random(1))
    ct, _ = M.two_square(pt, 1, 0, g, s1, s2, "A")
    hits = _two_square_hits(ct, CRIBS)
    assert (g, 1, 0, "A", s1, s2, "?" + pt) in hits
    assert all(h[6] == "?" + pt for h in hits)


def test_one_above_the_other_is_side_by_side_turned():
    g, t = (2, 13), (13, 2)
    top, bottom = _square("LODESTONE", g, ("rows", "")), _square("COMPASS", g, ("cols", ""))
    pt = _message(random.Random(2))
    ct, _ = M.vertical_encrypt(pt, 1, 1, g, top, bottom)
    assert ct == M.two_square(pt, 1, 1, t, M.transpose(top, g), M.transpose(bottom, g), "B")[0]
    assert M.transpose(top, g) == _square("LODESTONE", t, ("cols", ""))
    hits = _two_square_hits(ct, CRIBS)
    assert any(h[:4] == (t, 1, 1, "B") and h[6] == "?" + pt for h in hits)


def test_four_square_3x9_with_question_mark_found_and_read():
    g = (3, 9)
    ps = dict(M.plain_squares(g))
    p1, p2 = ps["KR+?last"], ps["AZ+?first"]
    q1, q2 = _square("BERLIN", g, ("rows", "last")), _square("ILLUSION", g, ("cols", "first"))
    rng = random.Random(3)
    while True:
        pt = _message(rng)
        ct, _ = M.four_square(pt, 1, 1, g, p1, p2, q1, q2, "A")
        if "?" not in ct[1:]:
            break
    plan = M.Plan(ct[1:], CRIBS)
    _, h4 = M.scan(plan, ITEMS)
    found = []
    for sid, a, b in M.join4(h4):
        w, o, gg, n1, n2, order, _, _ = plan.fs[sid]
        c1, c2 = M.cells(ALPHAS[a[2]], gg, plan.cfgs[gg][a[4]]), M.cells(ALPHAS[b[2]], gg, plan.cfgs[gg][b[4]])
        found.append((w, o, gg, n1, n2, order, c1, c2))
    assert found == [(1, 1, g, "KR+?last", "AZ+?first", "A", q1, q2)]
    assert M.four_square(ct, 1, 1, g, p1, p2, q1, q2, "A", decrypt=True)[0] == "?" + pt


def test_no_key_tests_never_reject_a_true_message():
    rng = random.Random(4)
    for _ in range(150):
        g = rng.choice(M.GRIDS)
        w = rng.randrange(1, 49)
        o, order = rng.randrange(2 * w), rng.choice("AB")
        s1, s2 = (M.cells("".join(rng.sample(M.AZ, 26)), g, rng.choice(M.configs(g))) for _ in range(2))
        pt = _message(rng)
        ct, _ = M.two_square(pt, w, o, g, s1, s2, order)
        assert M.two_square(ct, w, o, g, s1, s2, order, decrypt=True)[0] == "?" + pt
        if "?" in ct[1:]:
            continue
        assert M.pair_substitution_ok(ct[1:], CRIBS, w, o)[0]
        assert M.ts_any_square(M.ts_conditions(ct[1:], CRIBS, w, o, order), g)
        ps = M.plain_squares(g)
        p1, p2 = rng.choice(ps)[1], rng.choice(ps)[1]
        ct, _ = M.four_square(pt, w, o, g, p1, p2, s1, s2, order)
        if "?" not in ct[1:]:
            assert M.fs_conditions(ct[1:], CRIBS, w, o, g, p1, p2, order) is not None


def test_k4_facts():
    # Bean's seriated result at width 7: cipher pair BQ would stand for two plain pairs
    assert not M.pair_substitution_ok(K4, CRIBS, 7, 0)[0]
    # ordinary pairs pass Part 1, but no two squares on any of the four grids fit them
    for o in (0, 1):
        assert M.pair_substitution_ok(K4, CRIBS, 1, o)[0]
        for order in "AB":
            conds = M.ts_conditions(K4, CRIBS, 1, o, order)
            assert not any(M.ts_any_square(conds, g) for g in M.GRIDS)
    assert K4[73] == CRIBS[73] == "K"       # a letter that stays: no Playfair on any rectangle


if __name__ == "__main__":
    _runner.run(globals())
