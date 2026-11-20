"""Idea 143: two-step plain-autokey chains on one hidden alphabet. Planted recovery, the K4 count, and
the two ways a cell is decided (forced collision, verified witness)."""
import random
import _runner  # noqa: F401

from kryptos import K4
from kryptos import idea143_chains as H


def test_chain_counts_match_idea_100():
    assert [len(H.chains(d)) for d in (19, 20, 21, 22)] == [9, 11, 11, 9]
    assert all(j in H.CLUE and h in H.CLUE and i not in H.CLUE for d in H.LAGS for j, i, h in H.chains(d))


def test_planted_lags_20_and_22_are_possible_and_true_alphabet_fits():
    rng = random.Random(7)
    for d in (20, 22):
        for dn in H.DIRS:
            for form in H.FORMS:
                fn, a, b = form
                p = H.plant(rng, d, form, dn)
                assert H.decrypt(p["ct"], p["alpha"], d, a, b, p["E"], dn, p["primer"]) == p["pt"]
                rows = H.chain_rows(p["ct"], d, a, b, dn)
                assert H.satisfies(rows, p["alpha"], a, b, p["E"])            # the true alphabet, true constant
                assert H.witness_ok(p["ct"], p["alpha"], d, a, b, dn, p["E"])
                st, alpha = H.decide(rows)
                assert st == "ok" and H.witness_ok(p["ct"], alpha, d, a, b, dn)


def test_constant_moves_into_the_alphabet():
    rng = random.Random(3)
    p = H.plant(rng, 21, H.FORMS[1], "back")                                  # C = P - K, ab = -1
    rows = H.chain_rows(p["ct"], 21, 1, -1, "back")
    moved = "".join(p["alpha"][(x + p["E"]) % 26] for x in range(26))
    assert H.satisfies(rows, moved)                                           # no constant needed
    p = H.plant(rng, 21, H.FORMS[0], "ahead")                                 # C = P + K, ab = 1
    assert H.satisfies(H.chain_rows(p["ct"], 21, 1, 1, "ahead"), p["alpha"])  # constant never appears


def test_forced_collision_and_wrong_alphabet():
    r1, r2 = [0] * 26, [0] * 26
    r1[0], r1[1], r1[2], r1[3] = 1, 25, 25, 1                                 # A - B - C + D = 0
    r2[0], r2[1], r2[2], r2[4] = 1, 25, 25, 1                                 # A - B - C + E = 0  =>  D = E
    st, why = H.decide([r1, r2])
    assert st == "none" and "D and E" in why
    st, alpha = H.decide([r1])
    assert st == "ok" and H.satisfies([r1], alpha)
    assert not H.satisfies([r1], "ABDCEFGHIJKLMNOPQRSTUVWXYZ")                # 0 - 1 - 3 + 2 != 0
    assert not H.satisfies([r1], "AACDEFGHIJKLMNOPQRSTUVWXYZ")                # not an alphabet


def test_k4_cells_all_decided():
    cells = H.cells(K4)
    assert sum(v[0] == "ok" for v in cells.values()) == 14
    assert sum(v[0] == "none" for v in cells.values()) == 18
    assert {k[0] for k, v in cells.items() if v[0] == "ok"} == {19, 20, 21, 22}
    assert all(cells[20, "back", fn][0] == "none" for fn, _, _ in H.FORMS)
    for (d, dn, fn), (st, alpha, _) in cells.items():
        if st == "ok":
            a, b = next((a, b) for n, a, b in H.FORMS if n == fn)
            assert H.witness_ok(K4, alpha, d, a, b, dn)


if __name__ == "__main__":
    _runner.run(globals())
