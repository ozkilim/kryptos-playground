"""Planted tests for idea 104: two stacked keys at the length pairs the old pre-filter dropped, and
autokey / progressive keys numbered on A-Z or KRYPTOS instead of on the keyword alphabet. The loop
test must agree with attack 66's exact mod-13 / mod-2 solve, the dropped pairs must be the 20 the
idea-91 audit named, and planted messages (textbook encryptors of idea 91) must be found and read."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea104_holes as H
from kryptos import idea91_audit as audit
from kryptos.round9 import shuffled_control
from kryptos.round11 import POS, dictionary_alphabets

DROPPED = [(3, 11), (3, 13), (4, 11), (4, 13), (5, 9), (5, 11), (5, 12), (5, 13), (6, 9), (6, 10), (6, 11), (6, 13),
           (7, 8), (7, 9), (7, 10), (7, 11), (8, 9), (8, 10), (8, 12), (9, 12)]
ALPHAS = dictionary_alphabets(mixed=True)[:40]


def test_dropped_pairs_are_the_twenty_of_idea_91():
    rows = H.pairs(POS)
    assert len(rows) == 41
    assert [(p, q) for p, q, g, old in rows if not old] == DROPPED


def test_loop_test_equals_the_exact_linear_solve():
    exact = audit.attack("66")._stacked_exact
    rng = random.Random(104)
    fits = 0
    for p in range(2, 13):
        for q in range(p + 1, 14):
            if q % p == 0:
                continue
            g = H.Graph(POS, p, q)
            a, b = [rng.randrange(26) for _ in range(p)], [rng.randrange(26) for _ in range(q)]
            true = [(a[i % p] + b[i % q]) % 26 for i in POS]
            assert g.fits(true) and exact(true, p, q) == g.n_checks
            for _ in range(3):                      # one key value changed, and plain noise
                k = list(true)
                k[rng.randrange(24)] = (k[rng.randrange(24)] + rng.randrange(1, 26)) % 26
                assert g.fits(k) == (exact(k, p, q) >= 0)
                fits += g.fits(k)
                k = [rng.randrange(26) for _ in range(24)]
                assert g.fits(k) == (exact(k, p, q) >= 0)
    assert fits                                     # some changed keys still fit (letter put back, or unchecked)


def _found(kind, seed):
    rng = random.Random(seed)
    ct, cribs, name, m, want, pt = H.plant(kind, rng, ALPHAS)
    H.init(ct, cribs)
    mine = [h for h in H.work(ALPHAS) if h[1] == name and h[2:6] == want]
    assert mine, (kind, want)
    text = H.read(mine[0], m, ct, cribs)
    wrong = sum(x != y and x != "?" for x, y in zip(text, pt))
    assert wrong <= (kind == "drop"), (kind, text, pt)
    return sum(x == y for x, y in zip(text, pt))


def test_planted_stacked_pairs_are_found_and_read():
    assert _found("stacked", 1) == 97 and _found("stacked", 2) == 97
    assert _found("stacked long", 3) > 60


def test_planted_autokey_and_progressive_numbered_off_the_tableau():
    for kind in ("autokey cipher strip", "autokey A-Z label", "autokey plain strip", "progressive A-Z order"):
        assert _found(kind, 4) >= 90, kind


def test_planted_variants():
    for kind in ("gap", "mod", "multiplier", "drop", "breaks"):
        _found(kind, 5)


def test_idea_91_stacked_map_is_now_complete():
    judged = [r for r in H.audit_stacked_map(7) if r[2] >= 7]
    assert len(judged) == 41 and all(r[3] == 2 for r in judged)


def test_idea_91_hole_cells_are_found():
    # one message each: stacked keys on M/M, autokey on the cipher strip of M/AZ, the three A-Z label cells
    recs = H.audit_cells(1, pick=(10, 21, 70, 71, 72))
    assert [r["status"] for r in recs] == ["found"] * 5, [(r["model"], r["status"]) for r in recs]


def test_k4_and_a_shuffled_k4_give_nothing_on_a_few_alphabets():
    for ct in (K4, shuffled_control(1)):
        H.init(ct, CRIBS)
        assert H.work(ALPHAS) == []


if __name__ == "__main__":
    _runner.run(globals())
