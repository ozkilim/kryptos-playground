"""Idea 159: letter shapes. The three codings must hold the stencil facts the idea rests on; a text masked by
one-stroke changes at every third place with a repeating key elsewhere must be found by both exact tests and
read back; K4 must have 7 near clue pairs in the stroke coding and no surviving setting."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea159_shapes as S
from kryptos.round11 import POS, english97


def test_codings():
    for c in S.NAMES:
        for a, b in ("EF", "RP", "OQ", "IT"):
            assert S.near(c, a, b) and S.near(c, b, a)
        assert not S.near(c, "A", "L") and not S.near(c, "B", "N")
        assert all(S.DIST[c][x + x] == 0 for x in S.AZ)
    assert S.near_pairs("STROKE") == ["BP", "CG", "EF", "IT", "OQ", "PR"]
    pairs = [(CRIBS[i], K4[i]) for i in sorted(CRIBS)]
    assert S.stats(pairs)[0::2] == [7, 8, 7]
    assert S.profile(pairs) == (2, 9, 1, 12)


def test_controls_keep_what_they_should():
    pairs = [(CRIBS[i], K4[i]) for i in sorted(CRIBS)]
    rng = random.Random(1)
    for x in S.null_matched(pairs, rng, 20, thin=20, burn=100):
        assert S.profile(x) == S.profile(pairs)
        assert sorted(c for _, c in x) == sorted(c for _, c in pairs)
    for x in S.null_sign(pairs, rng, 5):
        assert [S.alpha_dist(p, c) for p, c in x] == [S.alpha_dist(p, c) for p, c in pairs]
    ps, corr, _ = S.p_values(S.stats(pairs), [S.stats(x) for x in S.null_permute(pairs, rng, 400)])
    assert min(ps) < 0.05 and corr < 0.1


def test_planted_mask_found_and_read():
    rng = random.Random(159)
    pt = english97(rng)
    ct, want = S.encrypt(pt, rng, coding="STROKE", p=3, classes={1}, L=5, mode="skip")
    cribs = {i: pt[i] for i in POS}
    t, j, sv = S.clue_test(ct, cribs, "STROKE")
    hit = [s for s in sv if s[1:8] == want]
    assert hit and hit[0][0] >= 5
    sc, txt, _ = S.complete(ct, cribs, hit[0])
    assert sum(a != b for a, b in zip(txt, pt)) <= 9
    masked = tuple(i for i in sorted(cribs) if i % 3 == 1)
    free = S.free_mask_test(ct, cribs, "STROKE")[2]
    assert any(s[2] == masked and s[3] == 5 and s[4] == "skip" for s in free)


def test_k4_has_no_setting():
    for c in S.NAMES:
        assert not S.clue_test(K4, CRIBS, c)[2]
    assert not S.free_mask_test(K4, CRIBS, "STROKE")[2]
    assert S.pattern_stat([S.near("STROKE", CRIBS[i], K4[i]) for i in sorted(CRIBS)], sorted(CRIBS))[0] == 4


if __name__ == "__main__":
    _runner.run(globals())
