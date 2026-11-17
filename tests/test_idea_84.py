"""Planted tests for idea 84: two repeating-key layers on two different tableaux."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.idea84_twotab import compile_scan, decrypt, encrypt, plan, plans, solve, tables
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, english97
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
SMALL = Quadgrams()                      # the small table is enough to rank the readings here


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "84_two_tableaux.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_plan_counts_checks():
    # 24 clue letters, 6 + 8 key letters, one connected piece: 10 checks
    assert plan(6, 8, POS)["checks"] == 10
    # same length twice: 7 separate pairs of key letters, still 24 - 14 checks
    pl = plan(7, 7, POS)
    assert pl["checks"] == 10 and len(pl["comps"]) == 7
    # every plan in the run has 7+ checks, and all p + q <= 17 are in it
    got = {(p["p"], p["q"]) for p in plans(POS, 7)}
    assert all((p, q) in got for p in range(1, 17) for q in range(1, 17) if p + q <= 17)
    assert (21, 4) in got and (13, 13) not in got


def test_fast_scan_agrees_with_slow_solver():
    rng = random.Random(3)
    pls = plans(POS, 7)[::9]
    scan = compile_scan(pls, len(POS))
    m = keyword_alphabet("PALIMPSEST")
    for trial in range(6):
        a, b = ((KRYPTOS_ALPHABET, AZ), (m, KRYPTOS_ALPHABET), (AZ, m))[trial % 3]
        e1, e2 = rng.choice((1, -1)), rng.choice((1, -1))
        pl = pls[rng.randrange(len(pls))]
        pt = english97(rng)
        ct = encrypt(pt, a, b, [rng.randrange(26) for _ in range(pl["p"])],
                     [rng.randrange(26) for _ in range(pl["q"])], e1, e2)
        F, G = tables(a, b, e1, e2, [pt[i] for i in POS], [ct[i] for i in POS])
        fast = dict(scan(F, G))
        for k, x in enumerate(pls):
            assert fast.get(k, 0) == len(solve(x, F, G))
        assert fast[pls.index(pl)] >= 1                     # the true key lengths always pass
        # letters come back right; '?' only where the clues do not reach the key (long keys)
        assert any(all(g in ("?", c) for g, c in zip(decrypt(ct, a, b, sa, sb, pl["p"], pl["q"], e1, e2), pt))
                   for sa, sb in solve(pl, F, G))


def test_planted_two_tableaux_found_and_k4_clean():
    m = attack()
    rng = random.Random(84)
    dic = keyword_alphabet("LODESTONE")
    small = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)]
    pairs = m.part1_pairs(small) + m.part2_pairs(
        [(w, keyword_alphabet(w)) for w in ("LODESTONE", "SHADOW", "MEDUSA", "BERLIN", "CLOCK")], small)
    cases = [("KRYPTOS", KRYPTOS_ALPHABET, "(A-Z)", AZ, 1, 1, "SHADOW", "LANTERN"),
             ("LODESTONE", dic, "KRYPTOS", KRYPTOS_ALPHABET, 1, -1, "BERLIN", "ILLUSION"),
             ("(A-Z)", AZ, "LODESTONE", dic, -1, 1, "ABSCISSA", "EGYPT")]
    for an, a, bn, b, e1, e2, w1, w2 in cases:
        pt, ct, cribs = m.plant(rng, an, a, bn, b, e1, e2, w1, w2)
        m.init(ct, cribs)
        hits = m.headline(m.work(pairs)[1])
        assert any((h[2], h[4], h[5], h[6], h[7], h[8]) == (a, b, e1, e2, len(w1), len(w2)) for h in hits)
        done = m.complete_all(hits, ct, cribs, SMALL)
        assert done[0][1] == pt                             # the best reading is the planted message
        assert all(m.agrees(r[1], pt) for r in done)        # and no survivor reads anything else
        # the keys come back as the planted words, in their own alphabet's letters
        assert done[0][2].split("/")[0] == w1 and done[0][3].split("/")[0] == w2
    m.init(K4, CRIBS)
    assert not m.work(pairs)[1]                             # K4: nothing, not even at 5-6 checks


if __name__ == "__main__":
    _runner.run(globals())
