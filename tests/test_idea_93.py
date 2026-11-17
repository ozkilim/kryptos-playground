"""Planted test for idea 93: known word keys on a hidden tableau are found, with the alphabet recovered."""
import importlib.util
import random
from collections import Counter
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea93_hidden as H

ROOT = Path(__file__).resolve().parent.parent
DECOYS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS", "LAYERTWO",
          "WELTZEITUHR", "IQLUSION", "UNDERGRUUND", "DESPARATLY", "MAGNETICFIELD", "NORTHWEST", "SANBORN", "SCHEIDT",
          "LANGLEY", "TUTANKHAMUN", "INVISIBLE", "XLAYERTWO", "CHECKPOINT", "ALEXANDERPLATZ", "CANDLE", "TRANSMITTED"]


def attack():
    spec = importlib.util.spec_from_file_location("a93", ROOT / "attacks" / "93_word_keys_hidden_tableau.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _recover(m, spec, seed):
    name, vn, kind, word = spec
    ct, pt, alpha, word, phi = m.plant(random.Random(seed), name, vn, kind, word, None)
    cribs = {i: pt[i] for i in CRIBS}
    hits = H.scan_words(H.Tables(ct, cribs), DECOYS + [word], Counter(), [])
    mine = [h for h in hits if h[:5] == (name, vn, kind, word, phi)]
    assert mine, spec
    best = 0
    for rd, X, E in H.readings(mine[0], ct, cribs):
        if all(a == b or a == "?" for a, b in zip(rd, pt)) and m.same_alphabet(X, alpha):
            best = max(best, sum(a == b for a, b in zip(rd, pt)))
    assert best >= 60, (spec, best)


def test_planted_word_keys_on_a_hidden_alphabet():
    m = attack()
    for seed, spec in enumerate([("Quagmire III, C = P + K", None, "R", "SCULPTURE"),
                                 ("Quagmire III, C = K - P", None, "R", "UNDERGROUNDTRANSMISSIONS"),
                                 ("one hidden alphabet, C = P + k", "AZ", "S", "KRYPTOS"),
                                 ("Quagmire III, C = P - K", None, "S", "ILLUSION"),
                                 ("Quagmire II, plain on KR", None, "R", "PALIMPSEST")]):
        _recover(m, spec, seed)


def test_k4_theme_words_do_not_fit():
    hits = H.scan_words(H.Tables(K4, CRIBS), DECOYS + ["KRYPTOS"], Counter(), [])
    assert not hits


def test_fixed_points_force_equal_key_letters():
    # true Quagmire III, C = P + K: S->S (33) and K->K (74) need the same key letter; R->P twice as well
    t = H.Tables(K4, CRIBS).loc[0]
    assert (11, 23) in t["eq"] and (6, 15) in t["eq"]


def test_all_in_one_place_is_not_a_solution():
    rows = [[0] * 27 for _ in range(3)]
    for r, (a, b, c) in zip(rows, ((0, 1, 2), (1, 2, 3), (2, 3, 0))):
        r[a], r[b], r[c] = 1, 25, 25
    sols, status = H.solve_injective(rows, [0, 0, 0])
    assert sols and all(len(set(X.values())) == 4 for X, _ in sols)
    assert H.solve_injective([[1, 25] + [0] * 25], [0]) == ([], "none")


if __name__ == "__main__":
    _runner.run(globals())
