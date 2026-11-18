"""Planted test for idea 132: two wrong clue letters, found and named by the drop-two battery."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea132_droptwo as T
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS

ROOT = Path(__file__).resolve().parent.parent
WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]


def attack():
    spec = importlib.util.spec_from_file_location("a132", ROOT / "attacks" / "132_two_wrong_clue_letters.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_drop_sets_exact():
    # repeating key of 5 with two letters spoiled: the only drop set is the two spoiled letters
    rng = random.Random(1)
    w = [rng.randrange(26) for _ in range(5)]
    k = [w[i % 5] for i in POS]
    k[3] = (k[3] + 1) % 26
    k[17] = (k[17] + 5) % 26
    assert T.drop_sets(k, T.TPL["repeating p=5"]) == [(3, 17)]
    assert T.drop_sets([w[i % 5] for i in POS], T.TPL["repeating p=5"]) == [()]


def test_planted_two_wrong_letters():
    m = attack()
    rng = random.Random(7)
    for rule, where in (("sliding", "cross"), ("progressive", "B2")):
        ct, cribs, pt, (name, alpha), want = m.plant_key(rng, ALPHAS, rule, where)
        hits = T.test_alphabet(name, alpha, [cribs[i] for i in POS], [ct[i] for i in POS], parts=("battery",))
        good = [h for h in hits if h[1:5] == want[:4] and h[5] == want[4] == h[6]]
        assert good, (rule, where)
        text = T.read(good[0], alpha, ct, cribs)
        assert all(text[POS[j]] == pt[POS[j]] for j in want[4])
        assert sum(a == b for a, b in zip(text, pt)) >= 90


def test_k4_small_set_clean():
    pl, cl = [CRIBS[i] for i in POS], [K4[i] for i in POS]
    for name, alpha in ALPHAS:
        assert not T.test_alphabet(name, alpha, pl, cl, parts=("battery", "akhole"))


if __name__ == "__main__":
    _runner.run(globals())
