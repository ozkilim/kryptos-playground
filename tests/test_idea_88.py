"""Planted tests for idea 88: the key runs on over word spaces (one slip per word break)."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea88_slip as S
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS

ROOT = Path(__file__).resolve().parent.parent
WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "88_spaces_use_key_letters.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_positions_count_the_breaks():
    pos = S.positions(2, 1, 5, 3)                    # EAST|NORTH|EAST, BERLIN|CLOCK, 3 breaks before, 5 between
    assert pos[:13] == [24, 25, 26, 27, 29, 30, 31, 32, 33, 35, 36, 37, 38]
    assert pos[13:] == [73, 74, 75, 76, 77, 78, 80, 81, 82, 83, 84]
    assert S.positions(0, 0, 0) == POS


def test_fast_search_equals_the_plain_battery_loop():
    rng = random.Random(4)
    total = 0
    for trial in range(3):
        if trial == 0:
            k = [rng.choice((0, 0, 0, 5)) for _ in range(24)]
        else:
            p = rng.randrange(4, 8)
            w = [rng.randrange(26) for _ in range(p)]
            pos = S.positions(rng.randrange(3), rng.randrange(2), rng.randrange(26), rng.randrange(12))
            st = rng.randrange(1, 26) if trial == 2 else 0
            k = [(w[i % p] + st * (i // p)) % 26 for i in pos]
        slow = S.slow_hits(k)
        assert slow == S.fast_hits(k)
        total += len(slow)
    assert total > 20


def test_planted_slipping_keys_are_found_and_k4_is_clean():
    m = attack()
    rng = random.Random(88)
    for rule in ("repeating", "sliding", "progressive", "sliding"):
        ct, cribs, want = S.plant(rng, ALPHAS, rule)
        name, alpha = next(x for x in ALPHAS if x[0] == want[0])
        hits = m.test_alphabet(name, alpha, [cribs[i] for i in POS], [ct[i] for i in POS], 7)
        assert any(h[1:] == want for h in hits), want
        assert not any(h[4:7] == (0, 0, 0) for h in hits)        # invisible with the carved positions
    for name, alpha in ALPHAS:
        assert not m.test_alphabet(name, alpha, [CRIBS[i] for i in POS], [K4[i] for i in POS], 7)


if __name__ == "__main__":
    _runner.run(globals())
