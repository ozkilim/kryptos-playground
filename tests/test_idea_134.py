"""Planted test for idea 134: one hidden strip used twice in the same direction."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ
from kryptos.idea134_onestrip import decrypt, encrypt, solve, test as strip_test
from kryptos.round11 import POS, english97

ROOT = Path(__file__).resolve().parent.parent


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "134_one_strip_twice.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_solver_recovers_planted_wiring_and_text():
    rng = random.Random(7)
    for _ in range(5):
        pt = english97(rng)
        r = list(range(26))
        rng.shuffle(r)
        key = [rng.randrange(26) for _ in range(3)]
        s = [key[i % 3] for i in range(97)]
        t = [(5 + i // 3) % 26 for i in range(97)]
        cv = encrypt([AZ.index(ch) for ch in pt], r, s, t)
        status, sols, _ = strip_test([AZ.index(pt[i]) for i in POS], [cv[i] for i in POS],
                               [s[i] for i in POS], [t[i] for i in POS])
        assert status == "alive"
        w = sols[0]
        assert all(v is None or v == r[i] for i, v in enumerate(w))
        got = decrypt(cv, w, s, t)
        assert all(g is None or AZ[g] == p for g, p in zip(got, pt))
        assert sum(g is not None for g in got) >= 30


def test_random_settings_die_on_k4():
    rng = random.Random(3)
    pv = [AZ.index(CRIBS[i]) for i in POS]
    cv = [AZ.index(K4[i]) for i in POS]
    for _ in range(300):
        s = [rng.randrange(26) for _ in POS]
        t = [rng.randrange(26) for _ in POS]
        assert strip_test(pv, cv, s, t)[0] == "dead"


def test_attack_finds_planted_speed_pair():
    m = attack()
    rng = random.Random(11)
    ct, cribs, pt, want = m.plant(rng, "speed")
    m.init(ct, cribs)
    order, fname, gname, c = want
    f = dict(m.small_fasts(ct))[fname]
    stats, hits = m.collections.Counter(), []
    m.run_fixed([(fname, f)], m.small_slows(), False, stats, hits, "small")
    assert any(h[1] == "ptAZ/ctAZ" and (h[2], h[3], h[4], h[5]) == want for h in hits)
    assert stats["settings"] > 100000


if __name__ == "__main__":
    _runner.run(globals())
