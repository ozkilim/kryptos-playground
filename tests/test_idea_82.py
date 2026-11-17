"""Planted tests for idea 82: two paper rotors in series with hidden wirings."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.idea82_tworotor import loops, loops_back

from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
BIG = Quadgrams()                        # the small table is enough to pick the right reading
WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS", "CLOCK",
         "KRYPTOS", "SANBORN", "LANGLEY", "ILLUSION", "IQLUSION", "DESPARATLY", "MESSAGE", "TUNNEL"]


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "82_two_paper_rotors.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_loop_test_basics():
    # R1[0]-q[0]=1, R1[1]-q[0]=2, R1[1]-q[1]=5, R1[0]-q[1]=4: the loop closes (1-2+5-4 = 0)
    assert loops([0, 1, 1, 0], [0, 0, 1, 1], [1, 2, 5, 4]) == 1
    assert loops([0, 1, 1, 0], [0, 0, 1, 1], [1, 2, 5, 3]) == -1
    # two different contacts of the second rotor forced onto one letter
    assert loops([0, 0], [0, 1], [3, 3]) == -1
    assert loops([0, 0], [0, 1], [3, 4]) == 0
    # one strip there and back: R[0]-R[1]=1, R[1]-R[2]=1, R[0]-R[2]=2 closes; =0 would merge two contacts
    assert loops_back([0, 1, 0], [1, 2, 2], [1, 1, 2]) == 1
    assert loops_back([0, 1], [1, 2], [1, -1]) == -1
    assert loops_back([4], [4], [0]) == 1 and loops_back([4], [4], [7]) == -1


def test_planted_two_rotors_found_and_k4_clean():
    m = attack()
    rng = random.Random(82)
    m.KFULL.update(H=0, B=0)             # keys: forward directions only, to keep the test fast
    for mode in "HB":
        for kind in ("word", "key"):
            ct, cribs, want, r, _, pt = m.plant(rng, WORDS, mode, kind)
            assert r >= m.MIN[mode, "words" if kind == "word" else "keys"]
            m.init(ct, cribs)
            if kind == "word":
                res = m.work_words(WORDS)
            else:
                key = [m.AZ.index(ch) for ch in want[4].split()[1]]
                res = m.work_keys([(mode, len(key), tuple(key[:-2]))])
            hits = [h for mo, _, _, _, hh in res if mo == mode for h in hh]
            assert any(h[1:] == want for h in hits), (mode, kind, want)
            if mode == "B":              # the strip is rebuilt and the message read back
                sc, got, n = m.complete((r,) + want, ct, cribs, BIG)
                assert n and m.same_text(got, pt, (r,) + want)
    m.init(K4, CRIBS)
    assert not [h for _, _, _, _, hh in m.work_words(WORDS) for h in hh]
    # a K4 survivor of the loop test (3 loops) whose wiring pieces do not fit on one strip
    dead = (3, "B", "ptAZ/ctAZ", "fast first", "+1+1", "word + 1 per letter APOCRENIC (AZ)",
            "slow: start 10, block 2 is 0 on")
    m.init(K4, CRIBS)
    assert dead in [h for _, _, _, _, hh in m.work_words(["APOCRENIC"]) for h in hh]
    assert m.complete(dead, K4, CRIBS, BIG)[2] == 0


def test_true_settings_always_pass():
    m = attack()
    rng = random.Random(7)
    for mode in "HB":
        for kind in ("word", "key", "speed"):
            for _ in range(20):
                m.plant(rng, WORDS, mode, kind, need=0)      # asserts inside that the true setting passes


if __name__ == "__main__":
    _runner.run(globals())
