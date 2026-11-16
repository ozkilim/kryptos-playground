"""Planted tests for round 6: heat-bath two-key solver, shifting matrices."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import load
from kryptos.ciphers import KRYPTOS_ALPHABET as KA
from kryptos.score import Quadgrams
from kryptos.solvers import twokeys as T
from kryptos.solvers.twokeys_fast import FastTwoKey

ROOT = Path(__file__).resolve().parent.parent
PT = load("k3")["plaintext"][40:137]
CR = {i: PT[i] for i in list(range(21, 34)) + list(range(63, 74))}


def test_heat_bath_recovers_planted_two_key_message():
    ct, _ = T.plant(PT, random.Random(13 * 8), KA, "vigenere", 13, 17)
    comps = T.solve_exact(T.equations(ct, CR, KA, "vigenere", 13, 17))
    q, got = FastTwoKey(ct, KA, "vigenere", 13, 17, comps, Quadgrams()).solve(random.Random(1), sweeps=150, restarts=3)
    assert sum(a == b for a, b in zip(got, PT)) >= 85, got


def test_shifting_matrix_wheels_found():
    spec = importlib.util.spec_from_file_location("a39", ROOT / "attacks" / "39_shifting_matrices.py")
    a = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(a)
    a.CRIBS = CR
    shape = (5, 6)
    to_c, to_l = a.grid(shape, KA)
    rng = random.Random(3)
    for _ in range(1000):  # plant only the clue positions (all the wheel test reads), all on letter cells
        w = [[rng.randrange(5) for _ in range(4)], [rng.randrange(6) for _ in range(7)]]
        ct = ["A"] * 97
        ok = True
        for i, p in CR.items():
            cell = ((to_c[p][0] + w[0][i % 4]) % 5, (to_c[p][1] + w[1][i % 7]) % 6)
            if cell not in to_l:
                ok = False
                break
            ct[i] = to_l[cell]
        if ok:
            allowed = a.wheels("".join(ct), shape, to_c)
            assert 4 in allowed[0] and 7 in allowed[1]
            return
    raise AssertionError("could not plant")


if __name__ == "__main__":
    _runner.run(globals())
