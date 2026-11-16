"""Planted tests for round 7: selective masking, sentence restarts, system per part, one mistake."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ
from kryptos.solvers import twokeys as TK

ROOT = Path(__file__).resolve().parent.parent


def attack(name):
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), ROOT / "attacks" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_selective_masking_closeness_on_k4():
    m = attack("42_selective_masking.py")
    assert m.closeness(K4, CRIBS, m.LIGHT) == (9, 10)


def test_selective_masking_recovers_planted():
    m = attack("42_selective_masking.py")
    ct, pt = m.plant(random.Random(7))
    res = m.run(ct, {i: pt[i] for i in CRIBS})
    assert res and sum(a == b for a, b in zip(res[0][1], pt)) >= 60


def test_sentence_restart_finds_planted_breaks():
    m = attack("43_sentence_breaks.py")
    ct, pt, (s1, s2, L) = m.plant(random.Random(43))
    hits, scored = m.run(ct, {i: pt[i] for i in CRIBS}, {"AZ": AZ})
    assert any(h[3] == s1 and h[4] == s2 and h[2] == L and h[1] == "vigenere" for h in hits)
    assert sum(a == b for a, b in zip(scored[0][1], pt)) >= 85


def test_system_per_part_recovers_planted():
    m = attack("44_system_per_sentence.py")
    ct, pt, (b, _, _) = m.plant(random.Random(44))
    *_, scored = m.run(ct, {i: pt[i] for i in CRIBS})
    assert scored[0][2] == b and sum(a == x for a, x in zip(scored[0][1], pt)) >= 90


def test_one_mistake_drop_restores_true_config():
    m = attack("45_one_mistake.py")
    ct, pt, cribs, bad = m.plant_mistake(random.Random(4545))
    assert TK.solve_exact(TK.equations(ct, cribs, AZ, "vigenere", 7, 11)) is None
    fixed = {j: p for j, p in cribs.items() if j != bad}
    assert TK.solve_exact(TK.equations(ct, fixed, AZ, "vigenere", 7, 11)) is not None


if __name__ == "__main__":
    _runner.run(globals())
