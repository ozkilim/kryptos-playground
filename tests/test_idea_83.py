"""Planted tests for idea 83: state machines moved by a hidden table of the letter (moore, mealy,
cipher-fed), the digram rule, and the known-alphabet drift test."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.idea83_devices import (FEEDS, digram_rule, drift_checks, drift_encrypt, drift_table, moduli,
                                    ring_encrypt, solve_linear)
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, english97, streams

ROOT = Path(__file__).resolve().parent.parent
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "83_repeats_any_state_machine.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_solver_small_cases():
    # x + y = 3, x - y = 1 (mod 7) -> x = 2, y = 1; adding x != 2 leaves nothing
    eqs = [({"x": 1, "y": 1}, -3, True), ({"x": 1, "y": -1}, -1, True)]
    assert solve_linear(7, eqs) == ("yes", {"x": 2, "y": 1})
    assert solve_linear(7, eqs + [({"x": 1}, -2, False)])[0] == "no"
    # 2x = 1 has no solution mod 26; 2x = 4 has two (2 and 15)
    assert solve_linear(26, [({"x": 2}, -1, True)])[0] == "no"
    assert solve_linear(26, [({"x": 2}, -4, True), ({"x": 1}, -2, False)])[1] == {"x": 15}


def test_k4_breaks_the_digram_rule_and_no_modulus_fits():
    assert digram_rule(K4, CRIBS) == [("ST", [32], [23])]
    ms = [14, 26, 27, 39, 60]
    for kind, flags in (("moore", {}), ("moore", dict(decipherable=False)), ("tables", {})):
        assert set(moduli(K4, CRIBS, ms, kind, **flags).values()) == {"no"}
    # the escape hatch: several values showing the same letter (m > 26) is not constrained
    assert moduli(K4, CRIBS, [31], "mealy", same_state=False) == {31: "yes"}


def test_planted_devices_are_found():
    m = attack()
    rng = random.Random(83)
    for kind, label in (("moore", "moore, F one-to-one, decipherable"), ("mealy", "mealy, F one-to-one"),
                        ("cipher-fed", "cipher-fed, F one-to-one")):
        ct, cribs = m.plant_device(rng, kind, 26)
        model = [x for x in m.MODELS if x[0] == label][0]
        assert moduli(ct, cribs, [26], model[1], cap=400000, tries=8, **model[2]) == {26: "yes"}
        if kind != "cipher-fed":
            assert not digram_rule(ct, cribs)


def test_rule_holds_on_one_to_one_devices_and_the_clock():
    m = attack()
    bad, bad_many = m.rule_on_devices(random.Random(5), 200)
    assert bad == 0 and bad_many > 0
    rng = random.Random(6)
    pt = english97(rng)
    pos = dict(zip(AZ, rng.sample(range(27), 26)))
    assert not digram_rule(ring_encrypt(pt, pos, 27, rng.sample(AZ, 26)), dict(enumerate(pt)))


def test_drift_on_known_alphabets():
    rng = random.Random(7)
    alpha = keyword_alphabet("PALIMPSEST")
    for feed, beau in zip(FEEDS, (False, True, False, True)):
        pt = english97(rng)
        ct = drift_encrypt(pt, alpha, alpha, drift_table(rng, alpha, feed), feed, beaufort=beau, start=5)
        pl, cl = [pt[i] for i in POS], [ct[i] for i in POS]
        got = {(lay, form): drift_checks(k, pl, cl)[feed] for lay, form, k, _, _ in streams(alpha, pl, cl)}
        assert got[("M/M", "beau" if beau else "vig")] >= 0          # the planted view passes every check
    # K4 on the two sculpture alphabets: nothing passes
    pl, cl = [CRIBS[i] for i in POS], [K4[i] for i in POS]
    for a in (AZ, keyword_alphabet("KRYPTOS")):
        for _, _, k, _, _ in streams(a, pl, cl):
            assert max(drift_checks(k, pl, cl).values()) == -1


if __name__ == "__main__":
    _runner.run(globals())
