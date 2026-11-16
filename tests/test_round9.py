"""Planted tests for round 9: exact linear solving, formula mining, hidden-alphabet autokey,
interrupted keys, sentence keys on keyword tableaux, sculpture readings, stacked autokey, interleaving."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import round9

ROOT = Path(__file__).resolve().parent.parent


def attack(name):
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_mod26_solver_finds_every_solution():
    # 2x + y = 5, x + 3y = 7 (mod 26): brute force agrees with the CRT solver
    rows, rhs = [[2, 1], [1, 3]], [5, 7]
    brute = sorted([x, y] for x in range(26) for y in range(26)
                   if (2 * x + y) % 26 == 5 and (x + 3 * y) % 26 == 7)
    assert sorted(round9.solutions_mod26(rows, rhs)) == brute and brute
    assert round9.solutions_mod26([[2, 0]], [1]) is None      # 2x = 1 has no solution mod 26


def test_key_views_match_known_vigenere_keys():
    v = dict(round9.key_views())
    assert [v["ptAZ/ctAZ/m1"][i] for i in range(21, 25)] == [1, 11, 25, 2]   # F-E, L-A, R-S, V-T


def test_formula_miner_fits_planted_formula_only():
    m = attack("54_formula_mining.py")
    ct, cribs, truth = m.plant(random.Random(1))
    lib = m.library(ct, cribs, small=True)
    az = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    tgt = {i: az.index(ct[i]) for i in round9.POS}
    plain = {i: az.index(cribs[i]) for i in round9.POS}
    res = m.test_combo(truth, lib, tgt, plain)
    assert res and res[1]
    assert m.test_combo(("i", "i^2", "tri(i)"), lib, tgt, plain) is None
    # and K4 itself has no fit for the simplest formulas
    lib4 = m.library(K4, CRIBS, small=True)
    t4 = {i: az.index(K4[i]) for i in round9.POS}
    p4 = {i: az.index(CRIBS[i]) for i in round9.POS}
    assert m.test_combo(("i",), lib4, t4, p4) is None


def test_hidden_alphabet_autokey_survives_when_planted():
    m = attack("55_hidden_alphabet_autokey.py")
    ct, cribs, _ = m.plant_autokey(random.Random(5), "P", 1, 1, 1)
    _, sv = m.survivors(ct, cribs)
    assert any(x[0] == "autokey ?/? src=P lag=1 a=+1 b=+1" for x in m.strong(sv))
    _, sv4 = m.survivors(K4, CRIBS)
    assert not m.strong(sv4)


def test_interrupted_key_block_logic():
    m = attack("56_interrupted_key.py")
    ct, cribs, truth = m.plant(random.Random(4))
    a = m.KRYPTOS_ALPHABET
    key = {i: (a.index(ct[i]) - a.index(cribs[i])) % 26 for i in cribs}
    trig = truth[2].split()[-1]
    zero = {i + 1 for i in cribs if cribs[i] == trig and i + 1 in cribs}
    assert m.best_checks(zero, truth[3], key) >= m.MIN_CHECKS


def test_sentence_key_scores_as_english_under_true_alphabet():
    m = attack("57_running_key_keyword_alphabets.py")
    alphas = [("PALIMPSEST", round9.keyword_alphabet("PALIMPSEST")), ("WRONGWORD", round9.keyword_alphabet("WRONGWORD"))]
    ct, cribs, w, key = m.plant(random.Random(3), alphas[:1], "Q3")
    tab = m.quad_table()
    true = max(m.score_alphabet(alphas[0], ct, cribs, tab))[0]
    wrong = max(m.score_alphabet(alphas[1], ct, cribs, tab))[0]
    assert true > -4.9 and true > wrong + 0.3


def test_sculpture_reading_found_exactly():
    m = attack("58_sculpture_readings.py")
    m.MAX_SKIP = 3
    ct, cribs = m.plant(random.Random(2))
    assert m.scan(ct, cribs)[0][0] == 24


def test_autokey_plus_repeating_key_found():
    m = attack("59_autokey_plus_repeating_key.py")
    rng = random.Random(8)
    ct, cribs, truth = m.plant(rng)
    _, hits = m.search(ct, cribs)
    assert any(h[1:] == truth for h in hits)


def test_switching_and_interleaving_planted():
    m = attack("60_two_systems_interleaved.py")
    rng = random.Random(6)
    assert m.best_cover(*m.plant_switch(rng, 2), 2)[0] == 24
    assert m.interleaved(*m.plant_interleaved(rng, 2), 2)[0] >= 10
    assert m.interleaved(K4, CRIBS, 2)[0] == -1


if __name__ == "__main__":
    _runner.run(globals())
