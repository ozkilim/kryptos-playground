"""Planted tests for round 10: three key words (hash join), chain addition and grid keys,
the keyword-tableau battery, the '?' offset and the reversed (DIANA) table."""
import importlib.util
import os
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.round9 import keyword_alphabet

ROOT = Path(__file__).resolve().parent.parent
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def attack(name):
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _text(rng):
    from kryptos import load
    from kryptos.data import letters
    t = letters(load("k2")["plaintext"])
    o = rng.randrange(len(t) - 97)
    return t[o:o + 97]


def test_three_keywords_hash_join_finds_planted_pair():
    m = attack("63_three_keywords.py")
    words = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
    alphas = [(w, keyword_alphabet(w)) for w in words]
    rng = random.Random(1)
    pt = _text(rng)
    m1, m2, key = alphas[2][1], alphas[6][1], "WELTZEITUHR"
    ct = "".join(m2[(m1.index(ch) + m2.index(key[i % len(key)])) % 26] for i, ch in enumerate(pt))
    hits = m.search(ct, {i: pt[i] for i in CRIBS}, alphas)
    assert (11, "vig", 2, 6) in hits
    dec, _ = m.decrypt(ct, {i: pt[i] for i in CRIBS}, 11, "vig", m1, m2)
    assert dec == pt
    assert not [h for h in m.search(K4, CRIBS, alphas) if h[0] <= 20]


def test_mixes_are_permutations():
    m = attack("63_three_keywords.py")
    for _, a in m.mixes("PALIMPSEST"):
        assert sorted(a) == list(AZ)


def test_chain_and_grid_keys_planted():
    m = attack("65_chain_addition_and_grid_keys.py")
    rng = random.Random(14)
    for f in (m.plant_chain, m.plant_grid):
        ct, cribs, truth = f(rng)
        assert any(h[1:] == truth for h in m.search(ct, cribs)[1])
    assert not m.search(K4, CRIBS)[1]


def test_battery_finds_sliding_and_stacked_keys():
    m = attack("66_keyword_tableau_battery.py")
    alphas = [(w, keyword_alphabet(w)) for w in ("SHADOW", "MEDUSA", "LODESTONE")]
    rng = random.Random(31)
    for rule in ("sliding", "stacked", "autokey"):
        ct, cribs, name, want = m.plant(rng, alphas, rule)
        hits = m.test_alphabet(name, dict(alphas)[name], [cribs[i] for i in m.POS], [ct[i] for i in m.POS])
        assert any(h[2] == "M/M" and h[4] == want for h in hits), (rule, want)
    kr = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    assert not m.test_alphabet("KRYPTOS", kr, [CRIBS[i] for i in m.POS], [K4[i] for i in m.POS])


def test_question_mark_offset_shifts_the_grid():
    os.environ["KRYPTOS_QMARK"] = "1"
    try:
        m = attack("61_transposed_key.py")
        assert m.N == 98 and m.OFF == 1
        assert len(m.rotate(list(range(98)), 14)) == 98
    finally:
        del os.environ["KRYPTOS_QMARK"]


def test_diana_sign_present_in_text_key_attacks():
    m = attack("58_sculpture_readings.py")
    views, _ = m.needles(K4, CRIBS)
    assert any("/diana " in v[0] for v in views)


if __name__ == "__main__":
    _runner.run(globals())
