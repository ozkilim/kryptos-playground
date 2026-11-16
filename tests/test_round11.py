"""Planted tests for round 11: gap slack, rows of 21, wrong modulus, multiplier words, paper rotor,
evolving alphabets, keyed-lag autokey, Wheatstone, bit keys / Morse switch, copper overlay."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, battery, english97

ROOT = Path(__file__).resolve().parent.parent
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]


def attack(name):
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_battery_rules_and_modulus():
    for n in (26, 27, 31):
        w, k, t = [3, 7, 1, 9, 4], [], 0
        for i in range(74):
            t = (t + w[i % 5]) % n
            if i in CRIBS:
                k.append(t)
        assert any(r == "sliding p=5" for _, r in battery(k, POS, n))
    a, b = [1, 2, 3, 4], [5, 9, 2, 11, 6, 8, 1]
    assert (14, "two stacked keys p=4 q=7") in battery([(a[i % 4] + b[i % 7]) % 26 for i in POS], POS)
    rng = random.Random(3)
    assert not battery([rng.randrange(26) for _ in POS], POS)


def test_gap_slack_finds_dropped_letter_and_k4_is_clean():
    m = attack("68_blocks_alone_and_gap_slack.py")
    ct, cribs, want = m.plant_dropped_letter(random.Random(5), ALPHAS)
    name, alpha = next(x for x in ALPHAS if x[0] == want[0])
    hits = m.test_alphabet(name, alpha, [cribs[i] for i in POS], [ct[i] for i in POS])
    assert any(h[1:] == want for h in hits)
    for name, alpha in ALPHAS:
        assert not m.test_alphabet(name, alpha, [CRIBS[i] for i in POS], [K4[i] for i in POS])


def test_rows_of_21_join():
    m = attack("69_rows_of_21.py")
    ct, cribs, w1, w2 = m.plant(random.Random(2), ALPHAS, True)
    m.init(ct, cribs)
    _, s2, s4 = m.work(ALPHAS)
    joined = set(s4) & set(s2)
    assert any(x == (w1, "M/M", "vig") and y == (w2, "M/M", "vig") for x, y in m.name_join(ct, cribs, ALPHAS, joined))
    m.init(K4, CRIBS)
    h, s2, s4 = m.work(ALPHAS)
    assert not h and not set(s2) & set(s4)


def test_wrong_modulus_planted():
    m = attack("70_wrong_modulus.py")
    ct, cribs, want = m.plant(random.Random(4), ALPHAS, 27)
    alpha = dict(ALPHAS)[want[0]]
    assert any(h[1:] == want for h in m.test_alphabet(want[0], alpha, [cribs[i] for i in POS], [ct[i] for i in POS]))


def test_multiplier_and_adder_words():
    m = attack("71_multiplier_and_adder_words.py")
    ct, cribs, want = m.plant_pair(random.Random(6))
    assert any(h[1] == "ptAZ/ctAZ" and h[2] == want for h in m.pairs_search(ct, cribs)[1])
    assert not m.pairs_search(K4, CRIBS)[1]


def test_paper_rotor_wires():
    m = attack("72_paper_rotor.py")
    rng = random.Random(8)
    pt = english97(rng)
    wiring = list(range(26))
    rng.shuffle(wiring)
    key = [AZ.index(c) for c in "LODESTONE"]
    s = [key[i % 9] for i in range(97)]
    ct = m.encrypt(pt, wiring, s)
    pv, cv = [AZ.index(pt[i]) for i in POS], [AZ.index(ct[i]) for i in POS]
    assert m.wires(pv, cv, [s[i] for i in POS], 1) >= 4
    assert m.wires(pv, cv, [(s[i] + i) % 26 for i in POS], 1) == -1
    assert not m.fixed_rules(K4, CRIBS)[1]


def test_evolving_alphabet_round_trip():
    m = attack("73_evolving_alphabet.py")
    rng = random.Random(9)
    pt = english97(rng)
    cribs = {i: pt[i] for i in CRIBS}
    start = keyword_alphabet("PALIMPSEST")
    for rule in m.RULES:
        for driver in ("cipher", "plain"):
            for mode in (("cipher", "AZ"), ("plain", "KR"), ("self", 7)):
                ct = m.encrypt(pt, start, rule, driver, mode)
                assert m.run(ct, cribs, start, rule, driver, mode) == 24
    assert m.run(K4, CRIBS, start, "move to front", "cipher", ("cipher", "AZ")) < 12


def test_keyed_lag_autokey():
    m = attack("74_keyed_lag_autokey.py")
    for seed, src in ((1, "cipher"), (2, "plain")):
        ct, cribs, name, s, p = m.plant(random.Random(seed), ALPHAS, src)
        im = {c: i for i, c in enumerate(dict(ALPHAS)[name])}
        hits = m.test_view(name, im, im, im, ct, cribs)
        assert any(h[2] == "vig" and h[3] == "%s feed +1" % s and h[4].startswith("period %d " % p) for h in hits)
    iz = {c: i for i, c in enumerate(AZ)}
    assert not m.test_view("AZ", iz, iz, iz, K4, CRIBS)


def test_wheatstone_proof_and_planted_ring():
    m = attack("75_wheatstone_hidden_ring.py")
    assert m.proof() == [] and m.repeat_argument(K4, CRIBS)
    rng = random.Random(10)
    inner = list(AZ)
    rng.shuffle(inner)
    pt = english97(rng)
    outer = keyword_alphabet("LODESTONE")
    ct = m.encrypt(pt, outer, inner, 1, 9)
    hits = m.test_ring("LODESTONE", outer, ct, {i: pt[i] for i in CRIBS})[1]
    assert any(h[1:] == ("LODESTONE", 27, 9, False) for h in hits)
    assert not m.test_ring("KRYPTOS", keyword_alphabet("KRYPTOS"), K4, CRIBS)[1]


def test_bit_keys_and_morse_switch():
    m = attack("76_digital_interpretation.py")
    rng = random.Random(11)
    pl, cn = m.plant_bits(rng)
    assert m.bits_search(pl, cn)[0] >= 60
    assert m.bits_search([CRIBS[i] for i in POS], m.cnums_of(K4))[0] < 45
    sels = m.selectors()[::40]
    ct, cribs, want = m.plant_switch(rng, sels)
    assert any(h[1:] == want for h in m.switch_search(ct, cribs, sels)[1])


def test_overlay_through_the_copper():
    m = attack("77_overlay_through_the_copper.py")
    assert len(m.CELLS) == 97
    key = m.overlay(-12, False, True, 3, 1, "left", "right", True, positions=range(97))
    assert key and len(key) == 97
    pt = english97(random.Random(12))
    a = m.KRYPTOS_ALPHABET
    ct = "".join(a[(a.index(p) + a.index(k)) % 26] for p, k in zip(pt, key))
    m.init(ct, {i: pt[i] for i in CRIBS})
    old = m.DCS, m.SLANTS
    m.DCS, m.SLANTS = range(2, 5), (0, 1)
    try:
        assert m.work([(-12, False)])[1][0] == 24
    finally:
        m.DCS, m.SLANTS = old
