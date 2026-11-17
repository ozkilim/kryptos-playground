"""Planted tests for idea 81: the battery, multiplier+adder words and the rotor with one clue letter dropped."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS
from kryptos.idea81_dropone import (DROPS, battery_alphabet, cut, pair_fit, pairs_search, plant_pair, plant_rotor,
                                    plant_sliding, rotor_word, views, wires, wires_drop_one)

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]


def test_sliding_key_with_one_wrong_clue_letter():
    ct, cribs, want = plant_sliding(random.Random(81), ALPHAS)
    name, alpha = next(a for a in ALPHAS if a[0] == want[0])
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    hits = battery_alphabet(name, alpha, pl, cl)
    assert any(h[1:] == want for h in hits)
    # the wrong letter really breaks the test when a different letter is dropped
    assert not any(h[2:5] == want[1:4] and h[5] != want[4] for h in hits)


def test_k4_clean_on_theme_alphabets_for_three_drops():
    pl, cl = [CRIBS[i] for i in POS], [K4[i] for i in POS]
    for name, alpha in ALPHAS[:3]:
        assert not battery_alphabet(name, alpha, pl, cl, drops=DROPS[::8])


def test_multiplier_and_adder_with_one_wrong_clue_letter():
    ct, cribs, want = plant_pair(random.Random(82))
    p, q = int(want[1].split()[2]), int(want[1].split()[-1])
    j = POS.index(want[2])
    _, pv, cv = views(ct, cribs)[0]
    assert pair_fit(p, q, POS, pv, cv) == -1                       # all 24 letters: fails
    assert pair_fit(p, q, cut(POS, j), cut(pv, j), cut(cv, j)) >= 7  # wrong letter dropped: fits
    _, hits = pairs_search(ct, cribs, pmax=6, drops=DROPS[j:j + 1])
    assert any(h[1:] == want for h in hits)


def test_rotor_with_one_wrong_clue_letter():
    words = ["PALIMPSEST", "ABSCISSA", "SHADOW", "LODESTONE", "COMPASS", "BERLIN"]
    ct, cribs, want = plant_rotor(random.Random(83), words)
    hits = []
    for w in words:
        hits += rotor_word(w, views(ct, cribs))
    assert any(h[1:] == want for h in hits)


def test_drop_one_shortcut_matches_brute_force():
    rng = random.Random(84)
    for _ in range(300):
        wiring = list(range(26))
        rng.shuffle(wiring)
        n = 12
        pv = [rng.randrange(26) for _ in range(n)]
        s = [rng.randrange(26) for _ in range(n)]
        cv = [(wiring[(x + t) % 26] - t) % 26 for x, t in zip(pv, s)]
        for _ in range(rng.randrange(3)):                           # 0, 1 or 2 wrong letters
            cv[rng.randrange(n)] = rng.randrange(26)
        brute = sorted((wires(cut(pv, j), cut(cv, j), cut(s, j), 1), j) for j in range(n)
                       if wires(cut(pv, j), cut(cv, j), cut(s, j), 1) >= 0)
        assert sorted(wires_drop_one(pv, cv, s, 1, min_checks=0)) == brute


if __name__ == "__main__":
    _runner.run(globals())
