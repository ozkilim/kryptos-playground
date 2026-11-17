"""Planted test for idea 99: Quagmire IV with one dictionary alphabet and one freely written alphabet."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea99_half as H
from kryptos.data import DATA_DIR
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import english97, mixes
from kryptos.score import Quadgrams

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS", "LAYERTWO",
         "WELTZEITUHR", "IQLUSION", "MAGNETICFIELD", "NORTHWEST", "SANBORN", "SCHEIDT", "LANGLEY", "TUTANKHAMUN",
         "INVISIBLE", "CHECKPOINT", "ALEXANDERPLATZ", "CANDLE", "TRANSMITTED", "KRYPTOS"]
ALPHAS = [(w + tag, m) for w in WORDS for tag, m in mixes(w)] + [("(A-Z)", AZ)]
_BIG = []


def big():
    if not _BIG:
        _BIG.append(Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt"))
    return _BIG[0]


def _plant(seed, case, word, sliding, beaufort, name):
    rng = random.Random(seed)
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    pt = "".join(pt)
    alpha = dict(ALPHAS)[name]
    hidden = "".join(rng.sample(AZ, 26))
    pa, ca = (alpha, hidden) if case == 1 else (hidden, alpha)
    return H.quagmire4(pt, pa, ca, H.key_stream(word, sliding), beaufort), pt


def _find(ct, pt):
    cribs = {i: pt[i] for i in CRIBS}
    pl, cl = H.clue_letters(ct, cribs)
    return H.scan(H.plans(ct, cribs), pl, cl, ALPHAS)[0], cribs


def test_planted_half_hidden_quagmire_is_found_and_read():
    for seed, (case, word, sliding, beaufort, name) in enumerate([
            (1, "CLUE", False, False, "PALIMPSEST"),
            (2, "LIGHT", False, False, "WELTZEITUHR~keyed"),
            (1, "KEY", True, False, "ABSCISSA~cols"),
            (2, "BERLIN", False, True, "SHADOW")]):
        ct, pt = _plant(seed, case, word, sliding, beaufort, name)
        hits, cribs = _find(ct, pt)
        mine = [h for h in hits if h[0] == case and h[1] == len(word) and bool(h[2]) == sliding and h[5] == name]
        assert mine, (case, word, name)
        sc, rd, offs, forced = H.Reader(mine[0], ct, cribs, big()).anneal(random.Random(1), iters=2500, restarts=1)
        assert all(a == b or a == "?" for a, b in zip(forced, pt))
        assert sum(a == b for a, b in zip(rd, pt)) >= 80, (word, rd)
        assert sc > -5.0


def test_vigenere_and_beaufort_form_are_one_test():
    ct, pt = _plant(7, 1, "SHADOW", False, True, "LODESTONE")
    hits, _ = _find(ct, pt)
    assert any(h[:3] == (1, 6, 0) and h[5] == "LODESTONE" for h in hits)


def test_k4_theme_alphabets_do_not_fit_and_most_key_lengths_fit_no_alphabet():
    pl, cl = H.clue_letters(K4, CRIBS)
    pls = H.plans(K4, CRIBS)
    assert not H.scan(pls, pl, cl, ALPHAS)[0]
    # hidden cipher alphabet, repeating key: only length 8 leaves any alphabet a chance
    assert [p.L for p in pls[1] if not p.impossible()] == [8]


def test_all_in_one_place_is_not_a_solution():
    # H and B on the same place: loops can close, letters cannot be told apart
    comps = [({"H": 3, "B": 3, "Q": 5}, {0: 1})]
    assert len(set(comps[0][0].values())) < 3
    assert H.place([({"H": 3, "B": 4}, {0: 1}), ({"Q": 0, "Z": 1}, {1: 0})]) is not None
    full = [({AZ[i]: i for i in range(25)}, {}), ({"Z": 0, "?": 1}, {})]
    assert H.place(full) is None


def test_keyword_alphabet_is_what_the_plan_expects():
    assert keyword_alphabet("KRYPTOS").startswith("KRYPTOSABC")
    p = H.Plan(list("AAB"), 1, [0, 1, 2], list("XYX"))
    assert p.kinds == ["diff"] and p.impossible()


if __name__ == "__main__":
    _runner.run(globals())
