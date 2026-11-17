"""Planted tests for idea 89: alphabets that are not keyword alphabets (text orders, QWERTY,
Morse, frequency orders), on the key-rule battery, the key-text score and the two-alphabet join."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.round9 import keyword_alphabet
from kryptos import idea89_orders as o

FIXED = dict(o.fixed_orders())
QWERTY, MORSE = FIXED["qwerty rows"], FIXED["morse by length, dot first"]
K2_OPEN = o.fill(o.first_seen("ITWASTOTALLYINVISIBLE"))
NEW = list(FIXED.items()) + [("K2 opening", K2_OPEN), ("K3 opening", o.fill(o.first_seen("SLOWLYDESPARATLY"), o.ZA))]
DIC = [("KRYPTOS", KRYPTOS_ALPHABET)] + [(w, keyword_alphabet(w)) for w in
                                         ("SHADOW", "BERLIN", "LODESTONE", "PALIMPSEST", "ABSCISSA", "COMPASS")]


def cribs_of(pt):
    return {i: pt[i] for i in CRIBS}


def test_the_orders():
    assert QWERTY == "QWERTYUIOPASDFGHJKLZXCVBNM"
    assert MORSE == "ETIANMSURWDKGOHVFLPJBXCYZQ"
    assert K2_OPEN == "ITWASOLYNVBECDFGHJKMPQRUXZ"
    assert o.fill("ITWAS", o.ZA) == "ITWASZYXVURQPONMLKJHGFEDCB"
    for name, m in o.fixed_orders():
        assert sorted(m) == list(AZ), name
    tx = o.texts()
    assert "ILLUSION" in tx["K1fix"] and "UNDERGROUND" in tx["K2fix"] and "DESPERATELY" in tx["K3fix"]
    assert tx["K2layer"].endswith("XLAYERTWO") and tx["CT"].endswith(K4)


def test_planted_sliding_key_on_k2_sentence_alphabet():
    ct, pt = o.plant_sliding(random.Random(89), K2_OPEN, 7)
    cr = cribs_of(pt)
    pl, cl = [cr[i] for i in o.POS], [ct[i] for i in o.POS]
    hits = [h for n, m in NEW for h in o.battery_hits(n, m, pl, cl)]
    assert any(h[0] >= o.MIN_CHECKS and h[1:] == ("K2 opening", "M/M", "vig", "sliding p=7") for h in hits)
    # the same message is not found on the wrong alphabets
    assert all(h[1] == "K2 opening" for h in hits if h[0] >= o.MIN_CHECKS)


def test_planted_three_words_with_qwerty_plain_alphabet():
    rng = random.Random(8)
    ct, pt = o.plant_three_words(rng, QWERTY, keyword_alphabet("LODESTONE"), "PALIMPSEST")
    r = o.analyse(ct, cribs_of(pt), NEW, DIC)
    best = r["best"]
    assert best[4] == "qwerty rows" and best[5] == "LODESTONE" and best[2] == 10
    assert best[7] == pt and best[0] > -5.1
    assert any(x[8] == "PALIMPSEST" for x in r["worded"])
    # the other way round, and new alphabets on both sides
    ct, pt = o.plant_three_words(rng, keyword_alphabet("BERLIN"), MORSE, "ILLUSIONS")
    assert pt in [x[7] for x in o.analyse(ct, cribs_of(pt), NEW, DIC)["top"]]   # length 18 fits too, in part
    ct, pt = o.plant_three_words(rng, K2_OPEN, QWERTY, "UNDERGROUND")
    assert pt in [x[7] for x in o.analyse(ct, cribs_of(pt), NEW, DIC)["top"]]


def test_planted_sentence_key_ranks_first():
    ct, pt, key = o.plant_running_key(random.Random(4), QWERTY)
    o.init(ct, cribs_of(pt))
    _, top = o.work(NEW)
    assert top[0][1] == "qwerty rows" and top[0][4] == key[21:34] + "|" + key[63:74]


def test_k4_is_clean_on_the_fixed_orders():
    pl, cl = [CRIBS[i] for i in o.POS], [K4[i] for i in o.POS]
    assert not [h for n, m in NEW for h in o.battery_hits(n, m, pl, cl)]
    assert o.analyse(K4, CRIBS, NEW, DIC)["n"] == 0


if __name__ == "__main__":
    _runner.run(globals())
