"""Planted test for idea 124: a sentence key on a keyword tableau, grown outward from the clues."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS
from kryptos import idea124_grow as G
from kryptos.data import letters, load
from kryptos.round9 import keyword_alphabet


def _texts(rng):
    t = letters("".join(load(k)["plaintext"] for k in ("k2", "k3", "k1")))
    a = rng.randrange(len(t) - 97)
    b = (a + 150 + rng.randrange(100)) % (len(t) - 97)
    return t[a:a + 97], t[b:b + 97]


def test_key_table_inverts_encrypt():
    rng = random.Random(1)
    pt, key = _texts(rng)
    m = keyword_alphabet("PALIMPSEST")
    for lay in G.LAYOUTS:
        for form in G.FORMS:
            for read in G.READS:
                ct = G.encrypt(pt, key, m, lay, form, read, 7)
                kt = G.key_table(ct, m, lay, form, read, 7)
                assert "".join(G.AZ[kt[i][ord(pt[i]) - 65]] for i in range(97)) == key


def test_planted_sentence_key_bridges_and_beats_wrong_settings():
    rng = random.Random(4)
    pt, key = _texts(rng)
    m = keyword_alphabet("SHADOW")
    ct = G.encrypt(pt, key, m, "Q3", "vig", "M", 0)
    cribs = {i: pt[i] for i in CRIBS}
    true = G.grow(ct, cribs, m, "Q3", "vig", "M", 0, 20, sides=False)
    assert true["bridges"] and true["joint"] > -8.6
    wrong = []
    for w in ("KRYPTOS", "BERLIN", "CLOCK", "EGYPT", "MEDUSA"):
        for lay in ("Q1", "Q2", "Q4a"):
            for form in ("beau", "var"):
                wrong.append(G.grow(ct, cribs, keyword_alphabet(w), lay, form, "AZ", rng.randrange(26), 20,
                                    sides=False)["joint"])
    assert true["joint"] > max(wrong)


if __name__ == "__main__":
    _runner.run(globals())
