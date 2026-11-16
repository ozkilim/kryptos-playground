"""Planted tests for idea 78: the round 11 battery (attacks 68, 70, 71B, 74) on transposition-mixed
keyword alphabets. Each planted message is built on a ~cols or ~keyed alphabet and must be found
by the original attack's own test, called through kryptos.idea78_mixed."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import mixes
from kryptos import idea78_mixed as i78

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
PLAIN = {keyword_alphabet(w) for w in WORDS}
MIXED = [(w + tag, m) for w in WORDS for tag, m in mixes(w) if tag and m not in PLAIN]


def run(test, ct, cribs):
    i78.init(ct, cribs, (test,))
    return i78.work(MIXED)[test]


def test_mixed_forms_are_new_alphabets():
    assert len(MIXED) == 2 * len(WORDS)
    assert ("KRYPTOS~cols", "KAHURBIVYCJWPDLXTEMZOFNSGQ") in [(w + t, m) for w in ["KRYPTOS"] for t, m in mixes(w)]
    for name, m in MIXED:
        assert sorted(m) == list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def test_planted_on_mixed_alphabets_recovered():
    for j, (test, variant) in enumerate((("68", 0), ("68", 1), ("70", 0), ("71", 0), ("74", 0), ("74", 1))):
        ct, cribs, want, found = i78.plant(test, random.Random(780 + j), MIXED, variant)
        assert "~" in want[0]
        assert found(run(test, ct, cribs)), (test, want)


def test_k4_is_clean_on_these_alphabets():
    for test in i78.TESTS:
        assert not run(test, K4, CRIBS)


if __name__ == "__main__":
    _runner.run(globals())
