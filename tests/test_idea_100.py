"""Planted tests for idea 100: plaintext autokey at a long lag (9-33), decided by chains."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.ciphers.substitution import AZ
from kryptos.data import DATA_DIR
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import mixes
from kryptos.score import Quadgrams
from kryptos.idea100_chains import (CLUE, DIRS, FREE, HIGH, LAGS, LOW, checks, extra_score, forced, numberings,
                                    plant, survivors)

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w + tag, m) for w in WORDS for tag, m in mixes(w)]
PL = [CRIBS[i] for i in CLUE]
_BIG = []


def big():
    if not _BIG:
        _BIG.append(Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt"))
    return _BIG[0]


def test_checks_per_lag():
    assert [checks(L) for L in LAGS] == [15, 14, 13, 12, 11, 11, 9, 8, 7, 7, 9, 11, 11, 9, 7, 5, 3, 1, 0, 0, 0, 1, 2, 3, 4]
    assert HIGH == tuple(range(9, 24)) and LOW == tuple(range(24, 34)) and FREE == (27, 28, 29)


def test_fast_test_agrees_with_the_plain_model():
    """On a random ciphertext the fast chain test and the slow plain model pass exactly the same settings."""
    rng = random.Random(100)
    lags = (26, 28, 30, 31)
    for name, m in (ALPHAS[4], ("(A-Z)", AZ)):
        ct = "".join(rng.choice(AZ) for _ in range(97))
        fast = set(survivors(m, ct, PL, allc=True, gate=False, lags=lags))
        plain, feeds = numberings(m)
        slow = set()
        for pn, cns in plain:
            for cn in cns:
                for form in ("vig", "beau"):
                    for fn in feeds:
                        for sign in (1, -1):
                            for d in DIRS:
                                for L in lags:
                                    for c in range(26):
                                        spec = (pn + "/" + cn, form, fn, sign, d, L, c)
                                        if forced(ct, CRIBS, m, spec)[0]:
                                            slow.add(spec)
        assert fast == slow and len(fast) > 100


def test_planted_long_lag_autokeys_are_found_and_read_back():
    rng = random.Random(1000)
    b = big()
    for d, L, c in (("back", 21, None), ("ahead", 13, None), ("back", 9, None), ("ahead", 14, None), ("back", 17, None),
                    ("ahead", 23, None), ("back", 24, None), ("ahead", 26, None), ("back", 28, 0), ("ahead", 27, None),
                    ("back", 33, None)):
        ct, cribs, name, spec, pt, m = plant(rng, ALPHAS, d, L, c)
        got = survivors(m, ct, [cribs[i] for i in CLUE], allc=True, logp=b.logp, floor=b.floor, lags=(L,))
        assert spec in got, spec
        if checks(L) >= 7:
            # nothing else passes all the checks, except that a key symmetric in the two plaintext letters
            # (fed letter numbered like the plaintext, Vigenere +, Beaufort -) leaves c open on two-step chains
            assert len(got) in (1, 26) and all(s[:6] == spec[:6] for s in got)
        ok, text = forced(ct, cribs, m, spec)
        assert ok and all(x == "." or x == y for x, y in zip(text, pt))
        assert 97 - text.count(".") >= 58 and extra_score(text, b.logp, b.floor)[0] > -5.1
        if L <= 13:
            assert text == pt                               # short lags: the clues unlock every letter
        best = max(got, key=lambda s: extra_score(forced(ct, cribs, m, s)[1], b.logp, b.floor)[0])
        assert best == spec                                 # the true setting reads best (low lags: found by English alone)


def test_k4_is_clean_on_theme_alphabets():
    for name, m in ALPHAS + [("(A-Z)", AZ), ("KRYPTOS", keyword_alphabet("KRYPTOS"))]:
        assert not survivors(m, K4, PL, gate=False, lags=HIGH)


if __name__ == "__main__":
    _runner.run(globals())
