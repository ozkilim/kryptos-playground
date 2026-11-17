"""Planted tests for idea 94: each word is the key for the next word (word autokey)."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.ciphers.substitution import AZ
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import mixes
from kryptos.score import Quadgrams
from kryptos.idea94_wordkey import (CLUE, CORE, HIDDEN_FORMS, PARTS, PRIMERS, TESTS, hidden_encrypt, hidden_test,
                                    latin_conflicts, plant, planted_words, read_hit, same_alphabet, state,
                                    test_alphabet as run_alphabet, triples, wanted)

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w + tag, m) for w in WORDS for tag, m in mixes(w)]


def _pairs(t):
    mode, n1, n2 = TESTS[t]
    return mode, (PARTS[n1]["pairs"] if n1 is not None else ()) + (PARTS[n2]["pairs"] if n2 is not None else ())


def _find(mode, p1, L1, p2, L2):
    return next(t for t, (md, n1, n2) in enumerate(TESTS) if md == mode and n1 is not None and n2 is not None
                and (p1, L1) in PARTS[n1]["labels"] and (p2, L2) in PARTS[n2]["labels"])


def test_scope_of_tests():
    assert len(CORE) == 8                       # EAST|NORTH|EAST and EAST|NORTHEAST x forwards/reversed x wrap/run-on
    mode, pairs = _pairs(_find(("plain", "fwd", "wrap", 1), "E|N|E", None, "B|C", None))
    assert len(pairs) == 14
    assert (29, 21) in pairs and (33, 28) in pairs and (73, 67) in pairs     # H<-E (wrap), T<-T, K<-I
    mode, pairs = _pairs(_find(("plain", "fwd", "run", 1), "E|NE", None, "B|C", None))
    assert (29, 25) in pairs and (33, 29) in pairs                           # run-on: H<-N, T<-H
    mode, pairs = _pairs(_find(("cipher", "rev", "wrap", 1), "E|N|E", 3, "B|C", 5))
    assert len(pairs) == 24 and (21, 20) in pairs and (24, 20) in pairs and (63, 62) in pairs


def test_planted_word_autokeys_are_found_and_read_back():
    rng = random.Random(94)
    quad = Quadgrams()
    cases = ((("plain", "fwd", "wrap", 1), "E|N|E", "B|C", 0, 13), (("plain", "rev", "run", 1), "E|NE", "B|C", 1, 13),
             (("cipher", "fwd", "wrap", 1), "E|N|E", "B|C", 0, 23), (("cipher", "rev", "run", 1), "ENE", "BC", 1, 23),
             (("cipher", "fwd", "wrap", 2), "E|NE", "B|C", 0, 13), (("plain", "fwd", "wrap", 1), "EN|E", "B|C", 1, 8))
    for mode, p1, p2, text, need in cases:
        ct, cribs, want, pt, m = plant(rng, ALPHAS, mode, p1, p2, text)
        mine = wanted(run_alphabet(want[0], m, state(ct, cribs)), want, mode, p1, p2)
        assert mine and mine[0][0] >= need, (mode, want, mine)
        got = read_hit(ct, cribs, m, mine[0], quad, width=60)
        assert sum(a == b for a, b in zip(got[34:], pt[34:])) >= 50, (mode, got)


def test_planted_hidden_alphabet():
    rng = random.Random(940)
    words, pt = planted_words(0, "E|N|E", "B|C")
    cribs_pt = "".join(pt[i] if i in CLUE else "A" for i in range(97))
    mode = ("cipher", "fwd", "wrap", 1)
    pinned = 0
    for f, (name, pcoef, sg) in enumerate(HIDDEN_FORMS):
        alpha = "".join(rng.sample(AZ, 26))
        ct = hidden_encrypt(words, alpha, pcoef, sg, rng.randrange(26), mode, PRIMERS)
        _, pairs = _pairs(_find(mode, "E|N|E", 3, "B|C", 3))
        status, sols = hidden_test(triples(pairs, "cipher", ct, cribs_pt), pcoef, sg)
        # the truth is never thrown out; when solutions are listed, the true alphabet is among them
        assert status == "open" or any(same_alphabet(s, alpha, AZ) for s, _ in sols), (name, status)
        pinned += status in ("ok", "capped")
        _, wrong = _pairs(_find(mode, "E|N|E", 5, "B|C", 3))             # wrong length of the word in front
        assert hidden_test(triples(wrong, "cipher", ct, cribs_pt), pcoef, sg)[0] in ("none", "tableau")
    assert pinned >= 3


def test_k4_forward_east_north_east_fails_on_any_tableau():
    s = state(K4, CRIBS)
    mode, pairs = _pairs(_find(("plain", "fwd", "wrap", 1), "E|N|E", None, "B|C", None))
    bad = latin_conflicts(triples(pairs, "plain", K4, s["pt"]))
    assert (("T", "T", "R"), ("T", "T", "S")) in bad        # T under key T gives R at 28 and S at 33


def test_k4_is_clean_on_theme_alphabets():
    s = state(K4, CRIBS)
    for name, m in ALPHAS + [("(A-Z)", AZ), ("KRYPTOS", keyword_alphabet("KRYPTOS"))]:
        assert not run_alphabet(name, m, s)


if __name__ == "__main__":
    _runner.run(globals())
