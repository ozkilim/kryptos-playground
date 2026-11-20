"""Planted tests for idea 142: plaintext autokey at lags 9-14 with a repeating word of 2-4 on top."""
import itertools
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.ciphers.substitution import AZ
from kryptos.data import DATA_DIR
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import mixes
from kryptos.score import Quadgrams
from kryptos import idea100_chains as i100
from kryptos.idea142_wordchain import (CLUE, DIRS, LAGS, PERIODS, PLANS, chains, checks, extra_score, forced, plant,
                                       primitive, survivors)

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w + tag, m) for w in WORDS for tag, m in mixes(w)]
PL = [CRIBS[i] for i in CLUE]


def test_chains_come_from_text_positions():
    """Every chain joins two clue letters a whole number of lags apart, and its steps sit on true positions
    (the run-break mistake of attack 90 was to split on the clue index instead)."""
    assert [checks(L) for L in LAGS] == [15, 14, 13, 12, 11, 11]
    for d in DIRS:
        for L in LAGS:
            for j0, j1, ws in chains(d, L):
                p0, p1 = CLUE[j0], CLUE[j1]
                assert p1 - p0 == L * len(ws)
                assert ws == tuple(range(p0 + L, p1 + 1, L) if d == "back" else range(p0, p1, L))
            for p in PERIODS:
                ops = PLANS[d, L, p]
                used = sum(2 if o[0] == "join" else o[0] != "branch" for o in ops)
                assert used == checks(L)                    # every chain is used exactly once


def test_planted_words_are_found_and_read_back():
    rng = random.Random(142)
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    for d in DIRS:
        for L in LAGS:
            for p in PERIODS:
                ct, cribs, name, spec, pt, m = plant(rng, ALPHAS, d, L, p)
                got = survivors(m, ct, [cribs[i] for i in CLUE], lags=(L,))
                assert spec in got, spec
                ok, text = forced(ct, cribs, m, spec)
                assert ok and all(x == "." or x == y for x, y in zip(text, pt))
                assert 97 - text.count(".") >= 90 and extra_score(text, big.logp, big.floor)[0] > -5.1
                for s in got:                               # anything else that passes is truly consistent
                    assert forced(ct, cribs, m, s)[0]


def test_fast_solver_lists_exactly_the_words_the_plain_model_accepts():
    """All 26^p words through the slow model against the solver's list, on planted texts (so the list is not
    empty), including views where the clues leave a family of words open."""
    rng = random.Random(7)
    cases = [("back", 14, 2), ("ahead", 13, 2), ("back", 11, 2), ("ahead", 9, 2), ("back", 12, 2), ("ahead", 10, 2)]
    for d, L, p in cases:
        ct, cribs, name, spec, pt, m = plant(rng, ALPHAS, d, L, p)
        fast = {s for s in survivors(m, ct, [cribs[i] for i in CLUE], lags=(L,), periods=(p,)) if s[:6] == spec[:6]}
        slow = {spec[:6] + (primitive(w),) for w in itertools.product(range(26), repeat=p)
                if forced(ct, cribs, m, spec[:6] + (w,))[0]}
        assert fast == slow and spec in fast
    # a view where only the sum of the three word letters is fixed: Beaufort, fed letter numbered like the plaintext
    m = ALPHAS[3][1]
    spec = ("M/M", "beau", "M", 1, "ahead", 14, (3, 20, 11))
    from kryptos.idea142_wordchain import encrypt
    from kryptos.round11 import english97
    pt = english97(rng)
    ct = encrypt(pt, m, spec, rng)
    cribs = {i: pt[i] for i in CLUE}
    fast = {s for s in survivors(m, ct, [cribs[i] for i in CLUE], lags=(14,), periods=(3,)) if s[:6] == spec[:6]}
    slow = {spec[:6] + (primitive(w),) for w in itertools.product(range(26), repeat=3)
            if forced(ct, cribs, m, spec[:6] + (w,))[0]}
    assert fast == slow and len(fast) == 676 and spec in fast


def test_a_constant_of_idea_100_is_found_as_a_word_of_one_letter():
    """Cross-check against idea 100's own encryptor: its constant c comes back as the word (c)."""
    rng = random.Random(100)
    for d, L in (("back", 14), ("ahead", 13), ("back", 9)):
        ct, cribs, name, spec, pt, m = i100.plant(rng, ALPHAS, d, L)
        got = survivors(m, ct, [cribs[i] for i in CLUE], lags=(L,))
        assert spec[:6] + ((spec[6],),) in got


def test_k4_is_clean_on_theme_alphabets():
    for name, m in ALPHAS + [("(A-Z)", AZ), ("KRYPTOS", keyword_alphabet("KRYPTOS"))]:
        assert not survivors(m, K4, PL)


if __name__ == "__main__":
    _runner.run(globals())
