"""Planted tests for idea 109: each plain letter keeps its own place in the key word."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.ciphers import KRYPTOS_ALPHABET
from kryptos.idea109_cycling import (chain_fits, chains, clue_keyvals, encrypt, hidden_tableaux_possible, near_pairs,
                                     restart_plans, row_starts, word_values)
from kryptos.round9 import keyword_alphabet
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
SMALL = Quadgrams()                      # the small table is enough to rank the readings here
WORDS = ["ABSCISSA", "BERLIN", "COMPASS", "EGYPT", "ILLUSION", "LODESTONE", "MEDUSA", "PALIMPSEST", "SHADOW",
         "SHADOWY", "TUNNEL"]
ALPHAS = [(w, keyword_alphabet(w)) for w in ("LODESTONE", "SHADOW", "MEDUSA", "BERLIN")] + [("KRYPTOS", KRYPTOS_ALPHABET)]


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "109_letter_counters.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = attack()
PLANS = restart_plans(CRIBS, len(K4), min_checks=M.ROW_CHECKS)


def run(ct):
    return M.run_all("test", ct, CRIBS, ALPHAS, WORDS, SMALL, PLANS, 0.0, quiet=True, pool=False)


def test_proofs_and_clue_structure():
    pr = M.proofs()
    assert pr["common numeric step per occurrence"] and pr["counters restart at each word"]
    assert pr["key of 1 or 2 letters / 2 tableaux in turn"]
    assert not pr["3 hidden tableaux"] and not pr["4 hidden tableaux"]      # these cannot be decided
    assert len(near_pairs(chains(CRIBS))) == 7
    assert hidden_tableaux_possible(3, K4, CRIBS)
    carved = [p for p in PLANS.values() if (31, 4) in p[2]]
    assert len(carved) == 1 and carved[0][0] == 6


def test_planted_word_key_found_and_read():
    rng = random.Random(109)
    m = keyword_alphabet("LODESTONE")
    for lay, form, lab, word in (("M/M", "vig", "plain", "COMPASS"), ("AZ/M", "beau", "plain", "PALIMPSEST"),
                                 ("M/KR", "var", "cipher", "ILLUSION")):
        a, b = M.layout(m, lay)
        pt = M.spliced(rng)
        wv = word_values(word, M.label_alphabet(a, b, lab))
        ct = encrypt(pt, a, b, form, wv)
        assert chain_fits(wv, clue_keyvals(ct, CRIBS, a, b, form), chains(CRIBS))
        s = run(ct)
        top = s["wout"][0]
        assert M.same_text(top[1], pt) and ("key word %s " % word) in top[2]
        assert all(M.same_text(r[1], pt) for r in s["readings"])


def test_planted_short_key_and_row_restart():
    rng = random.Random(7)
    m = keyword_alphabet("MEDUSA")
    pt = M.spliced(rng)
    s = run(encrypt(pt, m, KRYPTOS_ALPHABET, "vig", [7, 19, 2, 24]))        # four letters, not a word
    assert s["short_streams"] >= 1 and M.same_text(s["sout"][0][1], pt)
    pt = M.spliced(rng)
    s = run(encrypt(pt, m, m, "beau", word_values("SHADOW", m), row_starts(31, 4)))
    assert s["rows"]["6"] >= 1
    assert any("key word SHADOW," in r[2] and M.same_text(r[1], pt) for r in s["rout"])
    assert all(M.same_text(r[1], pt) for r in s["readings"])


def test_k4_gives_nothing_here():
    s = run(K4)
    assert s["chains"] == 0 and s["short_streams"] == 0 and not s["readings"] and not s["threes"]
    assert sum(s["rows"].values()) == 0


if __name__ == "__main__":
    _runner.run(globals())
