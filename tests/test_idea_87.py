"""Planted tests for idea 87: free choice per letter between Vigenere / Beaufort (or two tableaux)."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea87_freeform as F
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
SMALL = Quadgrams()
ALPHAS = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)] + [(w, keyword_alphabet(w)) for w in
                                                         ("PALIMPSEST", "ABSCISSA", "BERLIN", "SHADOW")]


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "87_free_choice_per_letter.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_letter_round_trip_and_strength_scale():
    m = keyword_alphabet("PALIMPSEST")
    for sy in (F.system(m, AZ, "vig"), F.system(AZ, m, "beau"), F.system(m, m, "var", m)):
        for p in range(26):
            for k in range(26):
                c = F.enc_letter(sy, p, k)
                assert F.key_label(sy, p, c) == k and F.dec_letter(sy, c, k) == p
    # one system per letter: strength = clue letters minus key letters (24 - 7 = 17)
    sy = [F.system(AZ, AZ, "vig")]
    ms = F.masks(sy, [F.IDX[CRIBS[i]] for i in POS], [F.IDX[K4[i]] for i in POS])
    assert abs(F.logsum(ms) - 7 - 17) < 1e-9


def test_planted_coin_flip_found_and_read():
    a = attack()
    for label, word, m, kind in (("M/M vig/beau", "LANTERN", KRYPTOS_ALPHABET, "rep"),
                                 ("M/AZ vig/beau", "UNDERGROUND", ALPHAS[3][1], "rep"),
                                 ("tableau M|AZ vig", "COMPASS", ALPHAS[4][1], "rep"),
                                 ("AZ/AZ vig/beau", "BERLIN", AZ, "slide")):
        pt, ct, cribs = a.plant(random.Random(len(word)), m, label, kind, word)
        hits = []
        for name, alpha in ALPHAS:
            hits += a.test_alphabet(name, alpha, [F.IDX[cribs[i]] for i in POS], [F.IDX[ct[i]] for i in POS])[3]
        true = [h for h in hits if h[0] >= 7 and h[3] == m and h[4] == label and h[1] == kind and h[5] == len(word)]
        assert true, (label, word)
        sc, txt, _ = a.read_hit(true[0], ct, cribs, SMALL, width=150)
        assert a.agreement(txt, pt) >= 0.8, (label, word, txt)


def test_k4_has_nothing_over_the_bar_on_small_alphabets():
    a = attack()
    for name, alpha in ALPHAS:
        hits = a.test_alphabet(name, alpha, [F.IDX[CRIBS[i]] for i in POS], [F.IDX[K4[i]] for i in POS])[3]
        assert not [h for h in hits if h[0] >= 7], name


if __name__ == "__main__":
    _runner.run(globals())
