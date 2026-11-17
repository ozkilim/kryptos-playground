"""Planted tests for idea 111: vowels and consonants keyed by two separate words; a key that holds or skips."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea111_classes as C
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, english97
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]
_M = {}


def attack():
    if "m" not in _M:
        spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "111_vowel_and_consonant_keys.py")
        _M["m"] = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_M["m"])
        _M["lm"] = Quadgrams()
    return _M["m"], _M["lm"]


def hits_for(m, ct, cribs):
    m.init(ct, cribs)
    out = []
    for name, alpha in ALPHAS:
        out += m.test_alphabet(name, alpha)[0]
    return m.best_per_stream(sorted(out, key=lambda h: (-h[0], h[1:5])))


def test_equal_pair_masks_and_offsets():
    k = [3, 5, 3, 7, 5, 3] + list(range(8, 26))
    eq, pids = C.eq_mask(k)
    assert sorted(pids) == sorted([C.PID[0][2], C.PID[0][5], C.PID[2][5], C.PID[1][4]])
    need, c = C.need_of([(0, 0), (1, 1), (2, 0), (4, 1), (5, 0)])
    assert c == 3 and need & eq == need
    pl = [CRIBS[i] for i in POS]
    mem = [ch in C.VOWELS for ch in pl]
    #                                  E  A  S  T  N  O  R  T  H  E  A  S  T
    assert C.offsets(mem, "hold-after")[:13] == (0, 0, 0, 1, 2, 3, 3, 4, 5, 6, 6, 6, 7)
    assert C.offsets(mem, "skip-at")[:13] == (0, 2, 3, 4, 5, 7, 8, 9, 10, 12, 14, 15, 16)
    assert C.offsets([False] * 24, "hold-at") == tuple(range(13)) + tuple(range(11))


def test_planted_two_words_and_holding_key_are_found_and_read_back():
    m, lm = attack()
    rng = random.Random(111)
    for kind in ("A", "B", "C"):
        ct, pt, want, label = m.plant(rng, ALPHAS, kind)
        cribs = {i: pt[i] for i in POS}
        hits = hits_for(m, ct, cribs)
        mine = [h for h in hits if want(h)]
        assert mine and mine[0] == hits[0], label
        # the small quadgram model may pick a wrong twin for a few letters (model A is ambiguous to read)
        assert max(m.agree(r, pt) for r in m.readings(mine[0], ct, cribs, dict(ALPHAS)[mine[0][2]], lm)) >= 90, label
        # invisible to a position-based repeating key: the plain pattern is not among the hits
        assert not any(h[1] == "B" and "no hold" in m.describe(h, ct, cribs) for h in hits)


def test_planted_subset_key_is_found_and_k4_is_clean():
    m, lm = attack()
    rng = random.Random(7)
    small = ALPHAS[:3]
    ct, pt, want, label = m.plant(rng, small, "S")
    cribs = {i: pt[i] for i in POS}
    hits = m.subset_search(ct, cribs, small)
    mine = [h for h in hits if want(h)]
    assert mine, label
    assert pt in m.readings(mine[0], ct, cribs, dict(small)[mine[0][2]], lm)
    assert not hits_for(m, K4, CRIBS)
    assert not m.subset_search(K4, CRIBS, small[:1])


def test_two_word_cipher_has_more_than_one_reading():
    """The reader has to guess the class of each letter, so a message can decrypt in several ways."""
    rng = random.Random(3)
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    pt = "".join(pt)
    alpha = keyword_alphabet("SHADOW")
    v, w = [4, 17, 9], [1, 22, 13, 6, 19, 11]
    nv = sum(ch in C.VOWELS for ch in pt[:21])          # the reader numbers both words from position 21
    ct = C.encrypt_a(pt, alpha, "M/M", "vig", "vig", v, w, -nv % 3, -(21 - nv) % 6)
    out, total = C.decrypt_a(ct, alpha, "M/M", "vig", "vig", v, w, cribs={i: pt[i] for i in POS},
                             lm=attack()[1], beam=5000, cap=5000, count=True)
    assert total > 1 and max(sum(x == y for x, y in zip(r, pt)) for r in out) >= 90


if __name__ == "__main__":
    _runner.run(globals())
