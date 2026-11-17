"""Planted test for idea 108: the strip is moved by a text (the key is the running sum of the text)."""
import random
import tempfile
import _runner  # noqa: F401

from kryptos import CRIBS, K4, load
from kryptos import idea108_moving as H
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.data import letters
from kryptos.round11 import english97, mixes

WORDS = ["SHADOW", "PALIMPSEST", "ABSCISSA", "BERLIN", "LODESTONE", "COMPASS", "SANBORN", "SCHEIDT", "KRYPTOS"]
ALPHAS = [("(A-Z)", AZ)] + [(w + tag, m) for w in WORDS for tag, m in mixes(w)]
SENTENCE = letters("THE OLD LIGHTHOUSE KEEPER CLIMBED THE STAIRS EVERY EVENING AND WATCHED THE SHIPS COME HOME "
                   "THROUGH THE WINTER STORMS BEFORE DARK")[:97]
_IDX = []


def _index():
    if not _IDX:
        strs = H.text_streams(2)
        paths = H.build_index(strs, tempfile.mkdtemp(prefix="idea108_test_"))
        _IDX.append((strs, paths))
    return _IDX[0]


def _scan(ct, cribs, parts):
    strs, paths = _index()
    pl, cl = H.clue_letters(ct, cribs)
    H.init(paths[0], paths[1], pl, cl, parts, None)
    return H.scan(ALPHAS)


def _plant(seed, name, lay, form, text, numbering, off, sign, order):
    rng = random.Random(seed)
    pt = english97(rng)
    m = dict(ALPHAS)[name]
    num = {"AZ": AZ, "KR": KRYPTOS_ALPHABET, "M": m}[numbering]
    return H.encrypt(pt, m, lay, form, text, num, off, sign, order, k0=rng.randrange(26)), {i: pt[i] for i in CRIBS}


def test_k2_plaintext_moves_the_strip():
    text = letters(load("k2")["plaintext"])[40:137]
    ct, cribs = _plant(1, "LODESTONE~keyed", "M/M", "vig", text, "M", 1, 1, 1)
    r = _scan(ct, cribs, "AC")
    hits = [s for s in r["seeds_a"] if s[0][0] == 22]
    assert hits and all(s[1] == "LODESTONE~keyed" for s in hits)
    assert H.undig(hits[0][5]) == text[22:34] and H.undig(hits[0][6]) == text[64:74]
    assert not [s for s in r["seeds_c"] if s[0][0] == 20]


def test_second_order_sculpture_reading():
    strs, _ = _index()
    text = dict(strs)["cipher panel / columns, left-aligned / every 2 from 1"][100:197]
    ct, cribs = _plant(2, "SCHEIDT", "M/AZ", "beau", text, "KR", 0, -1, 2)
    r = _scan(ct, cribs, "AC")
    hits = [s for s in r["seeds_c"] if s[0][0] == 20]
    assert hits and hits[0][1] == "SCHEIDT" and hits[0][2:4] == ("M/AZ", "beau")
    assert H.undig(hits[0][5]) == text[23:34]


def test_unseen_sentence_scores_best():
    ct, cribs = _plant(3, "PALIMPSEST", "AZ/M", "vig", SENTENCE, "KR", 1, -1, 1)
    r = _scan(ct, cribs, "B")
    best = max(r["top"])
    assert best[1] == "PALIMPSEST" and H.undig(best[5]) == SENTENCE[22:34] and H.undig(best[6]) == SENTENCE[64:74]
    assert best[0] / 16 > -4.9
    assert not r["seeds_a"]


def test_k4_has_no_full_match_here():
    r = _scan(K4, CRIBS, "ABC")
    assert not [s for s in r["seeds_a"] if s[0][0] == 22 or s[0][2] == 22]
    assert not [s for s in r["seeds_c"] if s[0][0] == 20 or s[0][2] == 20]
    assert max(r["top"])[0] / 16 < -5.0


def test_locate_counts_partial_and_free_gap():
    big = H.dig("XXXXABCDEFGHIJKLXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXMNOPQRSTUVXXXX") + H.SEP
    starts = H.stream_starts(big)
    t1, t2 = H.dig("ABCDEFGHIJKL"), H.dig("MNOPQRSTUV")
    fixed, pos, free, p1, p2 = H.locate(t1, t2, big, starts)
    assert (free, p1, p2) == (22, 4, 50) and fixed == 12 and pos == 4      # block 2 sits 46 after block 1, not 42


if __name__ == "__main__":
    _runner.run(globals())
