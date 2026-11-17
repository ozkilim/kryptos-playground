"""Planted tests for idea 97: a key written with few symbols (digits in any base, clock hours,
Roman numerals) shows up as a small window / few distinct key values on the right tableau."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS
from kryptos import idea97_fewsymbols as f

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS",
         "ILLUSION", "WELTZEITUHR", "SANBORN", "SCHEIDT", "LANGLEY", "QUARTZ", "MAGNETIC", "VIRGINIA"]
ALPHAS = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)] + [(w, keyword_alphabet(w)) for w in WORDS]


def scan(ct, pt):
    return f.scan(ALPHAS, [pt[i] for i in POS], [ct[i] for i in POS])


def test_profile_numbers():
    win, start, d, covs, tops, c = f.profile([24, 25, 0, 1, 1, 3])
    assert (win, start, d) == (6, 24, 5)
    assert covs[0] == 5 and covs[1] == 6            # windows of 5 and 8
    assert tops == (3, 4, 5, 6)
    win, start, d, _, _, _ = f.profile([7] * 24)
    assert (win, start, d) == (1, 7, 1)
    # a view and its negative: same window and distinct count
    rng = random.Random(1)
    k = [rng.randrange(26) for _ in range(24)]
    a, b = f.profile(k), f.profile([(-v) % 26 for v in k])
    assert (a[0], a[2], a[3], a[4]) == (b[0], b[2], b[3], b[4])
    # digits and base take the better sign
    c = f.profile([0, 25, 24, 20])[5]
    assert f.signed(c) == (4, 7)


def test_planted_digit_key_ranks_first():
    rng = random.Random(97)
    name, m = ALPHAS[5]
    ct, pt, key = f.plant(rng, m, list(range(10)), "M/M", "vig")
    t = scan(ct, pt)
    first = t.top("win")[0][1]
    assert first[:3] == (name, "M/M", "vig") and first[4] <= 10
    assert list(first[3]) == [key[i] for i in POS]
    assert t.top("win")[1][1][4] > 12                # nothing else comes close


def test_planted_clock_hours_and_base_12():
    rng = random.Random(12)
    for values, lay, form, idx in ((list(range(1, 13)), "KR/M", "vig", 7), (list(range(12)), "M/AZ", "beau", 9)):
        name, m = ALPHAS[idx]
        ct, pt, key = f.plant(rng, m, values, lay, form)
        top = scan(ct, pt).top("win")
        truth = [key[i] for i in POS]
        # the hit rule is "a window of 12 or less": the planted setting must be among the hits with its exact key.
        # (It need not be alone: keyword alphabets are close to shifted A-Z, so a related tableau can show the
        # same key plus a constant and a little jitter, here SCHEIDT KR/M for a COMPASS M/AZ key.)
        hits = [r for _, r in top if r[4] <= 12]
        assert any(r[:3] == (name, lay, form) and list(r[3]) == truth for r in hits)
        assert len(hits) <= 2


def test_planted_roman_key():
    rng = random.Random(7)
    name, m = ALPHAS[11]
    ct, pt, key = f.plant(rng, m, f.roman_values(AZ), "AZ/M", "vig")
    t = scan(ct, pt)
    first = t.top("top7")[0][1]
    assert first[:3] == (name, "AZ/M", "vig") and first[6] <= 7 and first[8][3] == 24
    rkey, rrec = t.top("roman")[0]
    assert -rkey[0] == 24 and rrec[9] == "A-Z" and rrec[:3] == (name, "AZ/M", "vig")


def test_k4_has_no_small_window_on_these_alphabets():
    t = f.scan(ALPHAS, [CRIBS[i] for i in POS], [K4[i] for i in POS])
    s = t.summary()
    assert s["all win"][0] > 12 and s["all d"][0] > 7 and s["all roman"][0] < 24
    assert t.n == 4 * 2 + (len(ALPHAS) - 1) * 10


if __name__ == "__main__":
    _runner.run(globals())
