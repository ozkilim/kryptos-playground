"""The fingerprint statistics reproduce K4's published oddities, and every
simulated family produces valid 97-letter ciphertext."""
import random
import _runner  # noqa: F401

from kryptos import fingerprint as FP
from kryptos.data import K4


def test_k4_fingerprint_matches_published_values():
    s = FP.stats(K4)
    assert round(s["ioc"], 4) == 0.0361          # flat letter counts
    assert s["stehle"] == 5                       # DIAWINFBN lag-4 run (Stehle 2000)
    assert s["vpairs"] == 11                      # 11 repeated pairs at width 21 (Bean 2021)
    assert s["close"] == 12                       # 12/24 clue letters within 3 places (Bean's "one-to-one")
    assert s["doublets"] > 4                      # 5 of 6 doublets on one residue mod 7


def test_every_family_makes_valid_ciphertext_and_ioc_behaves():
    text = FP.english_windows()
    fams = FP.families(text)
    rng = random.Random(1)
    for name, fn in fams.items():
        ct = fn(FP.k4_like_plaintext(text, rng), rng)
        assert len(ct) == 97 and ct.isalpha() and ct.isupper(), name
    eng = [FP.stats(FP.k4_like_plaintext(text, rng))["ioc"] for _ in range(200)]
    rnd = [FP.stats(fams["random letters (one-time pad)"]("A" * 97, rng))["ioc"] for _ in range(200)]
    assert sum(eng) / 200 > 0.055 and abs(sum(rnd) / 200 - 0.0385) < 0.004


if __name__ == "__main__":
    _runner.run(globals())
