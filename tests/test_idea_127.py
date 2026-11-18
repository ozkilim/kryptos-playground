"""Idea 127: Gromark with one dictionary alphabet and the other free. Planted recovery through the join."""
import random
import _runner  # noqa: F401

from kryptos import K4, CRIBS
from kryptos import idea127_gromark as G
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import english97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS", "KRYPTOS",
         "QUARTZ", "SANBORN", "ILLUSION", "UNDERGROUND", "LANGLEY", "WELTZEITUHR", "HOROLOGE"]
ALPHAS = [("(A-Z)", AZ)] + [(w, keyword_alphabet(w)) for w in WORDS]


def _join(texts, space):
    T = G.Texts(texts)
    arrs = T.alpha_arrays(ALPHAS)
    rule, base, m = space
    hits = [h for f0 in range(base) for h in G.scan(T, arrs, rule, base, m, f0)]
    return G.resolve(T, ALPHAS, hits, rule, base)


def test_planted_both_sides_recovered():
    rng = random.Random(4)
    for side, base, f, m in (("A", 10, 1, 4), ("B", 12, -1, 4)):
        pt = english97(rng)
        ct, cribs, info = G.plant(rng, pt, ALPHAS, side, base, m, "fib", f)
        surv = _join([("plant", ct, cribs)], ("fib", base, m))
        ai = next(i for i, a in enumerate(ALPHAS) if a[1] == info["alpha"])
        assert (0, side, f, ai, info["primer"]) in surv
        d = G.stream(info["primer"], base, "fib", n=97)
        part = G.forced(info["alpha"], ct, cribs, side, f, d)[0]
        assert all(a == b for a, b in zip(part, pt) if a != ".") and part.count(".") < 40


def test_stream_rules_and_k4_az_dead():
    assert G.stream((0, 1), 10, "fib", 8) == [0, 1, 1, 2, 3, 5, 8, 3]
    assert G.stream((1, 2, 3), 10, "fib3", 5) == [1, 2, 3, 6, 1]
    assert G.stream((1, 2, 3), 10, "ends", 5) == [1, 2, 3, 4, 6]
    # Bean: straight A-Z plain side is dead for any base-10 stream; also no small K4 survivor here
    assert not _join([("K4", K4, dict(CRIBS))], ("fib", 10, 4))


if __name__ == "__main__":
    _runner.run(globals())
