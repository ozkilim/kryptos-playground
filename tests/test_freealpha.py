"""Free-alphabet engine: exact clue equations and English completion recover
planted answers (hidden alphabets, K4-style clue positions)."""
import random
import _runner  # noqa: F401

from kryptos import load
from kryptos.solvers import freealpha as F

PT = load("k3")["plaintext"][40:137]
CRIBS = {i: PT[i] for i in list(range(21, 34)) + list(range(63, 74))}


def test_union_find_offsets():
    uf = F.UF()
    assert uf.union("a", "b", 3) and uf.union("b", "c", 4)
    assert uf.union("a", "c", 7) and not uf.union("a", "c", 8)


def test_gromark_true_primer_survives_most_wrong_ones_die():
    key = F.gromark_stream([3, 1, 4, 1, 5])
    ct, _ = F.plant("gromark", PT, random.Random(2), key=key)
    assert F.solve_exact(F.equations("gromark", ct, CRIBS, key=key)) is not None
    wrong = sum(F.solve_exact(F.equations("gromark", ct, CRIBS, key=F.gromark_stream([a, b, 7, 2, 9])))
                is None for a in range(10) for b in range(10))
    assert wrong >= 80  # ~8% of primers survive the clues by chance on this text


def test_reproduces_beans_39_gromark_survivors_on_k4():
    from itertools import product
    from kryptos import K4, CRIBS as K4C
    alive = [p for p in product(range(10), repeat=5)
             if F.solve_exact(F.equations("gromark", K4, K4C, key=F.gromark_stream(p))) is not None]
    assert len(alive) == 39  # Bean, Cryptodiagnosis of Kryptos K4 (HistoCrypt 2021)


def test_completion_recovers_planted_gromark_and_quagmire():
    # A known-good case: recovery is stochastic in general (attack 19 measures the rate on planted texts).
    for model, kw in (("gromark", {"key": F.gromark_stream([3, 1, 4, 1, 5])}), ("quag1", {"period": 13})):
        ct, _ = F.plant(model, PT, random.Random(11), **kw)
        comps = F.solve_exact(F.equations(model, ct, CRIBS, **kw))
        q, got, _ = F.Completer(model, ct, comps, **kw).anneal(random.Random(1), iters=20000, restarts=4)
        assert q > -5.0 and sum(a == b for a, b in zip(got, PT)) >= 85, (model, q, got)


if __name__ == "__main__":
    _runner.run(globals())
