"""Two stacked keys: exact equations + completion recover planted messages."""
import random
import _runner  # noqa: F401

from kryptos import load
from kryptos.ciphers import KRYPTOS_ALPHABET as KA, AZ
from kryptos.solvers import twokeys as T

PT = load("k3")["plaintext"][40:137]
CRIBS = {i: PT[i] for i in list(range(21, 34)) + list(range(63, 74))}


def test_planted_two_key_messages_are_recovered():
    for alpha, variant, L1, L2 in ((KA, "vigenere", 8, 13), (AZ, "beaufort", 11, 14)):
        ct, _ = T.plant(PT, random.Random(L1 * L2), alpha, variant, L1, L2)
        comps = T.solve_exact(T.equations(ct, CRIBS, alpha, variant, L1, L2))
        assert comps is not None
        q, got, _ = T.KeyCompleter(ct, alpha, variant, L1, L2, comps).anneal(random.Random(1), iters=20000, restarts=3)
        assert sum(a == b for a, b in zip(got, PT)) >= 90, (L1, L2, got)


def test_wrong_pairs_mostly_contradict():
    ct, _ = T.plant(PT, random.Random(3), KA, "vigenere", 8, 13)
    bad = sum(T.solve_exact(T.equations(ct, CRIBS, KA, "vigenere", a, b)) is None
              for a in range(2, 8) for b in range(a + 1, 9) if b % a)
    assert bad >= 15


if __name__ == "__main__":
    _runner.run(globals())
