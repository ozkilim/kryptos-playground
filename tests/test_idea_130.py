"""Idea 130: exact Quagmire III (Beaufort form) decision. Planted alphabets must come out SAT and be
listed; K4 at key length 18 must be closed by the certificate x[B] = x[H]."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.idea130_exact import (AZ, certificate, check, decide, encrypt, enumerate_fixed, equations,
                                   letters_of, read)
from kryptos.round11 import english97


def test_k4_length_18_has_no_alphabet():
    rows = equations(K4, CRIBS, 18, "beau")
    assert len(rows) == 7
    assert certificate(rows) == [("B", "H")]
    assert decide(rows)[0] == "UNSAT"
    # the open lengths of the community search: 23 and 26 satisfiable, 13 closed
    assert decide(equations(K4, CRIBS, 23, "beau"))[0] == "SAT"
    assert decide(equations(K4, CRIBS, 26, "beau"))[0] == "SAT"
    assert certificate(equations(K4, CRIBS, 13, "beau"))


def test_planted_alphabet_found_and_read_back():
    rng = random.Random(7)
    for L in (18, 18, 23):
        alpha = "".join(rng.sample(AZ, 26))
        word = [rng.randrange(26) for _ in range(L)]
        pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(english97(rng)))
        ct = encrypt(pt, alpha, word, "beau")
        rows = equations(ct, CRIBS, L, "beau")
        assert check(alpha, rows) and not certificate(rows)
        verdict, wit, _ = decide(rows)
        assert verdict == "SAT" and wit
        free = rng.sample(letters_of(rows), 5)
        assert alpha in enumerate_fixed(rows, alpha, free)
        back, ok = read(alpha, ct, CRIBS, L, "beau")
        assert ok and all(a == b or a == "?" for a, b in zip(back, pt))


if __name__ == "__main__":
    _runner.run(globals())
