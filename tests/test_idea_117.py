"""Planted tests for idea 117: the Latin-square clash test and one hidden alphabet on fed-key models."""
import random
import _runner  # noqa: F401

from kryptos import K4, load
from kryptos.ciphers.substitution import AZ
from kryptos.data import letters
from kryptos import idea117_clash as C


def _k2():
    return letters(load("k2")["plaintext"])


def test_random_latin_square_is_latin_and_not_a_group_table():
    sq = C.latin_square(random.Random(1))
    assert C.is_latin(sq)
    # a cyclic (Vigenere-like) square has T[a][b] - T[a][0] independent of a for every b; this one does not
    assert len({(sq[a][1] - sq[a][0]) % 26 for a in range(26)}) > 1


def test_true_model_never_clashes_on_a_latin_square():
    rng = random.Random(117)
    k2 = _k2()
    for _ in range(3):
        pt = C.plant_text(rng)
        sq = C.latin_square(rng)
        primer = "".join(rng.choice(AZ) for _ in range(97))
        for model in (("plain", 3), ("cipher", 11)):
            ct = C.encrypt_square(pt, model, sq, primer)
            assert not C.clashes(C.triples(C.model_spec(model), ct, C.clue_plain()[1]))
        off = rng.randrange(len(k2) - 97)
        ct = C.encrypt_square(pt, ("run", k2[off:off + 97]), sq, primer)
        rules, span = C.pair_rules(ct)
        m, n = C.running_survivors(k2, rules, span)
        assert m >> (off + 21) & 1
        assert bin(m).count("1") < n            # the test still kills other offsets


def test_planted_hidden_alphabet_recovered():
    rng = random.Random(1170)
    pt = C.plant_text(rng)
    primer = "".join(rng.choice(AZ) for _ in range(97))
    for fn, a, b in C.FORMS[:2]:
        alpha = "".join(rng.sample(AZ, 26))
        ct = C.encrypt_hidden(pt, ("cipher", 11), alpha, a, b, 5, primer)
        tr = C.triples(C.model_spec(("cipher", 11)), ct, C.clue_plain()[1])
        rows, rhs = C.rows_hidden(tr, a, b)
        st, sols = C.decide(rows, rhs, tr)
        assert C.satisfies(rows, rhs, alpha, 5)
        assert st in ("ok", "capped"), st
        used = {ch for t in tr for ch in t[:3]}
        assert any(C.same_alphabet(s, alpha, used) for s, _ in sols)


def test_k4_low_lag_plain_autokey_dies_on_every_tableau():
    A = C.part_a(K4)
    for L in (1, 2, 3, 4):
        assert A["plain back %d" % L][2] > 0
    assert A["plain back 5"][2] == 0             # survives: undecided, not supported
    pos, pt = C.clue_plain()
    # plain autokey 1 back: A keyed by E gives L at 22 but K at 31 (EAST appears twice, with different cipher)
    tr = C.triples(C.model_spec(("plain", 1)), K4, pt)
    assert any(tr[x][:3] == ("A", "E", "L") and tr[y][:3] == ("A", "E", "K") for x, y in C.clashes(tr))
    # 27 and 65 both have plain R and cipher P: every tableau forces the same key letter there
    rules, _ = C.pair_rules(K4)
    assert [(a + 21, b + 21) for a, b, m in rules if m] == [(27, 65)]


if __name__ == "__main__":
    _runner.run(globals())
