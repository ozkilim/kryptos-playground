"""Planted test for idea 131: Quagmire IV with two keyword alphabets (any letters) solved from their tails."""
import itertools
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea131_two as T
from kryptos.idea86_tail import keyword_alphabet
from kryptos.round11 import english97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _uniq(ms, forms, s):
    seen = {}
    for p in itertools.permutations(AZ, ms[s]):
        seen.setdefault(T.apply_form(keyword_alphabet("".join(p)), forms[s], ms[s]), 1)
    return ["".join(a) for a in seen]


def test_solver_matches_brute_force():
    rng = random.Random(3)
    ct = "".join(rng.choice(AZ) for _ in range(97))
    for form in ("vig", "beau"):
        for forms, ms in ((("kw", "kw"), (2, 2)), (("cols", "kw"), (3, 1))):
            eqs, _ = T.equations(ct, CRIBS, 4, form, T.B1[:6])
            got = T.solve(eqs, ms, forms)["count"]

            def places(al, s):
                return {ord(ch) - 65 + 26 * s: i for i, ch in enumerate(al)}
            P0 = [places(a, 0) for a in _uniq(ms, forms, 0)]
            P1 = [places(a, 1) for a in _uniq(ms, forms, 1)]
            n = 0
            for a in P0:
                for b in P1:
                    p = dict(a)
                    p.update(b)
                    n += all(sum(c * p[v] for v, c in co) % 26 == 0 for co, _ in eqs)
            assert got == n, (form, forms, got, n)


def test_planted_two_keywords_found_and_read_back():
    rng = random.Random(7)
    pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(english97(rng)))
    for w1, w2, L, form, forms in (("SANBORN", "KRIPTOS", 11, "beau", ("kw", "kw")),
                                   ("QZXWJV", "SANBORN", 8, "vig", ("kw", "cols"))):
        ms = (len(set(w1)), len(set(w2)))
        pa = T.apply_form(keyword_alphabet(w1), forms[0], ms[0])
        ca = T.apply_form(keyword_alphabet(w2), forms[1], ms[1])
        ct = T.encrypt(pt, pa, ca, form, [rng.randrange(26) for _ in range(L)])
        eqs, _ = T.equations(ct, CRIBS, L, form)
        r = T.solve(eqs, ms, forms, keep=100)
        assert r["count"] >= 1
        found = False
        for part in r["partials"]:
            pl, cl = T.expand(part, ms, forms, 30000)
            if pa in pl and ca in cl:
                found = True
                assert T.decrypt(ct, pa, ca, form, L, CRIBS) == pt
        assert found
        # the same system on K4 has no solution at all
        eqk, _ = T.equations(K4, CRIBS, L, form)
        assert T.solve(eqk, ms, forms)["count"] == 0


if __name__ == "__main__":
    _runner.run(globals())
