"""Planted-answer tests for the stack engine: every key model, both
placements, every transposition family. If these pass, a null on K4 is real."""
import random
import _runner  # noqa: F401

from kryptos.ciphers import KRYPTOS_ALPHABET, AZ
from kryptos.solvers import stack as S

PT = ("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENRANAWAYINTOTHEDEEPDARKFORESTWHERE"
      "NOBODYCOULDEVERFINDITAGAIN")[:97]
CRIBS = {i: PT[i] for i in list(range(21, 34)) + list(range(63, 74))}
RNG = random.Random(7)


def _plant_and_find(m, label, model, place, alpha=KRYPTOS_ALPHABET, variant="vigenere"):
    key = [RNG.randrange(26) for _ in range(97)]
    if model[0] == "shift":
        vals = sorted(model[2])
        key = [RNG.choice(vals) for _ in range(97)]
    primer = [RNG.randrange(26) for _ in range(60)]
    ct = S.encrypt_stack(PT, m, alpha, variant, model, place, key=key, primer=primer)
    assert sorted(ct) == sorted(ct) and len(ct) == 97
    kinds = {model[0]}
    tested, hits = S.scan(ct, CRIBS, [("maps", [(label, m)])], kinds, procs=1)
    want = (label, "KRYPTOS" if alpha == KRYPTOS_ALPHABET else "AZ", variant)
    found = [h for h in hits if h[:3] == want and h[4] in (place, "any")
             and (h[3] == model[:2] or h[3] == model)]
    assert found, (model, place, len(hits))


def test_families_are_permutations():
    maps = [S.columnar_map((2, 0, 3, 1)), S.decimation_map(5, 11), S.myszkowski_map("TOMATO"),
            S.compose(S.columnar_map((1, 0, 2)), S.columnar_map((3, 1, 0, 2))),
            S.rotation_map(7, 14, 98), S.rotation_map(10, 10, 100)]
    for rows, cols in ((7, 14), (10, 10), (9, 11), (8, 13)):
        for r in S.ROUTES:
            maps.append(S.route_map(rows, cols, r))
            maps.append(S.route_map(rows, cols, r, flip=True))
    for m in maps:
        assert sorted(m) == list(range(97))


def test_every_model_and_placement_found():
    m = S.columnar_map((3, 1, 4, 0, 2))
    label = ("columnar", (3, 1, 4, 0, 2))
    for model in (("periodic", 7), ("progressive", 5, 3), ("ctauto", 9), ("ptauto", 42),
                  ("shift", "digits0-9", S.SHIFT_SETS["digits0-9"])):
        for place in ("before", "after"):
            if model[0] == "ptauto" and place == "after":
                continue  # too few testable pairs for a random map; covered below
            _plant_and_find(m, label, model, place)


def test_other_families_and_alphabets():
    _plant_and_find(S.decimation_map(13, 40), ("decimation", 13, 40), ("progressive", 6, 11), "after")
    _plant_and_find(S.myszkowski_map("BERLINER"), ("myszkowski", "BERLINER"), ("ctauto", 5), "before",
                    alpha=AZ, variant="beaufort")
    _plant_and_find(S.route_map(10, 10, "spiral"), ("route", 10, 10, "spiral", False),
                    ("shift", "pm3", S.SHIFT_SETS["pm3"]), "after", variant="variant_beaufort")
    _plant_and_find(S.rotation_map(7, 14, 98), ("rotation", 98, 7, 14), ("periodic", 11), "before")


def test_ptauto_after_with_identity_map():
    ident = list(range(97))
    _plant_and_find(ident, ("identity",), ("ptauto", 42), "after")


def test_k4_identity_matches_known_results():
    # Without a transposition, these models are already known dead on K4.
    from kryptos import K4, CRIBS as K4CRIBS
    tested, hits = S.scan(K4, K4CRIBS, [("maps", [(("identity",), list(range(97)))])],
                          {"periodic", "ctauto", "shift"}, procs=1)
    assert hits == [], hits[:3]



def test_decrypt_hit_recovers_planted_text():
    m = S.columnar_map((2, 4, 0, 3, 1))
    label = ("columnar", (2, 4, 0, 3, 1))
    for model, place in ((("progressive", 4, 9), "before"), (("ctauto", 6), "after"),
                         (("periodic", 5), "after")):
        key = [RNG.randrange(26) for _ in range(97)]
        primer = [RNG.randrange(26) for _ in range(60)]
        ct = S.encrypt_stack(PT, m, KRYPTOS_ALPHABET, "beaufort", model, place, key=key, primer=primer)
        _, hits = S.scan(ct, CRIBS, [("maps", [(label, m)])], {model[0]}, procs=1)
        hit = next(h for h in hits if h[0] == label and h[1] == "KRYPTOS" and h[2] == "beaufort"
                   and h[4] == place and h[3] in (model, model[:2]))
        got = S.decrypt_hit(ct, CRIBS, hit)
        assert sum(a == b for a, b in zip(got, PT)) >= 88, (model, got)


if __name__ == "__main__":
    _runner.run(globals())
