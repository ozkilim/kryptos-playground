"""Planted tests for idea 120: a known K1/K2 layer (ABSCISSA / PALIMPSEST on KRYPTOS or A-Z) in front of or
behind a key rule on a second tableau must be found at the true variant and read back in full."""
import importlib.util
import random
from pathlib import Path
import _runner  # noqa: F401

from kryptos import idea104_holes as H
from kryptos import idea120_layer as L
from kryptos.ciphers.substitution import KRYPTOS_ALPHABET as KR
from kryptos.data import load, letters
from kryptos.round11 import POS, dictionary_alphabets

_spec = importlib.util.spec_from_file_location(
    "a120", str(Path(__file__).resolve().parent.parent / "attacks" / "120_known_first_layer.py"))
A = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(A)


def test_known_layer_reproduces_k1_and_k2():
    for k, w in (("k1", "PALIMPSEST"), ("k2", "ABSCISSA")):
        d = load(k)
        assert L.layer(letters(d["plaintext"]), KR, w, 1, 0) == letters(d["ciphertext"])
        assert L.layer(letters(d["ciphertext"]), KR, w, 1, 0, inverse=True) == letters(d["plaintext"])


def test_fast_progressive_equals_idea104():
    rng = random.Random(3)
    alphas = dictionary_alphabets(mixed=False)[:40]
    for name, m in alphas:
        pl = [rng.choice(m) for _ in POS]
        cl = [rng.choice(m) for _ in POS]
        assert sorted(L.progressive_other(name, m, pl, cl)) == sorted(H.test_alphabet(name, m, pl, cl, ("progressive",)))


def test_three_plants_found_and_read_back():
    vs = L.variants()
    alphas = dictionary_alphabets(mixed=False)[:3000]
    rng = random.Random(1200)
    decoys = alphas[1:11]
    for kind in ("ABSCISSA then sliding", "progressive then PALIMPSEST", "plain autokey lag 2 under ABSCISSA"):
        ct, cribs, pt, vi, (name, m), rule, lay, form = A.plant(kind, rng, alphas, vs)
        jobs = L.jobs_for(vs, ct, cribs)
        hits = []
        for j, pl, cl in jobs:                         # every variant on the true alphabet
            hits += [h + (j,) for h in L.test_alphabet(name, m, pl, cl)]
        _, pl, cl = jobs[vi]
        for dn, dm in decoys:                          # decoy alphabets at the true variant
            assert not [h for h in L.test_alphabet(dn, dm, pl, cl) if h[0] >= L.MIN_CHECKS], (kind, dn)
        mine = [h for h in hits if h[7] == vi and h[2] == lay and h[3] == form and h[4].startswith(rule)]
        assert mine, kind
        assert all(h[7] == vi for h in hits), (kind, [vs[h[7]]["label"] for h in hits])
        assert L.read(mine[0], vs[vi], m, ct, cribs) == pt, kind
        for h in hits:                                 # sister rules may leave '?', never a wrong letter
            t = L.read(h, vs[vi], m, ct, cribs)
            assert all(a == "?" or a == b for a, b in zip(t, pt)), (kind, h)


if __name__ == "__main__":
    _runner.run(globals())
