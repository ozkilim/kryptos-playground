"""Planted tests for round 5: self-masking, Baudot/Vernam, Lorenz wheels, historic alphabets."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import load
from kryptos.ciphers import AZ
from kryptos.historic_alphabets import alphabets
from kryptos.teleprinter import CODE, LETTER

ROOT = Path(__file__).resolve().parent.parent
PT = load("k3")["plaintext"][40:137]
CR = {i: PT[i] for i in list(range(21, 34)) + list(range(63, 74))}


def _attack(n):
    path = next((ROOT / "attacks").glob(f"{n:02d}_*.py"))
    spec = importlib.util.spec_from_file_location(path.stem, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_historic_alphabets_are_permutations():
    for name, a in alphabets().items():
        assert sorted(a) == list(AZ), name


def test_self_masking_planted_found():
    a = _attack(33)
    a.CRIBS = CR
    s = [(5 * i + 3) % 97 for i in range(97)]
    ct = "".join(AZ[(AZ.index(PT[i]) + AZ.index(PT[s[i]])) % 26] for i in range(97))  # plaintext-keyed
    a._init(ct)
    _, hits = a._work(("decimation",))
    assert any(h[1] == "pt-keyed" and h[2] == ("decimation", 5, 3) and h[3] == "AZ" and h[4] == "vigenere"
               for h in hits)


def test_baudot_models_find_planted_keys():
    """Plant the clue equations directly (a real Vernam text can leave the letter set)."""
    a = _attack(34)
    rng = random.Random(4)
    key = [rng.randrange(32) for _ in range(9)]
    req = {i: key[i % 9] for i in CR}
    assert any(h[:2] == ("periodic", 9) for h in a.periodic(req))
    ct = "".join(rng.choice(AZ) for _ in range(97))
    req = {i: CODE[ct[i - 7]] for i in CR}  # ciphertext autokey, lag 7
    assert ("ct-autokey", 7) in a.autokey(ct, req)
    A = [rng.randrange(32) for _ in range(5)]
    B = [rng.randrange(32) for _ in range(7)]
    req = {i: A[i % 5] ^ B[i % 7] for i in CR}
    assert ("stacked", 5, 7) in a.stacked(req)


def test_lorenz_bit_wheels_found():
    a = _attack(36)
    rng = random.Random(9)
    periods = [3, 4, 5, 6, 7]
    wheels = [[rng.randrange(2) for _ in range(p)] for p in periods]
    req = {i: sum(wheels[b][i % periods[b]] << (4 - b) for b in range(5)) for i in CR}
    for b in range(5):
        assert periods[b] in a.bit_periods(req, b)


if __name__ == "__main__":
    _runner.run(globals())
