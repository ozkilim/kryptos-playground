"""K4 crib checks, the experiment harness, the submission guard, and a
positive control for the crib-consistency attack."""
import contextlib
import csv
import importlib.util
import io
import _runner  # noqa: F401
from pathlib import Path

from kryptos import K4, CRIBS, crib_hits, passes_cribs, letters
from kryptos.check import crib_keys
from kryptos.ciphers import columnar_encrypt, vigenere_encrypt
from kryptos.harness import Experiment

ROOT = Path(__file__).resolve().parent.parent


def _fake_pass():
    fake = ["A"] * 97
    for i, ch in CRIBS.items():
        fake[i] = ch
    return "".join(fake)


def test_internal_check():
    fake = _fake_pass()
    assert crib_hits(fake) == 24 and passes_cribs(fake)
    assert crib_hits(K4) < 24 and not passes_cribs(K4)
    assert not passes_cribs(fake[:-1])
    assert letters("Berlin clock!") == "BERLINCLOCK"


def test_known_berlinclock_keystream():
    # Well-known result: under plain Vigenere, BERLINCLOCK needs key MUYKLGKORNA
    assert crib_keys()["vigenere"][-11:] == "MUYKLGKORNA"


def test_harness_logs_and_flags_passes(tmp_path):
    ledger = tmp_path / "ledger.csv"
    with Experiment("unit", puzzle="k4", quiet=True, results_dir=tmp_path, ledger=ledger) as ex:
        ex.add(K4, note="ciphertext")
        ex.add(_fake_pass(), note="planted")
    assert len(ex.passes) == 1 and ex.best[0]["cribs"] == 24
    rows = list(csv.DictReader(open(ledger)))
    assert rows[0]["full_passes"] == "1" and rows[0]["tried"] == "2"
    assert len(list(tmp_path.glob("*_k4_unit.json"))) == 1


def test_crib_consistency_attack_finds_a_planted_solution():
    spec = importlib.util.spec_from_file_location("a02", ROOT / "attacks" / "02_transposition_plus_vigenere.py")
    a02 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(a02)
    pt = ("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENRANAWAYINTOTHEDEEPDARKFORESTWHERE"
          "NOBODYCOULDEVERFINDITAGAIN")[:97]
    cribs = {i: pt[i] for i in list(range(21, 34)) + list(range(63, 74))}
    ct = vigenere_encrypt(columnar_encrypt(pt, [3, 1, 4, 0, 2]), "KEY")
    best = a02.scan(ct, cribs, max_width=5, max_period=4)
    assert best[3][0] == 24, best[3]


def test_submission_guard(tmp_path):
    from kryptos import external
    old = external.LOG
    external.LOG = tmp_path / "subs.csv"
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            assert external.prepare(K4, "k4", open_browser=False) is False    # fails cribs
            good = _fake_pass()
            assert external.prepare(good, "k4", open_browser=False) is True   # logged
            assert external.prepare(good, "k4", open_browser=False) is False  # no double paying
            assert external.prepare("HELLO", "k1", open_browser=False) is False  # solved: nothing to submit
    finally:
        external.LOG = old


if __name__ == "__main__":
    _runner.run(globals())
