"""Planted test for idea 115: two sculpture texts added together as the key, and one text plus a word."""
import importlib.util
import _runner  # noqa: F401
from pathlib import Path

from kryptos import idea115_twotexts as H
from kryptos.ciphers import AZ
from kryptos.ciphers.substitution import KRYPTOS_ALPHABET
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent


def attack():
    spec = importlib.util.spec_from_file_location("a115", ROOT / "attacks" / "115_two_sculpture_texts.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_part_b_functionals_count_checks():
    for L in range(1, 11):
        assert len(H.functionals("rep", L)) == H.checks_periodic(L)
        assert len(H.functionals("slide", L)) == 23 - L


def test_planted_two_texts_and_text_plus_word():
    m = attack()
    m.TESTS = [("rep", 6)]                      # only the table plant 4 needs, to stay fast
    m.FUNCS = {t: H.functionals(*t) for t in m.TESTS}
    texts = H.all_texts()
    tabs = m.part_b_tables(texts)
    big = Quadgrams()                         # the small model is enough to read back a planted text
    ok1, lines1 = m.planted([("KRYPTOS", KRYPTOS_ALPHABET)], texts, tabs, big, procs=1, only=(1,))
    ok2, lines2 = m.planted([("A-Z", AZ)], texts, tabs, big, procs=1, only=(2, 4))
    assert ok1 + ok2 == 3, lines1 + lines2


if __name__ == "__main__":
    _runner.run(globals())
