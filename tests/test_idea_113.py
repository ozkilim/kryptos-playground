"""Planted test for idea 113: Quagmire IV with both alphabets hidden and a key of 8, searched by the plain places."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea113_both as B
from kryptos.data import DATA_DIR
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
SMALL = DATA_DIR / "english" / "quadgrams.txt"


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "113_both_hidden_length8.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_k4_structure():
    s = B.System(K4, CRIBS, 0)
    assert s.shape() == (4, (11, 3), 13)
    assert s.open_checks() and B.Enumerator(s, True).regular()
    assert len(s.forced) == 45


def test_planted_found_and_read_back():
    A = attack()
    want = B.System(K4, CRIBS, 0).shape()
    for seed, W in ((5, 0), (6, 13)):
        ct, pt, pa, beau, _ = A.plant(random.Random(seed), W, want)
        sysm = B.System(ct, CRIBS, W)
        en = B.Enumerator(sysm, True)
        order = en.plan_order()
        X = [((-1 if beau else 1) * pa.index(c)) % 26 for c in sysm.letters]
        vals, _ = B.true_vals(en, order, X)
        Xc = B.leaf_to_X(en, order, vals)
        assert sysm.evaluate(Xc) is not None
        # the forced letters of the true setting are the plaintext's letters
        fr = B.forced_reading(sysm, Xc)
        assert all(f == p or (f == "?" and p not in sysm.letters) for f, p in zip(fr, pt) if f != ".")
        # a search with the first free letters fixed generates the true setting and ranks it near the top
        T0, T, C = B.class_tables(SMALL, sysm.letters)
        fn = B.build(ct, CRIBS, W, True)[3]
        doms = [[v] for v in vals[:4]] + [list(range(26))] * (len(vals) - 4)
        cnt, above, top, _, _ = fn(doms, T, T0, C, 50, fn(B.single(vals), T, T0, C, 1, 1e300)[2][0][0])
        assert cnt > 1000 and any(tuple(v) == tuple(vals) for _, v in top), (cnt, above)
        # completion reads the message back
        sc, reading = B.Completer(sysm, Xc, Quadgrams(SMALL)).anneal(random.Random(1), 6000, 2)
        assert sum(a == b for a, b in zip(reading, pt)) >= 70, reading


if __name__ == "__main__":
    _runner.run(globals())
