"""Planted tests for idea 101: the second pass of the key word differs (read backwards, other form, other tableau)."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea101_passes as ip
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, english97
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
SMALL = Quadgrams()                      # the small table is enough to rank the readings here
WORDS = ("LODESTONE", "SHADOW", "MEDUSA", "BERLIN", "CLOCK", "PALIMPSEST", "ABSCISSA")
ALPHABETS = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)] + [(w, keyword_alphabet(w)) for w in WORDS]


def attack():
    spec = importlib.util.spec_from_file_location("__main__x101", ROOT / "attacks" / "101_second_pass_differs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_mirror_streams_and_checks():
    ks, T, c = ip.mirror_stream([1, 2, 3, 4], 2, 0)
    assert ks[:9] == [1, 2, 3, 4, 4, 3, 2, 1, 1] and (T, c) == (8, 7)
    ks, T, c = ip.mirror_stream([1, 2, 3, 4], 0, 0)
    assert ks[:7] == [1, 2, 3, 4, 3, 2, 1] and (T, c) == (6, 0)
    ks, T, c = ip.mirror_stream([1, 2, 3, 4], 1, 3)
    assert ks[3:11] == [1, 2, 3, 4, 4, 3, 2, 1] and T == 7
    assert all(ks[i] == ks[(c - i) % T] for i in range(20))            # the rule the test uses
    # carved rows restart at K4 letters 1, 5, 36, 67
    assert [ip.row_g(i) for i in (0, 3, 4, 34, 35, 65, 66, 96)] == [0, 3, 0, 30, 0, 30, 0, 30]
    tt = ip.catalogue(5)
    by = {}
    for t in tt:
        for st in t.aliases:
            by[st] = t.checks
    assert by["mirror", "V", 0, 0, 96] == 11                           # one fold at the middle letter of 97
    assert by["mirror", "V", 0, 32, 31] >= 7 and by["mirror", "B", 0, 48, 47] >= 7
    assert by["alt", ("V", "B"), 0, 11, 0] == 13 and by["period", "V", 42] == 11


def test_fast_scan_agrees_with_slow_test():
    m = attack()
    tt = m.tests()
    rng = random.Random(7)
    alpha = keyword_alphabet("PALIMPSEST")
    pt = english97(rng)
    ct = ip.encrypt_shift(pt, alpha, KRYPTOS_ALPHABET, "B", [rng.randrange(26) for _ in range(6)], 9, 2)
    pl, cl = [pt[i] for i in POS], [ct[i] for i in POS]
    ea, ec = ip.EngineA(tt), ip.EngineC(tt, pl, cl)
    fast = set(ip.scan_alphabet(alpha, pl, cl, ea, ec, tt))
    slow = set()
    for tid, t in enumerate(tt):                                       # first setting of every test, one at a time
        st = t.aliases[0]
        if st[0] == "tab":
            if ip.slow_pass(st, ("tab", alpha, st[1]), pl, cl):
                slow.add(("tab", tid))
        else:
            for lay in ip.LAYS:
                if ip.slow_pass(st, ip.layout_ctx(alpha, lay), pl, cl):
                    slow.add((lay, tid))
    assert fast == slow and any(tt[tid].aliases[0][:2] == ("shift", "B") and lay == "M/KR" for lay, tid in fast)


def test_planted_second_pass_found_and_k4_clean():
    m = attack()
    rng = random.Random(101)
    for case in m.planted_cases(rng, ALPHABETS + [("WELTZEITUHR", keyword_alphabet("WELTZEITUHR"))]):
        label, pt, ct, (name, alpha), lay, st = case
        cribs = {i: pt[i] for i in POS}
        m.init(ct, cribs)
        hits = m.headline(m.work(ALPHABETS + [(name, alpha)])[2])
        done = m.complete_all(sorted(hits, key=lambda h: -h[0]), ct, cribs, SMALL)
        true = [r for r in done if r[4] == st and r[5][2] == alpha and r[5][3] == lay]
        assert true, label                                             # the planted setting is a survivor
        assert true[0][5][0] == max(h[0] for h in hits)                # and no survivor has more checks
        assert all(a == b for a, b in zip(true[0][2], pt) if a != "?")
        if true[0][0] > -99:                                           # enough new text: it reads as the message
            assert all(a == b for a, b in zip(done[0][2], pt) if a != "?"), label
    m.init(K4, CRIBS)
    assert not m.headline(m.work(ALPHABETS)[2])                        # K4: nothing with 7+ checks on these tableaux


if __name__ == "__main__":
    _runner.run(globals())
