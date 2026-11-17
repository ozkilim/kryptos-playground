"""Planted tests for idea 92: key formulas with a hidden tableau alphabet (kryptos/idea92_hidden.py)."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
from kryptos.data import DATA_DIR, load, letters
from kryptos.score import Quadgrams
from kryptos.solvers.freealpha import solve_exact
from kryptos import idea92_hidden as h

TEXT = letters(load("k2")["plaintext"] + load("k3")["plaintext"] + load("k1")["plaintext"])
LIB = h.library(small=True)
SCORE = h.Scorer(Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt"))


def brute(layout, ct, cribs, k):
    """An independent check: can one alphabet satisfy every clue letter with key values k?"""
    if layout == "V":       # the union-find of kryptos/solvers/freealpha.py, both sides on one alphabet
        return solve_exact([(("P", ct[i]), ("P", p), k[i]) for i, p in cribs.items()]) is not None
    if layout == "B":       # piece by piece: try every position for one letter and follow the clue letters
        edges = [(ct[i], p, k[i]) for i, p in cribs.items()]
        done = set()
        for start in sorted({u for u, _, _ in edges} | {v for _, v, _ in edges}):
            if start in done:
                continue
            fits = False
            for r in range(26):
                x, ok, grew = {start: r}, True, True
                while grew and ok:
                    grew = False
                    for u, v, kk in edges:
                        for a, b_ in ((u, v), (v, u)):
                            if a in x:
                                want = (kk - x[a]) % 26
                                if b_ not in x:
                                    x[b_], grew = want, True
                                elif x[b_] != want:
                                    ok = False
                done |= set(x)
                if ok and len(set(x.values())) == len(x):
                    fits = True
                    break
            if not fits:
                return False
        return True
    fixed = AZ if layout.endswith("AZ") else KRYPTOS_ALPHABET
    x = {}
    for i, p in cribs.items():
        letter, v = (p, fixed.index(ct[i]) - k[i]) if layout.startswith("hp") else (ct[i], fixed.index(p) + k[i])
        if x.setdefault(letter, v % 26) != v % 26:
            return False
    return len(set(x.values())) == len(x)


def test_k4_clue_graph():
    v, b = h.plan("V", K4, CRIBS), h.plan("B", K4, CRIBS)
    assert h.loops(v) == (4, 0, 21, 1)             # 24 clue letters, 21 letters in one piece, 4 loops
    assert h.loops(b) == (3, 1, 21, 1)             # Beaufort: one loop only fixes where the alphabet sits
    assert h.loops(h.plan("hpAZ", K4, CRIBS))[:3] == (11, 0, 13)
    assert h.loops(h.plan("hcKR", K4, CRIBS))[:3] == (10, 0, 14)
    assert abs(h.pass_chance(v)[1] / 1.42e-11 - 1) < 0.01
    # S encrypts to S (position 32) and K to K (position 73): in layout V the key must be 0 there
    pos = sorted(CRIBS)

    def passes(ks):
        return all((sum(a * b for a, b in zip(f, ks)) + f[-1]) % 26 == 0 for f in v["c26"])

    assert passes([0] * 24)
    for i in (32, 73):
        assert not passes([int(p == i) for p in pos])
    assert not passes([1] * 24)


def test_fast_test_agrees_with_plain_solvers():
    rng = random.Random(92)
    few = {i: CRIBS[i] for i in sorted(CRIBS)[:9]}          # few clue letters, so that keys pass often
    seen = {True: 0, False: 0}
    for lay in h.LAYOUTS:
        for ct, cribs in ((K4, few), (K4, CRIBS)):
            t = h.Tables(lay, ct, cribs, lib=LIB)
            pos = t.pl["pos"]
            for _ in range(150):
                es = tuple(sorted(rng.sample(range(t.nE), rng.randrange(0, 4))))
                if len({e // 25 for e in es}) < len(es):
                    continue
                c = rng.choice(t.pl["cvals"])
                ks = t.clue_stream(es, c)
                key_ok = all((sum(a * b for a, b in zip(f, ks)) + f[-1]) % 26 == 0 for f in t.pl["c26"][:h.KEY])
                fast = key_ok and bool(t.check(es, c))
                slow = brute(lay, ct, cribs, dict(zip(pos, ks)))
                assert fast == slow, (lay, es, c)
                seen[slow] += 1
    assert seen[True] > 20 and seen[False] > 200


def planted(lay, terms, seed, sizes=(0, 1, 2)):
    rng = random.Random(seed)
    ct, cribs, pt, x, k, _ = h.plant(lay, terms, rng, TEXT, LIB)
    r = h.search(lay, ct, cribs, small=True, sizes=sizes, procs=1)
    for es, c, _ in r["hits"][::17]:                        # the fits are real fits
        assert brute(lay, ct, cribs, dict(zip(r["tables"].pl["pos"], r["tables"].clue_stream(es, c))))
    rows, total, nread = h.read_hits(r, ct, SCORE, rng)
    assert h.canon(lay, k) in {h.canon(lay, row[4]) for row in rows}
    # the best reading is the message (a rare letter the clues do not place may be guessed wrong)
    assert h.same_reading(rows[0][1], pt) >= 90 and rows[0][0] > -5.1, (lay, terms, rows[0][:3])
    return r


def test_planted_progressive_key():
    planted("V", [(3, "i")], 1)
    planted("B", [(3, "i")], 2)


def test_planted_quadratic_key():
    planted("V", [(5, "i^2"), (10, "i")], 3)
    planted("B", [(5, "i^2"), (10, "i")], 4)
    planted("hpKR", [(5, "i^2"), (10, "i")], 5)


def test_planted_row_plus_column_key():
    planted("V", [(7, "row7"), (4, "col7")], 6)
    planted("B", [(7, "row7"), (4, "col7")], 7)
    planted("hcAZ", [(7, "row7"), (4, "col7")], 8)


def test_planted_three_ingredients():
    planted("V", [(7, "row7"), (4, "col7"), (9, "prime+0")], 9, sizes=(3,))


def test_wrong_layout_and_k4_do_not_fit():
    rng = random.Random(10)
    ct, cribs, pt, x, k, _ = h.plant("V", [(7, "row7"), (4, "col7")], rng, TEXT, LIB)
    assert not h.search("hpAZ", ct, cribs, small=True, sizes=(0, 1, 2), procs=1)["hits"]
    for lay in h.LAYOUTS:                                   # K4 on the small library: nothing
        assert not h.search(lay, K4, CRIBS, small=True, sizes=(0, 1, 2), procs=1)["hits"]


if __name__ == "__main__":
    _runner.run(globals())
