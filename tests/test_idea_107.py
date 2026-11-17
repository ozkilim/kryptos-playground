"""Planted tests for idea 107: one word per worksheet line (column key plus a free letter per line)."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea107_lines as H
from kryptos.round9 import keyword_alphabet, solve_mod_p
from kryptos.round11 import POS, streams

ROOT = Path(__file__).resolve().parent.parent
TESTS = H.tests()
SCAN = H.Scanner(TESTS)
_A = []


def attack():
    if not _A:
        spec = importlib.util.spec_from_file_location("__main__x107", ROOT / "attacks" / "107_one_word_per_line.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _A.append(mod)
    return _A[0]


def _system(t):
    """The model of a test as plain linear equations: rows over its unknown key letters, one per clue letter."""
    cols = {}
    rows, where = [], []

    def u(name):
        return cols.setdefault(name, len(cols))

    prev = None
    for li, (blk, js) in enumerate(t.lines):
        for tt, j in enumerate(js):
            c = t.col(li, tt)
            if t.model == "add":
                r = {u(("a", li)): 1, u(("b", c)): 1}
            elif t.model == "speed":
                r = {u(("a", li)): c + t.base, u("b0"): 1}
            elif t.model == "ownspeed":
                r = {u(("a", li)): c, u(("s", li)): 1}
            else:           # slide: K_i = start of block + the moves so far
                if prev is None or prev[0] != blk:
                    acc = {u(("start", blk)): 1}
                else:
                    acc = dict(prev[1])
                    acc[u(("d", c))] = acc.get(u(("d", c)), 0) + 1
                prev = (blk, acc)
                r = acc
            rows.append(r)
            where.append(t.var(li, j))
    n = len(cols)
    return [[r.get(i, 0) for i in range(n)] for r in rows], where


def test_check_lists_match_the_linear_solver():
    rng = random.Random(107)
    assert len(TESTS) == 262 and min(len(t.checks) for t in TESTS) == 9
    t0 = TESTS[0]
    assert t0.parsing == "EAST|NORTH|EAST + BERLIN|CLOCK" and t0.model == "add" and len(t0.checks) == 14
    broken = 0
    for t in TESTS:
        rows, where = _system(t)
        # as many checks as the equations have spare, mod 13 and mod 2
        for p in (13, 2):
            part, basis = solve_mod_p(rows, [0] * 24, p)
            assert len(t.checks) == 24 - (len(rows[0]) - len(basis)), (t.name(), p)
        # a key stream made by the model passes; with one letter changed the checks say what the solver says
        # (a letter alone in its column is free, so a change there still fits)
        key = [rng.randrange(26) for _ in rows[0]]
        x = [rng.randrange(26) for _ in range(48)]
        for r, w in zip(rows, where):
            x[w] = sum(a * b for a, b in zip(r, key)) % 26
        assert H.slow_pass(t, x) and t.id in SCAN.scan(x), t.name()
        H.solve(t, x)
        y = list(x)
        y[where[rng.randrange(24)]] += 1 + rng.randrange(25)
        rhs = [y[w] % 26 for w in where]
        fits = solve_mod_p(rows, rhs, 13) is not None and solve_mod_p(rows, rhs, 2) is not None
        assert fits == H.slow_pass(t, y) == (t.id in SCAN.scan(y)), t.name()
        broken += not fits
    assert broken > 200


def test_east_clash_kills_the_headline_parsing_on_k4():
    w1, w2, possible = H.east_clash(K4)
    assert (w1, w2, possible) == ("FLRV", "GKSS", False)
    dead = [t for t in TESTS if H.clash_dead(t)]
    assert len(dead) == 68 and TESTS[0] in dead
    # so on any tableau those tests fail for K4: try a few hundred alphabets
    rng = random.Random(1)
    pl, cl = [CRIBS[i] for i in POS], [K4[i] for i in POS]
    for _ in range(150):
        m = "".join(rng.sample(H.AZ, 26))
        it = streams(m, pl, cl)
        for lay, _, kv, _, _ in it:
            kb = next(it)[2]
            assert not any(H.slow_pass(t, kv + kb) for t in dead)


def test_planted_lines_are_found_and_read():
    a = attack()
    vocab = H.reading_vocab()
    big = a.Quadgrams()                      # the small table is enough here
    words = ["SHADOW", "PALIMPSEST", "ABSCISSA", "LODESTONE", "COMPASS", "WELTZEITUHR", "CHECKPOINT", "CANDLE"]
    alphabets = [("(A-Z)", H.AZ), ("KRYPTOS", H.KRYPTOS_ALPHABET)] + [(w, keyword_alphabet(w)) for w in words]
    a.init(K4, CRIBS)
    for seed, (spec, name) in enumerate([(a.PLANTS[0], "PALIMPSEST"), (a.PLANTS[1], "LODESTONE"),
                                         (a.PLANTS[2], "COMPASS"), (a.PLANTS[4], "CANDLE")]):
        rng = random.Random(seed)
        m = dict(alphabets)[name]
        ct, pt, clue_forms = a.plant(rng, spec, m)
        t = a.true_test(TESTS, spec, clue_forms)
        a.init(ct, CRIBS)
        hits = a.work(alphabets)[0]
        assert (name, m, spec[6], t.id) in hits, spec
        assert all(h[0] == name for h in hits), hits        # only the true tableau passes anything
        r = a.read_hit((name, m, spec[6], t.id), ct, CRIBS, TESTS, vocab, big, noise=1)
        right = sum(x == y for i, (x, y) in enumerate(zip(r["reading"], pt)) if i not in CRIBS)
        wrong = sum(x != y and x != "?" for x, y in zip(r["reading"], pt))
        assert right >= 35 and wrong <= 6, (spec, right, wrong, r["reading"])
        assert r["evidence"] > 2 * max(r["chance_evidence"]) + 5


def test_k4_fails_on_the_two_carved_tableaux():
    a = attack()
    a.init(K4, CRIBS)
    hits, hist, n, near = a.work([("(A-Z)", H.AZ), ("KRYPTOS", H.KRYPTOS_ALPHABET)])
    assert hits == [] and n == 9


if __name__ == "__main__":
    _runner.run(globals())
