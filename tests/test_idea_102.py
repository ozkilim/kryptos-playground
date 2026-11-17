"""Planted tests for idea 102: one place lost in the key inside a clue word."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea102_slip as S
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS
from kryptos.score import quadgram_score

ROOT = Path(__file__).resolve().parent.parent
WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "102_lost_place_in_key.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_slip_equations():
    # repeating key, block 1, key letter skipped before letter 3: places 0 1 2 4 5 ...
    terms, zeros, sums = S.block_system("repeating", 0, 5, 3, 1)
    assert [r for r, _ in terms][:6] == [0, 1, 2, 4, 0, 1] and not zeros and not sums
    # running key, a place used twice gives a zero difference; a skipped place gives a sum of two word letters
    assert S.block_system("slide-stream", 1, 4, 2, -1)[1] == [24 + 13 + 1]
    assert S.block_system("slide-stream", 1, 4, 2, 1)[2] == [(2, 3, 24 + 13 + 1)]
    assert S.block_system("slide-word", 1, 4, 2, -1)[0][:3] == [(1, 37), (1, 38), (2, 39)]


def test_fast_search_equals_the_plain_loop():
    rng = random.Random(5)
    st = S.all_settings(5)
    total = 0
    for trial in range(3):
        if trial == 0:
            k = [rng.choice((0, 0, 0, 5)) for _ in range(24)]
        else:
            test, ck, rule, L, c1, c2, x = rng.choice([s for s in st if s[0] == "BC"[trial - 1]])
            w = [rng.randrange(26) for _ in range(L)]
            terms, zeros, sums = S.system(rule, L, c1, c2, max(x, 0))
            V = [rng.randrange(26) for _ in range(48)]
            for r, vi in terms:
                V[vi] = w[r]
            for vi in zeros:
                V[vi] = 0
            for r1, r2, vi in sums:
                V[vi] = (w[r1] + w[r2]) % 26
            k = V[:24]
            if rule != "repeating":
                k = [3]
                for j in range(23):
                    k.append((k[-1] + V[24 + j]) % 26)
        slow = S.slow_hits(k, 5)
        assert slow == S.fast_hits(k, 5)
        total += len(slow)
    assert total >= 3


def test_planted_slips_are_found_named_and_read_back():
    m = attack()
    rng = random.Random(102)
    for kind in ("skip27", "double-berlin", "both", "alone"):
        ct, cribs, pt, (name, lay, form), want = S.plant(rng, ALPHAS, kind)
        alpha = dict(ALPHAS)[name]
        hits = m.test_alphabet(name, alpha, [cribs[i] for i in POS], [ct[i] for i in POS], 5)
        assert (want[1], name, lay, form, want) in hits, want
        assert want[0] == S.PLANTS[kind][3]
        if kind != "alone":
            text, unknown = S.decrypt(ct, cribs, alpha, lay, form, want, quadgram_score)
            assert unknown == 0
            assert sum(1 for p, q in zip(pt, text) if p == q) >= 90
    assert S.describe(want).endswith("clue 2: key letter used twice before text letter 66")
    for name, alpha in ALPHAS:
        hits = m.test_alphabet(name, alpha, [CRIBS[i] for i in POS], [K4[i] for i in POS], 5)
        assert not [h for h in hits if h[0] >= 7]


if __name__ == "__main__":
    _runner.run(globals())
