"""Planted tests for idea 114: a tableau with one flaw (header, row labels, strip, or one carved row)."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea114_flaw as F
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS, battery

ROOT = Path(__file__).resolve().parent.parent
WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS"]
ALPHAS = [("KRYPTOS", keyword_alphabet("KRYPTOS"))] + [(w, keyword_alphabet(w)) for w in WORDS]


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "114_flawed_chart.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pre_check_never_misses_a_battery_hit():
    rng = random.Random(7)
    hits = 0
    for trial in range(1500):
        p = rng.randrange(1, 13)
        w = [rng.randrange(26) for _ in range(p)]
        s = rng.randrange(1, 26)
        k = [w[i % p] for i in POS] if trial % 3 == 0 else [(w[i % p] + s * (i // p)) % 26 for i in POS]
        if trial % 3 == 2:
            k = [rng.choice((0, 1)) for _ in POS]
        xp = [rng.randrange(26) for _ in POS]
        want = sorted(battery(k, POS, xp=xp, xc=xp, skip=F.NEVER))
        assert sorted(F.check(k, xp, xp)) == want
        hits += len(want)
    assert hits > 1000


def test_flawed_encryption_round_trips_where_one_to_one():
    for flaw in (("col", 9, 1), ("row", 4, -1), ("body", 20, 1), ("cell", 15, 1, 13), None):
        for form in ("vig", "beau") if not flaw or flaw[0] != "cell" else ("vig",):
            for kv in range(26):
                for a in range(26):
                    b = F.enc_index(a, kv, form, flaw)
                    assert F.kv_of(a, b, form, flaw) is not None


def test_planted_flaws_found_with_the_cell_named_and_k4_is_clean():
    m = attack()
    rng = random.Random(114)
    for kind in ("col", "row", "body", "cell"):
        ct, cribs, truth, pt = m.plant(rng, ALPHAS, kind)
        name, alpha = next(x for x in ALPHAS if x[0] == truth[0])
        pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
        hits = m.test_cell(name, alpha, pl, cl, (13,))[0] if kind == "cell" else m.test_alphabet(name, alpha, pl, cl)[0]
        f = m.found(hits, truth)
        assert f is not None, truth
        txt = m.decrypt_hit(f, ct, cribs, dict(ALPHAS))
        assert sum(1 for x, y in zip(txt, pt) if x == y) >= 80, (truth, txt)
    pl, cl = [CRIBS[i] for i in POS], [K4[i] for i in POS]
    for name, alpha in ALPHAS[:4]:
        assert not m.test_alphabet(name, alpha, pl, cl)[0]
    assert not m.test_cell("KRYPTOS", ALPHAS[0][1], pl, cl)[0]


if __name__ == "__main__":
    _runner.run(globals())
