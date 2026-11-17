"""Planted tests for idea 95: two rotors in series, one wired from a keyword, one hidden."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea95_rotor as R
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
BIG = Quadgrams()                        # the small table is enough here
THEME = ["SHADOW", "PALIMPSEST", "ABSCISSA", "BERLIN", "LUXOR", "CLOCK"]
POOL = [(w, keyword_alphabet(w)) for w in ("MEDUSA", "LODESTONE", "COMPASS", "TUNNEL")]
AZAZ = ["ptAZ/ctAZ"]


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "95_keyword_rotor_plus_hidden_rotor.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pieces():
    assert R.wires_ok([1, 2, 1], [5, 6, 5])
    assert not R.wires_ok([1, 2, 1], [5, 6, 7])          # one contact to two places
    assert not R.wires_ok([1, 2], [5, 5])                # two contacts to one place
    m = keyword_alphabet("KRYPTOS")
    w = R.wiring(m, "strip/A-Z")
    assert R.inverse(w) == R.wiring(m, "A-Z/strip")
    assert R.wiring(m, "strip+0") == list(range(26))
    assert R.wiring(m, "strip+1")[R.AZI["K"]] == R.AZI["R"]
    shapes = R.slow_shapes()
    assert len(shapes) == 48 and len(set(r for _, r in shapes)) == 48
    # the model and its reader agree: a true setting reads back its own text
    rng = random.Random(1)
    hidden = list(range(26))
    rng.shuffle(hidden)
    pn = [rng.randrange(26) for _ in range(97)]
    s = [rng.randrange(26) for _ in range(97)]
    t = [0] * 50 + [7] * 47
    for cfg, r1, r2 in (("A", hidden, w), ("B", w, hidden)):
        cn = R.encrypt(pn, r1, r2, s, t)
        got = R.read(cfg, w, {i: pn[i] for i in range(97)}, cn, s, t)
        assert got == pn


def test_planted_found_and_read_back():
    m = attack()
    rng = random.Random(95)
    for cfg in "AB":
        for kind in ("speed", "key", "word"):
            ct, cribs, want, pt, tries = m.plant(rng, POOL, THEME, cfg, kind)
            m.init(ct, cribs, THEME, AZAZ, only=AZAZ)
            n, hits = m.work([(w, a, False) for w, a in POOL])
            assert want in hits, (cfg, kind, want)
            sc, got = m.complete(want, ct, cribs, BIG, dict(R.fast_rules(ct, THEME)))
            assert m.same_text(got, pt, want) and sc > -6.5, (cfg, kind, sc, got)
            assert all(got[i] == pt[i] for i in POS)


def test_step_inside_a_clue_block_form_a():
    m = attack()
    rng = random.Random(5)
    found = 0
    for _ in range(3):
        while True:
            ct, cribs, want, k, pt = m.draw(rng, POOL[:1], THEME, "A", "key", split=True)
            if k >= R.MIN:
                break
        m.init(ct, cribs, THEME, AZAZ, only=AZAZ)
        hits = m.work([(POOL[0][0], POOL[0][1], True)])[1]
        # this shape is only tried for rules with a forced pair of wires in the steady block
        pa, rel = m._S["pa"]["ptAZ/ctAZ"], dict(m._S["shapes"])[want[6]]
        need = [r[5] for r in pa["rec"] if m._S["rules"][r[0]][0] == want[4]][0]
        steady1 = len(set(rel[:R.N1])) == 1
        covered = any((b < R.N1) if steady1 else (a >= R.N1) for a, b, _ in need)
        assert ((k, "A") + want in hits) == covered
        found += covered
    assert found >= 2


def test_k4_clean_on_the_test_strips():
    m = attack()
    m.init(K4, CRIBS, THEME, AZAZ, only=AZAZ)
    n, hits = m.work([(w, a, False) for w, a in POOL])
    assert n > 10 ** 6 and not hits


if __name__ == "__main__":
    _runner.run(globals())
