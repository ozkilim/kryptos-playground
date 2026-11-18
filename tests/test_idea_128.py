"""Planted test for idea 128: two-word keys on one hidden alphabet, joined through the forced key slots."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea93_hidden as H
from kryptos import idea128_pairs as P
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
DECOYS = ["SHADOW", "FORCES", "BERLIN", "CLOCK", "WISE", "PALIMPSEST", "ABSCISSA", "LAYER", "TWO", "EAST",
          "NORTH", "LIGHT", "MAGNETIC", "FIELD", "UNDERGROUND", "POSITION", "LUCID", "MEMORY", "SECRET", "AGENCY",
          "COMPASS", "DIRECTION", "WORLD", "QUARTER", "MINUTES", "SECONDS", "DEGREES", "LANGLEY", "VIRGINIA",
          "TOMB", "CHAMBER", "CANDLE", "PASSAGE", "DEBRIS", "OPENING", "VISIBLE", "INVISIBLE", "DIGETAL"]


def attack():
    spec = importlib.util.spec_from_file_location("attack128", ROOT / "attacks" / "128_two_word_keys_hidden_tableau.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_planted_two_word_keys_are_found_and_read_back():
    m = attack()
    small = Quadgrams()
    for n, spec in ((0, m.PLANTS[0]), (3, m.PLANTS[3])):      # SHADOW+FORCES (Quagmire III), CLOCK+WISE (numeric)
        assert m.planted_case(random.Random(1280 + n), spec, list(DECOYS), small, procs=1)


def test_joins_match_brute_force():
    """The joined pairs are exactly the pairs that pass the forced-equal / forced-different conditions."""
    from kryptos.round9 import shuffled_control
    T = H.Tables(shuffled_control(7), CRIBS)
    t = T.loc[2]
    words = sorted(set(DECOYS))
    by = {}
    for w in words:
        by.setdefault(len(w), []).append(w)
    alive = joined = 0
    for a, b, phi in [(a, b, phi) for a, b in ((6, 6), (5, 8), (7, 6)) for phi in range(a + b)]:
        cond = P.located_conditions(t, P.clue_slots(P.template("pair", a, b), phi))
        if cond is None:
            continue
        alive += 1
        _, groups = P.located_join(cond, by.get(a, []), by.get(b, []))
        got = {(A, B) for la, lb in groups for A in la for B in lb}
        want = set()
        for A in by.get(a, []):
            for B in by.get(b, []):
                key = A + B
                kl = [key[(i + phi) % len(key)] for i in H.POS]
                if all(kl[p] == kl[q] for p, q in t["eq"]) and all(kl[p] != kl[q] for p, q in t["ne"]):
                    want.add((A, B))
        assert got == want
        joined += len(got)
    assert alive >= 5 and joined >= 5, (alive, joined)


def test_k4_quagmire3_plus_and_minus_dead_at_periods_up_to_26():
    T = H.Tables(K4, CRIBS)
    for li in (0, 1):
        for L in range(4, 27):
            assert P.located_conditions(T.loc[li], P.clue_slots(P.template("pair", 2, L - 2), 0)) is None


if __name__ == "__main__":
    _runner.run(globals())
