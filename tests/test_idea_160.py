"""Idea 160: find the letter on the panel, write its neighbour. A message written by the search-and-step
rule on the cipher panel with the east-north-east offset must be read back from its start cell (forward
role), and a message whose PLAIN letters were searched must pass the exact clue-word test and decode with
the clue letters (reverse role). K4 itself must not pass either on that panel."""
import importlib.util
import random
from pathlib import Path

import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea160_neighbour as H

ROOT = Path(__file__).resolve().parent.parent
PANELS = H.panels()
CP = H.Text("cipher panel, K1-K3 cells only", PANELS["cipher panel, K1-K3 cells only"], "left", "rows")
ENE = (-1, 2)


def attack():
    spec = importlib.util.spec_from_file_location("a160", ROOT / "attacks" / "160_find_letter_write_neighbour.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_panels_are_the_carved_text():
    assert CP.n == 772 and CP.T.startswith("EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQ") and CP.T.endswith("DOHW?")
    full = PANELS["cipher panel, all 28 rows"]
    assert "".join(full).endswith(K4) and sum(len(r) for r in full) == 869
    pp = PANELS["K1-K3 plaintext in the carved cells"]
    assert pp[0].startswith("BETWEENSUBTLESHADING") and [len(r) for r in pp] == [len(r) for r in CP_ROWS()]
    # east-north-east of the first cell of row 1 (Y) is the third cell of row 0 (U)
    oi = CP.off(ENE)
    j = CP.cell.index((1, 0))
    assert CP.T[j] == "Y" and CP.offs[oi][2][j] == "U"


def CP_ROWS():
    return PANELS["cipher panel, K1-K3 cells only"]


def test_forward_planted_read_back():
    rng = random.Random(160)
    oi = CP.off(ENE)
    for rule in ("next", "row-reset", "jump"):
        s = rng.randrange(CP.n)
        pt = None
        while pt is None:
            pt = H.word_message(CP, rule, oi, s, rng)
        ct = CP.encode(pt, rule, oi, s, rng)
        assert ct and len(ct) == 97 and CP.read(ct, rule, oi, s) == pt
        hits = [(r, o) for r, o, text, s0, m in CP.readings(ct, rules=(rule,)) if text == pt]
        assert (rule, oi) in hits


def test_reverse_planted_passes_and_decodes():
    m = attack()
    rng = random.Random(161)
    oi = CP.off(ENE)
    pt = H.english_message(rng)
    ct = None
    while ct is None:
        s = rng.randrange(CP.n)
        ct = CP.write(pt, "next", oi, s)
    assert CP.segment_fit(pt[21:34], ct[21:34], "next", oi, 21) == 13
    assert CP.segment_fit(pt[63:74], ct[63:74], "next", oi, 63) == 11
    n, dec = CP.decode_reverse(ct, {i: pt[i] for i in CRIBS}, "next", oi, m.big(), beam=200)
    assert dec and sum(a == b for a, b in zip(dec[0][1], pt)) >= 85


def test_k4_does_not_pass_on_the_cipher_panel():
    best = max(H.clue_count(r, CRIBS) for rule, oi, r, s, mult in CP.readings(K4))
    assert best < 12
    oi = CP.off(ENE)
    a = CP.segment_fit("EASTNORTHEAST", K4[21:34], "next", oi, 21)
    b = CP.segment_fit("BERLINCLOCK", K4[63:74], "next", oi, 63)
    assert a + b < 12


def test_ordinary_english_cannot_be_written_forward():
    rng = random.Random(162)
    oi = CP.off(ENE)
    assert all(CP.reach(H.english_message(rng), "next", oi) < 97 for _ in range(10))


if __name__ == "__main__":
    _runner.run(globals())
