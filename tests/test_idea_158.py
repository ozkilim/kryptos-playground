"""Idea 158: recited lists as exact running keys. A message keyed by the boxed compass from ENE must be found
on a dictionary tableau (hash join) and on a hidden alphabet (linear solve); the lists must hold what they
claim; K4 itself must have no hit on the plain tableaux."""
import importlib.util
import random
from pathlib import Path

import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea158_lists as L
from kryptos.ciphers import AZ
from kryptos.round9 import keyword_alphabet

ROOT = Path(__file__).resolve().parent.parent
STRS = L.streams()


def attack():
    spec = importlib.util.spec_from_file_location("a158", ROOT / "attacks" / "158_recited_list_keys.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_lists_say_what_they_should():
    texts = dict(STRS)
    box = texts["compass 32 points, English long"]
    assert box.startswith("NORTHNORTHBYEASTNORTHNORTHEASTNORTHEASTBYNORTHNORTHEASTNORTHEASTBYEASTEASTNORTHEAST")
    assert texts["compass 32 points, English long, said backwards"].startswith("NORTHBYWESTNORTHNORTHWEST")
    assert texts["German numbers 0-120"].startswith("NULLEINSZWEIDREIVIERFUENFSECHS")
    assert "EINUNDZWANZIGZWEIUNDZWANZIG" in texts["German numbers 0-120"]
    assert texts["German numbers 0-120 (umlauts dropped)"].startswith("NULLEINSZWEIDREIVIERFUNFSECHS")
    assert "NINETYNINEONEHUNDREDONEHUNDREDONE" in texts["English numbers 0-120"]
    assert "TWENTYFIRSTTWENTYSECOND" in texts["English ordinals 0-120"]
    assert texts["months"].startswith("JANUARYFEBRUARY") and "DECEMBERJANUARY" in texts["months"]
    assert texts["World Clock ring, best 1989 state, all plates"].startswith("AMSTERDAMBERLIN")
    assert L.roman(94) == "XCIV" and L.german(101) == "HUNDERTEINS" and L.english(115, True) == "ONEHUNDREDANDFIFTEEN"
    assert all(len(t) >= L.SPAN and set(t) <= set(AZ) for _, t in STRS) and len(STRS) > 500


def test_gate_is_the_known_k4_fact():
    eq, ne = L.gate_pairs(K4, CRIBS)
    assert [(L.POS[a], L.POS[c]) for a, c in eq] == [(27, 65)] and len(ne) == 22


def test_planted_compass_key_found():
    m = attack()
    rng = random.Random(158)
    small = [(n, t) for n, t in STRS if "compass 32" in n or "months" in n or n == "German numbers 0-120"
             or n.startswith("World Clock ring, best 1989 state, all plates")]
    alphabets = [("(A-Z)", AZ)] + [(w, keyword_alphabet(w)) for w in
                                   ("KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "LODESTONE", "BERLIN")]
    for label, ct, pt, kind, truth in m.plants(small, alphabets, rng)[:2]:
        case = m.planted_case((label, ct, pt, kind, truth, small, alphabets))
        assert case[1], case
    # an encrypt / decrypt round trip in every form
    key = small[0][1][7:7 + 97]
    pt = m.planted_text(rng)
    for lay in ("M/M", "M/AZ", "AZ/M", "M/KR", "KR/M"):
        for form in ("vig", "beau"):
            for sign in (1, -1):
                for kn in ("M", "AZ", "KR"):
                    a = alphabets[3][1]
                    assert L.decrypt(L.encrypt(pt, key, a, lay, form, sign, kn, 5), key, a, lay, form, sign, kn, 5) == pt


def test_k4_has_no_list_hit_on_small_tableaux():
    m = attack()
    small = [(n, t) for n, t in STRS if "compass" in n]
    alphabets = [("(A-Z)", AZ), ("KRYPTOS", keyword_alphabet("KRYPTOS"))]
    assert m.run_join(small, [K4], CRIBS, alphabets, procs=1) == []


if __name__ == "__main__":
    _runner.run(globals())
