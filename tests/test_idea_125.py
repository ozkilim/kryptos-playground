"""Planted tests for idea 125: misspelled keyword alphabets and other alphabet constructions through
the key-rule battery, and the Quagmire IV join with part-2 alphabets."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea125_alphabets as A
from kryptos import idea120_layer as L
from kryptos.round9 import keyword_alphabet
from kryptos.round11 import POS

ROOT = Path(__file__).resolve().parent.parent
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def attack():
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / "125_misspelled_keyword_alphabets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _decoys(rng, n=40):
    out = []
    for w in ("SHADOW", "MEDUSA", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS", "LANGLEY"):
        out += [(e + "<-" + w, keyword_alphabet(e)) for e in rng.sample(A.edits(w), 3)]
        out += [(w + "@" + how, A.construct(w, how)) for how in A.HOWS]
    return out[:n]


def test_constructions():
    assert "PALIMPCEST" in A.edits("PALIMPSEST")
    assert "DESPARATELY" in A.edits("DESPERATELY")
    assert "UNDERGRUND" in A.edits("UNDERGROUND") and "UNDERGROUUND" in A.edits("UNDERGROUND")
    assert A.construct("KRYPTOS", "rev") == "KRYPTOSZXWVUQNMLJIHGFEDCBA"
    assert A.construct("KRYPTOS", "wrap") == "KRYPTOSUVWXZABCDEFGHIJLMNQ"
    assert A.construct("KRYPTOS", "end") == "ABCDEFGHIJLMNQUVWXZKRYPTOS"
    assert A.construct("BANANA", "last") == "BNACDEFGHIJKLMOPQRSTUVWXYZ"
    assert A.construct("CLUE", "swapQL") == "CQUEABDFGHIJKMNOPLRSTVWXYZ"
    for how in A.HOWS:
        assert sorted(A.construct("HOROLOGE", how)) == list(AZ)


def test_planted_battery_only_true_reading():
    mod = attack()
    rng = random.Random(7)
    decoys = _decoys(rng)
    p1 = [("BERLINKLOCK<-BERLINCLOCK", keyword_alphabet("BERLINKLOCK"))]
    p2 = [("CLOCK@wrap", A.construct("CLOCK", "wrap"))]
    for kind in mod.PLANTS:
        ct, pt, (name, m), rule, lay, form = mod.plant(kind, rng, p1, p2, [])
        alphas = decoys + [(name, m)]
        A.init([CRIBS[i] for i in POS], [ct[i] for i in POS])
        _, hits = A.work(alphas)
        assert hits and all(h[1] == name for h in hits), (kind, hits[:3])
        mine = [h for h in hits if h[2] == lay and h[3] == form and h[4].startswith(rule)]
        assert mine, (kind, hits)
        assert A.read(mine[0], m, ct, CRIBS) == pt, kind
    A.init([CRIBS[i] for i in POS], [K4[i] for i in POS])
    assert A.work(decoys)[1] == []


def test_planted_join():
    rng = random.Random(9)
    pt = attack().with_clues("".join(rng.choice(AZ) for _ in range(97)))
    dic = [keyword_alphabet(w) for w in ("SHADOW", "MEDUSA", "ABSCISSA", "BERLIN", "COMPASS")]
    p2 = [A.construct(w, h) for w in ("KRYPTOS", "LANGLEY") for h in ("rev", "end", "wrap")]
    key = [rng.randrange(26) for _ in range(13)]
    ct = A.quag4_encrypt(pt, p2[1], dic[2], key, "beau")
    A.join_init(dic + p2, len(dic))
    p, out, counts = A.join_one((13, CRIBS, [("planted", ct), ("K4", K4)]))
    assert ("beau", len(dic) + 1, 2) in out["planted"] and counts["K4"] == 0
    got = A.join_decrypt(ct, CRIBS, 13, "beau", p2[1], dic[2])
    assert got == pt


if __name__ == "__main__":
    _runner.run(globals())
