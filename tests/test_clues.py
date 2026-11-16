"""The clue pre-filter: probes measure what they claim on families we understand."""
import random
import _runner  # noqa: F401

from kryptos import clues as C
from kryptos.ciphers import AZ


def test_probes_on_known_families():
    two = C.probe(C._two_long, n=40)
    assert two["aligned"] == 1 and two["k5"] == 1
    tr = C.probe(C._columnar_only, n=40)
    assert tr["aligned"] < 0.3 and tr["k5"] < 0.1
    auto = C.probe("plaintext autokey", n=40)
    assert auto["aligned"] > 0.9 and auto["k5"] < 0.1  # in place, but the key depends on the message


def test_selective_masking_explains_kryptos_closeness():
    pr = C.probe(C._selective, n=60)
    m = C.marks_from_probe(pr, C.baseline())
    assert m["kryptos_close"][0] == C.E


def test_prefilter_verdicts():
    cd, _, _ = C.prefilter("pure transposition", C._columnar_only, {"not_pure_tr": (C.F, "")}, n=20, verbose=False)
    assert cd["verdict"] == "REJECT"
    cd, _, _ = C.prefilter("autokey", "plaintext autokey", {}, n=20, verbose=False)
    assert cd["verdict"] == "FLAG" and "k5" in cd["firm_fails"]
    cd, _, _ = C.prefilter("two keys", C._two_long, {"layer_two": (C.E, "")}, n=20, verbose=False)
    assert cd["verdict"] == "PASS" and "layer_two" in cd["explains"]


def test_every_family_marks_known_clues():
    ids = {c.id for c in C.CLUES}
    for f in C.FAMILIES:
        assert set(f.marks) <= ids, (f.id, set(f.marks) - ids)
        assert "cribs" in f.marks and "hand" in f.marks


if __name__ == "__main__":
    _runner.run(globals())
