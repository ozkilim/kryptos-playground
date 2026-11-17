"""Planted tests for idea 105: the independent-encryptor audit, part 2. The new textbook encryptors
(kryptos/idea105_textbook.py, no shared code with the attacks) must reproduce Byrne's Chaocipher
example and the carved K3, and K4-shaped messages made with them must be found by the test
functions of the attacks audited (68, 70, 81, 88, 90, 54, 60, 61, 62, 65, 69, 73, 79, 84,
86). A deliberately misplaced clue must NOT be found, so the audit can see a mistake."""
import json
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import idea105_audit as audit
from kryptos import idea105_textbook as X
from kryptos import idea91_textbook as T

ROOT = Path(__file__).resolve().parent.parent


def test_textbook_file_shares_no_code_with_the_attacks():
    src = (ROOT / "kryptos" / "idea105_textbook.py").read_text()
    imports = [ln for ln in src.split("\n") if ln.startswith(("import ", "from "))]
    assert imports == ["import random", "from . import idea91_textbook as T"], imports


def test_textbook_encryptors_against_known_answers():
    assert X.chaocipher_encrypt(X.CHAO_PLAIN, X.CHAO_LEFT, X.CHAO_RIGHT) == X.CHAO_CIPHER
    k3 = json.load(open(ROOT / "data" / "sculpture" / "k3.json"))
    plain = [c for c in k3["plaintext"].upper() if c.isalpha()]
    carved = [c for c in k3["ciphertext"].upper() if c.isalpha()]
    assert X.quarter_turn(X.quarter_turn(plain, 42), 14) == carved
    m = T.keyword_alphabet("SHADOW")
    text, key = T.only_letters(T.FILLER)[:50], T.repeating_key("LEMON", 50)
    assert X.wheel_encrypt(text, m, T.A2Z, key, "A", True) == T.tableau_encrypt(text, m, T.A2Z, key, "A", True)
    words = X.spaced_k4(random.Random(5))
    flat = "".join(words)
    assert len(flat) == 97 and flat[21:34] == "EASTNORTHEAST" and flat[63:74] == "BERLINCLOCK"


def test_independent_plants_are_found():
    a = audit.Audit(random.Random(105), n_decoys=3)
    a.plant_68("clue 1 alone", "sliding")
    a.plant_68("gap", "repeating")
    a.plant_70("sliding")
    a.plant_81("sliding", "plain")
    a.plant_88("repeating")
    a.plant_90("cipher", 7, 7)
    a.plant_54("grid row + column")
    a.plant_60_slidefair("Beaufort")
    a.plant_61("quarter turn")
    a.plant_62(4, 6)
    a.plant_65_chain("taps up to 8 back")
    a.plant_69("two tableaux, same cipher strip")
    a.plant_73("Chaocipher")
    a.plant_54("position", gap=True)
    a.plant_84("A-Z, KRYPTOS and theme alphabets")
    a.plant_86("slide")
    bad = [(r["attack"], r["model"], r["status"], r["params"]) for r in a.records if r["status"] == "HOLE"]
    assert not bad, bad
    assert sum(r["status"] == "found" for r in a.records) >= 13, [(r["attack"], r["status"]) for r in a.records]


def test_a_misplaced_clue_is_not_found():
    found = []
    for i in (1, 3, 8):                             # attacks 68, 70, 61
        found += [r for r in audit.planted_mistake((i, 1, 105)) if r["status"] == "found"]
    assert not found, found


if __name__ == "__main__":
    _runner.run(globals())
