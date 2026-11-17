"""Planted tests for idea 91: the independent-encryptor audit. The textbook encryptors
(kryptos/idea91_textbook.py, no shared code with the attacks) must reproduce the sculpture, and
K4-shaped messages made with them must be found by the test functions of attacks 63, 66, 71, 72
and 74. A deliberately misplaced clue must NOT be found, so the audit can see a mistake."""
import json
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos import idea91_audit as audit
from kryptos import idea91_textbook as T

ROOT = Path(__file__).resolve().parent.parent


def test_textbook_file_shares_no_code():
    src = (ROOT / "kryptos" / "idea91_textbook.py").read_text()
    assert [ln for ln in src.split("\n") if ln.startswith(("import ", "from "))] == ["import random"]


def test_basics_typed_by_hand_agree_with_data():
    assert K4 == T.K4_TYPED and [len(r) for r in T.K4_ROWS] == [4, 31, 31, 31]
    assert dict(CRIBS) == T.clue_map()
    for first, last, plain, cipher in T.CLUES:
        assert K4[first - 1:last] == cipher
        assert "".join(CRIBS[i] for i in range(first - 1, last)) == plain
    rows = json.load(open(ROOT / "data" / "sculpture_layout.json"))["cipher_panel"]
    assert rows[-4].endswith("?OBKR") and tuple(rows[-3:]) == T.K4_ROWS[1:]


def test_textbook_encryptors_reproduce_the_sculpture():
    k2 = json.load(open(ROOT / "data" / "sculpture" / "k2.json"))
    assert T.k1_k2_check(k2["plaintext"], k2["ciphertext"]) == (True, True)
    assert T.k1_k2_check(k2["plaintext_corrected"], k2["ciphertext_corrected"])[1]
    panel = json.load(open(ROOT / "data" / "sculpture_layout.json"))["tableau_panel"]
    assert T.tableau_panel_check(panel) == 26
    key = T.repeating_key("LEMON", 30)
    text = T.only_letters(T.FILLER)[:30]
    assert T.tableau_encrypt(text, T.A2Z, T.A2Z, key, "A", True) == T.beaufort_by_square(text, key)
    assert T.column_mixed("KRYPTOS", False) == "KAHURBIVYCJWPDLXTEMZOFNSGQ"


def test_independent_plants_are_found():
    a = audit.Audit(random.Random(91), n_decoys=3)
    a.plant_63("Quagmire IV", True)
    a.plant_63("Quagmire I", False)
    a.plant_66("repeating", "M/AZ", True)
    a.plant_66("sliding", "KR/M", False)
    a.plant_66("progressive", "M/M", True)
    a.plant_66("autokey cipher", "AZ/M", False)
    a.plant_71a("KR", "AZ")
    a.plant_72("word")
    a.plant_72("previous cipher letter")
    a.plant_74("cipher", "A-Z/KRYPTOS faces")
    a.plant_74("cipher", "dictionary M/M")
    assert [r["status"] for r in a.records] == ["found"] * 11, [(r["model"], r["status"]) for r in a.records]


def test_a_misplaced_clue_is_not_found():
    n, found = audit.planted_mistake(91, 2)
    assert n == 6 and found == 0


if __name__ == "__main__":
    _runner.run(globals())
