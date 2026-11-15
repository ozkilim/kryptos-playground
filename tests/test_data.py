"""Puzzle data integrity: lengths, cribs, nothing mistyped."""
import _runner  # noqa: F401
from kryptos import K4, CRIBS, load, all_ids, letters


def test_all_puzzles_load_with_right_lengths():
    ids = all_ids()
    assert ids[:4] == ["k1", "k2", "k3", "k4"] and len(ids) == 14
    for pid in ids:
        d = load(pid)
        assert len(letters(d["ciphertext"])) == d["length"], pid


def test_sculpture_totals_match_wikipedia():
    # Left side: 869 characters = 865 letters + 4 question marks
    # (3 inside K2, 1 between K3 and K4 which we don't store).
    assert sum(len(load(k)["ciphertext"]) for k in ("k1", "k2", "k3", "k4")) == 868
    assert sum(load(k)["length"] for k in ("k1", "k2", "k3", "k4")) == 865


def test_k4_cribs_line_up():
    assert len(K4) == 97
    assert K4[21:34] == "FLRVQQPRNGKSS"
    assert K4[63:74] == "NYPVTTMZFPK"
    assert "".join(CRIBS[i] for i in range(21, 34)) == "EASTNORTHEAST"
    assert "".join(CRIBS[i] for i in range(63, 74)) == "BERLINCLOCK"


def test_solved_plaintexts_present():
    for k in ("k1", "k2", "k3"):
        d = load(k)
        assert d["status"] == "solved" and len(letters(d["plaintext"])) == d["length"]


if __name__ == "__main__":
    _runner.run(globals())
