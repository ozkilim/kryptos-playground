"""The negatives database: add, search, build, and pick up our own ledger runs."""
import csv
import _runner  # noqa: F401

from kryptos import negatives as neg
from kryptos.harness import LEDGER_FIELDS


def test_add_search_build(tmp_path):
    comm = tmp_path / "community.jsonl"
    eid = neg.add({"family": "polygraphic", "hypothesis": "Playfair with keyword KRYPTOS",
                   "outcome": "impossible: Playfair never maps a letter to itself in a digraph",
                   "confidence": "solid", "source": "https://example.com"}, path=comm)
    eid2 = neg.add({"family": "polygraphic", "hypothesis": "Playfair with keyword KRYPTOS",
                    "outcome": "dup", "confidence": "partial", "source": "x"}, path=comm)
    assert eid != eid2  # ids stay unique
    rows = neg.load_community(comm)
    assert len(neg.search("playfair", community=rows, ours=[])) == 2
    ledger = tmp_path / "ledger.csv"
    with open(ledger, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=LEDGER_FIELDS)
        w.writeheader()
        w.writerow({"timestamp": "2026-11-15T000000Z", "puzzle": "k4", "experiment": "demo",
                    "tried": "1000", "seconds": "1", "best_cribs": "3", "full_passes": "0",
                    "best_score": "-7", "best_plaintext": "X", "best_params": "{}", "notes": "n"})
        w.writerow({"timestamp": "2026-11-15T000001Z", "puzzle": "pk1", "experiment": "skip-me",
                    "tried": "5", "seconds": "1", "best_cribs": "", "full_passes": "0",
                    "best_score": "-5", "best_plaintext": "X", "best_params": "{}", "notes": ""})
    ours = neg.load_ours(ledger)
    assert [r["hypothesis"] for r in ours] == ["demo"]
    out, n_comm, n_ours = neg.build(tmp_path / "N.md", community=rows, ours=ours)
    text = out.read_text()
    assert (n_comm, n_ours) == (2, 1) and "Playfair with keyword KRYPTOS" in text and "demo" in text


def test_bad_confidence_rejected(tmp_path):
    try:
        neg.add({"family": "x", "hypothesis": "h", "outcome": "o", "confidence": "maybe",
                 "source": "s"}, path=tmp_path / "c.jsonl")
    except ValueError:
        return
    raise AssertionError("bad confidence accepted")


if __name__ == "__main__":
    _runner.run(globals())
