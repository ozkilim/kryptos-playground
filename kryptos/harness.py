"""The experiment harness: run lots of free tests, keep score, never lose a result.

    from kryptos.harness import Experiment

    with Experiment("vigenere-wordlist", puzzle="k4", notes="dict words, both alphabets") as ex:
        for key in words:
            ex.add(vigenere_decrypt(K4, key), key=key)

For each candidate it computes crib hits (K4 only) and quadgram score, and
keeps the best N. When the block ends it:
  * writes every kept candidate to  results/<date>_<name>.json   (gitignored)
  * appends one summary line to     experiments/ledger.csv       (committed:
    the team's shared memory of what has already been tried)
  * shouts if anything passed all 24 cribs.
"""

import csv
import hashlib
import heapq
import json
import time
from datetime import datetime, timezone

from .data import ROOT, letters
from .check import crib_hits, passes_cribs
from .score import quadgram_score

RESULTS_DIR = ROOT / "results"
LEDGER = ROOT / "experiments" / "ledger.csv"
LEDGER_FIELDS = ["timestamp", "puzzle", "experiment", "tried", "seconds", "best_cribs",
                 "full_passes", "best_score", "best_plaintext", "best_params", "notes"]


class Experiment:
    def __init__(self, name, puzzle="k4", notes="", keep=50, quiet=False,
                 results_dir=None, ledger=None):
        self.name, self.puzzle, self.notes = name, puzzle.lower(), notes
        self.keep, self.quiet = keep, quiet
        self.results_dir = results_dir or RESULTS_DIR
        self.ledger = ledger or LEDGER
        self.use_cribs = self.puzzle == "k4"
        self.tried = 0
        self.passes = []
        self._heap = []  # (rank tuple, counter, record)

    # -- context manager --
    def __enter__(self):
        self.t0 = time.time()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.finish(interrupted=exc_type is KeyboardInterrupt)
        return exc_type is KeyboardInterrupt  # Ctrl-C still saves results

    # -- the one method attacks call --
    def add(self, plaintext, **params):
        p = letters(plaintext)
        self.tried += 1
        hits = crib_hits(p) if self.use_cribs else 0
        score = quadgram_score(p)
        rank = (hits, score)
        rec = {"cribs": hits, "score": round(score, 3), "plaintext": p, "params": params}
        if self.use_cribs and passes_cribs(p):
            self.passes.append(rec)
            if not self.quiet:
                print(f"\n*** FULL CRIB PASS *** {params}\n{p}\n")
        if len(self._heap) < self.keep:
            heapq.heappush(self._heap, (rank, self.tried, rec))
        elif rank > self._heap[0][0]:
            heapq.heapreplace(self._heap, (rank, self.tried, rec))
        return hits, score

    @property
    def best(self):
        return [r for _, _, r in sorted(self._heap, key=lambda x: x[0], reverse=True)]

    def finish(self, interrupted=False):
        secs = round(time.time() - self.t0, 1)
        best = self.best
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        out = self.results_dir / f"{stamp}_{self.puzzle}_{self.name}.json"
        with open(out, "w") as f:
            json.dump({"experiment": self.name, "puzzle": self.puzzle, "notes": self.notes,
                       "tried": self.tried, "seconds": secs, "interrupted": interrupted,
                       "full_passes": self.passes, "top": best}, f, indent=1)
        top = best[0] if best else {"cribs": 0, "score": None, "plaintext": "", "params": {}}
        row = {
            "timestamp": stamp, "puzzle": self.puzzle, "experiment": self.name,
            "tried": self.tried, "seconds": secs, "best_cribs": top["cribs"] if self.use_cribs else "",
            "full_passes": len(self.passes), "best_score": top["score"],
            "best_plaintext": top["plaintext"][:40], "best_params": json.dumps(top["params"])[:120],
            "notes": (self.notes + (" [interrupted]" if interrupted else "")).strip(),
        }
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        new = not self.ledger.exists()
        with open(self.ledger, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=LEDGER_FIELDS)
            if new:
                w.writeheader()
            w.writerow(row)
        if not self.quiet:
            self.print_summary(out)

    def print_summary(self, out_path=None, n=8):
        print(f"\n[{self.name}] tried {self.tried:,} candidates on {self.puzzle.upper()}")
        for r in self.best[:n]:
            crib = f"{r['cribs']:>2}/24  " if self.use_cribs else ""
            print(f"  {crib}q={r['score']:6.2f}  {r['plaintext'][:50]}  {r['params']}")
        if self.use_cribs:
            print(f"  full crib passes: {len(self.passes)}")
        if out_path:
            print(f"  saved -> {out_path.relative_to(ROOT)}  (+1 line in experiments/ledger.csv)")


def fingerprint(text):
    return hashlib.sha256(letters(text).encode()).hexdigest()
