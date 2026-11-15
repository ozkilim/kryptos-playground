"""Idea 12: Myszkowski transposition (keyword with repeated letters: equal
letters' columns are read together) from every dictionary word of 5-16
letters, x every key model. Others covered Myszkowski widths 3-9 with a
periodic key only.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos.campaign import run_stack_idea  # noqa: E402
from kryptos.solvers.periodic import default_wordlist  # noqa: E402

def words():
    ws = sorted({w for w in default_wordlist() if 5 <= len(w) <= 16 and len(set(w)) < len(w)})
    return ws

if __name__ == "__main__":
    ws = words()
    jobs = [("myszkowski", ws[k:k + 300]) for k in range(0, len(ws), 300)]
    run_stack_idea("12", "myszkowski x all key models", jobs,
                   {"periodic", "progressive", "ctauto", "ptauto", "shift"},
                   notes=f"Myszkowski from {len(ws)} dictionary words (5-16 letters, repeated letters); periodic<=26, "
                         "progressive, ct/pt autokey<=60, shifts; before/after; AZ+KRYPTOS",
                   control_jobs=jobs[: max(1, len(jobs) // 10)])
