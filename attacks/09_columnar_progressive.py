"""Idea 09: columnar transposition (every order, widths 2-10) + a PROGRESSIVE
key (a repeating key that shifts by s each time it wraps), placed before or
after the transposition. Progressive alone is dead; stacked it is untested.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos.campaign import run_stack_idea  # noqa: E402
from kryptos.solvers.stack import columnar_jobs  # noqa: E402

if __name__ == "__main__":
    run_stack_idea("09", "columnar+progressive-key", columnar_jobs(2, 10), {"progressive"},
                   notes="columnar all orders w2-10 + progressive key p1-13 step 1-25, before/after, vig/beau, AZ+KRYPTOS",
                   control_jobs=columnar_jobs(2, 7))
