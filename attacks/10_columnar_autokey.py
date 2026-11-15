"""Idea 10: columnar transposition (every order, widths 2-10) + AUTOKEY (key =
ciphertext or plaintext L letters back, L 1-60), before or after the
transposition. Autokey alone is dead; stacked it is untested.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos.campaign import run_stack_idea  # noqa: E402
from kryptos.solvers.stack import columnar_jobs  # noqa: E402

if __name__ == "__main__":
    run_stack_idea("10", "columnar+autokey", columnar_jobs(2, 10), {"ctauto", "ptauto"},
                   notes="columnar all orders w2-10 + ct/pt autokey lag 1-60, before/after, vig/beau/varbeau, AZ+KRYPTOS",
                   control_jobs=columnar_jobs(2, 7))
