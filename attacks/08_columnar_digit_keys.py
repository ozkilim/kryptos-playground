"""Idea 08: columnar transposition (every column order, widths 2-11) + an
APERIODIC small-shift key: Gronsfeld digits 0-9, or shifts within +-3 / +-5.

Why: digit keys alone are dead (no alphabet makes all 24 shifts digits), but
nobody has tried them behind a transposition. Digits were the CIA-era hand
standard (VIC), and Bean found plain and cipher letters sit unusually close,
which is what a small-shift key would do.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos.campaign import run_stack_idea  # noqa: E402
from kryptos.solvers.stack import columnar_jobs  # noqa: E402

if __name__ == "__main__":
    run_stack_idea("08", "columnar+digit-or-small-shift-key", columnar_jobs(2, 11), {"shift"},
                   notes="columnar all orders w2-11 + aperiodic key in {0-9} / +-3 / +-5, vig/beau/varbeau, AZ+KRYPTOS",
                   control_jobs=columnar_jobs(2, 8), n_controls=2)
