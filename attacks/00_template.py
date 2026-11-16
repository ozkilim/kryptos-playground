"""TEMPLATE: copy me to attacks/NN_your_idea.py and fill in generate().

  python attacks/NN_your_idea.py

The pattern every attack follows:
  generate candidate plaintexts -> ex.add(pt, **how_you_got_it) -> done.
The harness scores everything (24 K4 cribs + English score), keeps the best
50, saves them to results/, and adds one line to experiments/ledger.csv so
nobody repeats this experiment by accident.

Before writing a new attack, run it through the clue pre-filter (docs/CLUE_MATRIX.md):
  from kryptos.clues import prefilter
  prefilter("my idea", encrypt=my_encrypt, marks={"hand": ("pass", "paper chart"), ...})
my_encrypt(pt, rng) -> ct must draw its key from rng only (same seed = same key).
REJECT = breaks a fact (don't build it); FLAG = breaks a firm statement (build only
with a written reason); PASS = go, and the score says how many hints it explains.

Then skim:
  python -m kryptos ledger        what we've already tried
  docs/dead-ends.md               what the community already ruled out
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4  # noqa: E402
from kryptos.ciphers import vigenere_decrypt, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402


def generate():
    """Yield (plaintext, params) pairs. Replace this with your idea."""
    for key in ["KRYPTOS", "BERLIN"]:
        yield vigenere_decrypt(K4, key, KRYPTOS_ALPHABET), {"key": key}


if __name__ == "__main__":
    with Experiment("template", puzzle="k4", notes="describe the hypothesis here") as ex:
        for pt, params in generate():
            ex.add(pt, **params)
