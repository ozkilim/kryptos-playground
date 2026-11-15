"""Every dictionary word as a Vigenere / Beaufort / variant key, on both the
plain and KRYPTOS alphabets, ranked by K4 crib hits.

This has been tried to death and won't crack K4 (see `python -m kryptos
cribkeys`: the crib keystream isn't periodic). It's here as a baseline and
to show the loop.

  python attacks/01_vigenere_wordlist.py               # data/keys.txt + /usr/share/dict/words
  python attacks/01_vigenere_wordlist.py words.txt     # your own list
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.solvers.periodic import VARIANTS, ALPHABETS, default_wordlist  # noqa: E402


def main():
    if len(sys.argv) > 1:
        words = [w.strip().upper() for w in open(sys.argv[1]) if w.strip().isalpha()]
    else:
        words = default_wordlist()
    with Experiment("vigenere-family-wordlist", puzzle="k4",
                    notes=f"{len(words)} words x vig/beau/varbeau x AZ/KRYPTOS") as ex:
        for aname, alpha in ALPHABETS.items():
            for vname, fn in VARIANTS.items():
                for w in words:
                    ex.add(fn(K4, w, alpha), key=w, cipher=vname, alphabet=aname)


if __name__ == "__main__":
    main()
