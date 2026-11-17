"""Idea 97, side check (not a logged experiment): the first clue block alone.

In the main run K4's EASTNORTHEAST block fits a window of 5 values on one tableau and none of 50
shuffled K4s did (best 6). This repeats only that number on many more shuffled K4s.

  python attacks/97_side_block1.py [number of shuffles]
"""
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets  # noqa: E402
from kryptos import idea97_fewsymbols as f  # noqa: E402

if __name__ == "__main__":
    t0 = time.time()
    n = int(sys.argv[1]) if len(sys.argv) > 1 else (4 if SMOKE else 300)
    alphas = dictionary_alphabets(mixed=True)
    cts = [K4] + [shuffled_control(s) for s in range(51, 51 + n)]
    best = f.block_windows(cts, CRIBS, alphas)
    hist = Counter(best[1:])
    print("EASTNORTHEAST alone, smallest window over %d alphabets x 10 key streams" % len(alphas))
    print("K4: %d" % best[0])
    print("%d shuffled K4s (seeds 51-%d): %s" % (n, 50 + n, "  ".join("%d: %d" % kv for kv in sorted(hist.items()))))
    print("shuffles with a window as small as K4's: %d of %d" % (sum(b <= best[0] for b in best[1:]), n))
    print("letters in the block's ciphertext: K4 has %d different; shuffles with %d or fewer: %d of %d" % (
        len(set(K4[21:34])), len(set(K4[21:34])), sum(len(set(c[21:34])) <= len(set(K4[21:34])) for c in cts[1:]), n))
    print("total %.0f s" % (time.time() - t0))
