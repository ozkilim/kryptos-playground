"""Gap: KEYED DOUBLE COLUMNAR transposition + a periodic substitution.

Double columnar (write in rows, read columns in key order, do it again with a
second key) was a standard hand cipher of the Cold War era, and "LAYER TWO"
plus Sanborn's "two separate systems" make a two-layer design natural.
Single columnar + periodic key is ruled out to width 14 by others; double
columnar WITH a substitution layer is listed as open (keithadler SEARCH.md).

Model: P -> T1 -> T2 -> C, with a periodic Vigenere or Beaufort (A-Z or
KRYPTOS alphabet) applied at one of three places:
  before  : C = T2(T1(S(P)))   key slot = plaintext position
  middle  : C = T2(S(T1(P)))   key slot = position between the layers
  after   : C = S(T2(T1(P)))   key slot = ciphertext position
For every (T1, T2) and every period 1-26, test with only the 24 clue letters
whether one repeating key fits. Survivors with enough constraints get
decrypted (unknown key slots left as A) and scored.

Stage A: every column order, widths 2-7 on both layers (~35M pairs).
Stage B: themed keyword orders (data/keys.txt) up to width 15, both layers,
         and themed keyword x every order of widths 2-7.

  python attacks/07_double_columnar.py            # both stages, all cores
  python attacks/07_double_columnar.py --bench    # time a slice and extrapolate
"""
import sys
import time
from multiprocessing import cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.solvers.double_columnar import (  # noqa: E402
    MAX_PERIOD, MIN_CONSTRAINTS, all_orders, decrypt, keyword_order, scan,
)


def themed_orders(max_w=15):
    words = [w.strip().upper() for w in open(DATA_DIR / "keys.txt")
             if w.strip() and not w.startswith("#")]
    return sorted({keyword_order(w) for w in words if 2 <= len(w) <= max_w})


def main():
    if "--bench" in sys.argv:
        orders = all_orders(2, 7)
        t0 = time.time()
        tested, hits = scan(K4, CRIBS, orders[:28], orders)
        dt = time.time() - t0
        print(f"{28 * len(orders):,} pairs in {dt:.1f}s on {cpu_count()} cores -> full stage A "
              f"~{dt * len(orders) / 28 / 60:.0f} min; {len(hits)} survivors so far")
        return
    with Experiment("double-columnar+periodic", puzzle="k4",
                    notes="double columnar (T1,T2) + periodic vig/beau AZ/KRYPTOS placed before/middle/after, "
                          f"periods 1-{MAX_PERIOD}, survivors need >={MIN_CONSTRAINTS} equalities") as ex:
        orders = all_orders(2, 7)
        tA, hA = scan(K4, CRIBS, orders, orders)
        th = themed_orders()
        tB1, hB1 = scan(K4, CRIBS, th, th)
        tB2, hB2 = scan(K4, CRIBS, th, orders)
        tB3, hB3 = scan(K4, CRIBS, orders, th)
        hits = hA + hB1 + hB2 + hB3
        ex.count(tA + tB1 + tB2 + tB3)
        for h in hits:
            o1, o2, aname, variant, place, p, con = h
            ex.add(decrypt(K4, CRIBS, o1, o2, aname, variant, place, p),
                   o1=list(o1), o2=list(o2), alphabet=aname, variant=variant, place=place,
                   period=p, constraints=con)
        ex.notes += (f"; stage A {len(orders):,}^2 orders widths 2-7: {len(hA)} survivors; "
                     f"stage B {len(th)} themed keyword orders: {len(hB1) + len(hB2) + len(hB3)} survivors")
    print(f"\nStage A (all orders, widths 2-7 x 2-7): {len(hA)} survivors")
    print(f"Stage B (themed keywords up to width 15): {len(hB1) + len(hB2) + len(hB3)} survivors")
    for h in sorted(hits, key=lambda h: -h[6])[:15]:
        print("  ", h)


if __name__ == "__main__":
    main()
