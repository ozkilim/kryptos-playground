"""Idea 13: extend attack 07 one width further. Double columnar with every
width-8 order (40,320) on one layer and every order of widths 2-6 on the
other (both ways round), + periodic Vigenere/Beaufort key length 1-26 placed
before, between or after. ~70M transposition pairs.
"""
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.campaign import report, shuffled, smoke  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.solvers.double_columnar import all_orders, decrypt, scan  # noqa: E402

if __name__ == "__main__":
    t0 = time.time()
    w8, small = smoke(all_orders(8, 8), 20), all_orders(2, 6)
    with Experiment("double-columnar-width8+periodic", puzzle="k4",
                    notes="double columnar: every w8 order x every w2-6 order, both layer orders; periodic vig/beau "
                          "AZ/KRYPTOS len 1-26, before/middle/after; survivors need >=6 equalities") as ex:
        t1, h1 = scan(K4, CRIBS, w8, small)
        t2, h2 = scan(K4, CRIBS, small, w8)
        hits = h1 + h2
        ex.count(t1 + t2)
        for h in hits:
            ex.add(decrypt(K4, CRIBS, *h[:6]), hit=str(h))
        ctrl = None
        if hits:  # how many would a shuffled K4 give on a 1/20 slice?
            ct, chits = scan(shuffled(K4, 0), CRIBS, w8[::20], small)
            ctrl = {"hypotheses": ct, "survivors": len(chits)}
        verdict = "dead: 0 survivors" if not hits else "survivors found: check against control"
        ex.notes += f"; {len(hits)} survivors; {verdict}"
    report("13", name="double-columnar-width8+periodic", hypotheses=t1 + t2, survivors=len(hits),
           control=ctrl, verdict=verdict, minutes=round((time.time() - t0) / 60, 1),
           top=[str(h) for h in hits[:10]])
    print(f"[13] {t1 + t2:,} hypotheses, {len(hits)} survivors -> {verdict}")
