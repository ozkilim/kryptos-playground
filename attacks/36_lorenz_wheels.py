"""Idea 36: Lorenz-style teleprinter wheels.

The WWII Lorenz machine enciphered each of the 5 teleprinter bits with its
own short repeating "chi" wheel (periods 41, 31, 29, 26, 23); hand-simulated
versions just need five short bit patterns. Because XOR works bit by bit,
each bit plane of K4 can be tested on its own: bit b of the key must repeat
with that wheel's period. For every bit, find the wheel lengths 2-61 the
clue letters allow (with enough repeat constraints to mean something), then
decrypt the combinations where all five wheels are fully pinned down.
"""
import sys
import time
from itertools import product
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import quadgram_score  # noqa: E402
from kryptos.teleprinter import CODE, LETTER, required_keys  # noqa: E402

MAXP = 30 if SMOKE else 61


def bit_periods(req, bit, min_tests=4):
    out = {}
    for p in range(2, MAXP + 1):
        seen, tests, ok = {}, 0, True
        for i, k in req.items():
            v = (k >> (4 - bit)) & 1
            r = i % p
            if r in seen:
                tests += 1
                if seen[r] != v:
                    ok = False
                    break
            else:
                seen[r] = v
        if ok and tests >= min_tests:
            out[p] = (seen, tests)
    return out


def decrypt(ct, wheels):
    out = []
    for i, c in enumerate(ct):
        k = 0
        for bit, (p, seen) in enumerate(wheels):
            v = seen.get(i % p)
            if v is None:
                return None
            k |= v << (4 - bit)
        out.append(LETTER.get(CODE[c] ^ k, None))
    return None if None in out else "".join(out)


def run(ct):
    req = required_keys(ct, CRIBS)
    per_bit = [bit_periods(req, b) for b in range(5)]
    n_combo = 1
    for pb in per_bit:
        n_combo *= max(1, len(pb))
    decrypts = []
    if all(per_bit) and n_combo <= 2_000_000:
        for combo in product(*[list(pb.items()) for pb in per_bit]):
            wheels = [(p, seen) for p, (seen, _) in combo]
            pt = decrypt(ct, wheels)
            if pt:
                decrypts.append((quadgram_score(pt), pt, [p for p, _ in wheels]))
    decrypts.sort(key=lambda x: -x[0])
    return [sorted(pb) for pb in per_bit], n_combo, decrypts


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("lorenz-style per-bit wheels (ITA2)", puzzle="k4", cribs_forced=True,
                    notes=f"each of 5 ITA2 key bits periodic with its own wheel length 2-{MAXP}; clue-consistent wheel "
                          "sets; fully pinned combinations decrypted and scored") as ex:
        allowed, n_combo, dec = run(K4)
        ex.count(5 * (MAXP - 1))
        for q, pt, ps in dec[:30]:
            ex.add(pt, wheels=ps)
        ctrl = []
        for s in range(2):
            a, n, d = run(shuffled(K4, 3600 + s))
            ctrl.append({"combos": n, "decrypts": len(d), "best_q": round(d[0][0], 3) if d else None})
        best = dec[0][0] if dec else None
        cb = max((c["best_q"] for c in ctrl if c["best_q"] is not None), default=None)
        if not dec:
            verdict = f"dead: no fully pinned 5-wheel combination decrypts to letters (allowed lengths per bit: {[len(a) for a in allowed]})"
        elif cb is not None and best - cb > 0.3:
            verdict = "WORTH A LOOK: a wheel combination beats shuffled controls"
        else:
            verdict = f"dead: {len(dec)} pinned decrypts, best {best:.2f} vs shuffled {cb}"
        ex.notes += f"; {verdict}"
    report("36", name="Lorenz-style wheels", allowed_lengths_per_bit=allowed, combos=n_combo, decrypts=len(dec),
           best_quadgram=best, control=ctrl, verdict=verdict, minutes=round((time.time() - t0) / 60, 1),
           top=[{"q": round(q, 3), "wheels": ps, "plaintext": pt} for q, pt, ps in dec[:5]])
    print("[36]", verdict)
