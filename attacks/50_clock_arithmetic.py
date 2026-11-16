"""Idea 50: clock arithmetic keys (the World Clock as a device) and keys tied to the carved rows.

Sanborn: "delve into that particular clock". A clock is modular arithmetic on a dial,
so these key schedules are what a clock "does", all exact on the 24 clue letters:

  dial       k_i = (a*i + b) mod m          m = 12, 24, 60 (a hand stepping a fixed amount per letter)
  dial26     k_i = round(26 * ((a*i + b) mod m) / m)   (the dial spread over the alphabet)
  two hands  k_i = ((a1*i + b1) mod 12) + ((a2*i + b2) mod 60)   (hour hand + minute hand)
  rows       key[col mod L], the key restarting at each carved row (rows start at 0, 4, 35, 66), L 1-26
  grid       k = a*row + b*col + c (mod 26) over the carved layout

Vigenere/Beaufort/variant x A-Z/KRYPTOS. Every survivor is a fully determined decrypt.
Idea 43 could not put a restart inside BERLINCLOCK; the carved row 4 starts at position 66, inside it.
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, load  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KEY_FROM, KRYPTOS_ALPHABET, PLAIN_FROM  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

N = 97
ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
ROW_STARTS = [0, 4, 35, 66]
POS = sorted(CRIBS)


def rowcol(i):
    r = max(k for k, s in enumerate(ROW_STARTS) if s <= i)
    return r, i - ROW_STARTS[r]


def required(ct, cribs):
    out = {}
    for an, al in ALPHAS.items():
        idx = {c: i for i, c in enumerate(al)}
        for v in VARIANTS:
            out[(an, v)] = [(i, KEY_FROM[v](idx[ct[i]], idx[cribs[i]])) for i in POS]
    return out


def schedules(smoke=False):
    """Yield (family, params, key function i -> value)."""
    for m in (12, 24, 60):
        for a in range(1, m):
            for b in range(m):
                yield "dial", (m, a, b), (lambda i, m=m, a=a, b=b: ((a * i + b) % m) % 26)
                yield "dial26", (m, a, b), (lambda i, m=m, a=a, b=b: round(26 * ((a * i + b) % m) / m) % 26)
    for a in range(1, 26):
        for b in range(26):
            for c in range(26):
                yield "grid", (a, b, c), (lambda i, a=a, b=b, c=c: (a * rowcol(i)[0] + b * rowcol(i)[1] + c) % 26)
    hands = [(a1, b1, a2, b2) for a1 in range(1, 12) for b1 in range(12) for a2 in range(1, 60) for b2 in range(60)]
    if smoke:
        hands = hands[::500]
    for a1, b1, a2, b2 in hands:
        yield "two_hands", (a1, b1, a2, b2), (lambda i, a1=a1, b1=b1, a2=a2, b2=b2:
                                              (((a1 * i + b1) % 12) + ((a2 * i + b2) % 60)) % 26)


def scan(ct, cribs, smoke=False):
    req = required(ct, cribs)
    hits, tested = [], 0
    for fam, params, f in schedules(smoke):
        ks = {i: f(i) for i in POS}
        for cfg, rq in req.items():
            tested += 1
            if all(ks[i] == k for i, k in rq):
                hits.append((fam, params, cfg, f))
    # rows: key[col mod L] restarting at each carved row
    for cfg, rq in req.items():
        for L in range(1, 27):
            tested += 1
            key, ok = {}, True
            for i, k in rq:
                r = rowcol(i)[1] % L
                if key.setdefault(r, k) != k:
                    ok = False
                    break
            if ok and len(rq) - len(key) >= 3:
                hits.append(("rows", (L, tuple(sorted(key.items()))), cfg, None))
    return hits, tested


def decrypt(ct, hit):
    fam, params, (an, v), f = hit
    al = ALPHAS[an]
    idx = {c: i for i, c in enumerate(al)}
    dec = PLAIN_FROM[v]
    if fam == "rows":
        L, key = params[0], dict(params[1])
        return "".join(al[dec(idx[c], key.get(rowcol(i)[1] % L, 0))] if rowcol(i)[1] % L in key else "?"
                       for i, c in enumerate(ct))
    return "".join(al[dec(idx[c], f(i))] for i, c in enumerate(ct))


def run(ct, cribs, smoke=False):
    hits, tested = scan(ct, cribs, smoke)
    qg = Quadgrams()
    scored = []
    for h in hits:
        pt = decrypt(ct, h)
        q = qg.score(pt.replace("?", "")) if pt.count("?") < 30 else -9.0
        scored.append((q, pt, h))
    scored.sort(key=lambda x: -x[0])
    return scored, tested


def plant(rng):
    text = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4))
    s0 = rng.randrange(0, len(text) - 100)
    pt = text[s0:s0 + 97]
    m, a, b = 24, rng.randrange(1, 24), rng.randrange(24)
    ct = "".join(AZ[(AZ.index(p) + ((a * i + b) % m) % 26) % 26] for i, p in enumerate(pt))
    return ct, pt, ("dial", (m, a, b))


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("clock arithmetic keys + carved-row restarts", puzzle="k4", cribs_forced=True,
                    notes="dial (a*i+b mod 12/24/60), dial spread to 26, hour+minute hands, key restarting per carved "
                          "row (L 1-26), affine row/col grid; vig/beau/varbeau x A-Z/KRYPTOS; exact on 24 clue letters") as ex:
        res, tested = run(K4, CRIBS, SMOKE)
        ex.count(tested)
        for q, pt, h in res[:20]:
            ex.add(pt, family=h[0], params=str(h[1]), alphabet=h[2][0], variant=h[2][1])
        ctrl = []
        for s in range(1 if SMOKE else 3):
            r, _ = run(shuffled(K4, 5000 + s), CRIBS, SMOKE)
            ctrl.append((len(r), round(r[0][0], 3) if r else None))
        rng = random.Random(50)
        planted = []
        for _ in range(2):
            ct, pt, truth = plant(rng)
            r, _ = run(ct, {i: pt[i] for i in CRIBS}, True)
            planted.append({"truth": truth, "found": any(h[0] == truth[0] and h[1] == truth[1] for _, _, h in r),
                            "top_is_truth": bool(r) and r[0][1] == pt})
        best = res[0][0] if res else None
        cmax = max((c[1] for c in ctrl if c[1] is not None), default=None)
        if best is not None and best > -5.3 and (cmax is None or best - cmax > 0.3):
            verdict = f"WORTH A LOOK: {res[0][2][:3]} decodes to {best:.2f}"
        else:
            verdict = (f"dead: {len(res)} schedules fit the clues out of {tested:,} (shuffled: {ctrl}); best decode "
                       f"{None if best is None else round(best, 2)}")
        ex.notes += f"; {verdict}"
    report("50", name="clock arithmetic + carved rows", tested=tested, survivors=len(res), controls=ctrl,
           best_quadgram=best, planted=planted, verdict=verdict,
           top=[{"q": round(q, 3), "family": h[0], "params": str(h[1]), "cfg": h[2], "plaintext": pt} for q, pt, h in res[:8]],
           minutes=round((time.time() - t0) / 60, 1))
    print("[50]", verdict, "| planted:", planted)
