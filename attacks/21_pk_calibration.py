"""Idea 21: calibrate on Paradigm's practice puzzles (PK1-PK10).

A public write-up (github.com/saul-g/kryptos-ctf-2026) lists each puzzle's
method and keys. This script rebuilds the decryptions from those keys
(trying the plausible layer orders and route conventions, since the write-up
doesn't pin them down) and keeps whatever reads as English. Verified answers
go into data/ctf/pkN.json. Then it checks whether our BLIND solvers could
have found the simpler ones without the keys, which says how far our toolkit
reaches on Paradigm's idea of "Kryptos-like".
"""
import json
import sys
import time
from itertools import permutations, product
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import load  # noqa: E402
from kryptos.campaign import SMOKE, report  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET as KA, columnar_decrypt, vigenere_decrypt  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.score import quadgram_score  # noqa: E402
from kryptos.solvers.periodic import crack_periodic  # noqa: E402

WRITEUP = "https://github.com/saul-g/kryptos-ctf-2026"


def vig(t, k):
    return vigenere_decrypt(t, k, KA)


def col(t, k):
    return columnar_decrypt(t, k)


def spiral_orders(n, w):
    """Index orders for clockwise/anticlockwise spirals from each corner on an n-letter grid w wide."""
    h = -(-n // w)
    outs = []
    for start in range(4):
        for cw in (True, False):
            g = [[r * w + c if r * w + c < n else None for c in range(w)] for r in range(h)]
            for _ in range(start):  # rotate grid so the spiral starts at another corner
                g = [list(x) for x in zip(*g[::-1])]
            if not cw:
                g = [list(x) for x in zip(*g)]
            seq = []
            while g:
                seq += g[0]
                g = [list(x) for x in zip(*g[1:])][::-1]
            outs.append([x for x in seq if x is not None])
    return outs


def spiral_variants(t, w):
    """Both directions of every spiral: read-off order and its inverse."""
    for order in spiral_orders(len(t), w):
        yield "".join(t[i] for i in order)            # text was written in rows, read in a spiral
        inv = [None] * len(t)
        for j, i in enumerate(order):
            inv[i] = t[j]
        yield "".join(inv)                            # text was written in a spiral, read in rows


def best_of(cands):
    best = max(cands, key=lambda x: quadgram_score(x[1]))
    return best[0], best[1], quadgram_score(best[1])


def chains(ct, steps):
    """Try every order of the decryption steps (each step: list of (label, fn) variants)."""
    out = []
    for order in permutations(range(len(steps))):
        for choice in product(*[steps[i] for i in order]):
            t, labels = ct, []
            for label, fn in choice:
                t = fn(t)
                labels.append(label)
            out.append((" -> ".join(labels), t))
    return out


def hill_rows(t, alpha, top=8):
    """Best rows of a 3x3 Hill decryption matrix by monogram fit (every third letter)."""
    from kryptos.score import chi_squared
    idx = [alpha.index(c) for c in t]
    blocks = [idx[i:i + 3] for i in range(0, len(idx) - len(idx) % 3, 3)]
    scored = []
    for a, b, c in product(range(26), repeat=3):
        s = "".join(alpha[(a * x + b * y + c * z) % 26] for x, y, z in blocks)
        scored.append((chi_squared(s), (a, b, c)))
    scored.sort()
    return [r for _, r in scored[:top]]


def hill_solve(t, alpha):
    rows = hill_rows(t, alpha)
    idx = [alpha.index(c) for c in t]
    blocks = [idx[i:i + 3] for i in range(0, len(idx) - len(idx) % 3, 3)]
    best = (-99, None, None)
    for r1, r2, r3 in permutations(rows, 3):
        s = "".join(alpha[(r[0] * x + r[1] * y + r[2] * z) % 26] for x, y, z in blocks for r in (r1, r2, r3))
        q = quadgram_score(s)
        if q > best[0]:
            best = (q, s, (r1, r2, r3))
    return best


def main():
    t0 = time.time()
    pk = {i: load(f"pk{i}")["ciphertext"] for i in range(1, 11)}
    results = {}

    results[1] = best_of([("vig PROVENANCE", vig(pk[1], "PROVENANCE"))])
    results[2] = best_of([("columnar MARGINS", col(pk[2], "MARGINS"))])
    results[3] = best_of([("vig PENTIMENTO + vig ORDINATE", vig(vig(pk[3], "PENTIMENTO"), "ORDINATE"))])
    results[8] = best_of([("vig METE+METER+METIER+MASTERY",
                           vig(vig(vig(vig(pk[8], "METE"), "METER"), "METIER"), "MASTERY"))])
    results[4] = best_of(chains(pk[4], [[("vig VERDIGRIS+OCHRE", lambda t: vig(vig(t, "VERDIGRIS"), "OCHRE"))],
                                        [("columnar UNDERLAY", lambda t: col(t, "UNDERLAY"))]]))
    results[6] = best_of(chains(pk[6], [[("vig PORTAL", lambda t: vig(t, "PORTAL"))],
                                        [("columnar HANDIWORK", lambda t: col(t, "HANDIWORK"))],
                                        [("columnar SMITHWORK", lambda t: col(t, "SMITHWORK"))]]))
    spirals = [(f"spiral{k}", lambda t, k=k: list(spiral_variants(t, 12))[k]) for k in range(16)]
    results[9] = best_of(chains(pk[9], [[("vig CLEPSYDRA", lambda t: vig(t, "CLEPSYDRA"))],
                                        spirals,
                                        [("columnar BEAMWORK", lambda t: col(t, "BEAMWORK"))]]))
    if results[4][2] > -5.4:  # PK5's running key is PK4's plaintext
        rk = results[4][1]
        rkey = (rk * 3)[:len(pk[5])]
        results[5] = best_of(chains(pk[5], [[("vig running=PK4", lambda t: vigenere_decrypt(t, rkey, KA))],
                                            [("columnar TWOYEARS", lambda t: col(t, "TWOYEARS"))]]))
    best7 = (-99, None, None)
    for order in ("vig-then-hill", "hill-then-vig"):
        for alpha in (KA, AZ):
            t = vig(pk[7], "ALCHEMIST") if order == "vig-then-hill" else pk[7]
            q, s, rows = hill_solve(t, alpha)
            if order == "hill-then-vig" and s:
                s = vig(s, "ALCHEMIST")
                q = quadgram_score(s)
            if q > best7[0]:
                best7 = (q, s, f"{order}, Hill rows {rows} over {'KRYPTOS' if alpha == KA else 'A-Z'} indices")
    results[7] = (best7[2], best7[1], best7[0])

    verified = {}
    for i in sorted(results):
        label, pt, q = results[i]
        ok = q > -5.4  # English-like (noise ~ -6.5); proper nouns pull real text down a little
        verified[i] = {"method": label, "q": round(q, 3), "verified": ok, "plaintext": pt}
        if ok and not SMOKE:
            p = DATA_DIR / "ctf" / f"pk{i}.json"
            d = json.loads(p.read_text())
            d.update({"status": "solved", "plaintext": pt, "how_found": f"keys from {WRITEUP}; {label}",
                      "notes": "Decrypted here from the public write-up's keys (reads as English). "
                               "Original solvers: see prize field."})
            p.write_text(json.dumps(d, indent=2) + "\n")

    blind = {}
    for i in (1, 3):
        cands = crack_periodic(pk[i], max_period=45 if i == 3 else 16)
        blind[i] = {"found": cands[0].plaintext == verified[i]["plaintext"], "params": cands[0].params,
                    "q": round(cands[0].score, 3)}
    n_ok = sum(v["verified"] for v in verified.values())
    verdict = (f"{n_ok}/{len(verified)} practice puzzles decrypted from the public keys "
               f"({', '.join(f'PK{i}' for i, v in verified.items() if v['verified'])}); blind period solver "
               f"recovers PK1: {blind[1]['found']}, PK3 (two keys, period 40): {blind[3]['found']}")
    verdict += "; PK7 (Hill 3x3 + Quagmire) not recovered by the simple Hill row attack; PK10 (all layers reversed) not attempted"
    report("21", name="PK calibration", puzzles=verified, blind=blind, verdict=verdict,
           minutes=round((time.time() - t0) / 60, 1))
    print("[21]", verdict)
    for i, v in verified.items():
        print(f"  PK{i}: q={v['q']} {v['verified']} {v['method']} {v['plaintext'][:60]}")


if __name__ == "__main__":
    main()
