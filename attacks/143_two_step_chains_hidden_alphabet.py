"""Idea 143: plain autokey at lags 19-22 on ONE fully hidden alphabet, decided by two-step chains.

The model. One mixed alphabet, unknown to us, numbers the plaintext letter, the cipher letter and the fed
letter: X[C] = a X[P] + b X[K] + E, a, b = +-1 (the four sign forms: C = P + K, C = P - K, C = K - P,
C = -P - K), with K the plaintext letter d places back (look-back) or d places ahead (look-ahead).

Why lags 19-22. The two clue blocks are 30-52 places apart, so a lag of 19-22 never joins two clue letters in
one step. But two steps do: j in EASTNORTHEAST, j + 2d in BERLINCLOCK, and the unknown letter at j + d
drops out of the pair of equations. Lags 19, 20, 21, 22 give 9, 11, 11, 9 such chains. Each chain is one
equation in the 26 unknown places of the letters, and after moving the alphabet along by E places the
equations have no constant at all (for ab = 1 the constant is never there; idea 100's worker saw this).

So each of the 4 lags x 2 directions x 4 forms = 32 cells asks one exact question: can the 26 letters
take 26 DISTINCT places mod 26 and satisfy 9-11 equations? Idea 117 asked it and left 14 of K4's 32 cells
undecided, because its solver lists solutions and there were too many to list. Here every cell is decided:
either a proof that two letters are forced into one place (or three into one residue mod 13), or a
witness alphabet found by backtracking and then checked by running the cipher itself through the chains.

What a "yes" means: only that the 24 clue letters cannot rule the cell out. A witness alphabet is one of
an astronomical number and is not a reading of K4.

Controls: the same 32 cells on 50 shuffled K4s. Planted: English texts with the clue words in place,
enciphered at lags 19-22 on random hidden alphabets; the true cell must come out satisfiable and the true
alphabet must satisfy the equations.

  python attacks/143_two_step_chains_hidden_alphabet.py              (--prefilter for the clue card)
"""
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos import idea117_clash as C117  # noqa: E402
from kryptos import idea143_chains as H  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import pmap  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
N_CTRL = 6 if SMOKE else 50
N_PLANT = 1 if SMOKE else 5                       # planted texts per (lag, direction, form)
PLANT_LAGS = (20, 22) if SMOKE else H.LAGS
WIDE_LAGS = tuple(range(15, 27))                  # every lag that has a two-step chain


def prefilter_encrypt(pt, rng):
    """Plain autokey 21 back on a random hidden alphabet, C = P - K; alphabet, constant, primer from rng."""
    alpha = "".join(rng.sample(AZ, 26))
    primer = "".join(rng.choice(AZ) for _ in range(len(pt)))
    return H.encrypt(pt, alpha, 21, 1, -1, rng.randrange(26), "back", primer)


def summary(cells):
    """Counts for one ciphertext over the 32 main cells."""
    ok = [k for k, v in cells.items() if v[0] == "ok"]
    return {"ok": len(ok),
            "none": sum(1 for v in cells.values() if v[0] == "none"),
            "undecided": sum(1 for v in cells.values() if v[0] == "undecided"),
            "lags": len({k[0] for k in ok}),
            "lagdirs": len({k[:2] for k in ok}),
            "same_sign": sum(1 for k in ok if k[2] in ("C = P + K", "C = -P - K")),
            "opp_sign": sum(1 for k in ok if k[2] in ("C = P - K", "C = K - P"))}


def job(item):
    label, ct = item
    main = H.cells(ct)
    for (d, dn, fn), (st, detail, _) in main.items():          # every witness re-checked through the cipher
        if st == "ok":
            a, b = next((a, b) for n, a, b in H.FORMS if n == fn)
            assert H.witness_ok(ct, detail, d, a, b, dn), (label, d, dn, fn)
    wide = H.cells(ct, lags=[d for d in WIDE_LAGS if d not in H.LAGS])
    return label, main, wide


def chunk_job(chunk):
    return [job(x) for x in chunk]


def planted(rng):
    """Returns (passed, total, lines, dead counts of the other 31 cells)."""
    good = total = 0
    others, lines = [], []
    for d in PLANT_LAGS:
        for dn in H.DIRS:
            for form in H.FORMS:
                fn, a, b = form
                for _ in range(N_PLANT):
                    p = H.plant(rng, d, form, dn)
                    total += 1
                    back = H.decrypt(p["ct"], p["alpha"], d, a, b, p["E"], dn, p["primer"]) == p["pt"]
                    rows = H.chain_rows(p["ct"], d, a, b, dn)
                    true_fits = H.satisfies(rows, p["alpha"], a, b, p["E"])
                    # the same alphabet moved along by E must satisfy the constant-free equations
                    moved = "".join(p["alpha"][(x + p["E"]) % 26] for x in range(26)) if a * b == -1 else p["alpha"]
                    moved_fits = H.satisfies(rows, moved)
                    cells = H.cells(p["ct"])
                    st, detail, _ = cells[d, dn, fn]
                    wit = st == "ok" and H.witness_ok(p["ct"], detail, d, a, b, dn)
                    dead = sum(1 for k, v in cells.items() if k != (d, dn, fn) and v[0] == "none")
                    und = sum(1 for v in cells.values() if v[0] == "undecided")
                    others.append(dead)
                    passed = back and true_fits and moved_fits and wit and und == 0
                    good += passed
                    if not passed or len(lines) < 8:
                        lines.append("  lag %d %-5s %-10s alphabet %s E=%2d: reads back %s, true alphabet fits %s, "
                                     "moved alphabet fits constant-free %s, cell %s, other cells impossible %d/31"
                                     % (d, dn, fn, p["alpha"], p["E"], back, true_fits, moved_fits, st, dead))
    return good, total, lines, others


def rng_line(vals):
    s = sorted(vals)
    return "%d-%d (median %d)" % (s[0], s[-1], s[len(s) // 2])


def main():
    t0 = time.time()
    rng = random.Random(143)
    good, total, lines, others = planted(rng)
    print("PLANTED: %d/%d true cells satisfiable with the true alphabet fitting (%.0f s)" % (good, total,
                                                                                          time.time() - t0))
    print("\n".join(lines))
    print("  the other 31 cells of a planted text: impossible %s; so a wrong cell dies about %.0f%% of the time"
          % (rng_line(others), 100.0 * sum(others) / (31 * len(others))))
    if good != total:
        print("PLANTED TEST FAILED: stopping")
        sys.exit(1)

    with Experiment("143 two-step plain-autokey chains on one hidden alphabet, lags 19-22, every cell decided",
                    puzzle="k4",
                    notes="X[C]=aX[P]+bX[K]+E, one hidden alphabet on plain/cipher/fed letter, K = plaintext "
                          "19-22 back or ahead, 4 sign forms; 9-11 constant-free equations per cell; exact: forced "
                          "collision proof or verified witness; extra lags 15-18, 23-26; 50 shuffled controls",
                    cribs_forced=True) as ex:
        items = [("K4", K4)] + [("shuffled %d" % s, shuffled_control(s)) for s in range(1, N_CTRL + 1)]
        res = {}
        for r in pmap(chunk_job, items, None, (), chunk=3, procs=4):
            for label, mainc, wide in r:
                res[label] = (mainc, wide)
        ex.count(len(items) * len(WIDE_LAGS) * 8 + total * 32)

        k4, k4w = res["K4"]
        print("\nK4, lags 19-22 (chains: %s)" % ", ".join("%d: %d" % (d, len(H.chains(d))) for d in H.LAGS))
        agree = 0
        for (d, dn, fn), (st, detail, info) in k4.items():
            a, b = next((a, b) for n, a, b in H.FORMS if n == fn)
            rows, rhs = C117.chain_rows(K4, d, a, b, 0, dn)
            old = C117.decide(rows, rhs)[0]
            agree += (old == "none") == (st == "none")
            print("  lag %d %-5s %-10s %-9s idea 117: %-5s rank mod 13/2: %d/%d of %d chains, %d letters  %s"
                  % (d, dn, fn, {"ok": "POSSIBLE", "none": "impossible", "undecided": "UNDECIDED"}[st], old,
                     info["rank13"], info["rank2"], info["chains"], info["letters"], detail))
        s = summary(k4)
        print("  K4: %d possible, %d impossible, %d undecided of 32; agreement with idea 117 on 'impossible': %d/32"
              % (s["ok"], s["none"], s["undecided"], agree))
        print("  K4: lags with a possible cell %d of 4; (lag, direction) pairs %d of 8; same-sign forms "
              "(P+K, -P-K) %d of 16, opposite-sign forms (P-K, K-P) %d of 16"
              % (s["lags"], s["lagdirs"], s["same_sign"], s["opp_sign"]))

        cs = [summary(res["shuffled %d" % n][0]) for n in range(1, N_CTRL + 1)]
        print("\nCONTROLS: %d shuffled K4s, the same 32 cells" % N_CTRL)
        for key, name, tot in (("ok", "possible cells", 32), ("none", "impossible cells", 32),
                               ("undecided", "undecided cells", 32), ("lags", "lags with a possible cell", 4),
                               ("lagdirs", "(lag, direction) pairs possible", 8),
                               ("same_sign", "same-sign forms possible", 16),
                               ("opp_sign", "opposite-sign forms possible", 16)):
            vals = [c[key] for c in cs]
            print("  %-34s K4 %2d of %2d   controls %s; controls below K4: %d, equal: %d, above: %d"
                  % (name, s[key], tot, rng_line(vals), sum(v < s[key] for v in vals),
                     sum(v == s[key] for v in vals), sum(v > s[key] for v in vals)))
        print("  controls with all 4 lags possible: %d of %d" % (sum(c["lags"] == 4 for c in cs), N_CTRL))
        und = s["undecided"] + sum(c["undecided"] for c in cs)
        print("  undecided cells anywhere: %d" % und)

        print("\nEXTRA: the other lags that have chains (15-18, 23-26), 8 cells each")
        for d in WIDE_LAGS:
            src = k4 if d in H.LAGS else k4w
            kk = sum(1 for k, v in src.items() if k[0] == d and v[0] == "ok")
            ku = sum(1 for k, v in src.items() if k[0] == d and v[0] == "undecided")
            cv = []
            for n in range(1, N_CTRL + 1):
                m, w = res["shuffled %d" % n]
                srcc = m if d in H.LAGS else w
                cv.append(sum(1 for k, v in srcc.items() if k[0] == d and v[0] == "ok"))
            print("  lag %2d (%2d chains): K4 possible %d of 8 (undecided %d); controls %s"
                  % (d, len(H.chains(d)), kk, ku, rng_line(cv)))

        print("\nWhat a full alphabet would fix (letters a whole number of lags from a clue letter):")
        for d in H.LAGS:
            an = H.anchored(d)
            print("  lag %d: %d of 97 letters (%d outside the clues), free dimensions left for the alphabet: %d"
                  % (d, len(an), len(an) - 24, 26 - len(H.chains(d))))
        print("\nNo reading of K4 comes out of this test: a possible cell leaves 15-17 free dimensions for the alphabet. %.0f s"
              % (time.time() - t0))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("plain autokey (lag 21) on one hidden alphabet", encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "paper tableau; key = plaintext letter 21 back (the letter above in "
                                          "rows of 21)")})
        sys.exit(0)
    main()
