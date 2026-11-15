"""Gap: a repeating key 27, 28 or 29 letters long.

Why these lengths: every key length 1-26 and 30-52 is ruled out because the
24 clue letters demand two different key letters in the same key slot. At
27-29 no two clue letters share a slot, so the clues can't decide (an open
gap in keithadler/kryptos and others; see negatives/open_gaps.md).

The trick: the 24 clue letters FIX 24 of the 27-29 key letters, so 85-90% of
K4's plaintext is forced. Only 3-5 key letters are free. Try them all (or
hill-climb them), and ask: does the result read as English? Compare against
the same procedure run on shuffled K4s (a null baseline), because optimizing
free letters inflates scores a bit even on noise.

Covers Vigenere / Beaufort / variant on plain A-Z and the KRYPTOS alphabet,
then (stage 2) every dictionary-keyword alphabet (Quagmire III style).

  python attacks/06_long_period_27_29.py            # stage 1 + null baseline
  python attacks/06_long_period_27_29.py --words    # + stage 2 keyword alphabets (~few min)
"""
import random
import sys
from itertools import product
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET, PLAIN_FROM, keyed_alphabet  # noqa: E402
from kryptos.cribtools import required_keys  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

PERIODS = (27, 28, 29)
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
QG = Quadgrams()


def forced(ct, cribs, alpha, variant, L):
    """(fixed key slots {residue: k}, free residues) or None if the clues conflict."""
    req = required_keys(ct, cribs, alpha, variant)
    fixed = {}
    for pos, k in req.items():
        r = pos % L
        if fixed.get(r, k) != k:
            return None
        fixed[r] = k
    return fixed, [r for r in range(L) if r not in fixed]


def decrypt(ct, alpha, variant, key):
    idx = {c: i for i, c in enumerate(alpha)}
    dec = PLAIN_FROM[variant]
    L = len(key)
    return "".join(alpha[dec(idx[c], key[i % L])] for i, c in enumerate(ct))


def partial_score(ct, alpha, variant, L, fixed):
    """Mean quadgram log-prob over 4-letter windows made only of forced letters."""
    idx = {c: i for i, c in enumerate(alpha)}
    dec = PLAIN_FROM[variant]
    pt = [alpha[dec(idx[c], fixed[i % L])] if (i % L) in fixed else None for i, c in enumerate(ct)]
    get, fl = QG.logp.get, QG.floor
    vals = [get("".join(pt[i:i + 4]), fl) for i in range(len(pt) - 3) if None not in pt[i:i + 4]]
    return sum(vals) / len(vals) if vals else fl


def solve_free(ct, alpha, variant, L, fixed, free, rng, restarts=6):
    """Best key for the free slots. Exhaustive for <=3 free, else hill-climb
    with single and adjacent-pair moves and random restarts."""
    base = [fixed.get(r, 0) for r in range(L)]

    def score(key):
        return QG.score(decrypt(ct, alpha, variant, key))

    if len(free) <= 3:
        best = (-99, None)
        for vals in product(range(26), repeat=len(free)):
            key = list(base)
            for r, v in zip(free, vals):
                key[r] = v
            s = score(key)
            if s > best[0]:
                best = (s, key)
        return best
    best = (-99, None)
    for _ in range(restarts):
        key = list(base)
        for r in free:
            key[r] = rng.randrange(26)
        cur = score(key)
        improved = True
        while improved:
            improved = False
            for r in free:  # single moves
                for v in range(26):
                    if v != key[r]:
                        old, key[r] = key[r], v
                        s = score(key)
                        if s > cur:
                            cur, improved = s, True
                        else:
                            key[r] = old
            for a, b in zip(free, free[1:]):  # adjacent pairs
                for va in range(26):
                    for vb in range(26):
                        oa, ob = key[a], key[b]
                        key[a], key[b] = va, vb
                        s = score(key)
                        if s > cur:
                            cur, improved = s, True
                        else:
                            key[a], key[b] = oa, ob
        if cur > best[0]:
            best = (cur, list(key))
    return best


def run(ct, cribs, alphabets, rng, ex=None):
    """Best (score, plaintext, params) over all alphabets x variants x periods."""
    out = []
    for aname, alpha in alphabets.items():
        for variant in VARIANTS:
            for L in PERIODS:
                f = forced(ct, cribs, alpha, variant, L)
                if f is None:
                    continue
                fixed, free = f
                s, key = solve_free(ct, alpha, variant, L, fixed, free, rng)
                pt = decrypt(ct, alpha, variant, key)
                params = {"alphabet": aname, "variant": variant, "period": L, "free_slots": len(free),
                          "key": "".join(alpha[k] for k in key)}
                if ex is not None:
                    ex.count(26 ** len(free) if len(free) <= 3 else 1)
                    ex.add(pt, **params)
                out.append((s, pt, params))
    out.sort(key=lambda x: -x[0])
    return out


def null_baseline(n, rng):
    """Same search on shuffled K4s: how good does pure noise look?"""
    scores = []
    for _ in range(n):
        letters_ = list(K4)
        rng.shuffle(letters_)
        fake = "".join(letters_)
        scores.append(run(fake, CRIBS, {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}, rng)[0][0])
    return sorted(scores)


def keyword_stage(ct, rng, ex=None, top=40, words=None):
    """Score every keyword alphabet on the forced letters, fully solve the top
    few. Returns (n_alphabets, best partial, best full)."""
    from kryptos.solvers.periodic import default_wordlist
    seen, cands = set(), []
    for w in (words or default_wordlist()):
        a = keyed_alphabet(w)
        if len(w) < 3 or a in seen:
            continue
        seen.add(a)
        for variant in VARIANTS:
            for L in PERIODS:
                f = forced(ct, CRIBS, a, variant, L)
                if f:
                    cands.append((partial_score(ct, a, variant, L, f[0]), w, variant, L))
                    if ex is not None:
                        ex.count(1)
    cands.sort(reverse=True)
    best = []
    for ps, w, variant, L in cands[:top]:  # fully solve only the most English-looking
        a = keyed_alphabet(w)
        fixed, free = forced(ct, CRIBS, a, variant, L)
        s, key = solve_free(ct, a, variant, L, fixed, free, rng, restarts=3)
        pt = decrypt(ct, a, variant, key)
        if ex is not None:
            ex.add(pt, keyword=w, variant=variant, period=L)
        best.append((s, w, variant, L, pt))
    best.sort(reverse=True)
    return len(seen), cands[0], best[0]


def main():
    rng = random.Random(97)
    with Experiment("long-period-27-29", puzzle="k4", cribs_forced=True,
                    notes="periods 27-29 (the only short lengths the cribs leave open); "
                          "24/27-29 key letters forced, free slots brute-forced/hill-climbed; "
                          "vig/beau/varbeau, AZ+KRYPTOS") as ex:
        res = run(K4, CRIBS, {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}, rng, ex=ex)
        print("Null baseline: same search on 20 shuffled K4s ...")
        null = null_baseline(20, rng)
        k4_best = res[0][0]
        margin = k4_best - null[-1]
        ex.notes += (f"; K4 best q={k4_best:.2f} vs shuffled-K4 null "
                     f"median {null[len(null) // 2]:.2f}, max {null[-1]:.2f} (English ~-4.7)")
        if "--words" in sys.argv:
            n_alpha, top_partial, top_full = keyword_stage(K4, rng, ex)
            print("Keyword-stage null: same selection on 4 shuffled K4s (a few minutes each) ...")
            wnull = []
            for _ in range(4):
                fake = list(K4)
                rng.shuffle(fake)
                wnull.append(keyword_stage("".join(fake), rng)[2][0])
            wnull.sort()
            ex.notes += (f"; +{n_alpha} keyword alphabets: K4 best q={top_full[0]:.2f} ({top_full[1]}) "
                         f"vs shuffled-K4 null {wnull[0]:.2f}..{wnull[-1]:.2f}")
    print("\nTop K4 candidates (English ~ -4.7, noise ~ -6.5):")
    for s, pt, p in res[:5]:
        print(f"  q={s:6.2f}  {p}\n           {pt}")
    print(f"\nShuffled-K4 null: min {null[0]:.2f}  median {null[len(null) // 2]:.2f}  max {null[-1]:.2f}")
    verdict = "WORTH A LOOK" if margin > 0.3 else "indistinguishable from noise"
    print(f"K4's best ({k4_best:.2f}) vs best shuffled fake ({null[-1]:.2f}): margin {margin:+.2f} -> {verdict}")
    if "--words" in sys.argv:
        wverdict = "WORTH A LOOK" if top_full[0] - wnull[-1] > 0.3 else "indistinguishable from noise"
        print(f"\nKeyword alphabets: {n_alpha:,} tried; best fully-solved q={top_full[0]:.2f} "
              f"keyword={top_full[1]} {top_full[2]} L={top_full[3]}\n  {top_full[4]}")
        print(f"Same selection on shuffled K4s: {', '.join(f'{x:.2f}' for x in wnull)} -> {wverdict}")


if __name__ == "__main__":
    main()
