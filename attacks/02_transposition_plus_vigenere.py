"""Hypothesis: K4 = columnar transposition + periodic Vigenere/Beaufort,
in either order. Tests ~46,000 transpositions x 12 periods in a few minutes
WITHOUT decrypting anything, using only the 24 crib letters.

The trick (crib consistency): fix a transposition and a period p. Each crib
letter then implies one key letter at one key position (0..p-1). If the
hypothesis is right, every crib landing on the same key position implies the
SAME key letter. Count how many of the 24 agree. Random hypotheses agree
rarely; the true one agrees 24/24.

  order "trans_then_vig":  C = Vig( T(P) )     key index = ciphertext position
  order "vig_then_trans":  C = T( Vig(P) )     key index = plaintext position

  python attacks/02_transposition_plus_vigenere.py [max_width=8] [max_period=12]
"""
import sys
from collections import Counter
from itertools import permutations
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET, columnar_decrypt  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402

def consistency(pairs, period):
    """pairs: (key_index, implied_key_value). Count agreeing cribs."""
    buckets = {}
    for k, v in pairs:
        buckets.setdefault(k % period, Counter())[v] += 1
    agree = sum(c.most_common(1)[0][1] for c in buckets.values())
    key = {r: c.most_common(1)[0][0] for r, c in buckets.items()}
    return agree, key


def scan(ct, cribs, max_width=8, max_period=12, alphabets=None, ex=None, report_at=22):
    """Return {period: best (agree, width, order, cipher, how, alphabet)}.
    If `ex` (an Experiment) is given, near-survivors are decrypted and logged."""
    alphabets = alphabets or {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
    n = len(ct)
    crib_pos = sorted(cribs)
    best_by_period = {}
    for aname, alpha in alphabets.items():
        idx = {c: i for i, c in enumerate(alpha)}
        C = [idx[c] for c in ct]
        P = {i: idx[ch] for i, ch in cribs.items()}
        for width in range(2, max_width + 1):
            for order in permutations(range(width)):
                # columnar_decrypt(T(P)) = P, so perm[i] = where plaintext letter i sits in T(P)
                perm = columnar_decrypt(list(range(n)), list(order))
                for cname in ("vig", "beau"):
                    for how in ("trans_then_vig", "vig_then_trans"):
                        pairs = []
                        for i in crib_pos:
                            j = perm[i]
                            kval = (C[j] - P[i]) % 26 if cname == "vig" else (C[j] + P[i]) % 26
                            pairs.append((j if how == "trans_then_vig" else i, kval))
                        if ex is not None:
                            ex.count(max_period)  # hypotheses tested, even with no plaintext
                        for period in range(1, max_period + 1):
                            agree, key = consistency(pairs, period)
                            b = best_by_period.get(period)
                            if b is None or agree > b[0]:
                                best_by_period[period] = (agree, width, list(order), cname, how, aname)
                            if ex is not None and agree >= report_at:
                                kfull = [key.get(r, 0) for r in range(period)]  # unknown key slots -> 'A'
                                out = []
                                for i in range(n):
                                    j = perm[i]
                                    kv = kfull[(j if how == "trans_then_vig" else i) % period]
                                    out.append(alpha[(C[j] - kv) % 26] if cname == "vig" else alpha[(kv - C[j]) % 26])
                                ex.add("".join(out), width=width, order=list(order), cipher=cname,
                                       how=how, period=period, alphabet=aname, agree=agree)
    return best_by_period


def main():
    max_width = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    max_period = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    with Experiment("columnar+vigenere-crib-consistency", puzzle="k4",
                    notes=f"widths 2-{max_width} all orders, periods 1-{max_period}, both orders, "
                          f"vig+beau, AZ+KRYPTOS") as ex:
        best = scan(K4, CRIBS, max_width, max_period, ex=ex)
        top = max(best.values())
        ex.notes += f"; best agreement {top[0]}/24 (period {max(best, key=lambda p: best[p])})"
    print("\nBest crib agreement by period (24 = hypothesis survives):")
    for p in sorted(best):
        a, w, o, c, h, al = best[p]
        print(f"  period {p:>2}: {a:>2}/24  width={w} order={o} {c} {h} {al}")
    print("If nothing reaches 24/24, this family is ruled out for these widths/periods."
          " Note it in docs/dead-ends.md.")


if __name__ == "__main__":
    main()
