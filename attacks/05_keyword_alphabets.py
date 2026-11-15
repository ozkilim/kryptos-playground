"""Hypothesis: K4 is a periodic cipher on a keyword-SCRAMBLED alphabet, like
K1/K2 (which used KRYPTOS), but with a different, unknown keyword. These are
the classic "Quagmire" ciphers:

  Quagmire I    plaintext alphabet scrambled by the keyword, ciphertext plain A-Z
  Quagmire II   plaintext plain A-Z, ciphertext alphabet scrambled
  Quagmire III  both alphabets scrambled the same way (K1/K2 are this, keyword KRYPTOS)

For every dictionary word as the alphabet keyword, and every key period 1-13,
it checks whether the 24 clue letters agree on a repeating key. Pure crib
consistency, no decryption, ~2.5M hypotheses per minute.

  python attacks/05_keyword_alphabets.py            # data/keys.txt + /usr/share/dict/words
  python attacks/05_keyword_alphabets.py words.txt
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, keyed_alphabet  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.solvers.periodic import default_wordlist  # noqa: E402

MAX_PERIOD = 13
CRIB_POS = sorted(CRIBS)


def _pairs_by_period(positions, max_period):
    """For each period: the (i, j) crib pairs that must share a key letter."""
    out = {}
    for p in range(1, max_period + 1):
        last, pairs = {}, []
        for i in positions:
            r = i % p
            if r in last:
                pairs.append((last[r], i))
            last[r] = i
        out[p] = pairs
    return out


def scan(ct, cribs, words, max_period=MAX_PERIOD, ex=None, kinds=("I", "II", "III")):
    """Returns list of survivors: (word, kind, period) where every constraint holds."""
    positions = sorted(cribs)
    pairs = _pairs_by_period(positions, max_period)
    survivors, best = [], (0.0, None)
    seen = set()
    for w in words:
        ka = keyed_alphabet(w)
        if ka in seen:
            continue
        seen.add(ka)
        ki = {c: i for i, c in enumerate(ka)}
        for kind in kinds:
            if kind == "I":
                pa, ca = ki, {c: i for i, c in enumerate(AZ)}
            elif kind == "II":
                pa, ca = {c: i for i, c in enumerate(AZ)}, ki
            else:
                pa = ca = ki
            k = {i: (ca[ct[i]] - pa[cribs[i]]) % 26 for i in positions}
            for p, prs in pairs.items():
                if ex is not None:
                    ex.count(1)
                sat = sum(k[a] == k[b] for a, b in prs)
                frac = sat / len(prs)
                if frac > best[0]:
                    best = (frac, (w, kind, p, sat, len(prs)))
                if sat == len(prs):
                    survivors.append((w, kind, p))
    return survivors, best, len(seen)


def main():
    if len(sys.argv) > 1:
        words = [w.strip().upper() for w in open(sys.argv[1]) if w.strip().isalpha()]
    else:
        words = default_wordlist()
    words = [w for w in words if len(w) >= 3]
    with Experiment("quagmire-keyword-alphabets", puzzle="k4",
                    notes=f"Quagmire I/II/III, {len(words)} keywords, periods 1-{MAX_PERIOD}") as ex:
        survivors, best, n_alpha = scan(K4, CRIBS, words, ex=ex)
        ex.notes += f"; {n_alpha} distinct alphabets; survivors {len(survivors)}"
    print(f"\n{n_alpha:,} distinct keyword alphabets x 3 Quagmire types x {MAX_PERIOD} periods")
    w, kind, p, sat, n = best[1]
    print(f"Best: keyword={w} Quagmire {kind} period {p}: {sat}/{n} key equalities hold")
    print(f"Survivors (every equality holds): {len(survivors)}")
    for s in survivors[:20]:
        print("  ", s)


if __name__ == "__main__":
    main()
