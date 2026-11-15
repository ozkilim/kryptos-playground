"""Idea 15: mine Sanborn's Nov 2025 hints. Theme words (data/keys_sanborn2025.txt:
Egypt 1986, the Berlin Wall, "delivering a message", the World Clock at
Alexanderplatz, plus Kryptos staples) used EVERYWHERE at once:

  (a) Quagmire I-IV: plaintext alphabet, ciphertext alphabet and repeating key
      all drawn from theme words (plus plain A-Z and KRYPTOS); exact decrypt.
  (b) theme-keyword columnar orders + theme-keyword alphabets x periodic,
      progressive, autokey and small-shift keys (stack engine).
"""
import sys
import time
from itertools import product
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.campaign import report, run_stack_idea  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET, keyed_alphabet  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.solvers.stack import columnar_map  # noqa: E402


def theme_words():
    ws = []
    for f in ("keys_sanborn2025.txt", "keys.txt"):
        ws += [w.strip().upper() for w in open(DATA_DIR / f) if w.strip() and not w.startswith("#")]
    return sorted(set(ws))


def quagmire(words):
    alphas = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
    alphas.update({w: keyed_alphabet(w) for w in words})
    alphas = {n: a for n, a in alphas.items() if list(alphas.values()).index(a) == list(alphas.keys()).index(n)}
    idx = {n: {c: i for i, c in enumerate(a)} for n, a in alphas.items()}
    crib = sorted(CRIBS)
    tested, hits = 0, []
    for (pn, pa), (cn, ca) in product(alphas.items(), repeat=2):
        pi, ci = idx[pn], idx[cn]
        for key in words:
            kv = [ci[ch] if ch in ci else 0 for ch in key]  # key letters read in the cipher alphabet
            L = len(kv)
            for beau in (False, True):
                tested += 1
                good = 0
                for i in crib:
                    k = kv[i % L]
                    p = pa[(k - ci[K4[i]]) % 26] if beau else pa[(ci[K4[i]] - k) % 26]
                    if p != CRIBS[i]:
                        break
                    good += 1
                if good == len(crib):
                    pt = "".join(pa[(kv[i % L] - ci[c]) % 26] if beau else pa[(ci[c] - kv[i % L]) % 26]
                                 for i, c in enumerate(K4))
                    hits.append((pn, cn, key, beau, pt))
    return tested, hits, len(alphas)


if __name__ == "__main__":
    t0 = time.time()
    words = theme_words()
    from kryptos.campaign import SMOKE
    if SMOKE:
        words = words[:12]
    with Experiment("sanborn2025-theme-quagmire", puzzle="k4",
                    notes=f"{len(words)} theme words as plaintext alphabet x cipher alphabet x repeating key "
                          "(Quagmire I-IV incl. A-Z/KRYPTOS), Vigenere and Beaufort forms, exact decrypt") as ex:
        tested, hits, n_alpha = quagmire(words)
        ex.count(tested)
        for pn, cn, key, beau, pt in hits:
            ex.add(pt, plain_alpha=pn, cipher_alpha=cn, key=key, beaufort=beau)
        verdict_a = "dead: no theme-word combination places all 24 clue letters" if not hits else "HITS: check"
        ex.notes += f"; {len(hits)} full crib matches; {verdict_a}"
    print(f"[15a] {tested:,} Quagmire combos over {n_alpha} alphabets: {len(hits)} hits")
    orders = sorted({tuple(sorted(range(len(w)), key=lambda i: (w[i], i))) for w in words if 2 <= len(w) <= 20})
    jobs = [("maps", [(("theme-columnar", o), columnar_map(o)) for o in orders])]
    alphas = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
    alphas.update({w: keyed_alphabet(w) for w in words})
    run_stack_idea("15", "sanborn2025-theme-columnar x theme-alphabets", jobs,
                   {"periodic", "progressive", "ctauto", "ptauto", "shift"},
                   notes=f"{len(orders)} theme-keyword columnar orders x {len(alphas)} theme alphabets x periodic<=26, "
                         "progressive, ct/pt autokey<=60, shifts, before/after",
                   alphabets=alphas, n_controls=2)
    import json
    from kryptos.campaign import RESULTS
    r = json.loads((RESULTS / "15.json").read_text())
    r["quagmire_part"] = {"hypotheses": tested, "alphabets": n_alpha, "full_crib_matches": len(hits),
                          "verdict": verdict_a}
    r["verdict"] = f"(a) {verdict_a}; (b) {r['verdict']}"
    (RESULTS / "15.json").write_text(json.dumps(r, indent=1))
