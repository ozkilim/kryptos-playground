"""Idea 80: the key is ordinary GERMAN text, on a tableau built from a keyword alphabet.

BERLIN CLOCK and the 1989 Berlin setting make a German sentence a natural running key. Attack 57 read off the
13 + 11 key letters that the clues force, for every keyword alphabet, and asked whether they are English. A
German key would have scored as noise there. This is the same search with a German quadgram table.

For each of ~236k keyword alphabets M (exactly attack 57's list and views):
  alphabets   plain M / cipher A-Z (Quagmire I), plain A-Z / cipher M (II), M / M (III),
              M / KRYPTOS and KRYPTOS / M (IV with the sculpture's alphabet)
  cipher      Vigenere, Beaufort, variant Beaufort, and the reversed (DIANA) table
  key letter  A-Z[s + c] for every Caesar offset c, or M[s], or KRYPTOS[s]
The 24 forced key letters are scored on the German quadgram table (18 quadgrams).

THE CATCH: the repository holds no German text and no German quadgram table, and no network is allowed. The
script looks for (see kryptos/idea80_german.py):

  data/german/quadgrams.txt   "ABCD count" per line, from a few million letters of German prose,
                              umlauts as AE OE UE, sharp s as SS
  data/german/sample.txt      a few thousand letters of German prose not used for the table (planted keys)

While they are missing it prints UNTESTABLE, writes nothing to the ledger, and only checks its own machinery:
with a table built from part of the Kryptos plaintexts (a stand-in language, NOT German) a planted key cut
from the held-out part must be recovered. That check says the code is right, nothing about K4.

  python attacks/80_german_sentence_keys.py            # K4 + 3 shuffled controls + planted German keys
"""
import os
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea80_german as g  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
MARGIN = 0.35   # attack 57's bar: K4's best must beat every shuffled control by this much


def rank_of(top, w):
    return next((i + 1 for i, t in enumerate(top) if keyword_alphabet(t[1]) == keyword_alphabet(w)), None)


def machinery_check(n_alpha=400, trials=4):
    """Stand-in language: table from K2+K3 plaintext, keys cut from the same text, plaintext K-texts too.
    The table has seen the key (no held-out text is large enough), so this only shows the plumbing works."""
    a57 = g.attack57()
    text = a57.english_text()
    tab = g.table_from_text(text)
    alphas = a57.alphabets(limit=n_alpha)
    rng, found = random.Random(80), 0
    for kind in ("Q3", "Q1") * (trials // 2):
        ct, cribs, w, key = g.plant(rng, alphas, text, kind)
        top = g.score_alphabets(alphas, ct, cribs, tab)
        r = rank_of(top, w)
        found += r == 1
        print("  stand-in planted %s keyword %-12s key %s|%s -> best %s rank of truth: %s" % (
            kind, w, key[21:34], key[63:74], top[0][4], r))
    return found, trials


if __name__ == "__main__":
    model, text_path = g.find_german()
    if model is None or text_path is None:
        print("UNTESTABLE: no German language model in the repository.")
        print("  German quadgram table: %s" % (model or "MISSING (wanted data/german/quadgrams.txt)"))
        print("  German key text:       %s" % (text_path or "MISSING (wanted data/german/sample.txt)"))
        print("Machinery check with a stand-in table (Kryptos plaintexts, not German):")
        found, n = machinery_check()
        print("machinery: %d/%d planted keys ranked first" % (found, n))
        print("VERDICT: untestable (K4 not run)")
        sys.exit(0 if found == n else 1)

    a57 = g.attack57()
    alphas = a57.alphabets(limit=3000 if SMOKE else None)
    key_text = g.german_letters(Path(text_path).read_text(encoding="utf-8", errors="ignore"))
    n_views = 5 * 4 * 28
    with Experiment("running key of unknown German text on keyword tableaux", puzzle="k4",
                    notes=f"{len(alphas)} keyword alphabets x Quagmire I-IV x 4 ciphers x 28 key letterings; "
                          f"forced 13+11 key letters scored on {Path(model).name}", cribs_forced=True) as ex:
        top = g.run(K4, CRIBS, alphas, model)
        ex.count(len(alphas) * n_views)
        print("K4 best key fragments (German model):")
        for t in top[:8]:
            print("  %.3f  %-14s %-9s %-6s %s" % t)
        ctrl = []
        for seed in (1, 2, 3):
            c = g.run(shuffled_control(seed), CRIBS, alphas, model)
            ctrl.append(c[0][0])
            print("shuffled K4 #%d best: %.3f  %s" % (seed, c[0][0], c[0][4]))
        rng, found = random.Random(9), 0
        for kind in ("Q3", "Q1", "Q3", "Q1"):
            ct, cribs, w, key = g.plant(rng, alphas, key_text, kind)
            p = g.run(ct, cribs, alphas, model)
            r = rank_of(p, w)
            found += r is not None and r <= 4
            print("planted %s keyword %-12s true key %s|%s -> best %.3f (%s) rank of truth: %s" % (
                kind, w, key[21:34], key[63:74], p[0][0], p[0][4], r))
        print("\nplanted German keys with the true alphabet in the top 4: %d/4" % found)
        print("K4 best %.3f vs shuffled best %s" % (top[0][0], ", ".join("%.3f" % c for c in ctrl)))
        print("VERDICT:", "K4 ABOVE CONTROLS - read the fragments" if top[0][0] > max(ctrl) + MARGIN
              else "no signal (K4 = shuffled)")
