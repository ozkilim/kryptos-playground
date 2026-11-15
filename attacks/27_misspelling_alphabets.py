"""Idea 27: K1-K3's deliberate misspellings as edits to the ALPHABET.

Sanborn: the answers to K1-K3 contain clues to K4, and his misspellings are
deliberate. The four "wrong letters":
  IQLUSION (K1): L -> Q     UNDERGRUUND (K2): O -> U
  DESPARATLY (K3): E -> A   PALIMPCEST (tableau): S -> C
Others tried those letters as keys and masks. Here they are SWAPS inside the
alphabet (plain A-Z or KRYPTOS), every combination: 30 near-plain
alphabets, which is the kind of alphabet our fingerprint ranking favours.

Tests, all exact against the 24 clue letters:
  (a) repeating, progressive, autokey and small-shift keys (stack engine, no transposition)
  (b) two stacked repeating keys (LAYER TWO), configurations the clues pin down completely,
      decrypted directly and scored, vs shuffled K4s.
"""
import sys
import time
from itertools import combinations
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.campaign import SMOKE, report, run_stack_idea, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import quadgram_score, word_coverage  # noqa: E402
from kryptos.solvers import twokeys as T  # noqa: E402

SWAPS = {"IQLUSION L/Q": ("L", "Q"), "UNDERGRUUND O/U": ("O", "U"),
         "DESPARATLY E/A": ("E", "A"), "PALIMPCEST S/C": ("S", "C")}
PAIRS = [(a, b) for a in range(2, 27) for b in range(a + 1, 27) if b % a != 0]


def swapped(base, pairs):
    a = list(base)
    for x, y in pairs:
        i, j = a.index(x), a.index(y)
        a[i], a[j] = a[j], a[i]
    return "".join(a)


def alphabets():
    out = {}
    for bname, base in (("AZ", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)):
        for r in range(1, 5):
            for combo in combinations(SWAPS, r):
                name = f"{bname}+" + "+".join(c.split()[0] for c in combo)
                out[name] = swapped(base, [SWAPS[c] for c in combo])
    return out


def _twokey(args):
    ct, name, alpha, variant = args
    out = []
    for L1, L2 in PAIRS:
        comps = T.solve_exact(T.equations(ct, CRIBS, alpha, variant, L1, L2))
        if comps is None or len(comps) != 1:
            continue
        c = T.KeyCompleter(ct, alpha, variant, L1, L2, comps)
        if c.freeA or c.freeB:
            continue
        pt = c.decrypt({"off": [0], "A": {}, "B": {}})
        out.append((quadgram_score(pt), pt, name, variant, L1, L2))
    return out


def twokey_run(ct, al):
    jobs = [(ct, n, a, v) for n, a in al.items() for v in ("vigenere", "beaufort", "variant_beaufort")]
    with Pool(cpu_count()) as pool:
        res = pool.map(_twokey, jobs)
    return sorted((h for r in res for h in r), key=lambda h: -h[0]), len(jobs) * len(PAIRS)


if __name__ == "__main__":
    t0 = time.time()
    al = alphabets()
    if SMOKE:
        al = dict(list(al.items())[:3])
    # (a) single-layer key models on the misspelling alphabets (stack engine, identity transposition)
    run_stack_idea("27a", "misspelling alphabets x periodic/progressive/autokey/shift", [("maps", [(("identity",), list(range(97)))])],
                   {"periodic", "progressive", "ctauto", "ptauto", "shift"},
                   notes=f"{len(al)} alphabets = A-Z/KRYPTOS with the K1-K3 misspelling swaps (L/Q, O/U, E/A, S/C); "
                         "no transposition; periodic<=26, progressive, ct/pt autokey<=60, shifts",
                   alphabets=al, n_controls=2, places=("after",))
    # (b) two stacked keys, fully clue-determined configs
    with Experiment("misspelling-alphabets x two-stacked-keys", puzzle="k4", cribs_forced=True,
                    notes=f"{len(al)} misspelling-swap alphabets x two stacked keys (pairs <=26) x vig/beau/varbeau; "
                          "only configs fully fixed by the clues, decrypted directly") as ex:
        hits, tested = twokey_run(K4, al)
        ex.count(tested)
        for q, pt, n, v, L1, L2 in hits[:30]:
            ex.add(pt, alphabet=n, variant=v, L1=L1, L2=L2)
        ctrl = [twokey_run(shuffled(K4, 1100 + s), al)[0] for s in range(2)]
        best = hits[0][0] if hits else None
        cbest = max((c[0][0] for c in ctrl if c), default=None)
        if not hits:
            verdict_b = "dead: no configuration fully fixed by the clues"
        elif cbest is not None and best - cbest > 0.3:
            verdict_b = "WORTH A LOOK: beats shuffled controls"
        else:
            verdict_b = f"dead: {len(hits)} determined decrypts, best {best:.2f} vs shuffled {cbest:.2f}"
        ex.notes += f"; {verdict_b}"
    import json
    from kryptos.campaign import RESULTS
    a = json.loads((RESULTS / "27a.json").read_text())
    report("27", name="K1-K3 misspellings as alphabet swaps", alphabets=list(al), single_layer=a,
           twokey_determined=len(hits), twokey_best=best, twokey_control_best=cbest,
           top=[{"q": round(q, 3), "words": round(word_coverage(pt), 2), "alphabet": n, "variant": v,
                 "L1": L1, "L2": L2, "plaintext": pt} for q, pt, n, v, L1, L2 in hits[:5]],
           hypotheses=a.get("hypotheses", 0) + tested,
           verdict=f"(a) {a['verdict']}; (b) {verdict_b}", minutes=round((time.time() - t0) / 60, 1))
    print("[27]", f"(a) {a['verdict']}; (b) {verdict_b}")
