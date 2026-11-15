"""Idea 37: Egypt-era alphabet orders (Sanborn's 1986 Egypt trip).

Hieroglyphic uniliteral order, Coptic (Egypt's own late script), Greek,
Phoenician/Hebrew and Arabic (abjad and modern) orders as Latin alphabets,
forward and reversed: 12 "near-plain" alphabets with an Egyptian logic.

  (a) single key layer on each alphabet: periodic, progressive, autokey, small shifts (exact)
  (b) Quagmire I/II/III/IV: every pair of {A-Z, KRYPTOS, these} as plaintext/ciphertext alphabets,
      repeating key 1-26 (exact clue consistency)
  (c) two stacked keys on each alphabet, configurations fully pinned by the clues (decrypted, scored)
"""
import sys
import time
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4  # noqa: E402
from kryptos.campaign import SMOKE, report, run_stack_idea, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.cribtools import periodic_agreement, required_keys  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.historic_alphabets import alphabets  # noqa: E402
from kryptos.score import quadgram_score  # noqa: E402
from kryptos.solvers import twokeys as T  # noqa: E402

PAIRS = [(a, b) for a in range(2, 27) for b in range(a + 1, 27) if b % a != 0]


def quagmire(ct, al_all):
    hits, tested = [], 0
    for pn, pa in al_all.items():
        for cn, ca in al_all.items():
            for v in ("vigenere", "beaufort"):
                req = required_keys(ct, CRIBS, ca, v, plain_alphabet=pa)
                for L in range(1, 27):
                    tested += 1
                    sat, con = periodic_agreement(req, L)
                    if con >= 6 and sat == con:
                        hits.append((pn, cn, v, L, con))
    return tested, hits


def _two(args):
    ct, name, al, v = args
    out = []
    for L1, L2 in PAIRS:
        comps = T.solve_exact(T.equations(ct, CRIBS, al, v, L1, L2))
        if comps is None or len(comps) != 1:
            continue
        c = T.KeyCompleter(ct, al, v, L1, L2, comps)
        if c.freeA or c.freeB:
            continue
        pt = c.decrypt({"off": [0], "A": {}, "B": {}})
        out.append((quadgram_score(pt), pt, name, v, L1, L2))
    return out


def twokeys(ct, al):
    with Pool(cpu_count()) as pool:
        r = pool.map(_two, [(ct, n, a, v) for n, a in al.items() for v in ("vigenere", "beaufort", "variant_beaufort")])
    return sorted((h for x in r for h in x), key=lambda h: -h[0])


if __name__ == "__main__":
    t0 = time.time()
    al = alphabets()
    if SMOKE:
        al = dict(list(al.items())[:2])
    run_stack_idea("37a", "Egypt-era alphabets x periodic/progressive/autokey/shift",
                   [("maps", [(("identity",), list(range(97)))])], {"periodic", "progressive", "ctauto", "ptauto", "shift"},
                   notes=f"{len(al)} alphabets (hieroglyph, Coptic, Greek, Phoenician/Hebrew, Arabic abjad/hijai orders, "
                         "+reversed); no transposition", alphabets=al, n_controls=2, places=("after",))
    al_all = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET, **al}
    with Experiment("Egypt-era alphabets: Quagmire I-IV + two stacked keys", puzzle="k4", cribs_forced=True,
                    notes="every plain/cipher alphabet pair from A-Z, KRYPTOS and the 12 Egypt-era orders, periodic "
                          "1-26 (exact); two stacked keys fully pinned by the clues") as ex:
        tq, qh = quagmire(K4, al_all)
        th = twokeys(K4, al)
        ex.count(tq + len(al) * 3 * len(PAIRS))
        for q, pt, n, v, L1, L2 in th[:20]:
            ex.add(pt, alphabet=n, variant=v, L1=L1, L2=L2)
        cq = [len(quagmire(shuffled(K4, 3700 + s), al_all)[1]) for s in range(2)]
        ct2 = [twokeys(shuffled(K4, 3800 + s), al) for s in range(2)]
        cbest = max((c[0][0] for c in ct2 if c), default=None)
        best = th[0][0] if th else None
        verdict_b = (f"Quagmire: {len(qh)} consistent (shuffled {cq}); two-key: "
                     + (f"{len(th)} pinned decrypts, best {best:.2f} vs shuffled {cbest:.2f}" if th else "none pinned"))
        flag = (len(qh) > 2 * max(cq) + 2) or (best is not None and cbest is not None and best - cbest > 0.3)
        ex.notes += f"; {verdict_b}"
    import json
    from kryptos.campaign import RESULTS
    a = json.loads((RESULTS / "37a.json").read_text())
    verdict = f"(a) {a['verdict']}; (b) " + ("WORTH A LOOK: " if flag else "dead: ") + verdict_b
    report("37", name="Egypt-era alphabets", alphabets=al, single_layer=a, quagmire_hits=[list(h) for h in qh[:20]],
           quagmire_controls=cq, twokey_best=best, twokey_control_best=cbest, verdict=verdict,
           hypotheses=a.get("hypotheses", 0) + tq, minutes=round((time.time() - t0) / 60, 1))
    print("[37]", verdict)
