"""Idea 14: keyword-scrambled alphabets with a repeating key of length 14-26.

At these lengths the 24 clue letters barely constrain the key, so crib
consistency can't decide (an open gap). But every key slot a clue touches is
FIXED, which forces 50-90% of the plaintext. Score those forced letters for
English. Quagmire I, II, III (Vigenere form) and III (Beaufort form), every
dictionary keyword alphabet. Compare K4's best against the same search on
shuffled K4s.
"""
import sys
import time
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.campaign import report, shuffled, smoke  # noqa: E402
from kryptos.ciphers import AZ, keyed_alphabet  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402
from kryptos.solvers.periodic import default_wordlist  # noqa: E402

PERIODS = range(14, 27)
KINDS = ("I", "II", "III", "III-beau")
_W = {}


def _init(ct):
    _W["ct"] = ct
    _W["qg"] = Quadgrams()


def _score_alpha(word):
    ct, qg = _W["ct"], _W["qg"]
    ka = keyed_alphabet(word)
    kidx = {c: i for i, c in enumerate(ka)}
    aidx = {c: i for i, c in enumerate(AZ)}
    best = []
    for kind in KINDS:
        if kind == "I":
            pa, ca, pal = kidx, aidx, ka
        elif kind == "II":
            pa, ca, pal = aidx, kidx, AZ
        else:
            pa, ca, pal = kidx, kidx, ka
        beau = kind == "III-beau"
        for L in PERIODS:
            key, ok = {}, True
            for i, p in CRIBS.items():
                k = (ca[ct[i]] + pa[p]) % 26 if beau else (ca[ct[i]] - pa[p]) % 26
                r = i % L
                if key.setdefault(r, k) != k:
                    ok = False
                    break
            if not ok:
                continue
            pt = []
            for i, c in enumerate(ct):
                k = key.get(i % L)
                if k is None:
                    pt.append(None)
                else:
                    pt.append(pal[(k - ca[c]) % 26] if beau else pal[(ca[c] - k) % 26])
            vals = [qg.logp.get("".join(pt[i:i + 4]), qg.floor)
                    for i in range(len(pt) - 3) if None not in pt[i:i + 4]]
            if len(vals) >= 20:
                best.append((sum(vals) / len(vals), word, kind, L, "".join(x or "." for x in pt)))
    best.sort(reverse=True)
    return best[:2], len(best)


def run(ct, words, procs=None):
    with Pool(procs or cpu_count(), initializer=_init, initargs=(ct,)) as pool:
        tops, consistent = [], 0
        for b, n in pool.imap_unordered(_score_alpha, words, chunksize=500):
            tops += b
            consistent += n
    tops.sort(reverse=True)
    return tops[:20], consistent


if __name__ == "__main__":
    t0 = time.time()
    seen, words = set(), []
    for w in default_wordlist():
        a = keyed_alphabet(w)
        if len(w) >= 3 and a not in seen:
            seen.add(a)
            words.append(w)
    words = smoke(words, 3000)
    with Experiment("keyword-alphabets-periods14-26-english", puzzle="k4", cribs_forced=True,
                    notes=f"Quagmire I/II/III/III-beau, {len(words)} keyword alphabets, periods 14-26; "
                          "forced plaintext scored for English vs shuffled K4") as ex:
        top, n_cons = run(K4, words)
        ex.count(len(words) * len(KINDS) * len(PERIODS))
        for q, w, kind, L, pt in top[:20]:
            ex.add(pt.replace(".", "A"), keyword=w, kind=kind, period=L, forced_score=round(q, 3))
        nulls = [((run(shuffled(K4, s), words)[0] or [(-99,)])[0][0]) for s in range(3)]
        if not top:
            top = [(-99, "-", "-", 0, "")]
        margin = top[0][0] - max(nulls)
        verdict = ("WORTH A LOOK: K4 beats every shuffled control" if margin > 0.25
                   else "dead: K4's best forced plaintext scores like shuffled K4s")
        ex.notes += f"; K4 best {top[0][0]:.2f} ({top[0][1]} {top[0][2]} L={top[0][3]}) vs nulls {[round(x, 2) for x in nulls]}; {verdict}"
    report("14", name="keyword-alphabets-periods14-26-english", hypotheses=len(words) * len(KINDS) * len(PERIODS),
           crib_consistent=n_cons, best=[{"q": round(q, 3), "keyword": w, "kind": k, "period": L, "forced": pt}
                                         for q, w, k, L, pt in top[:5]],
           null_best=nulls, verdict=verdict, minutes=round((time.time() - t0) / 60, 1))
    print(f"[14] K4 best {top[0][0]:.2f} vs shuffled {nulls} -> {verdict}")
