"""Idea 26: three stacked layers, one of them a theme word.

PK8 stacked FOUR keys; K2 says "LAYER TWO". Vigenere layers on one tableau add
up, so key = +-W[i mod |W|] + A[i mod L1] + B[i mod L2]. With W a known theme
word (Sanborn's 2025 hints + Kryptos keys), removing it leaves the two-key
problem, which the clue equations solve exactly. Only configurations where the
clues pin down EVERY key letter are kept, so each gives one deterministic
decrypt, which is scored for English and compared with shuffled K4s.
"""
import sys
import time
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET, vigenere_decrypt, vigenere_encrypt  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import quadgram_score, word_coverage  # noqa: E402
from kryptos.solvers import twokeys as T  # noqa: E402

ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
PAIRS = [(a, b) for a in range(2, 27) for b in range(a + 1, 27) if b % a != 0]


def theme_words():
    ws = set()
    for f in ("keys_sanborn2025.txt", "keys.txt"):
        ws |= {w.strip().upper() for w in open(DATA_DIR / f) if w.strip() and not w.startswith("#")}
    return sorted(w for w in ws if w.isalpha())


def _job(args):
    ct, word, sign, an = args
    al = ALPHAS[an]
    base = vigenere_decrypt(ct, word, al) if sign > 0 else vigenere_encrypt(ct, word, al)
    out, tested = [], 0
    for L1, L2 in PAIRS:
        tested += 1
        comps = T.solve_exact(T.equations(base, CRIBS, al, "vigenere", L1, L2))
        if comps is None or len(comps) != 1:
            continue
        c = T.KeyCompleter(base, al, "vigenere", L1, L2, comps)
        if c.freeA or c.freeB:
            continue
        pt = c.decrypt({"off": [0], "A": {}, "B": {}})
        out.append((quadgram_score(pt), pt, word, sign, an, L1, L2))
    return tested, out


def run(ct, words):
    jobs = [(ct, w, s, an) for w in words for s in (1, -1) for an in ALPHAS]
    with Pool(cpu_count()) as pool:
        res = pool.map(_job, jobs, chunksize=4)
    tested = sum(t for t, _ in res)
    hits = sorted((h for _, o in res for h in o), key=lambda h: -h[0])
    return tested, hits


if __name__ == "__main__":
    t0 = time.time()
    words = theme_words()[: 6 if SMOKE else None]
    with Experiment("three-layers-theme-word+two-keys", puzzle="k4", cribs_forced=True,
                    notes=f"key = +-theme word ({len(words)} words) + A[i mod L1] + B[i mod L2], pairs <=26, "
                          "A-Z/KRYPTOS; only configs fully fixed by the clues, decrypted directly") as ex:
        tested, hits = run(K4, words)
        ex.count(tested)
        for q, pt, w, s, an, L1, L2 in hits[:30]:
            ex.add(pt, word=w, sign=s, alphabet=an, L1=L1, L2=L2)
        ctrl = []
        for s in range(2):
            ct_t, ch = run(shuffled(K4, 900 + s), words)
            ctrl.append({"determined": len(ch), "best_q": round(ch[0][0], 3) if ch else None})
        best = hits[0][0] if hits else None
        cbest = max((c["best_q"] for c in ctrl if c["best_q"] is not None), default=None)
        if not hits:
            verdict = "dead: no configuration is fully fixed by the clues"
        elif cbest is not None and best - cbest > 0.3:
            verdict = "WORTH A LOOK: a determined decrypt beats the shuffled controls"
        else:
            verdict = f"dead: {len(hits)} fully determined decrypts, best {best:.2f} vs shuffled {cbest}"
        ex.notes += f"; {verdict}"
    report("26", name="three layers: theme word + two keys", hypotheses=tested, determined=len(hits),
           best_quadgram=best, control=ctrl, verdict=verdict, minutes=round((time.time() - t0) / 60, 1),
           top=[{"q": round(q, 3), "words": round(word_coverage(pt), 2), "word": w, "sign": s, "alphabet": an,
                 "L1": L1, "L2": L2, "plaintext": pt} for q, pt, w, s, an, L1, L2 in hits[:5]])
    print("[26]", verdict)
