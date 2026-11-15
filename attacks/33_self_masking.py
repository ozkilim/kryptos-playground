"""Idea 33: self-masking: K4 keyed by its OWN text read in a scrambled order.

"Masking" (Scheidt) on a plain alphabet could be as simple as adding the
message to a scrambled copy of itself: c[i] = E(p[i], x[s(i)]), where x is
the plaintext or the ciphertext and s is a permutation (reversal, "every
a-th letter" mod 97, a column order, a grid route, K3's rotation).
In natural order this is autokey (dead); scrambled, it was never tried.

  ciphertext-keyed: p[i] = D(c[i], c[s(i)]); decrypts directly, exact clue test.
  plaintext-keyed:  c[i] = E(p[i], p[s(i)]); testable wherever i and s(i) are both clue
                    positions; survivors are decrypted by propagating known letters along s.
Vigenere / Beaufort / variant, A-Z and KRYPTOS.
"""
import sys
import time
from itertools import permutations
from math import factorial
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KEY_FROM, KRYPTOS_ALPHABET, PLAIN_FROM  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import quadgram_score  # noqa: E402
from kryptos.solvers import stack as S  # noqa: E402

N = 97
ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")


def perm_jobs():
    jobs = [("reverse",), ("decimation",)]
    for w in range(2, 9 if not SMOKE else 4):
        f = factorial(w)
        jobs += [("columnar", w, s, min(s + 2000, f)) for s in range(0, f, 2000)]
    jobs.append(("routes",))
    return jobs


def perms(job):
    kind = job[0]
    if kind == "reverse":
        yield ("reverse",), [N - 1 - i for i in range(N)]
    elif kind == "decimation":
        for a in range(1, N):
            for b in range(N):
                if (a, b) != (1, 0):
                    yield ("decimation", a, b), [(a * i + b) % N for i in range(N)]
    elif kind == "columnar":
        from itertools import islice
        _, w, s0, s1 = job
        for o in islice(permutations(range(w)), s0, s1):
            yield ("columnar", o), S.columnar_map(o)
    elif kind == "routes":
        for rows in range(2, 53):
            for cols in range(2, 53):
                if 97 <= rows * cols <= 104:
                    for r in S.ROUTES:
                        for flip in (False, True):
                            yield ("route", rows, cols, r, flip), S.route_map(rows, cols, r, flip)


_W = {}


def _init(ct):
    _W["ct"] = ct
    _W["tabs"] = [(an, v, {c: i for i, c in enumerate(al)}, al, KEY_FROM[v], PLAIN_FROM[v])
                  for an, al in ALPHAS.items() for v in VARIANTS]


def _work(job):
    ct = _W["ct"]
    tested, hits = 0, []
    for label, s in perms(job):
        for an, v, idx, al, f, dec in _W["tabs"]:
            tested += 2
            # ciphertext-keyed: key at i is c[s(i)]
            if all(al[dec(idx[ct[i]], idx[ct[s[i]]])] == p for i, p in CRIBS.items()):
                pt = "".join(al[dec(idx[ct[i]], idx[ct[s[i]]])] for i in range(N))
                hits.append((quadgram_score(pt), "ct-keyed", label, an, v, pt))
            # plaintext-keyed: key at i is p[s(i)], testable where s(i) is a clue position
            tests = [(i, s[i]) for i in CRIBS if s[i] in CRIBS and s[i] != i]
            if len(tests) >= 6 and all(f(idx[ct[i]], idx[CRIBS[i]]) == idx[CRIBS[j]] for i, j in tests):
                known = dict(CRIBS)
                changed = True
                while changed:  # propagate: p[i] = D(c[i], p[s(i)])
                    changed = False
                    for i in range(N):
                        if i not in known and s[i] in known:
                            known[i] = al[dec(idx[ct[i]], idx[known[s[i]]])]
                            changed = True
                pt = "".join(known.get(i, "?") for i in range(N))
                hits.append((len(known) / N, "pt-keyed", label, an, v, pt))
    return tested, hits


def run(ct):
    with Pool(cpu_count(), initializer=_init, initargs=(ct,)) as pool:
        res = pool.map(_work, perm_jobs())
    return sum(t for t, _ in res), [h for _, hs in res for h in hs]


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("self-masking (keyed by own scrambled text)", puzzle="k4",
                    notes="c[i]=E(p[i], c[s(i)]) or E(p[i], p[s(i)]); s = reversal, decimation mod 97 (all a,b), "
                          "every columnar order w2-8, grid routes; vig/beau/varbeau, A-Z/KRYPTOS") as ex:
        tested, hits = run(K4)
        ex.count(tested)
        for h in hits[:30]:
            if h[1] == "ct-keyed":
                ex.add(h[5], kind=h[1], perm=str(h[2]), alphabet=h[3], variant=h[4])
        ctrl = [len(run(shuffled(K4, 3300 + s))[1]) for s in range(2)]
        verdict = ("dead: no scrambled self-key fits all clue letters (shuffled controls also 0)" if not hits else
                   f"{len(hits)} fits (shuffled controls {ctrl}): check")
        ex.notes += f"; {verdict}"
    report("33", name="self-masking", hypotheses=tested, survivors=len(hits), control=ctrl, verdict=verdict,
           top=[{"score": round(h[0], 3), "kind": h[1], "perm": str(h[2]), "alphabet": h[3], "variant": h[4],
                 "plaintext": h[5]} for h in sorted(hits, key=lambda h: -h[0])[:10]],
           minutes=round((time.time() - t0) / 60, 1))
    print("[33]", verdict)
