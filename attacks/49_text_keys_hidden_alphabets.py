"""Idea 49: K1-K3's own plaintexts as keys, with HIDDEN alphabets.

"The answers to the first three passages contain clues to the fourth" (Sanborn 2006).
Running keys from K1-K3 were tested before, but only on A-Z / KRYPTOS alphabets. Here
the key stream is a window of a K1-K3 plaintext (forwards or backwards; repeating
every L letters for L = 2-60, or running through all 97), and the alphabets are unknown:

  M1  hidden plain alphabet,  straight cipher alphabet   P[p] = c - k
  M2  hidden cipher alphabet, key letters located in it   C[c] - C[keyletter] = p   (true Quagmire II)
  M3  one hidden alphabet on both sides                   X[c] - X[p] = k
  M4  two independent hidden alphabets                    C[c] - P[p] = k

Each is a set of exact equations on the 24 clue letters (weighted union-find +
injectivity), so most key streams die outright; survivors are completed on English
and compared with shuffled K4s and planted answers. Key letters valued A-Z or KRYPTOS.
"""
import math
import random
import sys
import time
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, load  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import letters  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402
from kryptos.solvers import freealpha as FA  # noqa: E402
from kryptos.solvers.freealpha import UF  # noqa: E402

N = 97
VALUE = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
MODELS = ("M1", "M2", "M3", "M4")
G = {}


def texts():
    t = {"K1": letters(load("k1")["plaintext"]), "K2": letters(load("k2")["plaintext_corrected"]),
         "K3": letters(load("k3")["plaintext"])}
    t["K1K2K3"] = t["K1"] + t["K2"] + t["K3"]
    for k in list(t):
        t[k + "_rev"] = t[k][::-1]
    return t


def streams(maxL=60):
    """(text, offset, L) -> key letters for positions 0..96 (L = 0 means running key)."""
    for name, t in texts().items():
        for o in range(len(t)):
            for L in list(range(2, maxL + 1)) + [0]:
                if L and o + L > len(t):
                    continue
                if not L and o + N > len(t):
                    continue
                yield name, o, L


def keyletters(t, o, L):
    return t[o:o + N] if L == 0 else "".join(t[o + (i % L)] for i in range(N))


def equations(model, ct, cribs, kl, vname):
    val = VALUE[vname]
    eq = []
    for i, p in cribs.items():
        c, k = ct[i], val.index(kl[i])
        if model == "M1":
            eq.append((("P", p), ("Z", 0), (AZ.index(c) - k) % 26))
        elif model == "M2":
            eq.append((("C", c), ("C", kl[i]), AZ.index(p)))
        elif model == "M3":
            eq.append((("X", c), ("X", p), k))
        else:
            eq.append((("C", c), ("P", p), k))
    return eq


def consistent(eqs):
    uf = UF()
    for a, b, d in eqs:
        if not uf.union(a, b, d):
            return None
    comps = uf.components()
    for comp in comps:
        for side in ("P", "C", "X"):
            rels = [o for (s, _), o in comp if s == side]
            if len(rels) != len(set(rels)):
                return None
    return comps


def init(ct, cribs):
    G["ct"], G["cribs"], G["texts"] = ct, cribs, texts()


def check_chunk(items):
    out = []
    ct, cribs, T = G["ct"], G["cribs"], G["texts"]
    for name, o, L in items:
        kl = keyletters(T[name], o, L)
        for vname in VALUE:
            for m in MODELS:
                if consistent(equations(m, ct, cribs, kl, vname)) is not None:
                    out.append((name, o, L, vname, m))
    return out


# ------------------------------------------------------------ completion (penalty annealing)

def decrypt(model, ct, kl, vname, X, Y=None):
    """X (and Y for M4): alphabet strings. M1: X = plain alphabet; M2: X = cipher alphabet;
    M3: X = the shared alphabet; M4: X = plain, Y = cipher."""
    val = VALUE[vname]
    out = []
    for i, c in enumerate(ct):
        k = val.index(kl[i])
        if model == "M1":
            out.append(X[(AZ.index(c) - k) % 26])
        elif model == "M2":
            out.append(AZ[(X.index(c) - X.index(kl[i])) % 26])
        elif model == "M3":
            out.append(X[(X.index(c) - k) % 26])
        else:
            out.append(X[(Y.index(c) - k) % 26])
    return "".join(out)


def complete(model, ct, cribs, kl, vname, rng, qg, iters=20000):
    if model == "M4":  # constraint-respecting completer (clue letters correct by construction)
        val = VALUE[vname]
        key = [val.index(c) for c in kl]
        comps = FA.solve_exact(FA.equations("gromark", ct, cribs, key=key))
        if comps is None:
            return None
        q, pt, _ = FA.Completer("gromark", ct, comps, key=key, qg=qg).anneal(rng, iters=iters, restarts=3)
        return (q, pt) if pt else None

    def score(X, Y):
        pt = decrypt(model, ct, kl, vname, X, Y)
        miss = sum(pt[i] != p for i, p in cribs.items())
        return qg.score(pt) * (N - 3) - 12.0 * miss, pt, miss

    best = (-math.inf, None, 99)
    for _ in range(3):
        X = list(AZ)
        rng.shuffle(X)
        Y = list(AZ)
        rng.shuffle(Y)
        cur, pt, miss = score("".join(X), "".join(Y))
        for it in range(iters):
            t = 4.0 * (0.02 / 4.0) ** (it / iters)
            which = X if (model != "M4" or rng.random() < 0.5) else Y
            a, b = rng.sample(range(26), 2)
            which[a], which[b] = which[b], which[a]
            new, npt, nmiss = score("".join(X), "".join(Y))
            if new >= cur or rng.random() < math.exp((new - cur) / t):
                cur, pt, miss = new, npt, nmiss
                if miss == 0 and cur > best[0]:
                    best = (cur, pt, miss)
            else:
                which[a], which[b] = which[b], which[a]
    if best[1] is None:
        return None
    return qg.score(best[1]), best[1]


def run(ct, cribs, items, procs=None, complete_top=40, iters=20000):
    procs = procs or cpu_count()
    chunks = [items[k::procs * 4] for k in range(procs * 4)]
    with Pool(procs, initializer=init, initargs=(ct, cribs)) as pool:
        surv = [h for part in pool.map(check_chunk, chunks) for h in part]
    T = texts()
    qg = Quadgrams()
    rng = random.Random(49)
    scored = []
    by_model = {m: sum(1 for h in surv if h[4] == m) for m in MODELS}
    # complete the survivors whose key stream is most constraining: running keys and long periods first
    surv.sort(key=lambda h: (h[2] == 0, h[2]), reverse=True)
    for h in surv[:complete_top]:
        r = complete(h[4], ct, cribs, keyletters(T[h[0]], h[1], h[2]), h[3], rng, qg, iters if h[4] == "M4" else 3 * iters)
        if r:
            scored.append((r[0], r[1], h))
    scored.sort(key=lambda x: -x[0])
    return surv, by_model, scored


def plant(rng):
    T = texts()
    text = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4))
    s0 = rng.randrange(0, len(text) - 100)
    pt = text[s0:s0 + 97]
    name = rng.choice(["K2", "K3"])
    o, L = rng.randrange(0, 200), rng.choice([0, 23, 31, 40])
    kl = keyletters(T[name], o, L)
    PA, CA = "".join(rng.sample(AZ, 26)), "".join(rng.sample(AZ, 26))
    ct = "".join(CA[(PA.index(p) + AZ.index(kl[i])) % 26] for i, p in enumerate(pt))  # M4, A-Z key values
    return ct, pt, (name, o, L, "AZ", "M4")


if __name__ == "__main__":
    t0 = time.time()
    items = list(streams(20 if SMOKE else 60))
    if SMOKE:
        items = items[::40]
    ctop, iters = (4, 3000) if SMOKE else (40, 20000)
    with Experiment("K1-K3 plaintexts as keys with hidden alphabets", puzzle="k4", cribs_forced=True,
                    notes=f"{len(items)} key streams (K1/K2/K3/all, forwards+backwards, period 2-60 or running) x "
                          "M1 hidden plain / M2 Quagmire II / M3 shared hidden / M4 two hidden alphabets x key values "
                          "A-Z/KRYPTOS; exact union-find on 24 clue letters; survivors completed on English") as ex:
        surv, by_model, scored = run(K4, CRIBS, items, complete_top=ctop, iters=iters)
        ex.count(len(items) * 8)
        for q, pt, h in scored[:20]:
            ex.add(pt, text=h[0], offset=h[1], period=h[2], values=h[3], model=h[4])
        ctrl = []
        for s in range(1 if SMOKE else 2):
            cs, cm, cq = run(shuffled(K4, 4900 + s), CRIBS, items, complete_top=ctop, iters=iters)
            ctrl.append({"survivors": cm, "best_q": round(cq[0][0], 3) if cq else None})
        rng = random.Random(4949)
        planted = []
        for _ in range(1 if SMOKE else 3):
            ct, pt, truth = plant(rng)
            ps, pm, pq = run(ct, {i: pt[i] for i in CRIBS}, [truth[:3]], complete_top=4, iters=iters)
            hit = [x for x in pq if x[2][3] == "AZ" and x[2][4] == "M4"]
            planted.append({"truth": truth, "true_stream_survives": any(h[3] == "AZ" and h[4] == "M4" for h in ps),
                            "completion_q": round(hit[0][0], 3) if hit else None,
                            "letters_right": sum(a == b for a, b in zip(hit[0][1], pt)) if hit else 0})
        best = scored[0][0] if scored else None
        cmax = max((c["best_q"] for c in ctrl if c["best_q"] is not None), default=None)
        if best is not None and best > -5.3 and (cmax is None or best - cmax > 0.3):
            verdict = f"WORTH A LOOK: {scored[0][2]} completes to {best:.2f} (controls {cmax})"
        else:
            verdict = (f"dead: survivors by model {by_model} (shuffled: {[c['survivors'] for c in ctrl]}); best completion "
                       f"{None if best is None else round(best, 2)} vs shuffled {cmax}")
        ex.notes += f"; {verdict}"
    report("49", name="K1-K3 text keys with hidden alphabets", streams=len(items), survivors=by_model, controls=ctrl,
           best_quadgram=best, planted=planted, verdict=verdict,
           top=[{"q": round(q, 3), "text": h[0], "offset": h[1], "period": h[2], "values": h[3], "model": h[4],
                 "plaintext": pt} for q, pt, h in scored[:8]], minutes=round((time.time() - t0) / 60, 1))
    print("[49]", verdict, "| planted:", planted)
