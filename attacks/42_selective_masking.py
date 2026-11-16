"""Idea 42: selective masking: KRYPTOS letters encrypted lightly, the rest with a real key.

Observation (campaign 7 design): 9 of Bean's 12 "close" clue letters are
letters of the word KRYPTOS, and 9 of the 10 KRYPTOS-letter clues shift by 2 or
less (A-Z order), while the other 14 mostly jump far. So which letter is being
encrypted may decide how it is treated: a "mask" keyed by the sculpture's own
keyword.

(1) Is it real? Count KRYPTOS-letter clues within +-2, compared with shuffled K4s,
    and rank KRYPTOS among ALL subsets of the clue letters (is the keyword special,
    or would any common letters do?).
(2) Model: plaintext letters in {K,R,Y,P,T,O,S} get a small shift (|d| <= 2, at most one
    exception); every other letter gets a repeating key (period 1-26; Vigenere/
    Beaufort/variant; A-Z/KRYPTOS). Exact on the 14 other clue letters. Pinned keys
    are decoded by beam search (each position: the keyed letter, or a KRYPTOS letter
    within +-2) for maximum English, against shuffled and planted controls.
"""
import random
import sys
import time
from itertools import combinations
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, load  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KEY_FROM, KRYPTOS_ALPHABET, PLAIN_FROM  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

LIGHT = set("KRYPTOS")
ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
QG = Quadgrams()


def shift(c, p):
    d = (AZ.index(c) - AZ.index(p)) % 26
    return d - 26 if d > 13 else d


def closeness(ct, cribs, letters_set, tol=2):
    pos = [i for i, p in cribs.items() if p in letters_set]
    return sum(abs(shift(ct[i], cribs[i])) <= tol for i in pos), len(pos)


def significance(n_shuffles):
    k, n = closeness(K4, CRIBS, LIGHT)
    ge = sum(closeness(shuffled(K4, 4200 + s), CRIBS, LIGHT)[0] >= k for s in range(n_shuffles))
    p_shuffle = (ge + 1) / (n_shuffles + 1)
    letters = sorted(set(CRIBS.values()))
    frac_k = k / n
    better = total = 0
    for r in range(1, len(letters) + 1):
        for sub in combinations(letters, r):
            c, m = closeness(K4, CRIBS, set(sub))
            if m >= n:
                total += 1
                better += c / m >= frac_k
    return k, n, p_shuffle, better, total


def models(ct, cribs, maxp=26, min_tests=5):
    out = []
    light_bad = [i for i, p in cribs.items() if p in LIGHT and abs(shift(ct[i], p)) > 2]
    if len(light_bad) > 1:
        return out
    heavy = {i: p for i, p in cribs.items() if p not in LIGHT}
    for an, al in ALPHAS.items():
        idx = {c: i for i, c in enumerate(al)}
        for v in VARIANTS:
            f = KEY_FROM[v]
            req = {i: f(idx[ct[i]], idx[p]) for i, p in heavy.items()}
            for L in range(1, maxp + 1):
                seen, tests, ok = {}, 0, True
                for i, k in req.items():
                    r = i % L
                    if r in seen:
                        tests += 1
                        if seen[r] != k:
                            ok = False
                            break
                    else:
                        seen[r] = k
                if ok and tests >= min_tests:
                    out.append((an, v, L, seen, tests))
    return out


def beam_decode(ct, an, v, L, key, width=300):
    al = ALPHAS[an]
    idx = {c: i for i, c in enumerate(al)}
    dec = PLAIN_FROM[v]
    beams = [(0.0, "")]
    lp, fl = QG.logp, QG.floor
    for i, c in enumerate(ct):
        opts = set(p for p in LIGHT if abs(shift(c, p)) <= 2)
        if i % L in key:
            p = al[dec(idx[c], key[i % L])]
            if p not in LIGHT:
                opts.add(p)
        if not opts:
            return None
        nb = []
        for s, t in beams:
            for p in opts:
                t2 = t + p
                s2 = s + (lp.get(t2[-4:], fl) if len(t2) >= 4 else 0.0)
                nb.append((s2, t2))
        nb.sort(key=lambda x: -x[0])
        beams = nb[:width]
    best = beams[0][1]
    return QG.score(best), best


def run(ct, cribs):
    res = []
    for an, v, L, key, tests in models(ct, cribs):
        if len(key) < L:  # key not pinned by the clues
            continue
        d = beam_decode(ct, an, v, L, key)
        if d:
            res.append((d[0], d[1], an, v, L, tests))
    res.sort(key=lambda x: -x[0])
    return res


def plant(rng):
    text = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4))
    s0 = rng.randrange(0, len(text) - 100)
    pt = text[s0:s0 + 97]
    L = rng.randint(4, 9)
    key = [rng.randrange(26) for _ in range(L)]
    ct = "".join(AZ[(AZ.index(p) + (rng.randint(-2, 2) if p in LIGHT else key[i % L])) % 26] for i, p in enumerate(pt))
    return ct, pt


if __name__ == "__main__":
    t0 = time.time()
    k, n, p_sh, better, total = significance(300 if SMOKE else 20000)
    with Experiment("selective masking (KRYPTOS letters light, others keyed)", puzzle="k4", cribs_forced=True,
                    notes="KRYPTOS-letter plaintext shifted <=2 (1 exception allowed), others periodic key 1-26 "
                          "(vig/beau/varbeau, A-Z/KRYPTOS); pinned keys beam-decoded for English") as ex:
        res = run(K4, CRIBS)
        for q, pt, an, v, L, t in res[:20]:
            ex.add(pt, alphabet=an, variant=v, period=L)
        ex.count(26 * 6)
        ctrl = []
        for s in range(3):
            r = run(shuffled(K4, 4300 + s), CRIBS)
            ctrl.append(round(r[0][0], 3) if r else None)
        rng = random.Random(42)
        planted = []
        for _ in range(2 if SMOKE else 8):
            ct, pt = plant(rng)
            r = run(ct, {i: pt[i] for i in CRIBS})
            planted.append((round(r[0][0], 3), sum(a == b for a, b in zip(r[0][1], pt))) if r else (None, 0))
        best = res[0][0] if res else None
        cb = max((c for c in ctrl if c is not None), default=None)
        flag = best is not None and (cb is None or best - cb > 0.3)
        verdict = (f"closeness: {k}/{n} KRYPTOS-letter clues within +-2 (shuffled p={p_sh:.4f}; KRYPTOS beats "
                   f"{total - better}/{total} letter subsets of at least that size). Model: "
                   + ("no repeating key on the other letters fits the clues" if not res else
                      ("WORTH A LOOK: " if flag else "dead: ") + f"best decode {best:.2f} vs shuffled {cb}"))
        ex.notes += f"; {verdict}"
    report("42", name="selective masking", closeness=[k, n], p_shuffle=p_sh, subsets_at_least_as_close=better,
           subsets_total=total, configs=len(res), best_quadgram=best, control=ctrl, planted=planted, verdict=verdict,
           top=[{"q": round(q, 3), "alphabet": an, "variant": v, "L": L, "plaintext": pt} for q, pt, an, v, L, t in res[:5]],
           minutes=round((time.time() - t0) / 60, 1))
    print("[42]", verdict, "| planted:", planted)
