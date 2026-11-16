"""Idea 46: KRYPTOS letters lightly shifted only inside the clue sentences (selective masking x sentence restarts).

Built through the clue pre-filter (kryptos/clues.py). The pre-filter showed that
idea 42 (KRYPTOS letters ALWAYS lightly shifted) explains the KRYPTOS-letter
closeness but can never be as flat as K4: a third of English letters are KRYPTOS
letters, and keeping them near themselves leaks letter frequencies. This idea asks
what kind of masking can explain BOTH.

Part A (decide): measures it.
  * Is the closeness real once we account for (i) the two clue blocks and (ii) having looked
    at many "natural" letter sets? Within-block label shuffles, for every natural set.
  * How flat can a masked K4 be, as a function of how many letters are masked and of
    the key on the other letters? Likelihood ratio vs a one-time pad.
Part B (search the decidable slice): KRYPTOS letters within +-2 inside two sentences
  [s1, b1) and [s2, b2) that hold the clues; every other letter keyed by a repeating key that
  either restarts at each sentence start or runs straight through (L 1-26; vig/beau/varbeau;
  A-Z, KRYPTOS and theme-keyword alphabets). The 15 keyed clue letters (14 non-KRYPTOS + the
  KRYPTOS letter that moved too far, O->F at 71) are the exact test; pinned survivors are
  decoded by beam search over the light choices, against shuffled controls and planted answers.
  Long or stacked keys on the other letters (what flatness prefers) can't be decided from
  these 15 letters; they stay with the open two-key gap.
"""
import random
import sys
import time
from collections import Counter
from itertools import combinations
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, fingerprint as FP, load  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KEY_FROM, KRYPTOS_ALPHABET, PLAIN_FROM, keyed_alphabet  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

N = 97
LIGHT = set("KRYPTOS")
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
THEME = ["PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "BERLINCLOCK", "WELTZEITUHR", "SHADOW", "EGYPT",
         "SANBORN", "SCHEIDT", "LANGLEY", "CARTER", "LUCID", "ILLUSION", "LAYERTWO", "NORTHEAST"]
ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
ALPHAS.update({w: keyed_alphabet(w) for w in THEME})
NATURAL_SETS = {"KRYPTOS": "KRYPTOS", "PALIMPSEST": "PALIMPSEST", "ABSCISSA": "ABSCISSA", "BERLIN": "BERLIN",
                "CLOCK": "CLOCK", "BERLINCLOCK": "BERLINCLOCK", "EASTNORTHEAST": "EASTNORTHEAST",
                "vowels": "AEIOU", "ETAOINS (top-7 English)": "ETAOINS", "SHADOW": "SHADOW", "EGYPT": "EGYPT",
                "LAYERTWO": "LAYERTWO", "SANBORN": "SANBORN", "SCHEIDT": "SCHEIDT", "CIA": "CIA",
                "first half A-M": "ABCDEFGHIJKLM", "WELTZEITUHR": "WELTZEITUHR"}
BLOCKS = [[i for i in sorted(CRIBS) if i < 40], [i for i in sorted(CRIBS) if i > 40]]
QG = Quadgrams()


def shift(c, p):
    d = (AZ.index(c) - AZ.index(p)) % 26
    return d - 26 if d > 13 else d


# ------------------------------------------------------------------ Part A

def within_block_p(letters, n, tol=2, seed=1):
    lab = {i: CRIBS[i] in letters for i in CRIBS}
    m = sum(lab.values())
    if m < 3 or m == len(CRIBS):
        return None, None, m
    close = {i: abs(shift(K4[i], CRIBS[i])) <= tol for i in CRIBS}
    obs = sum(close[i] for i in CRIBS if lab[i])
    rng = random.Random(seed)
    ge = 0
    for _ in range(n):
        tot = 0
        for b in BLOCKS:
            v = [lab[i] for i in b]
            rng.shuffle(v)
            tot += sum(close[i] for i, x in zip(b, v) if x)
        ge += tot >= obs
    return obs, (ge + 1) / (n + 1), m


def ioc(ct):
    c = Counter(ct)
    return sum(v * (v - 1) for v in c.values()) / (N * (N - 1))


def flatness_curve(trials, seed=5):
    text = FP.english_windows()
    rng = random.Random(seed)
    k4 = ioc(K4) + 0.0005
    curves = {}
    for heavy in ("one-time pad", "two stacked keys", "short repeating key 5-11"):
        bins = {}
        for _ in range(trials):
            pt = FP.k4_like_plaintext(text, rng)
            a1, b1 = rng.randint(0, 21), rng.randint(34, 62)
            a2, b2 = rng.randint(b1, 63), rng.randint(74, 97)
            mask = set(range(97)) if rng.random() < 0.15 else set(range(a1, b1)) | set(range(a2, b2))
            if heavy == "one-time pad":
                kk = [rng.randrange(26) for _ in range(N)]
            elif heavy == "two stacked keys":
                L1, L2 = rng.randint(7, 13), rng.randint(14, 26)
                a, b = [rng.randrange(26) for _ in range(L1)], [rng.randrange(26) for _ in range(L2)]
                kk = [a[i % L1] + b[i % L2] for i in range(N)]
            else:
                L = rng.randint(5, 11)
                a = [rng.randrange(26) for _ in range(L)]
                kk = [a[i % L] for i in range(N)]
            light = 0
            out = []
            for i, p in enumerate(pt):
                if p in LIGHT and i in mask:
                    light += 1
                    out.append(AZ[(AZ.index(p) + rng.randint(-2, 2)) % 26])
                else:
                    out.append(AZ[(AZ.index(p) + kk[i]) % 26])
            b_ = min(light // 5 * 5, 35)
            s = bins.setdefault(b_, [0, 0])
            s[0] += 1
            s[1] += ioc("".join(out)) <= k4
        curves[heavy] = {f"{b}-{b + 4}": round(v[1] / v[0], 4) for b, v in sorted(bins.items()) if v[0] >= 30}
    rng2 = random.Random(9)
    chance = sum(ioc("".join(rng2.choice(AZ) for _ in range(N))) <= k4 for _ in range(trials)) / trials
    return curves, chance


# ------------------------------------------------------------------ Part B

def keyed_clues(ct, cribs):
    return {i: p for i, p in cribs.items() if p not in LIGHT or abs(shift(ct[i], p)) > 2}


def scan(ct, cribs, alphas, min_tests=2):
    heavy = keyed_clues(ct, cribs)
    out = []
    for an, al in alphas.items():
        idx = {c: i for i, c in enumerate(al)}
        for v in VARIANTS:
            f = KEY_FROM[v]
            req = {i: f(idx[ct[i]], idx[p]) for i, p in heavy.items()}
            for L in range(1, 27):
                for restart in (True, False):
                    pairs = [(s1, s2) for s1 in range(22) for s2 in [s1] + list(range(34, 64))] if restart else [(0, 0)]
                    for s1, s2 in pairs:
                        key, tests, ok = {}, 0, True
                        for i, k in req.items():
                            st = (s2 if (i >= s2 and s2 > s1) else (s1 if i >= s1 else 0)) if restart else 0
                            r = (i - st) % L
                            if r in key:
                                tests += 1
                                if key[r] != k:
                                    ok = False
                                    break
                            else:
                                key[r] = k
                        if ok and tests >= min_tests:
                            out.append((an, v, L, restart, s1, s2, key, tests))
    return out


def beam_decode(ct, an, v, L, restart, starts, light, key, width=300):
    """Beam over plaintext AND the key values the clues leave free: a free key slot is branched
    over all 26 values the first time it is needed, then held fixed (state carries it)."""
    al = ALPHAS[an]
    idx = {c: i for i, c in enumerate(al)}
    dec = PLAIN_FROM[v]
    bounds = sorted(set(starts))
    lp, fl = QG.logp, QG.floor
    beams = [(0.0, "", ())]
    for i, c in enumerate(ct):
        st = max((b for b in bounds if b <= i), default=0) if restart else 0
        r = (i - st) % L
        lights = {p for p in LIGHT if abs(shift(c, p)) <= 2} if i in light else set()
        nb = []
        for s, t, asg in beams:
            if r in key:
                choices = [(key[r], asg)]
            else:
                got = dict(asg).get(r)
                choices = [(got, asg)] if got is not None else [(x, asg + ((r, x),)) for x in range(26)]
            for kv, a2 in choices:
                opts = set(lights)
                p = al[dec(idx[c], kv)]
                if not (p in LIGHT and i in light):
                    opts.add(p)
                for q in opts:
                    t2 = t + q
                    nb.append((s + (lp.get(t2[-4:], fl) if len(t2) >= 4 else 0.0), t2, a2))
        if not nb:
            return None
        nb.sort(key=lambda x: -x[0])
        beams = nb[:width]
    return QG.score(beams[0][1]), beams[0][1]


def best_decode(ct, hit, step):
    an, v, L, restart, s1, s2, key, tests = hit
    best = None
    a1 = s1 if restart else 0
    for b1 in range(34, 64, step):
        for a2 in ([s2] if restart and s2 > s1 else range(max(b1, 34), 64, step)):
            if a2 < b1:
                continue
            for b2 in range(74, 98, step):
                light = set(range(a1, b1)) | set(range(a2, b2))
                d = beam_decode(ct, an, v, L, restart, [0, a1, b1, a2, b2], light, key)
                if d and (best is None or d[0] > best[0]):
                    best = (d[0], d[1], (a1, b1, a2, b2))
    return best


def run(ct, cribs, alphas, top=30, step=6):
    hits = scan(ct, cribs, alphas)
    hits.sort(key=lambda h: -h[7])
    # survivors come in clumps (one coincidence repeated over many sentence starts); keep a diverse slice
    per, pick = {}, []
    for h in hits:
        g = (h[0], h[1], h[2], h[3])
        if per.get(g, 0) < 2:
            per[g] = per.get(g, 0) + 1
            pick.append(h)
    scored = []
    for h in pick[:top]:
        d = best_decode(ct, h, step)
        if d:
            scored.append((d[0], d[1], h, d[2]))
    scored.sort(key=lambda x: -x[0])
    return hits, scored


def plant(rng):
    text = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4))
    s0 = rng.randrange(0, len(text) - 100)
    pt = text[s0:s0 + 97]
    a1, b1, a2, b2 = rng.randint(3, 21), rng.choice([40, 46]), rng.randint(46, 63), rng.choice([80, 86, 92])
    a2 = max(a2, b1)
    L = rng.randint(5, 9)
    key = [rng.randrange(26) for _ in range(L)]
    starts = [0, a1, b1, a2, b2]
    light = set(range(a1, b1)) | set(range(a2, b2))
    ct = []
    for i, p in enumerate(pt):
        st = max(b for b in starts if b <= i)
        k = rng.randint(-2, 2) if (p in LIGHT and i in light) else key[(i - st) % L]
        ct.append(AZ[(AZ.index(p) + k) % 26])
    return "".join(ct), pt, (a1, b1, a2, b2, L)


if __name__ == "__main__":
    t0 = time.time()
    nperm = 2000 if SMOKE else 100000
    sets = {}
    for name, letters in NATURAL_SETS.items():
        obs, p, m = within_block_p(set(letters), nperm)
        if p is not None:
            sets[name] = {"close": f"{obs}/{m}", "within_block_p": round(p, 5)}
    ranked = sorted(sets.items(), key=lambda kv: kv[1]["within_block_p"])
    p_k = sets["KRYPTOS"]["within_block_p"]
    p_corr = min(1.0, p_k * len(sets))
    curves, chance_flat = flatness_curve(3000 if SMOKE else 30000)
    # likelihood ratios: masking model vs chance, for (closeness AND flatness)
    lr = {h: {b: round((v / chance_flat) / p_corr, 2) for b, v in c.items()} for h, c in curves.items()}
    alphas = dict(list(ALPHAS.items())[:3]) if SMOKE else ALPHAS
    with Experiment("KRYPTOS-letter masking inside clue sentences (+ restarting key)", puzzle="k4", cribs_forced=True,
                    notes=f"light (+-2) KRYPTOS letters only in sentences [s1,b1),[s2,b2) holding the clues; other letters "
                          f"keyed L1-26 restarting per sentence or straight; {len(alphas)} alphabets x vig/beau/varbeau; "
                          "15 keyed clue letters exact, pinned survivors beam-decoded") as ex:
        hits, scored = run(K4, CRIBS, alphas, top=6 if SMOKE else 80, step=12 if SMOKE else 6)
        ex.count(len(alphas) * 3 * 26 * (22 * 31 + 1))
        for q, txt, h, mk in scored[:20]:
            ex.add(txt, alphabet=h[0], variant=h[1], L=h[2], restart=h[3], segments=str(mk), tests=h[7])
        ctrl = []
        for s in range(1 if SMOKE else 4):
            ch, cs = run(shuffled(K4, 4800 + s), CRIBS, alphas, top=6 if SMOKE else 80, step=12 if SMOKE else 6)
            ctrl.append((len(ch), round(cs[0][0], 3) if cs else None))
        rng = random.Random(46)
        planted = []
        for _ in range(1 if SMOKE else 4):
            ct, pt, truth = plant(rng)
            pc = {i: pt[i] for i in CRIBS}
            ph, ps = run(ct, pc, {"AZ": AZ}, top=12 if SMOKE else 60, step=6)
            top_ = ps[0] if ps else None
            tr = [h for h in ph if h[1] == "vigenere" and h[2] == truth[4] and h[3] and h[4] == truth[0] and h[5] == truth[2]]
            dt = best_decode(ct, tr[0], 6) if tr else None
            planted.append({"truth": truth, "survivors": len(ph), "top_q": round(top_[0], 3) if top_ else None,
                            "top_letters_right": sum(a == b for a, b in zip(top_[1], pt)) if top_ else 0,
                            "true_config_q": round(dt[0], 3) if dt else None,
                            "true_config_letters_right": sum(a == b for a, b in zip(dt[1], pt)) if dt else 0})
        best = scored[0][0] if scored else None
        cmax = max((c[1] for c in ctrl if c[1] is not None), default=None)
        partA = (f"closeness: KRYPTOS within-block p={p_k} (rank {[k for k, _ in ranked].index('KRYPTOS') + 1}/{len(sets)} "
                 f"natural sets; corrected p~{p_corr:.3f}); flatness needs <=~20 masked letters and a long/stacked key on "
                 f"the rest (LR vs chance, two stacked keys: {lr['two stacked keys']})")
        if best is not None and best > -5.3 and (cmax is None or best - cmax > 0.3):
            partB = f"WORTH A LOOK: decode {best:.2f} vs control {cmax}"
        elif not hits:
            partB = "dead: no repeating key (restarting or not) fits the 15 keyed clue letters"
        else:
            partB = f"dead: {len(hits)} survivors (controls {[c[0] for c in ctrl]}), best decode {best} vs control {cmax}"
        verdict = f"A) {partA}. B) {partB}"
        ex.notes += f"; {verdict}"
    report("46", name="KRYPTOS masking inside clue sentences", natural_sets=dict(ranked), kryptos_p=p_k,
           corrected_p=p_corr, flatness_curves=curves, chance_flat=chance_flat, likelihood_ratios=lr,
           survivors=len(hits), controls=ctrl, best_quadgram=best, planted=planted, verdict=verdict,
           top=[{"q": round(q, 3), "alphabet": h[0], "variant": h[1], "L": h[2], "restart": h[3], "segments": mk,
                 "plaintext": t} for q, t, h, mk in scored[:8]],
           minutes=round((time.time() - t0) / 60, 1))
    print("[46]", verdict, "| planted:", planted)
