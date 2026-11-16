"""Idea 45: tolerate ONE deliberate mistake.

Sanborn: his work is "rife with mistakes on purpose" (IQLUSION, UNDERGRUUND,
DESPARATLY, PALIMPCEST, the dropped S in K2). One wrong letter at a clue position,
whether a misspelled plaintext letter or a mis-cut copper letter, makes an exact
consistency test reject the true method. A mistake away from the clues changes
nothing in these tests, so "one mistake" = "drop one of the 24 clue letters".

Families re-run with every single clue dropped (24 drops):
  periodic       one repeating key, L 1-26, vig/beau/varbeau x A-Z/KRYPTOS (sanity family)
  two keys       A[i mod L1] + B[i mod L2], 1 <= L1 < L2 <= 26, same alphabets/variants
  gromark        base-10 chain addition, primer length 5 (all 100,000 primers), BOTH alphabets hidden
For each family: how many configurations become consistent only after a drop, on K4
vs shuffled K4s (a real mistake should make K4 stand out), and which clue letter
the drops point at. The most constrained new survivors are completed on English.
"""
import random
import sys
import time
from itertools import product
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, load  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KEY_FROM, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402
from kryptos.solvers import freealpha as FA  # noqa: E402
from kryptos.solvers import twokeys as TK  # noqa: E402
from kryptos.solvers.twokeys_fast import FastTwoKey  # noqa: E402

ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
POS = sorted(CRIBS)


def drops(cribs):
    yield None, cribs
    for i in sorted(cribs):
        yield i, {j: p for j, p in cribs.items() if j != i}


def periodic_ok(ct, cribs, al, v, L):
    idx = {c: i for i, c in enumerate(al)}
    f = KEY_FROM[v]
    key = {}
    for i, p in cribs.items():
        k = f(idx[ct[i]], idx[p])
        if key.setdefault(i % L, k) != k:
            return False
    return len(cribs) - len(key) >= 3


def fam_periodic(ct, cribs):
    out = []
    for (an, al), v, L in product(ALPHAS.items(), VARIANTS, range(1, 27)):
        res = [d for d, cr in drops(cribs) if periodic_ok(ct, cr, al, v, L)]
        out.append(((an, v, L), res))
    return out


def free_vars(comps, L1, L2):
    used = {n for c in comps for n, _ in c}
    return len(comps) + (L1 - sum(1 for k, _ in used if k == "A")) + (L2 - sum(1 for k, _ in used if k == "NB"))


def fam_twokeys(ct, cribs):
    out = []
    for (an, al), v in product(ALPHAS.items(), VARIANTS):
        for L1 in range(1, 27):
            for L2 in range(L1 + 1, 27):
                res = []
                for d, cr in drops(cribs):
                    comps = TK.solve_exact(TK.equations(ct, cr, al, v, L1, L2))
                    if comps is not None:
                        res.append((d, free_vars(comps, L1, L2)))
                out.append(((an, v, L1, L2), res))
    return out


def _gro_chunk(args):
    ct, cribs, lo, hi = args
    out = []
    for n in range(lo, hi):
        primer = [int(ch) for ch in f"{n:05d}"]
        stream = FA.gromark_stream(primer, 10)
        res = [d for d, cr in drops(cribs) if FA.solve_exact(FA.equations("gromark", ct, cr, key=stream)) is not None]
        if res:
            out.append((n, res))
    return out


def fam_gromark(ct, cribs, nprim, procs=8):
    step = max(1, nprim // (procs * 8))
    jobs = [(ct, cribs, lo, min(nprim, lo + step)) for lo in range(0, nprim, step)]
    with Pool(procs) as pool:
        parts = pool.map(_gro_chunk, jobs)
    return [x for p in parts for x in p]


def summarise(rows, getdrops):
    """rows: [(config, result list)] -> exact survivors, drop-only survivors, per-dropped-letter counts."""
    exact = drop_only = 0
    per_letter = {}
    for _, res in rows:
        ds = getdrops(res)
        if None in ds:
            exact += 1
        elif ds:
            drop_only += 1
            for d in ds:
                per_letter[d] = per_letter.get(d, 0) + 1
    return exact, drop_only, per_letter


def complete_twokeys(ct, cribs, cfg, drop, rng, sweeps):
    an, v, L1, L2 = cfg
    cr = {j: p for j, p in cribs.items() if j != drop}
    comps = TK.solve_exact(TK.equations(ct, cr, ALPHAS[an], v, L1, L2))
    fk = FastTwoKey(ct, ALPHAS[an], v, L1, L2, comps, Quadgrams())
    return fk.solve(rng, sweeps=sweeps, restarts=2)


def complete_gromark(ct, cribs, n, drop, rng, iters):
    primer = [int(ch) for ch in f"{n:05d}"]
    stream = FA.gromark_stream(primer, 10)
    cr = {j: p for j, p in cribs.items() if j != drop}
    comps = FA.solve_exact(FA.equations("gromark", ct, cr, key=stream))
    q, pt, _ = FA.Completer("gromark", ct, comps, key=stream).anneal(rng, iters=iters, restarts=2)
    return q, pt


def analyse(ct, cribs, nprim):
    per = fam_periodic(ct, cribs)
    two = fam_twokeys(ct, cribs)
    gro = fam_gromark(ct, cribs, nprim)
    s_per = summarise(per, lambda r: r)
    s_two = summarise(two, lambda r: [d for d, _ in r])
    s_gro = summarise(gro, lambda r: r)
    return per, two, gro, s_per, s_two, s_gro


def plant_mistake(rng):
    """Two stacked keys (7, 11) on AZ Vigenere, with one clue letter of the plaintext misspelled."""
    text = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4))
    s0 = rng.randrange(0, len(text) - 100)
    pt = text[s0:s0 + 97]
    ct, _ = TK.plant(pt, rng, AZ, "vigenere", 7, 11)
    bad = rng.choice(POS)
    cribs = {i: pt[i] for i in POS}
    cribs[bad] = AZ[(AZ.index(cribs[bad]) + rng.randint(1, 25)) % 26]  # the solver is told a wrong letter
    return ct, pt, cribs, bad


if __name__ == "__main__":
    t0 = time.time()
    nprim = 2000 if SMOKE else 100000
    nctrl = 1 if SMOKE else 3
    with Experiment("one deliberate mistake (drop-one-clue consistency)", puzzle="k4", cribs_forced=True,
                    notes=f"each of 24 clue letters dropped in turn; periodic L1-26, two stacked keys L1<L2<=26, "
                          f"gromark base 10 primer 5 ({nprim} primers) both alphabets hidden; vig/beau/varbeau x A-Z/KRYPTOS") as ex:
        per, two, gro, s_per, s_two, s_gro = analyse(K4, CRIBS, nprim)
        ex.count(len(per) * 25 + len(two) * 25 + nprim * 25)
        ctrls = []
        for s in range(nctrl):
            *_, cp, ct2, cg = analyse(shuffled(K4, 4700 + s), CRIBS, nprim)
            ctrls.append({"periodic": cp[:2], "twokeys": ct2[:2], "gromark": cg[:2]})
        # complete the best-determined drop-only survivors
        rng = random.Random(45)
        cand_two = []
        for cfg, res in two:
            if any(d is None for d, _ in res):
                continue
            for d, fv in res:
                cand_two.append((fv, cfg, d))
        cand_two.sort()
        completions = []
        for fv, cfg, d in cand_two[: (2 if SMOKE else 25)]:
            q, pt = complete_twokeys(K4, CRIBS, cfg, d, rng, 60 if SMOKE else 250)
            completions.append({"family": "twokeys", "cfg": cfg, "dropped": d, "free_vars": fv, "q": round(q, 3), "plaintext": pt})
            ex.add(pt, family="twokeys", cfg=str(cfg), dropped=d)
        cand_gro = [(n, d) for n, res in gro if None not in res for d in res]
        for n, d in cand_gro[: (2 if SMOKE else 25)]:
            q, pt = complete_gromark(K4, CRIBS, n, d, rng, 3000 if SMOKE else 20000)
            if pt:
                completions.append({"family": "gromark", "primer": f"{n:05d}", "dropped": d, "q": round(q, 3), "plaintext": pt})
                ex.add(pt, family="gromark", primer=f"{n:05d}", dropped=d)
        completions.sort(key=lambda c: -c["q"])
        # control completions: same budget on one shuffled K4's best two-key drop survivors
        sh = shuffled(K4, 4700)
        _, two_c, _, _, _, _ = analyse(sh, CRIBS, 0) if not SMOKE else (None, fam_twokeys(sh, CRIBS), None, None, None, None)
        cc = sorted((fv, cfg, d) for cfg, res in two_c if not any(x is None for x, _ in res) for d, fv in res)
        ctrl_q = []
        for fv, cfg, d in cc[: (1 if SMOKE else 10)]:
            q, _ = complete_twokeys(sh, CRIBS, cfg, d, rng, 60 if SMOKE else 250)
            ctrl_q.append(round(q, 3))
        # power: planted two-key text with one wrong clue letter
        prng = random.Random(4545)
        planted = []
        for _ in range(1 if SMOKE else 4):
            ct, pt, cr, bad = plant_mistake(prng)
            exact = TK.solve_exact(TK.equations(ct, cr, AZ, "vigenere", 7, 11)) is not None
            fixed = TK.solve_exact(TK.equations(ct, {j: p for j, p in cr.items() if j != bad}, AZ, "vigenere", 7, 11)) is not None
            planted.append({"bad_pos": bad, "exact_test_accepts": exact, "drop_bad_accepts": fixed})
        best = completions[0]["q"] if completions else None
        cmax = max(ctrl_q) if ctrl_q else None

        def fmt(name, s, key):
            cs = [c[key] for c in ctrls]
            return (f"{name}: exact {s[0]}, drop-only {s[1]} (shuffled: "
                    + ", ".join(f"{a}/{b}" for a, b in cs) + ")")
        lines = [fmt("periodic", s_per, "periodic"), fmt("two keys", s_two, "twokeys"), fmt("gromark", s_gro, "gromark")]
        stand_out = any(s[1] > 3 * max(1, max(c[k][1] for c in ctrls)) for s, k in
                        ((s_per, "periodic"), (s_two, "twokeys"), (s_gro, "gromark")))
        if best is not None and best > -5.3 and (cmax is None or best - cmax > 0.3):
            verdict = f"WORTH A LOOK: a one-mistake completion reads {best:.2f} (control {cmax}); " + "; ".join(lines)
        elif stand_out:
            verdict = "ODD: K4 gains far more drop-only survivors than shuffles; " + "; ".join(lines)
        else:
            verdict = (f"dead: one-mistake tolerance adds nothing over chance; " + "; ".join(lines)
                       + f"; best completion {best} vs control {cmax}")
        ex.notes += f"; {verdict}"
    report("45", name="one deliberate mistake", periodic=s_per[:2], twokeys=s_two[:2], gromark=s_gro[:2],
           per_letter={"periodic": s_per[2], "twokeys": s_two[2], "gromark": s_gro[2]}, controls=ctrls,
           completions=completions[:10], control_completions=ctrl_q, planted=planted, verdict=verdict,
           minutes=round((time.time() - t0) / 60, 1))
    print("[45]", verdict, "| planted:", planted)
