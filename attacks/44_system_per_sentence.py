"""Idea 44: a different system for each part ("two separate systems" read literally).

Sanborn (1990): the lower half uses two separate systems. Every earlier test
applied ONE system to all 97 letters. Here K4 is split at an unknown point b
(34..63), so EASTNORTHEAST lies in part 1 and BERLINCLOCK in part 2, and each part
may use its own simple system. Each clue block is tested on its own:

  periodic       key[(i - start) mod L], L 1-12
  progressive    key[(i - start) mod L] + s * ((i - start) div L), L 1-8, s 1-25
  gromark        chain-addition digits, primer length 2-5, bases 5-16, fixed alphabets
  ct autokey     key_i = ct[i - L], L 1-20
  pt autokey     key_i = pt[i - L], L 1-12
  mono           one keyword-free substitution (any injective map)

(Vigenere/Beaufort/variant x A-Z/KRYPTOS where it applies.) A block "fits" a
configuration when at least 3 of its letters are checks rather than free choices.
Fit counts are compared with 300 shuffled K4s, and every pairing of a part-1 fit with a
part-2 fit is decoded across all split points and scored for English.
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, load  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KEY_FROM, KRYPTOS_ALPHABET, PLAIN_FROM  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

N = 97
ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
BLOCK1 = list(range(21, 34))
BLOCK2 = list(range(63, 74))
SPLITS = range(34, 64)
MIN_TESTS = 3
QG = Quadgrams()


def gro_stream_both(window, at, m, base, lo, hi):
    """Chain-addition stream given m digits starting at index `at`; extend forward/backward over [lo, hi)."""
    d = {at + j: window[j] for j in range(m)}
    for n in range(at + m, hi):
        d[n] = (d[n - m] + d[n - m + 1]) % base
    for n in range(at - 1, lo - 1, -1):  # d[n+m] = d[n] + d[n+1]  ->  d[n] = d[n+m] - d[n+1]
        d[n] = (d[n + m] - d[n + 1]) % base
    return d


def fits(ct, cribs, block, start):
    """All (family, params, tests, decoder) that fit one clue block, for a part beginning at `start`."""
    out = []
    for an, al in ALPHAS.items():
        idx = {c: i for i, c in enumerate(al)}
        for v in VARIANTS:
            f, dec = KEY_FROM[v], PLAIN_FROM[v]
            req = {i: f(idx[ct[i]], idx[cribs[i]]) for i in block}
            # periodic
            for L in range(1, 13):
                key, ok = {}, True
                for i, k in req.items():
                    r = (i - start) % L
                    if key.setdefault(r, k) != k:
                        ok = False
                        break
                if ok and len(block) - len(key) >= MIN_TESTS:
                    out.append(("periodic", (an, v, L), len(block) - len(key), ("per", al, dec, L, key)))
            # progressive
            for L in range(1, 9):
                for s in range(1, 26):
                    key, ok = {}, True
                    for i, k in req.items():
                        r, cyc = (i - start) % L, (i - start) // L
                        if key.setdefault(r, (k - s * cyc) % 26) != (k - s * cyc) % 26:
                            ok = False
                            break
                    if ok and len(block) - len(key) >= MIN_TESTS:
                        out.append(("progressive", (an, v, L, s), len(block) - len(key), ("prog", al, dec, L, key, s)))
            # ct autokey
            for L in range(1, 21):
                tests, ok = 0, True
                for i, k in req.items():
                    if i - L >= start:
                        tests += 1
                        if idx[ct[i - L]] != k:
                            ok = False
                            break
                if ok and tests >= MIN_TESTS:
                    out.append(("ct_autokey", (an, v, L), tests, ("cta", al, dec, L)))
            # pt autokey
            for L in range(1, 13):
                tests, ok = 0, True
                for i, k in req.items():
                    if i - L in cribs and i - L >= start:
                        tests += 1
                        if idx[cribs[i - L]] != k:
                            ok = False
                            break
                if ok and tests >= MIN_TESTS:
                    out.append(("pt_autokey", (an, v, L), tests, ("pta", al, dec, L)))
    # gromark: plaintext alphabet A-Z, ciphertext alphabet AZ/KRYPTOS, digit = CA.index(c) - AZ.index(p)
    for an, ca in ALPHAS.items():
        cidx = {c: i for i, c in enumerate(ca)}
        digits = {i: (cidx[ct[i]] - AZ.index(cribs[i])) % 26 for i in block}
        for base in range(5, 17):
            if any(d >= base for d in digits.values()):
                continue
            for m in range(2, 6):
                if len(block) - m < MIN_TESTS:
                    continue
                win = [digits[block[0] + j] for j in range(m)]
                d = gro_stream_both(win, block[0], m, base, block[0], block[-1] + 1)
                if all(d[i] == digits[i] for i in block):
                    out.append(("gromark", (an, base, m), len(block) - m, ("gro", ca, win, block[0], m, base)))
    # monoalphabetic
    mp, inv, ok = {}, {}, True
    for i in block:
        p, c = cribs[i], ct[i]
        if mp.setdefault(p, c) != c or inv.setdefault(c, p) != p:
            ok = False
            break
    if ok and len(block) - len(mp) >= MIN_TESTS:
        out.append(("mono", (), len(block) - len(mp), ("mono", mp)))
    return out


def decode_part(ct, cribs, d, lo, hi):
    kind = d[0]
    out = [None] * (hi - lo)
    if kind in ("per", "prog"):
        al, dec, L, key = d[1], d[2], d[3], d[4]
        s = d[5] if kind == "prog" else 0
        idx = {c: i for i, c in enumerate(al)}
        for i in range(lo, hi):
            r = (i - lo) % L
            if r in key:
                out[i - lo] = al[dec(idx[ct[i]], (key[r] + s * ((i - lo) // L)) % 26)]
    elif kind == "cta":
        al, dec, L = d[1], d[2], d[3]
        idx = {c: i for i, c in enumerate(al)}
        for i in range(lo + L, hi):
            out[i - lo] = al[dec(idx[ct[i]], idx[ct[i - L]])]
    elif kind == "pta":
        al, dec, L = d[1], d[2], d[3]
        idx = {c: i for i, c in enumerate(al)}
        f = None
        for v, fn in PLAIN_FROM.items():
            if fn is dec:
                f = KEY_FROM[v]
        known = {i: p for i, p in cribs.items() if lo <= i < hi}
        for i, p in known.items():
            out[i - lo] = p
        changed = True
        while changed:
            changed = False
            for i in range(lo, hi):
                if out[i - lo] is None and i - L >= lo and out[i - L - lo] is not None:
                    out[i - lo] = al[dec(idx[ct[i]], idx[out[i - L - lo]])]
                    changed = True
                if out[i - lo] is not None and i - L >= lo and out[i - L - lo] is None:
                    out[i - L - lo] = al[f(idx[ct[i]], idx[out[i - lo]])]
                    changed = True
    elif kind == "gro":
        ca, win, at, m, base = d[1], d[2], d[3], d[4], d[5]
        cidx = {c: i for i, c in enumerate(ca)}
        dd = gro_stream_both(win, at, m, base, lo, hi)
        for i in range(lo, hi):
            out[i - lo] = AZ[(cidx[ct[i]] - dd[i]) % 26]
    elif kind == "mono":
        inv = {c: p for p, c in d[1].items()}
        for i in range(lo, hi):
            out[i - lo] = inv.get(ct[i])
    return out


def score_partial(chars):
    """Mean quadgram log-prob over windows with all four letters known (and coverage)."""
    lp, fl = QG.logp, QG.floor
    s = n = 0
    for i in range(len(chars) - 3):
        w = chars[i:i + 4]
        if None not in w:
            s += lp.get("".join(w), fl)
            n += 1
    return (s / n if n else -99.0), n


def run(ct, cribs, top=60):
    f1 = fits(ct, cribs, BLOCK1, 0)
    f2 = {b: fits(ct, cribs, BLOCK2, b) for b in SPLITS}
    n2 = sum(len(v) for v in f2.values())
    scored = []
    f1s = sorted(f1, key=lambda x: -x[2])[:top]
    for b in SPLITS:
        for a in f1s:
            pa = decode_part(ct, cribs, a[3], 0, b)
            for c in sorted(f2[b], key=lambda x: -x[2])[:top]:
                pc = decode_part(ct, cribs, c[3], b, N)
                q, n = score_partial(pa + pc)
                if n >= 60:
                    txt = "".join(x or "?" for x in pa + pc)
                    scored.append((q, txt, b, a[:3], c[:3]))
    scored.sort(key=lambda x: -x[0])
    return f1, f2, n2, scored


def counts(ct):
    f1 = fits(ct, CRIBS, BLOCK1, 0)
    f2 = {b: fits(ct, CRIBS, BLOCK2, b) for b in SPLITS}
    fam = {}
    for x in f1:
        fam[("1", x[0])] = fam.get(("1", x[0]), 0) + 1
    seen = set()
    for b, v in f2.items():
        for x in v:
            if (x[0], x[1]) not in seen:
                seen.add((x[0], x[1]))
                fam[("2", x[0])] = fam.get(("2", x[0]), 0) + 1
    return fam


def plant(rng):
    text = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4))
    s0 = rng.randrange(0, len(text) - 100)
    pt = text[s0:s0 + 97]
    b = rng.randint(34, 63)
    L1, L2 = rng.randint(3, 7), rng.randint(2, 5)
    k1 = [rng.randrange(26) for _ in range(L1)]
    k2 = [rng.randrange(26) for _ in range(L2)]
    ct = []
    for i, p in enumerate(pt):
        if i < b:
            ct.append(AZ[(AZ.index(p) + k1[i % L1]) % 26])
        else:
            ct.append(AZ[(AZ.index(p) - k2[(i - b) % L2]) % 26])  # variant Beaufort in part 2
    return "".join(ct), pt, (b, L1, L2)


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("different system per part (split 34-63)", puzzle="k4", cribs_forced=True,
                    notes="part 1 (EASTNORTHEAST) and part 2 (BERLINCLOCK) each tested alone: periodic L1-12, "
                          "progressive L1-8 s1-25, gromark m2-5 bases 5-16, ct/pt autokey, mono; vig/beau/varbeau x "
                          "A-Z/KRYPTOS; fit = >=3 checks; all pairings decoded over split points") as ex:
        f1, f2, n2, scored = run(K4, CRIBS)
        ex.count(30 * 3000)
        for q, txt, b, a, c in scored[:20]:
            ex.add(txt, split=b, part1=str(a), part2=str(c))
        k4_fam = counts(K4)
        nsh = 20 if SMOKE else 300
        ctrl_fam = {}
        for s in range(nsh):
            for k, v in counts(shuffled(K4, 4500 + s)).items():
                ctrl_fam.setdefault(k, []).append(v)
        fam_table = {}
        for k in sorted(set(k4_fam) | set(ctrl_fam)):
            vals = ctrl_fam.get(k, []) + [0] * (nsh - len(ctrl_fam.get(k, [])))
            mean = sum(vals) / nsh
            p = (sum(x >= k4_fam.get(k, 0) for x in vals) + 1) / (nsh + 1)
            fam_table[f"part{k[0]}:{k[1]}"] = {"k4": k4_fam.get(k, 0), "shuffled_mean": round(mean, 2), "p": round(p, 4)}
        ctrl_q = []
        for s in range(1 if SMOKE else 3):
            *_, cs = run(shuffled(K4, 4600 + s), CRIBS)
            ctrl_q.append(round(cs[0][0], 3) if cs else None)
        rng = random.Random(44)
        planted = []
        for _ in range(1 if SMOKE else 5):
            ct, pt, truth = plant(rng)
            *_, ps = run(ct, {i: pt[i] for i in CRIBS})
            top = ps[0] if ps else None
            planted.append({"truth": truth, "top_q": round(top[0], 3) if top else None,
                            "top_split": top[2] if top else None,
                            "letters_right": sum(a == b for a, b in zip(top[1], pt)) if top else 0})
        best = scored[0][0] if scored else None
        cmax = max((c for c in ctrl_q if c is not None), default=None)
        sig = {k: v for k, v in fam_table.items() if v["p"] < 0.01 and v["k4"] > v["shuffled_mean"]}
        if best is not None and best > -5.3 and (cmax is None or best - cmax > 0.3):
            verdict = f"WORTH A LOOK: best two-system decode {best:.2f} vs control {cmax}"
        else:
            verdict = (f"dead: part-1 fits {len(f1)}, part-2 fits {n2} (over splits); best two-system decode "
                       f"{best if best is None else round(best, 2)} vs shuffled {cmax}; families above chance: "
                       f"{sig or 'none'}")
        ex.notes += f"; {verdict}"
    report("44", name="different system per part", part1_fits=len(f1), part2_fits=n2, family_table=fam_table,
           best_quadgram=best, control=ctrl_q, planted=planted, verdict=verdict,
           top=[{"q": round(q, 3), "split": b, "part1": str(a), "part2": str(c), "plaintext": t}
                for q, t, b, a, c in scored[:8]],
           minutes=round((time.time() - t0) / 60, 1))
    print("[44]", verdict, "| planted:", planted)
