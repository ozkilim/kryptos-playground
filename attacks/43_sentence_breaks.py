"""Idea 43: the key restarts at every sentence (Cyrillic Projector style), X between sentences.

Why: the plaintext is several sentences, fixed before 1990 and cut into sentence
strips; K1-K3 separate sentences with X; Sanborn's Cyrillic Projector restarts its
Vigenere key at each block. A repeating key that restarts at unknown sentence
starts looks NON-periodic from outside, which is exactly what K4's statistics say.

Model: key[(i - start(i)) mod L], start(i) = start of the sentence holding i.
Only two starts matter for the 24 clue letters: s1 = start of the sentence
holding EASTNORTHEAST (0..21) and s2 = start of the one holding BERLINCLOCK
(s1, or 34..63). So the exact test enumerates (s1, s2) x L 1..26 x Vigenere/
Beaufort/variant x A-Z, KRYPTOS and theme-keyword alphabets (Quagmire III).
Optionally an X sits just before each break (adds a clue letter).
Survivors are decoded (free key slots completed on English, plus up to one more
sentence break anywhere) and compared with shuffled-K4 controls and planted answers.
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, load  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KEY_FROM, KRYPTOS_ALPHABET, PLAIN_FROM, keyed_alphabet  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

N = 97
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
THEME = ["PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "BERLINCLOCK", "WELTZEITUHR", "SHADOW", "EGYPT",
         "SANBORN", "SCHEIDT", "LANGLEY", "CARTER", "LUCID", "ILLUSION", "LAYERTWO", "NORTHEAST"]
ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
ALPHAS.update({w: keyed_alphabet(w) for w in THEME})
QG = Quadgrams()
S1 = range(0, 22)
S2 = list(range(34, 64))


def starts_for(s1, s2):
    return lambda i: s2 if i >= s2 and s2 > s1 else (s1 if i >= s1 else 0)


def check(ct, cribs, alpha, variant, L, s1, s2, x_breaks=False):
    """Return (key dict residue->value, tests) or None."""
    idx = {c: i for i, c in enumerate(alpha)}
    f = KEY_FROM[variant]
    st = starts_for(s1, s2)
    clues = dict(cribs)
    if x_breaks:
        for b in {s1, s2} - {0}:
            if b - 1 in clues and clues[b - 1] != "X":
                return None
            clues[b - 1] = "X"
    key, tests = {}, 0
    for i, p in clues.items():
        r = (i - st(i)) % L
        k = f(idx[ct[i]], idx[p])
        if r in key:
            tests += 1
            if key[r] != k:
                return None
        else:
            key[r] = k
    return key, tests


def scan(ct, cribs, min_tests=4, alphas=ALPHAS):
    out = []
    for an, al in alphas.items():
        for v in VARIANTS:
            for L in range(1, 27):
                for s1 in S1:
                    for s2 in [s1] + S2:
                        if s1 == 0 and s2 == 0:
                            continue  # no break at all = plain periodic (dead, campaign 1)
                        for xb in (False, True):
                            r = check(ct, cribs, al, v, L, s1, s2, xb)
                            if r and r[1] >= min_tests:
                                out.append((an, v, L, s1, s2, xb, r[0], r[1]))
    return out


def decode(ct, an, v, L, starts, key):
    al = ALPHAS[an]
    idx = {c: i for i, c in enumerate(al)}
    dec = PLAIN_FROM[v]
    bounds = sorted(set(starts))

    def st(i):
        s = 0
        for b in bounds:
            if i >= b:
                s = b
        return s

    res = [(i - st(i)) % L for i in range(N)]
    k = dict(key)
    free = [r for r in range(L) if r not in k]
    for r in free:
        k[r] = 0

    def pt():
        return "".join(al[dec(idx[c], k[res[i]])] for i, c in enumerate(ct))

    for _ in range(3):  # coordinate ascent on the free slots
        for r in free:
            best = max(range(26), key=lambda x: (k.__setitem__(r, x), QG.score(pt()))[1])
            k[r] = best
    p = pt()
    return QG.score(p), p


def best_decode(ct, hit):
    an, v, L, s1, s2, xb, key, tests = hit
    base = [0, s1, s2]
    q, p = decode(ct, an, v, L, base, key)
    best = (q, p, None)
    for extra in list(range(1, s1)) + list(range(s1 + 1, 22)) + list(range(34, s2)) + list(range(74, 96)):
        if extra in (s1, s2):
            continue
        # an extra break moves only non-clue letters; the pinned key stays valid only if it doesn't
        # change the residue of a clue letter, which holds for breaks outside [s1, 34) and [s2, 74)
        if s1 < extra <= 33 or s2 < extra <= 73:
            continue
        q2, p2 = decode(ct, an, v, L, base + [extra], key)
        if q2 > best[0]:
            best = (q2, p2, extra)
    return best


def run(ct, cribs, alphas=ALPHAS, decode_top=40):
    hits = scan(ct, cribs, min_tests=2, alphas=alphas)
    hits.sort(key=lambda h: -h[7])
    scored = []
    for h in hits[:decode_top]:
        q, p, extra = best_decode(ct, h)
        scored.append((q, p, h, extra))
    scored.sort(key=lambda x: -x[0])
    return hits, scored


def plant(rng):
    text = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4))
    s0 = rng.randrange(0, len(text) - 100)
    pt = list(text[s0:s0 + 97])
    s1, s2 = rng.randint(3, 21), rng.randint(36, 63)
    pt[s1 - 1] = pt[s2 - 1] = "X"
    pt = "".join(pt)
    L = rng.randint(5, 11)
    key = [rng.randrange(26) for _ in range(L)]
    st = starts_for(s1, s2)
    ct = "".join(AZ[(AZ.index(p) + key[(i - st(i)) % L]) % 26] for i, p in enumerate(pt))
    return ct, pt, (s1, s2, L)


if __name__ == "__main__":
    t0 = time.time()
    alphas = dict(list(ALPHAS.items())[:3]) if SMOKE else ALPHAS
    with Experiment("sentence-break key restarts (+X separators)", puzzle="k4", cribs_forced=True,
                    notes="key[(i - sentence_start) mod L], L 1-26, s1 in 0-21, s2 in s1|34-63, optional X before "
                          f"each break, vig/beau/varbeau x {len(alphas)} alphabets (A-Z, KRYPTOS, theme keywords)") as ex:
        hits, scored = run(K4, CRIBS, alphas)
        ex.count(len(alphas) * 3 * 26 * sum(1 + len(S2) for _ in S1) * 2)
        for q, p, h, extra in scored[:20]:
            ex.add(p, alphabet=h[0], variant=h[1], period=h[2], s1=h[3], s2=h[4], x=h[5], tests=h[7], extra=extra)
        ctrl = []
        for s in range(1 if SMOKE else 5):
            ch, cs = run(shuffled(K4, 4400 + s), CRIBS, alphas)
            ctrl.append((sum(h[7] >= 4 for h in ch), round(cs[0][0], 3) if cs else None,
                         {t: sum(h[7] >= t for h in ch) for t in (2, 3, 4, 5)}))
        rng = random.Random(43)
        planted = []
        for _ in range(1 if SMOKE else 6):
            ct, pt, truth = plant(rng)
            ph, ps = run(ct, {i: pt[i] for i in CRIBS}, {"AZ": AZ})
            found = any(h[3] == truth[0] and h[4] == truth[1] and h[2] == truth[2] and h[1] == "vigenere" for h in ph)
            top = ps[0] if ps else None
            planted.append({"truth": truth, "true_config_survives": found, "survivors": len(ph),
                            "top_q": round(top[0], 3) if top else None,
                            "top_letters_right": sum(a == b for a, b in zip(top[1], pt)) if top else 0})
        def bytests(hs):
            return {t: sum(h[7] >= t for h in hs) for t in (2, 3, 4, 5)}
        k4_t = bytests(hits)
        best = scored[0][0] if scored else None
        cmax = max((c[1] for c in ctrl if c[1] is not None), default=None)
        cn = sum(c[0] for c in ctrl) / max(len(ctrl), 1)
        strict = k4_t[4]
        if not hits:
            verdict = "dead: no restart schedule fits the clues"
        elif best is not None and (cmax is None or best - cmax > 0.3) and best > -5.3:
            verdict = f"WORTH A LOOK: survivors by clue repeats {k4_t} (controls ~{cn:.0f}), best decode {best:.2f} vs control {cmax}"
        else:
            verdict = (f"dead: survivors by clue repeats {k4_t} (>=4 repeats: {strict} vs ~{cn:.1f} per shuffled K4); best decode {best:.2f} vs control "
                       f"best {cmax} (chance level)")
        ex.notes += f"; {verdict}"
    report("43", name="sentence-break key restarts", survivors=len(hits), survivors_by_tests=k4_t, controls=ctrl, best_quadgram=best,
           planted=planted, verdict=verdict,
           top=[{"q": round(q, 3), "alphabet": h[0], "variant": h[1], "L": h[2], "s1": h[3], "s2": h[4], "x": h[5],
                 "tests": h[7], "extra_break": e, "plaintext": p} for q, p, h, e in scored[:8]],
           minutes=round((time.time() - t0) / 60, 1))
    print("[43]", verdict, "| planted:", planted)
