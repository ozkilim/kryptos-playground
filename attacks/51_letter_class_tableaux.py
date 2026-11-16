"""Idea 51: the letter decides the TABLE. KRYPTOS letters go through the KRYPTOS-alphabet tableau,
every other letter through a plain A-Z tableau, with ONE key.

The sculpture carries a KRYPTOS-alphabet tableau; K1/K2 used it. If K4 switches between that tableau
and a plain A-Z one depending on whether the plaintext letter is in the keyword KRYPTOS
("two separate systems", "masked the English"), the KRYPTOS-letter clues would behave
differently from the rest, which is what the clues show. Unlike idea 42 there is no "light" shift:
every letter is fully keyed, so letter counts can stay flat (the pre-filter checks that).

Key letters: repeating (L 1-26), or restarting at each carved row; Vigenere/Beaufort/variant;
both class-to-table assignments. Exact on the 24 clue letters (the key LETTER each one needs must agree);
pinned survivors decoded by beam search (each position: decode with either table, keep only letters
of the right class), against shuffled controls and planted answers.
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, load  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KEY_FROM, KRYPTOS_ALPHABET as KA, PLAIN_FROM  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

N = 97
LIGHT = set("KRYPTOS")
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
ROW_STARTS = [0, 4, 35, 66]
QG = Quadgrams()
ENC = {"vigenere": lambda p, k: (p + k) % 26, "beaufort": lambda p, k: (k - p) % 26,
       "variant_beaufort": lambda p, k: (p - k) % 26}


def tables(assign):
    """assign 'K->KA' : KRYPTOS letters use the KRYPTOS tableau, others A-Z; 'K->AZ' the reverse."""
    return (KA, AZ) if assign == "K->KA" else (AZ, KA)


def table_for(p, assign):
    tk, to = tables(assign)
    return tk if p in LIGHT else to


def residue(i, L, rows):
    """rows: False (plain repeating), True (restart at carved rows), or a tuple of sentence starts."""
    if rows is True:
        starts = ROW_STARTS
    elif rows:
        starts = (0,) + tuple(rows)
    else:
        return i % L
    st = max(s for s in starts if s <= i)
    return (i - st) % L


SENTENCES = [(s1, s2) for s1 in range(1, 22) for s2 in range(34, 64)] + [(s1,) for s1 in range(1, 22)] + [(s2,) for s2 in range(34, 64)]


def scan(ct, cribs, min_tests=3):
    hits = []
    for assign in ("K->KA", "K->AZ"):
        for v in VARIANTS:
            need = {}
            for i, p in cribs.items():
                T = table_for(p, assign)
                need[i] = T[KEY_FROM[v](T.index(ct[i]), T.index(p))]  # the key LETTER this clue needs
            for rows in [False, True] + SENTENCES:
                for L in range(1, 27):
                    for prog in ((0,) if rows else range(26)):  # progressive: key letter advances `prog` per cycle
                        key, ok = {}, True
                        for i, kl in need.items():
                            r = residue(i, L, rows)
                            base = AZ[(AZ.index(kl) - prog * (i // L)) % 26]
                            if key.setdefault(r, base) != base:
                                ok = False
                                break
                        if ok and len(need) - len(key) >= min_tests:
                            hits.append((assign, v, rows, L, key, len(need) - len(key), prog))
    return hits


def beam_decode(ct, hit, width=300):
    assign, v, rows, L, key, _, prog = hit
    tk, to = tables(assign)
    dec = PLAIN_FROM[v]
    lp, fl = QG.logp, QG.floor
    beams = [(0.0, "")]
    for i, c in enumerate(ct):
        r = residue(i, L, rows)
        if r not in key:
            return None
        kl = AZ[(AZ.index(key[r]) + prog * (i // L)) % 26]
        opts = set()
        p1 = tk[dec(tk.index(c), tk.index(kl))]
        if p1 in LIGHT:
            opts.add(p1)
        p2 = to[dec(to.index(c), to.index(kl))]
        if p2 not in LIGHT:
            opts.add(p2)
        if not opts:
            return None
        nb = []
        for s, t in beams:
            for p in opts:
                t2 = t + p
                nb.append((s + (lp.get(t2[-4:], fl) if len(t2) >= 4 else 0.0), t2))
        nb.sort(key=lambda x: -x[0])
        beams = nb[:width]
    return QG.score(beams[0][1]), beams[0][1]


def run(ct, cribs):
    hits = scan(ct, cribs)
    scored = []
    for h in hits:
        d = beam_decode(ct, h)
        if d:
            scored.append((d[0], d[1], h))
    scored.sort(key=lambda x: -x[0])
    return hits, scored


def encrypt(pt, key, assign, v, rows=False):
    L = len(key)
    out = []
    for i, p in enumerate(pt):
        T = table_for(p, assign)
        out.append(T[ENC[v](T.index(p), T.index(key[residue(i, L, rows)]))])
    return "".join(out)


def plant(rng):
    text = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4))
    s0 = rng.randrange(0, len(text) - 100)
    pt = text[s0:s0 + 97]
    key = "".join(rng.choice(AZ) for _ in range(rng.randint(4, 9)))
    assign, v, rows = rng.choice(["K->KA", "K->AZ"]), rng.choice(VARIANTS), rng.random() < 0.5
    return encrypt(pt, key, assign, v, rows), pt, (assign, v, rows, key)


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("letter-class tableau switch (KRYPTOS letters on the KRYPTOS tableau)", puzzle="k4",
                    cribs_forced=True, notes="KRYPTOS-letter plaintext via KRYPTOS tableau, others via A-Z (and reverse), "
                                             "one key: repeating (plain or progressive) L1-26, or restarting per carved row "
                                             "or at 1-2 sentence starts; vig/beau/varbeau; "
                                             "exact on 24 clue letters, pinned survivors beam-decoded") as ex:
        hits, scored = run(K4, CRIBS)
        ex.count(2 * 3 * 26 * (2 * 26 + len(SENTENCES)))
        for q, pt, h in scored[:20]:
            ex.add(pt, assign=h[0], variant=h[1], rows=h[2], L=h[3], tests=h[5])
        ctrl = []
        for s in range(2 if SMOKE else 20):
            ch, cs = run(shuffled(K4, 5100 + s), CRIBS)
            ctrl.append(len(ch))
        rng = random.Random(51)
        planted = []
        for _ in range(4):
            ct, pt, truth = plant(rng)
            ph, ps = run(ct, {i: pt[i] for i in CRIBS})
            planted.append({"truth": truth, "true_config_survives": any(h[0] == truth[0] and h[1] == truth[1] and h[2] == truth[2]
                                                                      and h[3] == len(truth[3]) for h in ph),
                            "letters_right": sum(a == b for a, b in zip(ps[0][1], pt)) if ps else 0})
        best = scored[0][0] if scored else None
        if best is not None and best > -5.3:
            verdict = f"WORTH A LOOK: {scored[0][2][:4]} decodes to {best:.2f}"
        elif not hits:
            verdict = f"dead: no key fits the clues (shuffled K4s: mean {sum(ctrl) / len(ctrl):.2f} survivors)"
        else:
            verdict = (f"dead: {len(hits)} survivors (shuffled mean {sum(ctrl) / len(ctrl):.2f}), best decode "
                       f"{None if best is None else round(best, 2)}")
        ex.notes += f"; {verdict}"
    report("51", name="letter-class tableau switch", survivors=len(hits), controls_mean=sum(ctrl) / len(ctrl), controls=ctrl,
           best_quadgram=best, planted=planted, verdict=verdict,
           top=[{"q": round(q, 3), "assign": h[0], "variant": h[1], "rows": h[2], "L": h[3], "plaintext": pt}
                for q, pt, h in scored[:8]], minutes=round((time.time() - t0) / 60, 1))
    print("[51]", verdict, "| planted:", planted)
