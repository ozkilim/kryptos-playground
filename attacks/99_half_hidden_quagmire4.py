"""Idea 99: half-hidden Quagmire IV. One alphabet is a dictionary keyword alphabet, the other is anything.

Sanborn (2005) said he changed the system "so that Scheidt could not decipher it"; Scheidt speaks of "key
word/s". Quagmire IV has two mixed alphabets and a short key. Idea 63 closed the case where both alphabets
come from dictionary words, idea 20 a hidden alphabet against A-Z or KRYPTOS, idea 86 an unknown keyword
alphabet. This is the case between them: one alphabet from a dictionary word (the part Scheidt would know),
the other written down freely (the part he would not), and a short key of unknown numbers.

Case 1, cipher alphabet hidden:  X[C_i] = A^-1(P_i) + K_i       A = the dictionary alphabet (plain side)
Case 2, plain alphabet hidden:   X[P_i] = B^-1(C_i) - K_i       B = the dictionary alphabet (cipher side)
Key K_i: repeating with length L = 1..12 (K_i = k[i mod L]), or sliding for L = 1..9 (K_i = the running sum
of an unknown L-letter word; every one of the 25 non-zero word sums W is tried). The idea asked for 1..9
and 1..6; the longer keys cost nothing to scan and are judged by reading only.

The test is exact. The hidden letters and the key slots are nodes, every one of the 24 clue letters is an
edge, and every closed loop is one check that the dictionary alphabet must pass (weighted union-find, done
once per key length as a spanning forest, kryptos/idea99_half.py). A setting survives only if every loop
closes AND the hidden letters land on different places. Vigenere and Beaufort form are the same test (turn
the hidden alphabet back to front), so each setting is tested once.

With K4's clue letters a repeating key leaves about 11 - L checks in case 1 and 12 - L in case 2 (more when
the clue letters fall into several pieces); a sliding key one fewer (W is free). The script prints, for
every key length, how many chance survivors to expect, so it is plain where the test decides (5+ checks)
and where it only gauges.

Survivors: the letters outside the clues are filled in by simulated annealing on the big English model
(a quick pass for every survivor, a long pass of 6 x 20,000 steps for the best 20), and the same is done for the survivors of
shuffled K4s. Planted: nine messages, found by name and read back.

  python attacks/99_half_hidden_quagmire4.py
"""
import json
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea99_half as H  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA99_PROCS", "4" if SMOKE else "8"))
NCTRL = int(os.environ.get("IDEA99_CONTROLS", "1" if SMOKE else "3"))
ENGLISH = -5.1        # big-model score per quadgram a reading must beat (planted readings: about -4.4)
PASS_CHECKS = 5       # exact checks (W counted off for sliding keys) at which a survivor counts as a pass
MAX_READ = int(os.environ.get("IDEA99_MAX_READ", "300" if SMOKE else "12000"))   # distinct systems read per text
READ_OK = 80          # letters of 97 a planted message must be read back with (the rest are rare letters)
LONG = 20             # best quick readings that get the long annealing pass
BIG = DATA_DIR / "english" / "quadgrams_big.txt"
CLUE = set(CRIBS)
G = {}


def init(ct, cribs):
    G["plans"] = H.plans(ct, cribs)
    G["pl"], G["cl"] = H.clue_letters(ct, cribs)


def work(chunk):
    return H.scan(G["plans"], G["pl"], G["cl"], chunk)


def search(ct, cribs, alphabets, chunk=2000):
    hits, collide = [], Counter()
    for h, c in pmap(work, alphabets, init, (ct, cribs), chunk=chunk, procs=PROCS):
        hits.extend(h)
        collide.update(c)
    hits.sort(key=lambda h: (h[0], h[1], h[2], h[5]))
    return hits, collide


def eff_checks(h):
    return h[3] - (1 if h[2] else 0)


def forced_score(forced, big):
    """(big-model score, count) over quadgrams that are fully forced and not wholly inside the clues."""
    q = [forced[i:i + 4] for i in range(len(forced) - 3)
         if "?" not in forced[i:i + 4] and not all(j in CLUE for j in range(i, i + 4))]
    return (sum(big.logp.get(x, big.floor) for x in q) / len(q) if q else -99.0), len(q)


def read_init(ct, cribs):
    G["ct"], G["cribs"], G["big"] = ct, cribs, Quadgrams(BIG)


def read_work(chunk):
    """Quick annealing pass: [(group number, score, reading, forced reading)]."""
    out = []
    for n, h in chunk:
        sc, pt, offs, forced = H.Reader(h, G["ct"], G["cribs"], G["big"]).anneal(random.Random(99000 + n), 2500, 1)
        out.append((n, sc, pt, forced))
    return out


def read(hits, ct, cribs, big, keep=()):
    """Group survivors that are the same system (same places for the clue letters) and read each group:
    a quick pass for all (at most MAX_READ: every group with 3+ checks, a random sample of the rest, and
    the groups holding a name in `keep`), then a long pass for the best LONG.
    Returns (rows best first, number of groups, number read)."""
    pl, cl = H.clue_letters(ct, cribs)
    groups = {}
    for h in hits:
        known = pl if h[0] == 1 else cl
        key = (h[0], h[1], h[2], tuple(h[6].index(c) for c in known))
        groups.setdefault(key, []).append(h)
    keys = sorted(groups)
    if len(keys) > MAX_READ:
        must = [k for k in keys if groups[k][0][3] - (1 if k[2] else 0) >= 3 or any(h[5] in keep for h in groups[k])]
        rest = [k for k in keys if k not in set(must)]
        keys = must + random.Random(99).sample(rest, max(0, MAX_READ - len(must)))
    jobs = [(n, groups[k][0]) for n, k in enumerate(keys)]
    quick = []
    if len(jobs) > 40:
        for part in pmap(read_work, jobs, read_init, (ct, cribs), chunk=25, procs=PROCS):
            quick.extend(part)
    elif jobs:
        read_init(ct, cribs)
        quick = read_work(jobs)
    quick.sort(key=lambda x: -x[1])
    rows = []
    for rank, (n, sc, pt, forced) in enumerate(quick):
        g = groups[keys[n]]
        h = g[0]
        if rank < LONG or any(x[5] in keep for x in g):
            sc2, pt2, offs, forced2 = H.Reader(h, ct, cribs, big).anneal(random.Random(99 + n), 3000 if SMOKE else 20000, 6)
            if sc2 > sc:
                sc, pt, forced = sc2, pt2, forced2
        fs, fq = forced_score(forced, big)
        rows.append({"case": h[0], "L": h[1], "W": h[2], "checks": eff_checks(h), "pieces": h[4],
                     "alphabets": [x[5] for x in g][:6], "names": {x[5] for x in g}, "n_alphabets": len(g),
                     "alphabet": h[6], "score": round(sc, 3), "reading": pt, "forced": forced,
                     "forced_letters": sum(c != "?" for c in forced), "forced_score": round(fs, 3),
                     "forced_quadgrams": fq})
    rows.sort(key=lambda r: -r["score"])
    return rows, len(groups), len(keys)


def table(ct, cribs, hits, collide, n_alph, rows):
    """One line per (case, key kind, L): checks, expected chance survivors, what was found."""
    pls = H.plans(ct, cribs)
    cnt = Counter((h[0], h[1], bool(h[2])) for h in hits)
    best = {}
    for r in rows:
        k = (r["case"], r["L"], bool(r["W"]))
        best[k] = max(best.get(k, -99), r["score"])
    out = []
    for case in (1, 2):
        for sliding in (False, True):
            for p in pls[case]:
                if sliding and p.L > H.SLIDE_MAX:
                    continue
                k = (case, p.L, sliding)
                out.append({"case": case, "key": "sliding" if sliding else "repeating", "L": p.L,
                            "checks": p.nchecks - (1 if sliding else 0), "pieces": p.ncomp,
                            "expected": float("%.3g" % p.expected(n_alph, sliding)),
                            "impossible_for_any_alphabet": p.impossible(sliding),
                            "loops_close_but_letters_collide": collide.get(k, 0), "survivors": cnt.get(k, 0),
                            "best_reading": best.get(k)})
    return out


def show(tab):
    for t in tab:
        print("   case %d %-9s L=%-2d: %2d checks, %d piece(s), chance expects %-23s loops close but letters "
              "collide %-7d survivors %-6d best reading %s"
              % (t["case"], t["key"], t["L"], t["checks"], t["pieces"],
                 "0 (no alphabet can fit)" if t["impossible_for_any_alphabet"] else "%.3g" % t["expected"],
                 t["loops_close_but_letters_collide"], t["survivors"], t["best_reading"]))


def summary(tab, hits, rows, ngroups, nread):
    scope = [t for t in tab if t["L"] <= (6 if t["key"] == "sliding" else 9)]
    return {"survivors": len(hits), "distinct_systems": ngroups, "read": nread,
            "passes_5plus_checks": sum(1 for h in hits if eff_checks(h) >= PASS_CHECKS),
            "survivors_in_idea_scope": sum(t["survivors"] for t in scope),
            "expected_in_idea_scope": float("%.3g" % sum(t["expected"] for t in scope)),
            "expected_total": float("%.3g" % sum(t["expected"] for t in tab)),
            "english": sum(r["score"] > ENGLISH for r in rows),
            "best": rows[0]["score"] if rows else None,
            "best_forced": max([r["forced_score"] for r in rows if r["forced_quadgrams"] >= 15], default=None)}


def run_text(label, ct, cribs, alphabets, big, verbose=True):
    hits, collide = search(ct, cribs, alphabets)
    rows, ngroups, nread = read(hits, ct, cribs, big)
    tab = table(ct, cribs, hits, collide, len(alphabets), rows)
    s = summary(tab, hits, rows, ngroups, nread)
    print("%s: %s" % (label, json.dumps(s)))
    show(tab)
    for r in rows[:8 if verbose else 3]:
        print("   %6.2f (forced part %6.2f over %2d quadgrams, %2d letters forced, word cover %.2f)  case %d L=%d W=%d "
              "%d checks  %s%s\n          %s\n          %s"
              % (r["score"], r["forced_score"], r["forced_quadgrams"], r["forced_letters"],
                 word_coverage(r["reading"]), r["case"],
                 r["L"], r["W"], r["checks"], ", ".join(r["alphabets"][:3]),
                 " (+%d more)" % (r["n_alphabets"] - 3) if r["n_alphabets"] > 3 else "", r["reading"], r["forced"]))
    return s, tab, rows


# ---------------------------------------------------------------- planted answers

PLANTS = [  # (case, key word, sliding, Beaufort form)
    (1, "CLUE", False, False),
    (1, "LANTERN", False, False),
    (2, "LIGHT", False, False),
    (1, "KEY", True, False),
    (2, "BERLIN", False, True),
    (2, "DUSK", True, False),
    (1, "UNDERGROUND", False, False),
    (2, "INTELLIGENCE", False, False),
    (1, "MAGNETIC", True, True),
]


def plant(rng, case, word, sliding, beaufort, alphabets):
    """An English message with the real clue words in place, enciphered by the textbook Quagmire IV with one
    dictionary alphabet and one random alphabet. Returns (ct, pt, dictionary name, dictionary alphabet)."""
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    pt = "".join(pt)
    name, alpha = alphabets[rng.randrange(1, len(alphabets))]
    hidden = "".join(rng.sample(AZ, 26))
    key = H.key_stream(word, sliding)
    assert not sliding or sum(H.IZ[c] for c in word) % 26
    pa, ca = (alpha, hidden) if case == 1 else (hidden, alpha)
    return H.quagmire4(pt, pa, ca, key, beaufort), pt, name, alpha


def planted_case(rng, spec, alphabets, decoys, big):
    case, word, sliding, beaufort = spec
    ct, pt, name, alpha = plant(rng, case, word, sliding, beaufort, alphabets)
    cribs = {i: pt[i] for i in CRIBS}
    hits, _ = search(ct, cribs, decoys + [(name, alpha)])
    rows, ngroups, nread = read(hits, ct, cribs, big, keep={name})
    mine = [r for r in rows if r["case"] == case and r["L"] == len(word) and bool(r["W"]) == sliding
            and name in r["names"]]
    right = max([sum(a == b for a, b in zip(r["reading"], pt)) for r in mine], default=0)
    sc = max([r["score"] for r in mine], default=None)
    better = [r for r in rows if sc is not None and r not in mine and r["score"] > sc + 1e-9
              and sum(a == b for a, b in zip(r["reading"], pt)) < READ_OK]
    ok = bool(mine) and right >= READ_OK and not better
    print("planted case %d %-9s key %-12s%s on %-22s -> found=%s (%d checks), %d/97 letters read, English %s; "
          "%d other survivors in %d systems, %d read, best wrong reading %s"
          % (case, "sliding" if sliding else "repeating", word, " Beaufort" if beaufort else "", name[:22], bool(mine),
             mine[0]["checks"] if mine else -1, right, sc, len(hits) - sum(r["n_alphabets"] for r in mine), ngroups,
             nread, max([r["score"] for r in rows if r not in mine and sum(a == b for a, b in zip(r["reading"], pt)) < READ_OK],
                        default=None)))
    return ok


if __name__ == "__main__":
    t0 = time.time()
    alphabets = dictionary_alphabets(mixed=True)
    big = Quadgrams(BIG)
    per = H.settings_per_alphabet()
    with Experiment("half-hidden Quagmire IV: dictionary alphabet on one side, any alphabet on the other",
                    puzzle="k4", cribs_forced=True,
                    notes="%d dictionary and transposition-mixed alphabets x 2 sides x (repeating key 1-%d + sliding "
                          "key 1-%d with 25 word sums); exact loop checks and distinct places"
                          % (len(alphabets), H.LMAX, H.SLIDE_MAX)) as ex:
        print("%d alphabets, %d settings each (Vigenere and Beaufort form are one test)" % (len(alphabets), per))
        k4, tab, rows = run_text("K4", K4, CRIBS, alphabets, big)
        ex.count(len(alphabets) * per)
        for r in rows[:20]:
            ex.add(r["reading"], english_big=r["score"], case=r["case"], L=r["L"], W=r["W"], checks=r["checks"],
                   alphabet=r["alphabets"][0])
        print("   (%.1f min)" % ((time.time() - t0) / 60))
        ctrl, ctabs = [], []
        for s in range(NCTRL):
            c, ctab, _ = run_text("shuffled K4 #%d" % (s + 1), shuffled_control(9900 + s), CRIBS, alphabets, big,
                                  verbose=False)
            ctrl.append(c)
            ctabs.append(ctab)
            print("   (%.1f min)" % ((time.time() - t0) / 60))
        rng = random.Random(99)
        decoys = alphabets[::40] if SMOKE else alphabets[::int(os.environ.get("IDEA99_DECOY_STEP", "4"))]
        MAX_READ = min(MAX_READ, 2000)
        ok = 0
        for spec in PLANTS:
            ok += planted_case(rng, spec, alphabets, decoys, big)
            print("   (%.1f min)" % ((time.time() - t0) / 60))
        print("planted recovered: %d/%d among %d decoy alphabets" % (ok, len(PLANTS), len(decoys)))
        cbest = [c["best"] for c in ctrl if c["best"] is not None]
        signal = k4["english"] > 0 and (not cbest or k4["best"] > max(cbest) + 0.3)
        verdict = ("K4 has a survivor that reads better than every control - inspect by eye" if signal else
                   "no half-hidden Quagmire IV fits: K4 %d survivors (%d with 5+ checks, %d in the idea's scope), best "
                   "reading %s; shuffled K4s %s survivors (%s with 5+ checks, %s in scope), best readings %s"
                   % (k4["survivors"], k4["passes_5plus_checks"], k4["survivors_in_idea_scope"], k4["best"],
                      [c["survivors"] for c in ctrl], [c["passes_5plus_checks"] for c in ctrl],
                      [c["survivors_in_idea_scope"] for c in ctrl], [c["best"] for c in ctrl]))
        print("RESULT " + json.dumps({"k4": k4, "k4_table": tab, "controls": ctrl, "control_tables": ctabs,
                                      "planted": "%d/%d" % (ok, len(PLANTS)), "alphabets": len(alphabets),
                                      "tested": len(alphabets) * per,
                                      "minutes": round((time.time() - t0) / 60, 1)}))
        print("VERDICT:", verdict)
        ex.notes += "; " + verdict + "; planted %d/%d" % (ok, len(PLANTS))
