"""Idea 135: a cipher-fed state device where one side is a keyword alphabet.

The device keeps a number s (the state) mod m. For each letter it reads C = F(s + h(P)) and then moves the
state on by g(C), an amount set by the cipher letter it just wrote:

    C_i = F(s_i + h(P_i))        s_(i+1) = s_i + g(C_i)        mod m

Idea 83 showed the plain-fed form is dead for any tables, and that this cipher-fed form with F, g and h all
hidden fits every m >= 14, so it cannot be judged. The idea here was that fixing one table to a keyword
alphabet, as on the K1/K2 tableau, leaves about 8 exact equations, enough to decide the class.

What the equations really say. Write u = F^-1. Inside a clue block s_i = u(C_i) - h(P_i), so the step after
letter i is u(C_(i+1)) - u(C_i) - h(P_(i+1)) + h(P_i), and it must equal g(C_i) every time the same cipher
letter is fed. K4's 22 fed clue letters repeat 8 times (F, R, V, Q, N, T twice, P three times): 8 equations.

  layout A   h a keyword alphabet, F and g hidden:  8 equations in 13 unknown places of F (14 letters, one
             shift is free). The equations have full rank in every modulus, so they ALWAYS have solutions:
             0 linear checks. What is left is that different cipher letters need different values of F.
  layout B   F^-1 a keyword alphabet, h and g hidden: 8 equations in 12 unknowns, again full rank, 0 linear
             checks; different plain letters need different values of h.
  layout C   both sides keyword alphabets (any two, not only the same one), only g hidden: 8 exact checks,
             and each check splits into a value of the cipher alphabet and a value of the plain alphabet, so
             a hash join decides every pair of the 666,993 x 666,993 alphabets at once. Idea 83 tested only
             the same alphabet on both sides (and A-Z / KRYPTOS against it).

The script prints the count of checks per layout first. Layouts A and B are then decided exactly per alphabet
(a depth-first search over the hidden places, compiled once per text, every "yes" re-checked by running the
device; a "no" is a proof). Layout C survivors are read: g is fixed for the 14 fed clue letters, the other g
values are filled in on English, with the gap between the clues as an exact equation.

Beaufort form (h = -index) is the same test as Vigenere form in layouts A and B (turn every table round);
in layout C both relative signs are tried. m = 26..31. m = 13 and m = 2 cannot hold a one-to-one F at all
(14 different cipher letters in the clues), so they are dead without a search.

Plain-fed devices are dead already (idea 83's doubled-pair rule). Both tables hidden stays undecidable.

  python attacks/135_cipher_fed_keyword_side.py
"""
import json
import os
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea135_fed as D  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA135_PROCS", "4" if SMOKE else "8"))
NCTRL = 3
MS = [26, 27, 28, 29, 30, 31]
ENGLISH = -5.1             # big-model score a reading must beat (planted readings: about -4.4)
READ_OK = 85               # letters of 97 a planted message must be read back with
MAX_READ = 6 if SMOKE else 50   # layout-C hits read per text (a random sample if there are more)
BIG = DATA_DIR / "english" / "quadgrams_big.txt"
CLUE = set(CRIBS)
_S = {}


# ---------------------------------------------------------------- layouts A and B: one side known

def one_init(ct, cribs):
    _S["comp"] = {hid: D.Eliminated(ct, cribs, hid) for hid in "uh"}


def one_work(chunk):
    """{(hidden, m): [yes, no, cap]} over a chunk of alphabets; every yes is re-checked."""
    out = {}
    for _, a in chunk:
        idx = {c: i for i, c in enumerate(a)}
        for hid, comp in _S["comp"].items():
            for m in MS:
                st, sol = comp.run(idx, m)
                if st == "yes":
                    assert comp.check(idx, m, sol), "solver answer does not reproduce the clues"
                r = out.setdefault((hid, m), [0, 0, 0])
                r[("yes", "no", "cap").index(st)] += 1
    return out


def one_side(ct, cribs, alphas):
    tot = {}
    for r in pmap(one_work, alphas, one_init, (ct, cribs), chunk=4000, procs=PROCS):
        for k, v in r.items():
            t = tot.setdefault(k, [0, 0, 0])
            for j in range(3):
                t[j] += v[j]
    return {"%s m=%d" % ("A (F hidden)" if hid == "u" else "B (h hidden)", m): tot[(hid, m)]
            for hid in "uh" for m in MS}


# ---------------------------------------------------------------- layout C: both sides known, hash join

def join_init(ct, cribs, alphas):
    _S["parts"] = D.side_vectors(ct, cribs)
    _S["alphas"] = alphas


def join_work(ms):
    up, hp = _S["parts"]
    alphas = _S["alphas"]
    hits = []
    for m in ms:
        table = {}
        idxs = [{c: i for i, c in enumerate(a)} for _, a in alphas]
        for n, idx in enumerate(idxs):
            table.setdefault(D.encode(D.vector(up, idx, m), m), []).append(n)
        for n, idx in enumerate(idxs):
            hv = D.vector(hp, idx, m)
            for sign in (1, -1):
                for c in table.get(D.encode([-sign * x for x in hv], m), ()):
                    hits.append((m, sign, c, n))
    return hits


def join(ct, cribs, alphas):
    hits = []
    for r in pmap(join_work, MS, join_init, (ct, cribs, alphas), chunk=1, procs=min(PROCS, len(MS))):
        hits += r
    return sorted(hits)


def expected_hits(neq, n_alphas):
    return sum(2.0 * n_alphas * n_alphas / m ** neq for m in MS)


def read_init(ct, cribs, alphas):
    _S["ct"], _S["cribs"], _S["alphas"] = ct, cribs, alphas
    _S["qg"] = Quadgrams()


def read_work(chunk):
    out = []
    ct, cribs, alphas = _S["ct"], _S["cribs"], _S["alphas"]
    for m, sign, ci, pi in chunk:
        u = {c: i for i, c in enumerate(alphas[ci][1])}
        h = {p: (sign * i) % m for i, p in enumerate(alphas[pi][1])}
        r = D.complete(ct, cribs, m, u, h, _S["qg"].logp, _S["qg"].floor)
        if r is None:
            continue
        out.append({"small": round(r[0], 3), "reading": r[1], "m": m, "sign": sign,
                    "cipher_alpha": alphas[ci][0], "plain_alpha": alphas[pi][0]})
    return out


def read_hits(ct, cribs, alphas, hits, big):
    rows = []
    if len(hits) > MAX_READ:
        hits = random.Random(len(hits)).sample(hits, MAX_READ)
    if hits:
        for r in pmap(read_work, hits, read_init, (ct, cribs, alphas), chunk=1, procs=PROCS):
            rows += r
    for r in rows:
        r["score"] = round(big.score(r["reading"].replace("?", "X")), 3)
        r["coverage"] = round(word_coverage(r["reading"]), 2)
    rows.sort(key=lambda r: -r["score"])
    return rows


# ---------------------------------------------------------------- one text

def run_text(label, ct, cribs, alphas, one_alphas, big):
    t0 = time.time()
    counts = {hid or "C": D.check_count(ct, cribs, hid) for hid in ("u", "h", "")}
    one = one_side(ct, cribs, one_alphas)
    hits = join(ct, cribs, alphas)
    neq = counts["C"][0]
    rows = read_hits(ct, cribs, alphas, hits, big)
    best = rows[0] if rows else None
    res = {"label": label, "checks": {"A": counts["u"], "B": counts["h"], "C": counts["C"]},
           "one_side": one, "one_side_alphabets": len(one_alphas),
           "C_hits": len(hits), "C_expected_by_chance": round(expected_hits(neq, len(alphas)), 2),
           "C_read": len(rows), "best": best["score"] if best else None,
           "best_reading": best["reading"] if best else None,
           "best_setting": {k: best[k] for k in ("m", "sign", "cipher_alpha", "plain_alpha")} if best else None,
           "best_coverage": best["coverage"] if best else None,
           "english": sum(1 for r in rows if r["score"] > ENGLISH),
           "hits_by_m": {m: sum(1 for h in hits if h[0] == m) for m in MS}}
    print("\n== %s  (%.1f min)" % (label, (time.time() - t0) / 60))
    print("   checks per layout (equations, unknowns, rank, linear checks left): A %s  B %s  C %s"
          % (counts["u"], counts["h"], counts["C"]))
    for k, (y, n, c) in one.items():
        print("   %-18s %7d fit  %7d proved impossible  %d undecided  (%.1f%% fit)"
              % (k, y, n, c, 100.0 * y / max(1, y + n + c)))
    print("   layout C: %d hits of %.3g pairs (chance %.1f), by m %s" % (
        len(hits), 2.0 * len(alphas) ** 2 * len(MS), res["C_expected_by_chance"], res["hits_by_m"]))
    for r in rows[:5]:
        print("     %.3f cov %.2f m=%d sign %+d %s / %s  %s" % (r["score"], r["coverage"], r["m"], r["sign"],
                                                             r["cipher_alpha"][:20], r["plain_alpha"][:20],
                                                             r["reading"]))
    return res, rows


# ---------------------------------------------------------------- planted answers

def planted_one_side(rng, alphas, decoys, m, hidden):
    """A device with one keyword side (the other random) must pass; how many decoys pass too."""
    while True:
        name, a = rng.choice(alphas)
        pt = english97(rng)
        r = D.plant_hidden(rng, pt, m, a, hidden)
        if r is None:
            continue
        ct = r[0]
        cribs = {i: pt[i] for i in CRIBS}
        if D.check_count(ct, cribs, hidden)[0] >= 7:
            break
    comp = D.Eliminated(ct, cribs, hidden)
    idx = {c: i for i, c in enumerate(a)}
    st, sol = comp.run(idx, m)
    ok = st == "yes" and comp.check(idx, m, sol)
    fit = sum(1 for _, b in decoys if comp.run({c: i for i, c in enumerate(b)}, m)[0] == "yes")
    print("   planted layout %s m=%d alphabet %s: true alphabet %s; %d of %d decoys fit too"
          % ("A" if hidden == "u" else "B", m, name, "fits" if ok else "MISSED", fit, len(decoys)))
    return ok, fit


def planted_both(rng, alphas, decoys, m, big):
    """Both sides keyword alphabets (different), random g: found by the join among the decoys and read back."""
    while True:
        (cn, ca), (pn, pa) = rng.sample(decoys, 2)
        sign = rng.choice((1, -1))
        pt = english97(rng)
        r = D.plant(rng, pt, m, ca, pa, sign)
        if r is None:
            continue
        ct = r[0]
        cribs = {i: pt[i] for i in CRIBS}
        if D.check_count(ct, cribs, "")[0] >= 7:
            break
    hits = join(ct, cribs, decoys)
    ci, pi = decoys.index((cn, ca)), decoys.index((pn, pa))
    found = (m, sign, ci, pi) in hits
    rows = read_hits(ct, cribs, decoys, [h for h in hits if h[0] == m], big)
    mine = [x for x in rows if x["cipher_alpha"] == cn and x["plain_alpha"] == pn and x["sign"] == sign]
    right = sum(a == b for a, b in zip(mine[0]["reading"], pt)) if mine else 0
    rank = rows.index(mine[0]) + 1 if mine else None
    print("   planted layout C m=%d %s / %s sign %+d: %s among %d hits at m=%d (all m: %d); read back %d/97, rank %s"
          % (m, cn, pn, sign, "found" if found else "MISSED", len(rows), m, len(hits), right, rank))
    if mine:
        print("     %s\n     %s" % (mine[0]["reading"], pt))
    return found and right >= READ_OK and rank == 1


if __name__ == "__main__":
    t0 = time.time()
    alphabets = dictionary_alphabets(mixed=True)
    big = Quadgrams(BIG)
    with Experiment("cipher-fed state device, one or both sides a keyword alphabet, m=26..31",
                    puzzle="k4", cribs_forced=True,
                    notes="%d dictionary and transposition-mixed alphabets; layouts A (h known) and B (F known) exact "
                          "per alphabet; layout C (both known, any pair, 2 signs) hash join, 8 checks"
                          % len(alphabets)) as ex:
        print("%d alphabets, m = %s" % (len(alphabets), MS))
        k4, rows = run_text("K4", K4, CRIBS, alphabets, alphabets, big)
        tested = len(alphabets) * 2 * len(MS) + 2 * len(alphabets) ** 2 * len(MS)
        ex.count(tested)
        for r in rows[:20]:
            ex.add(r["reading"], english_big=r["score"], m=r["m"], sign=r["sign"],
                   cipher_alpha=r["cipher_alpha"], plain_alpha=r["plain_alpha"])
        ctrl = []
        for s in range(NCTRL):
            c, _ = run_text("shuffled K4 #%d" % (s + 1), shuffled_control(13500 + s), CRIBS, alphabets,
                            alphabets[s::3], big)
            ctrl.append(c)
        print("\n== planted answers  (%.1f min)" % ((time.time() - t0) / 60))
        rng = random.Random(135)
        decoys = alphabets[::max(1, len(alphabets) // 9000)][:9000]
        p1 = [planted_one_side(rng, alphabets, decoys, 26, "u"), planted_one_side(rng, alphabets, decoys, 29, "u"),
              planted_one_side(rng, alphabets, decoys, 26, "h")]
        p2 = [planted_both(rng, alphabets, decoys, 26, big), planted_both(rng, alphabets, decoys, 29, big)]
        ok1, ok2 = sum(1 for ok, _ in p1 if ok), sum(p2)
        print("planted: one side known %d/3 true alphabets fit (decoys fitting too: %s of %d); both sides known "
              "%d/2 found and read back" % (ok1, [f for _, f in p1], len(decoys), ok2))
        cbest = [c["best"] for c in ctrl if c["best"] is not None]
        signal = k4["english"] > 0 and (not cbest or k4["best"] > max(cbest) + 0.3)
        verdict = ("K4 has a layout-C reading better than every control - inspect by eye" if signal else
                   "no signal: layout C K4 %d hits (chance %.1f), best reading %s; controls %s hits, best %s"
                   % (k4["C_hits"], k4["C_expected_by_chance"], k4["best"], [c["C_hits"] for c in ctrl], cbest))
        print("RESULT " + json.dumps({"k4": k4, "controls": ctrl, "planted_one_side": [[o, f] for o, f in p1],
                                      "planted_both": p2, "decoys": len(decoys), "alphabets": len(alphabets),
                                      "tested": tested, "minutes": round((time.time() - t0) / 60, 1)}))
        print("VERDICT:", verdict)
        ex.notes += "; " + verdict + "; planted one-side %d/3 fit, both-side %d/2 read back" % (ok1, ok2)
        assert ok1 == 3 and ok2 == 2, "planted answers not recovered"
