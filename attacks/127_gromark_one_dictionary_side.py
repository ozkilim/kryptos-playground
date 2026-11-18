"""Idea 127: Gromark with one dictionary alphabet and the other alphabet free (exact hash join).

Bean and Scheidt's "different math base" point to Gromark: a short digit primer grows into a long
digit key by chain addition, and each letter is moved along a mixed alphabet by its key digit:

    C_i = CA[ PA(P_i) + d_i ]      (also the subtractive form PA(P_i) - d_i; Beaufort is the same test)

Gromark with a straight A-Z plain side is dead (Bean: plain C and R both go to cipher P but sit more
than 10 apart). With both alphabets hidden it survives the clues, but idea 41 could only judge it by
English completion with about 50% power. K1 and K2 used keyword alphabets, so here ONE side is a
dictionary keyword alphabet and the other side is completely free. That makes the clue test exact:

  side A (plain alphabet from the dictionary, cipher alphabet free): the clue pairs with equal cipher
    letters (F 21/71, R 23/28, V 24/66, Q 25/26, P 27/65/72, N 29/63, K 31/73, S 32/33, T 67/68,
    0-indexed) force PA(P_a) + d_a = PA(P_b) + d_b mod 26, and different cipher letters must land
    on different slots.
  side B (cipher alphabet from the dictionary, plain alphabet free): the mirror, using the pairs with
    equal plain letters (E, A, S, T, N, O, R, L, C).

For each side the alphabet gives a vector of differences and the digit stream gives a vector of
differences; a hash join matches them, then the distinct-slot condition is checked exactly.

Alphabets: the 666,993 dictionary keyword alphabets and their two transposition-mixed forms
(kryptos.round11.dictionary_alphabets(mixed=True)), A-Z first.
Key streams (all mod the base b, bases 3-16):
  fib   d_i = d_{i-n} + d_{i-n+1}               (Gromark), primer lengths 2-7 while b^n <= 20M
                                                 (base 10 and 11 to 7 digits, 12-16 to 6)
  fib3  d_i = d_{i-n} + d_{i-n+1} + d_{i-n+2}    primer lengths 3-7 while b^n <= 5M
  ends  d_i = d_{i-n} + d_{i-1}                  primer lengths 3-7 while b^n <= 5M
  (134,945,192 primers in all.)
Streams that repeat with period 7/14/21/42 cannot pass (proof: any periodic substitution with those
periods contradicts the clues); the exact join rejects them by itself, so they are not filtered.

Controls: three shuffled K4s through the identical join. A shuffle usually has fewer equal cipher
letters at the clue positions than K4 (K4 has 10 such pairs, a shuffle often 5), which makes side A
much weaker for it, so the controls are the first three shuffles (seeds from 1270) with 8 or more. Planted (searched in the same pass, against
all alphabets and all primers): a base-10 5-digit Gromark with a dictionary plain alphabet and a random
cipher alphabet, and a base-12 5-digit Gromark mirrored (dictionary cipher alphabet, random plain
alphabet, subtractive form). Each must survive, ideally alone, and read back on completion.

  python attacks/127_gromark_one_dictionary_side.py
"""
import os
import random
import sys
import tempfile
import time
from array import array
from collections import Counter
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets, english97  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos import idea127_gromark as G  # noqa: E402

PROCS = max(2, min(12, cpu_count() - 2))
_W = {}


def spaces():
    if SMOKE:
        return [("fib", 10, 3), ("fib", 10, 4), ("fib", 10, 5), ("fib", 12, 4), ("fib", 12, 5), ("fib3", 5, 4),
                ("ends", 7, 3)]
    return sorted(G.spaces(cap_fib=20_000_000, cap_other=5_000_000))


def build_texts(alphas):
    rng = random.Random(127)
    texts = [("K4", K4, dict(CRIBS))]
    seed = 1270
    while len(texts) < 4:       # matched controls: as many equal-cipher-letter clue pairs as K4 (10) or 8+
        ct = shuffled_control(seed)
        if len(G.edges(ct, CRIBS, "A")) >= 8:
            texts.append(("shuffled seed %d" % seed, ct, dict(CRIBS)))
        seed += 1
    plants = []
    for side, base, f in (("A", 10, 1), ("B", 12, -1)):
        pt = english97(rng)
        ct, cribs, info = G.plant(rng, pt, alphas, side, base, 5, "fib", f)
        texts.append(("planted %s base %d" % (side, base), ct, cribs))
        plants.append((len(texts) - 1, pt, info))
    return texts, plants


# ---------------------------------------------------------------- workers

def _init_sig(texts):
    _W["T"] = G.Texts(texts)


def _sig_work(chunk):
    T = _W["T"]
    out = []
    for t, (_, ct, cr) in enumerate(T.texts):
        for side, eds in (("A", T.ea[t]), ("B", T.eb[t])):
            out.append({G.alpha_sig(m, ct, cr, side, f, eds) for _, m in chunk for f in (1, -1)})
    return out


def _init_scan(texts, path):
    _W["T"] = G.Texts(texts)
    arrs = []
    with open(path, "rb") as fh:
        for _ in range(2 * len(texts)):
            n = array("Q")
            n.fromfile(fh, 1)
            a = array("Q")
            a.fromfile(fh, n[0])
            arrs.append(a)
    _W["arr"] = arrs


def _scan_work(job):
    rule, base, m, first = job
    return job, G.scan(_W["T"], _W["arr"], rule, base, m, first)


def _init_res(texts, want):
    _W["T"] = G.Texts(texts)
    _W["want"] = want


def _res_work(chunk):
    T, want = _W["T"], _W["want"]
    keys = sorted({(t, side) for t, side, _ in want})
    out = []
    for ai, alpha in chunk:
        for t, side in keys:
            _, ct, cr = T.texts[t]
            eds = T.ea[t] if side == "A" else T.eb[t]
            for f in (1, -1):
                for rule, base, primer in want.get((t, side, G.alpha_sig(alpha, ct, cr, side, f, eds)), ()):
                    d = G.stream(primer, base, rule)
                    if G.distinct_ok(alpha, ct, cr, side, f, d):
                        out.append((t, side, f, ai, rule, base, primer))
    return out


def _init_comp(texts):
    _W["texts"] = texts
    _W["q"] = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")


def _comp_work(job):
    (t, side, f, ai, rule, base, primer), alpha, seed = job
    _, ct, cr = _W["texts"][t]
    d = G.stream(primer, base, rule, n=len(ct))
    part = G.forced(alpha, ct, cr, side, f, d)[0]
    sc, pt = G.complete(alpha, ct, cr, side, f, d, _W["q"], random.Random(seed),
                        iters=6000 if SMOKE else 25000, restarts=2 if SMOKE else 5)
    return job[0], part, sc, pt


# ---------------------------------------------------------------- main

def main():
    t0 = time.time()
    alphas = dictionary_alphabets(mixed=True)
    texts, plants = build_texts(alphas)
    sp = spaces()
    n_primers = sum(b ** m for _, b, m in sp)
    print("alphabets %d, primer spaces %d, primers %s, texts %d, procs %d" % (
        len(alphas), len(sp), "{:,}".format(n_primers), len(texts), PROCS), flush=True)

    # 1. alphabet signature arrays
    chunks = [alphas[i:i + 20000] for i in range(0, len(alphas), 20000)]
    sets = [set() for _ in range(2 * len(texts))]
    with Pool(PROCS, initializer=_init_sig, initargs=(texts,)) as pool:
        for r in pool.imap_unordered(_sig_work, chunks):
            for s, x in zip(sets, r):
                s |= x
    path = os.path.join(tempfile.mkdtemp(prefix="idea127_"), "sigs.bin")
    with open(path, "wb") as fh:
        for s in sets:
            array("Q", [len(s)]).tofile(fh)
            array("Q", sorted(s)).tofile(fh)
    print("signatures: %s distinct (%.0f s)" % ([len(s) for s in sets], time.time() - t0), flush=True)
    del sets

    # 2. primer scan
    jobs = [(r, b, m, f0) for r, b, m in sp for f0 in range(b)]
    jobs.sort(key=lambda j: -(j[1] ** (j[2] - 1)))
    hits = []
    with Pool(PROCS, initializer=_init_scan, initargs=(texts, path)) as pool:
        for k, (job, h) in enumerate(pool.imap_unordered(_scan_work, jobs)):
            hits += [(t, side, job[0], job[1], primer) for t, side, primer in h]
            if k % 200 == 0:
                print("  scan %d/%d jobs, %d hits (%.0f s)" % (k, len(jobs), len(hits), time.time() - t0), flush=True)
    os.remove(path)
    print("signature hits per text/side: %s (%.0f s)" % (dict(Counter((t, s) for t, s, *_ in hits)),
                                                        time.time() - t0), flush=True)

    # 3. resolve: matching alphabets + distinct-slot check
    want = {}
    T = G.Texts(texts)
    for t, side, rule, base, primer in hits:
        d = G.stream(primer, base, rule)
        eds = T.ea[t] if side == "A" else T.eb[t]
        want.setdefault((t, side, G.stream_sig(d, eds)), []).append((rule, base, primer))
    surv = []
    items = list(enumerate(m for _, m in alphas))
    with Pool(PROCS, initializer=_init_res, initargs=(texts, want)) as pool:
        for r in pool.imap_unordered(_res_work, [items[i:i + 20000] for i in range(0, len(items), 20000)]):
            surv += r
    surv.sort()
    print("survivors per text: %s (%.0f s)" % (dict(Counter(texts[s[0]][0] for s in surv)), time.time() - t0),
          flush=True)

    # 4. completion of every survivor (capped per text)
    cap = 300 if not SMOKE else 30
    rng = random.Random(5)
    todo = []
    for t in range(len(texts)):
        st = [s for s in surv if s[0] == t]
        if len(st) > cap:
            st = rng.sample(st, cap)
        todo += st
    comp = {}
    if todo:
        with Pool(PROCS, initializer=_init_comp, initargs=(texts,)) as pool:
            for k, (job, part, sc, pt) in enumerate(pool.imap_unordered(
                    _comp_work, [(s, alphas[s[3]][1], i) for i, s in enumerate(todo)])):
                comp[job] = (sc, part, pt)
    return t0, alphas, texts, plants, sp, n_primers, hits, surv, comp


def describe(alphas, s):
    t, side, f, ai, rule, base, primer = s
    return "side %s (%s alphabet %s), form %s, %s base %d primer %s" % (
        side, "plain" if side == "A" else "cipher", alphas[ai][0], "+" if f == 1 else "-", rule, base,
        "".join("%x" % x for x in primer))


if __name__ == "__main__":
    t0, alphas, texts, plants, sp, n_primers, hits, surv, comp = main()
    lines = []
    per = {}
    for t, (label, ct, cr) in enumerate(texts):
        st = [s for s in surv if s[0] == t]
        best = max(((comp[s][0], s) for s in st if s in comp), default=None)
        per[t] = (st, best)
        line = "%-22s survivors %d, signature hits %d" % (label, len(st), sum(1 for h in hits if h[0] == t))
        if best:
            sc, s = best
            line += ", best completion %.3f (%s)\n      forced  %s\n      full    %s  wordcover %.2f" % (
                sc, describe(alphas, s), comp[s][1], comp[s][2], word_coverage(comp[s][2]))
        lines.append(line)
    plant_res = []
    for t, pt, info in plants:
        st = per[t][0]
        true = [s for s in st if alphas[s[3]][1] == info["alpha"] and s[4:] == (info["rule"], info["base"], info["primer"])
                and s[1] == info["side"] and s[2] == info["f"]]
        right = 0
        if true and true[0] in comp:
            right = sum(a == b for a, b in zip(comp[true[0]][2], pt))
        forced_right = 0
        if true:
            part = comp[true[0]][1] if true[0] in comp else ""
            forced_right = sum(a == b for a, b in zip(part, pt))
        plant_res.append({"text": texts[t][0], "found": bool(true), "survivors": len(st), "true_is_best":
                          bool(true) and per[t][1] is not None and per[t][1][1] == true[0],
                          "forced_letters_right": forced_right, "completion_letters_right": right,
                          "settings": "%s %s base %d primer %s f %d" % (info["name"], info["rule"], info["base"],
                                                                        info["primer"], info["f"])})
    for p in plant_res:
        lines.append("PLANT %s" % p)
    for t, _, _ in plants:
        for s in per[t][0][:6]:
            lines.append("   %s survivor: %s -> %s" % (texts[t][0], describe(alphas, s), comp[s][2] if s in comp else "-"))
    for t, (label, ct, cr) in enumerate(texts):
        lines.append("%-22s clue pairs: side A %d, side B %d" % (label, len(G.edges(ct, cr, "A")), len(G.edges(ct, cr, "B"))))
    k4_n = len(per[0][0])
    ctrl_n = [len(per[t][0]) for t in (1, 2, 3)]
    tested = n_primers * len(alphas) * 2 * 2
    print("\n".join(lines))
    with Experiment("gromark one dictionary alphabet + one free alphabet, exact hash join, bases 3-16",
                    puzzle="k4", cribs_forced=True,
                    notes="%d alphabets x %d primers (fib/fib3/ends, bases 3-16) x 2 forms x 2 sides; K4 survivors %d, "
                          "controls %s; plants found %d/%d" % (len(alphas), n_primers, k4_n, ctrl_n,
                                                               sum(p["found"] for p in plant_res), len(plant_res))) as ex:
        ex.count(tested)
        for s in per[0][0]:
            if s in comp:
                ex.add(comp[s][2], setting=describe(alphas, s), q=round(comp[s][0], 3))
    print("K4 survivors %d, controls %s, plants %s, tested %s, %.1f min" % (
        k4_n, ctrl_n, [(p["found"], p["survivors"], p["completion_letters_right"]) for p in plant_res],
        "{:,}".format(tested), (time.time() - t0) / 60))
    if not SMOKE and not all(p["found"] for p in plant_res):
        sys.exit("planted answer not found")
