"""Idea 115: the key is two sculpture texts added together (LAYER TWO with two running keys).

K2 ends LAYER TWO and Sanborn says the solver needs "just to be able to read". One sculpture text as a
running key is dead, and two stacked keys were closed only for repeating words. Here the key is two
running texts laid over each other, so it never repeats:

    K[i] = T1[a+i] + T2[b+i] + c      or      K[i] = T1[a+i] - T2[b+i] + c          (mod 26)

T1, T2: any of 20 texts on the sculpture (K1-K3 plaintext as carved and corrected, K1-K3 ciphertext as
carved and with K2 corrected, the cipher panel and the tableau panel read by rows and by columns, the
Morse text, K4's own ciphertext; each forwards and backwards), any start a, b; letters numbered on A-Z
or KRYPTOS (each text on its own numbering). c is free: it covers numbering from 0 or 1 and any shift
of the tableau, and costs one check. K is the key the 24 clue letters force, in four views (C-P, P-C,
C+P, -C-P) on the A-Z / KRYPTOS tableaux (4 layouts) and on the 84 theme alphabets (5 layouts each).

Meet in the middle: the normalised 13-letter (block 1) and 11-letter (block 2) windows of every
(text, start) go into a hash table; for every (T1, a) the forced key minus T1 is looked up. Block 1
alone gives 12 checks, block 2 alone 10. Every block hit is then extended to the other block at the
true gap (all 24 letters: 23 checks) and with the gap off by up to 30 places either way.

Part B, one text plus a word (all 24 letters): K = T + W with W a repeating word of length 1-10
(24 - L... checks), K = T + a sliding word (running sum of a word, length 1-10), and K = S + W with S a
text used as a sliding key (its running sum, numbered from 0 or 1). These are exact hash joins too: the
tests are linear, so the test values of the forced key must equal those of the text window.

Survivors are decrypted over the 97 places and scored on the big English model. Controls: 5 shuffled
K4s, the same search. Planted: 6 messages made with the model, each must come back as the only reading.

Scope: only texts on the sculpture; a key text from outside cannot be found this way.

  python attacks/115_two_sculpture_texts.py
"""
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea115_twotexts as H  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.ciphers.substitution import KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR, letters, load  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402
from kryptos.wordkeys import theme_words  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA115_PROCS", "4" if SMOKE else "8"))
N_CONTROLS = 1 if SMOKE else 5
GAP_SCAN = 30
NUMS = ("AZ", "KR")
G = {}


def alphabets(smoke=False):
    small, seen = [("A-Z", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)], {AZ, KRYPTOS_ALPHABET}
    for w in theme_words():
        m = keyword_alphabet(w)
        if m not in seen:
            seen.add(m)
            small.append((w, m))
    return small[:6] if smoke else small


# ---------------------------------------------------------------- Part A worker

def init(texts):
    G["texts"] = texts
    G["vals"] = H.numbered(texts, NUMS)
    G["W"], G["T"] = {}, {}
    for nn in NUMS:
        for bn, blk in (("B1", H.B1), ("B2", H.B2)):
            w = H.windows(G["vals"][nn], blk)
            G["W"][nn, bn] = w
            G["T"][nn, bn] = H.table(w)


def other_block(item, nn1, nn2, s2, sid1, a, sid2, b, bn):
    """Agreement of the other block for gap shifts d in -GAP_SCAN..GAP_SCAN: {d: letters agreeing}."""
    _, _, _, _, k = item
    v1, v2 = G["vals"][nn1][sid1], G["vals"][nn2][sid2]
    blk, oth = (H.B1, H.B2) if bn == "B1" else (H.B2, H.B1)
    p0 = blk[0]
    c = (k[p0] - v1[a + p0] - s2 * v2[b + p0]) % 26
    out = {}
    for d in range(-GAP_SCAN, GAP_SCAN + 1):
        ag, ok = 0, True
        for p in oth:
            i1, i2 = a + p + d, b + p + d
            if not (0 <= i1 < len(v1) and 0 <= i2 < len(v2)):
                ok = False
                break
            if (v1[i1] + s2 * v2[i2] + c - k[p]) % 26 == 0:
                ag += 1
        if ok:
            out[d] = ag
    return out


def work(chunk):
    hits, hist, lookups = [], {"B1": Counter(), "B2": Counter()}, 0
    for item in chunk:
        _, _, _, _, k = item
        for bn, blk in (("B1", H.B1), ("B2", H.B2)):
            kn = [(k[p] - k[blk[0]]) % 26 for p in blk]
            for nn1 in NUMS:
                w1 = G["W"][nn1, bn]
                for nn2 in NUMS:
                    plus, minus = G["T"][nn2, bn]
                    for s2, tab in ((1, plus), (-1, minus)):
                        lookups += len(w1)
                        for sid1, a, sid2, b in H.join(kn, w1, tab, hist[bn]):
                            gaps = other_block(item, nn1, nn2, s2, sid1, a, sid2, b, bn)
                            hits.append((item[:4], bn, nn1, nn2, s2, sid1, a, sid2, b, gaps))
    return hits, hist, lookups


def part_a(ct, cribs, alphas, texts, procs=PROCS):
    am = dict(alphas)
    items = [(an, am[an], lay, view, k) for an, lay, view, k in H.forced_keys(ct, cribs, alphas)]
    hits, hist, lookups = [], {"B1": Counter(), "B2": Counter()}, 0
    if procs <= 1 or len(items) < 40:
        init(texts)
        parts = [work(items)]
    else:
        parts = pmap(work, items, init, (texts,), chunk=8, procs=procs)
    for h, hs, lk in parts:
        hits.extend(h)
        lookups += lk
        for bn in hs:
            hist[bn].update(hs[bn])
    return items, hits, hist, lookups


# ---------------------------------------------------------------- Part B (single process, exact joins)

TESTS = [("rep", L) for L in range(1, 11)] + [("slide", L) for L in range(1, 11)]
FUNCS = {t: H.functionals(*t) for t in TESTS}


def part_b_tables(texts):
    """{(test, numbering, cum shift or None): {signature: [(sid, a)]}}.  cum None = the text itself."""
    vals = H.numbered(texts, NUMS)
    tabs = {}
    for nn in NUMS:
        sources = [(None, vals[nn])] + [(s, H.cumulative([[x + s for x in v] for v in vals[nn]])) for s in (0, 1)]
        for cs, vs in sources:
            wins = H.windows(vs, H.POS)
            for t in TESTS:
                if cs is not None and t[0] == "slide":
                    continue          # the sliding key plus a word is tested with a repeating word only
                d = {}
                for sid, a, u in wins:
                    d.setdefault(H.signature(u, FUNCS[t]), []).append((sid, a))
                tabs[t, nn, cs] = (d, len(wins))
    return tabs


def part_b(items, tabs):
    hits, tested, expect = [], 0, 0.0
    for item in items:
        k = item[4]
        kv = [k[p] for p in H.POS]
        sig = {t: H.signature(kv, FUNCS[t]) for t in TESTS}
        for (t, nn, cs), (d, n) in tabs.items():
            tested += n
            expect += n * 26.0 ** -len(FUNCS[t])
            for sid, a in d.get(sig[t], ()):
                hits.append((item[:4], t, nn, cs, sid, a))
    return hits, tested, expect


# ---------------------------------------------------------------- reading survivors

def key_a(h, vals, k):
    _, bn, nn1, nn2, s2, sid1, a, sid2, b, gaps = h
    return H.pair_key(vals[nn1][sid1], a, vals[nn2][sid2], b, s2, k, p0=H.B1[0] if bn == "B1" else H.B2[0])


def key_b(h, vals, k):
    (_, _, _, _), (kind, L), nn, cs, sid, a = h
    v = vals[nn][sid]
    if cs is not None:
        v = H.cumulative([[x + cs for x in v]])[0]
    r = {p: (k[p] - v[a + p]) % 26 for p in H.POS}
    if kind == "rep":
        w = {p % L: r[p] for p in H.POS}
        return [(v[a + i] + w[i % L]) % 26 if 0 <= a + i < len(v) else None for i in range(97)]
    wd = {}
    for blk in (H.B1, H.B2):
        for p, q in zip(blk, blk[1:]):
            wd[q % L] = (r[q] - r[p]) % 26
    out, acc = [None] * 97, r[H.B1[0]]
    vals_r = {H.B1[0]: acc}
    for i in range(H.B1[0] + 1, 97):
        acc = (acc + wd[i % L]) % 26
        vals_r[i] = acc
    acc = r[H.B1[0]]
    for i in range(H.B1[0] - 1, -1, -1):
        acc = (acc - wd[(i + 1) % L]) % 26
        vals_r[i] = acc
    for i in range(97):
        if 0 <= a + i < len(v):
            out[i] = (v[a + i] + vals_r[i]) % 26
    return out


def read_all(ct, alphas, items, hits_a, hits_b, texts, big):
    vals = H.numbered(texts, NUMS)
    am = dict(alphas)
    kof = {it[:4]: it[4] for it in items}
    rows = []
    for h in hits_a:
        if h[1] == "B2" and h[9].get(0) == len(H.B1):
            continue           # already read as a block-1 hit
        full = h[1] == "B1" and h[9].get(0) == len(H.B2)
        an, m, lay, view = h[0]
        key = key_a(h, vals, kof[h[0]])
        rows.append(("A", h, full, H.decrypt(ct, key, m, lay, view)))
    for h in hits_b:
        an, m, lay, view = h[0]
        key = key_b(h, vals, kof[h[0]])
        rows.append(("B", h, True, H.decrypt(ct, key, m, lay, view)))
    out = []
    for part, h, full, pt in rows:
        seg = max(pt.split("?"), key=len)
        out.append({"part": part, "full24": full, "plain": pt, "big": round(big.score(seg), 3) if len(seg) >= 4 else -99,
                    "cover": round(word_coverage(seg), 3), "setting": describe(h, texts)})
    out.sort(key=lambda r: -r["big"])
    return out


def describe(h, texts):
    if len(h) == 10:
        (an, _, lay, view), bn, nn1, nn2, s2, sid1, a, sid2, b, gaps = h
        best = max(gaps.items(), key=lambda x: x[1]) if gaps else None
        return "%s %s %s | %s[%s]@%d %s %s[%s]@%d | hit %s, other block best %s" % (
            an, lay, view, texts[sid1][0], nn1, a, "+" if s2 > 0 else "-", texts[sid2][0], nn2, b, bn, best)
    (an, _, lay, view), (kind, L), nn, cs, sid, a = h
    src = texts[sid][0] if cs is None else "running sum of %s (from %d)" % (texts[sid][0], cs)
    return "%s %s %s | %s[%s]@%d + %s word L=%d" % (an, lay, view, src, nn, a, kind, L)


# ---------------------------------------------------------------- one full run

def expected(items, texts):
    """Chance matches: pairs x 26^-(checks) for block 1, block 2 and both blocks at the true gap."""
    vals = H.numbered(texts, NUMS)
    nw = {(nn, bn): len(H.windows(vals[nn], blk)) for nn in NUMS for bn, blk in
          (("B1", H.B1), ("B2", H.B2), ("ALL", H.POS))}
    out = {}
    for bn, chk in (("B1", 12), ("B2", 10), ("ALL", 23)):
        pairs = len(items) * 2 * sum(nw[n1, bn] * nw[n2, bn] for n1 in NUMS for n2 in NUMS)
        out[bn] = (pairs, pairs * 26.0 ** -chk)
    return out


def run(ct, cribs, alphas, texts, tabs, big, procs=PROCS, label="K4"):
    t0 = time.time()
    items, hits_a, hist, lookups = part_a(ct, cribs, alphas, texts, procs)
    hits_b, tested_b, exp_b = part_b(items, tabs)
    rows = read_all(ct, alphas, items, hits_a, hits_b, texts, big)
    exp = expected(items, texts)
    full_a = [h for h in hits_a if h[1] == "B1" and h[9].get(0) == 11]
    shifted = [h for h in hits_a if max([v for d, v in h[9].items() if d != 0] or [0]) >= (8 if h[1] == "B1" else 9)]
    res = {"label": label, "key_vectors": len(items), "lookups": lookups,
           "pairs_B1": exp["B1"][0], "pairs_B2": exp["B2"][0], "pairs_both": exp["ALL"][0],
           "expect_B1": exp["B1"][1], "expect_B2": exp["B2"][1], "expect_both": exp["ALL"][1],
           "hits_B1": sum(1 for h in hits_a if h[1] == "B1"), "hits_B2": sum(1 for h in hits_a if h[1] == "B2"),
           "hits_both_true_gap": len(full_a), "hits_other_block_shifted_8plus": len(shifted),
           "agree_hist_B1": dict(sorted(hist["B1"].items())), "agree_hist_B2": dict(sorted(hist["B2"].items())),
           "partB_tested": tested_b, "partB_expect": exp_b, "partB_hits": len(hits_b),
           "best_reading": rows[0] if rows else None, "readings": rows[:20], "seconds": round(time.time() - t0, 1),
           "_hits_a": hits_a, "_hits_b": hits_b, "_rows": rows}
    return res


def show(r):
    print("[%s] %d key vectors, %s lookups, %.0fs" % (r["label"], r["key_vectors"], format(r["lookups"], ","), r["seconds"]))
    print("   block 1 alone: %d hits (pairs %.3g, chance %.2g); block 2 alone: %d hits (pairs %.3g, chance %.2g)" % (
        r["hits_B1"], r["pairs_B1"], r["expect_B1"], r["hits_B2"], r["pairs_B2"], r["expect_B2"]))
    print("   both blocks, true gap: %d (pairs %.3g, chance %.2g); other block 8+ at a shifted gap: %d" % (
        r["hits_both_true_gap"], r["pairs_both"], r["expect_both"], r["hits_other_block_shifted_8plus"]))
    print("   prefix candidates by letters agreeing, block 1:", r["agree_hist_B1"])
    print("   prefix candidates by letters agreeing, block 2:", r["agree_hist_B2"])
    print("   part B: %s windows x tests, %d hits (chance %.2g)" % (format(r["partB_tested"], ","), r["partB_hits"], r["partB_expect"]))
    for row in r["readings"][:5]:
        print("     %s full=%s big=%.2f cover=%.2f %s\n        %s" % (row["part"], row["full24"], row["big"], row["cover"],
                                                                  row["setting"], row["plain"]))


# ---------------------------------------------------------------- planted answers

def plants(texts):
    """[(name, ct, cribs, plaintext, expected setting substring)] built with the model itself."""
    names = [n for n, _ in texts]
    vals = H.numbered(texts, NUMS)
    pt = H.PLANT_TEXT[:97]
    k3 = len(letters(load("k1")["plaintext"])) + len(letters(load("k2")["plaintext"]))
    out = []

    def mk(name, key, m, lay, view, want):
        ct = H.encrypt(pt, key, m, lay, view)
        out.append((name, ct, {i: pt[i] for i in CRIBS}, pt, want))

    def pair(t1, n1, a, t2, n2, b, s2, c):
        v1, v2 = vals[n1][names.index(t1)], vals[n2][names.index(t2)]
        return [(v1[a + i] + s2 * v2[b + i] + c) % 26 for i in range(97)]
    # 1. K3 plaintext minus K3 ciphertext at two offsets, KRYPTOS tableau
    mk("K3 plain - K3 cipher, KRYPTOS", pair("K1-K3 plain (carved)", "KR", k3 + 40, "K1-K3 cipher (carved)", "KR",
                                             k3 + 117, -1, 3), KRYPTOS_ALPHABET, "KR/KR", "vig",
       "K1-K3 plain (carved)[KR]@%d - K1-K3 cipher (carved)[KR]@%d" % (k3 + 40, k3 + 117))
    # 2. a K2 line plus a tableau column, A-Z, Beaufort
    mk("K2 line + tableau column, A-Z", pair("K1-K3 plain (corrected)", "AZ", 63 + 150, "tableau panel columns", "AZ",
                                             200, 1, 0), AZ, "AZ/AZ", "beau",
       "K1-K3 plain (corrected)[AZ]@213 + tableau panel columns[AZ]@200")
    # 3. a theme alphabet: tableau rows backwards minus K4 backwards (AZ / KR numbering)
    pal = keyword_alphabet("PALIMPSEST")
    mk("tableau rows rev - K4 rev, PALIMPSEST M/AZ", pair("tableau panel rows reversed", "AZ", 333, "K4 cipher reversed",
                                                          "KR", 0, -1, 11), pal, "M/AZ", "var",
       "tableau panel rows reversed[AZ]@333 - K4 cipher reversed[KR]@0")
    # 4. one text plus the word SHADOW
    v = vals["AZ"][names.index("cipher panel columns")]
    w = [AZ.index(c) for c in "SHADOW"]
    mk("cipher panel columns + SHADOW", [(v[300 + i] + w[i % 6]) % 26 for i in range(97)], AZ, "AZ/AZ", "vig",
       "cipher panel columns[AZ]@300 + rep word L=6")
    # 5. a text as a sliding key (running sum) plus LAYER
    s = H.cumulative([[x + 1 for x in vals["KR"][names.index("K1-K3 plain (carved)")]]])[0]
    w = [KRYPTOS_ALPHABET.index(c) for c in "LAYER"]
    mk("running sum of K1-K3 plain + LAYER", [(s[90 + i] + w[i % 5]) % 26 for i in range(97)], KRYPTOS_ALPHABET,
       "KR/AZ", "beau", "running sum of K1-K3 plain (carved) (from 1)[KR]@90 + rep word L=5")
    # 6. a text plus a sliding word BERLIN
    w = [AZ.index(c) for c in "BERLIN"]
    key, acc = [], 0
    for i in range(97):
        acc = (acc + w[i % 6]) % 26
        key.append(acc)
    v4 = vals["KR"][names.index("K1-K3 cipher (carved) reversed")]
    mk("K1-K3 cipher reversed + sliding BERLIN", [(v4[17 + i] + key[i]) % 26 for i in range(97)], AZ, "AZ/KR", "diana",
       "K1-K3 cipher (carved) reversed[KR]@17 + slide word L=6")
    return out


def planted(alphas, texts, tabs, big, procs, only=None):
    ok, lines = 0, []
    for n, (name, ct, cribs, pt, want) in enumerate(plants(texts), 1):
        if only and n not in only:
            continue
        r = run(ct, cribs, alphas, texts, tabs, big, procs, label="planted: " + name)
        full = [x for x in r["_rows"] if x["full24"]]
        readings = {x["plain"].replace("?", "") for x in full}
        found = [x for x in full if want in x["setting"]]
        agree = all(all(c in ("?", d) for c, d in zip(x["plain"], pt)) for x in full)
        good = bool(found) and found[0]["plain"] == pt and agree
        ok += good
        lines.append("%s: %s (full-24 settings %d, all of them the planted text: %s; read back 97/97: %s)" % (
            name, "FOUND" if good else "MISSED", len(full), agree, found[0]["plain"] == pt if found else False))
        print("  planted", lines[-1])
    return ok, lines


def main():
    texts = H.all_texts()
    alphas = alphabets(smoke=bool(SMOKE))
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    t0 = time.time()
    tabs = part_b_tables(texts)
    print("texts %d, alphabets %d, part B tables built in %.0fs" % (len(texts), len(alphas), time.time() - t0))
    pal = [("A-Z", AZ), ("KRYPTOS", KRYPTOS_ALPHABET), ("PALIMPSEST", keyword_alphabet("PALIMPSEST"))]
    p_alphas = pal + [x for x in alphas if x[1] not in {m for _, m in pal}][:3 if SMOKE else 20]
    ok, plines = planted(p_alphas, texts, tabs, big, PROCS)
    n_pl = len(plines)
    assert ok == n_pl, "planted answers missed: %d/%d" % (ok, n_pl)
    with Experiment("idea115-two-sculpture-texts", notes="K = T1 +- T2 (+c), 20 sculpture texts, all starts; "
                    "A-Z/KRYPTOS + 84 theme alphabets; blocks alone, gap scan, part B text + word",
                    cribs_forced=True) as ex:
        res = run(K4, CRIBS, alphas, texts, tabs, big, PROCS, label="K4")
        show(res)
        ex.count(res["lookups"] + res["partB_tested"])
        for row in res["_rows"][:30]:
            ex.add(row["plain"].replace("?", "X"), setting=row["setting"], big=row["big"])
        ctrl = []
        for s in range(1, N_CONTROLS + 1):
            c = run(shuffled_control(s), CRIBS, alphas, texts, tabs, big, PROCS, label="shuffle %d" % s)
            show(c)
            ctrl.append(c)
            ex.count(c["lookups"] + c["partB_tested"])
    out = {"k4": {k: v for k, v in res.items() if not k.startswith("_")},
           "controls": [{k: v for k, v in c.items() if not k.startswith("_")} for c in ctrl],
           "planted": plines, "planted_ok": "%d/%d" % (ok, n_pl)}
    dest = Path(SMOKE) if SMOKE else Path(__file__).resolve().parent.parent / "results"
    dest.mkdir(parents=True, exist_ok=True)
    with open(dest / "idea115_summary.json", "w") as f:
        json.dump(out, f, indent=1, default=str)
    print("planted %d/%d; summary -> %s" % (ok, n_pl, dest / "idea115_summary.json"))


if __name__ == "__main__":
    main()
