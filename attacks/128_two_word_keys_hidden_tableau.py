"""Idea 128: two-word keys on ONE hidden alphabet (word A then word B, joined through the forced key slots).

Scheidt: K4 runs "with the correct key word/s". Idea 93 closed single known words on a fully hidden
alphabet; it did not try two words written one after the other (SHADOW + FORCES, BERLIN + WALL), because
265k x 265k pairs cannot be listed one by one.

They do not need to be. On any one-alphabet tableau the clue letters put conditions on the KEY ALONE:

  true Quagmire III / II (the key letter is found on the hidden alphabet too)
      S->S and K->K (0-based 32 and 73) force the same key letter, R->P at 27 and 65 does the same, and
      22-63 pairs of clue places must carry DIFFERENT key letters (their equations would otherwise put
      two letters in one place);
  one hidden alphabet with a numeric key (idea 93's model a: X[C] = X[P] + k + c or k + c - X[P], the key
      valued on A-Z or KRYPTOS)
      6 fixed dot products of the key values mod 13 / mod 2.

With a key of length L = a + b made of word A then word B, every condition names one or two key slots, and
each slot belongs to A or to B. So every word is reduced to the letters (or the partial sums) it puts on
the touched slots, and the two sides are joined: hash for "equal" and dot products, bit masks for "must
differ". Only joined pairs go to the exact test of idea 93 (24 equations mod 26 with every letter in a
different place, kryptos/idea93_hidden.py); survivors are decrypted and scored on the big English model.

Key forms   pair A + B (L = 4-30, a, b >= 2), and sandwich A + B + A (L = 2a + b <= 30), repeating, every
            phase. Numeric models also take the sliding form (running sum of the repeated A + B).
Models      true Quagmire III: C = P + K, C = P - K (Vigenere-like), C = K - P (Beaufort-like);
            true Quagmire II (plain on A-Z or KRYPTOS); one hidden alphabet with numeric key (C = P + k,
            C = k - P; key on A-Z or KRYPTOS; repeating and sliding).
Vocabulary  tiers per cell (one cell = form, L, split, phase, model): the first tier whose joined count is at
            most CAP is solved: big x big (264,828 words and K1-K3 phrase windows), big x common, common x
            common (37,896), theme x common. Numeric models: common x common. Every tier used and every
            skipped cell is logged.
Controls    3 shuffled K4s, each on a third of the cells, same tiers and caps.
Planted     SHADOW+FORCES (L 12), BERLIN+WALL (L 10), a sandwich EAST+BERLIN+EAST and two numeric keys on
            random hidden alphabets, found among decoys and read back.

  python attacks/128_two_word_keys_hidden_tableau.py
"""
import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos import idea93_hidden as H  # noqa: E402
from kryptos import idea128_pairs as P  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA128_PROCS", "4" if SMOKE else "10"))
CAP = int(os.environ.get("IDEA128_CAP", "15000"))         # joined pairs solved per cell, located models
CAP_NUM = int(os.environ.get("IDEA128_CAP_NUM", "4000"))  # the same for each numeric model / valuation / kind
MAX_L = 14 if SMOKE else 26
ENGLISH = -5.1
MIN_Q = 15
CLUE = set(CRIBS)
LOC_NAMES = [m.name for m in H.LOCATED]
NUM_IDX = (0, 1)                                  # one hidden alphabet, C = P + k and C = k - P
NUM_KINDS = ("R", "S")
G = {}


# ---------------------------------------------------------------- vocabulary tiers

def bylen(words):
    d = defaultdict(list)
    for w in words:
        d[len(w)].append(w)
    return d


def standard_vocab():
    big, com, th = wordkeys.vocabulary("big"), wordkeys.vocabulary("common"), wordkeys.vocabulary("theme")
    if SMOKE:
        big, com = big[::40], com[::8]
        big = sorted(set(big) | set(com))
        com = sorted(set(com) | set(th))
    return {"big": big, "common": com, "theme": th}


def tiers(V):
    """{name: [(A list name, B list name)]} in order of preference."""
    return [("big", [("big", "big")]),
            ("mixed", [("big", "common"), ("common", "big-common")]),
            ("common", [("common", "common")]),
            ("theme", [("theme", "common"), ("common-theme", "theme")])]


def build_lists(V):
    big, com, th = (set(V[k]) for k in ("big", "common", "theme"))
    com |= th
    big |= com
    lists = {"big": big, "common": com, "theme": th, "big-common": big - com, "common-theme": com - th}
    return {k: bylen(sorted(v)) for k, v in lists.items()}


def init(ct, cribs, vocab, models, numeric, thin=None):
    G["T"] = H.Tables(ct, cribs)
    G["L"] = build_lists(vocab if vocab is not None else standard_vocab())
    G["models"] = models
    G["numeric"] = numeric
    G["thin"] = thin
    G["NS"] = {mi: P.NumericSolver(G["T"], mi) for mi in numeric}


def words(level, n, side):
    w = G["L"][level].get(n, [])
    th = G["thin"]
    if th and side == 0:
        w = w[th[0]::th[1]]
    return w


# ---------------------------------------------------------------- one cell

def work(cells):
    T = G["T"]
    cnt, hits, skipped = Counter(), [], []
    for form, L, a, b, phi in cells:
        tm = P.template(form, a, b)
        cs = P.clue_slots(tm, phi)
        # ---------- located models
        for li in G["models"]:
            t = T.loc[li]
            name = LOC_NAMES[li]
            cond = P.located_conditions(t, cs)
            if cond is None:
                cnt["dead cells", name] += 1
                continue
            chosen = None
            for tier, parts in (tiers(None) if form == "pair" else tiers(None)[2:]):
                tot, joined, space = 0, [], 0
                for la, lb in parts:
                    A, B = words(la, a, 0), words(lb, b, 1)
                    space += len(A) * len(B)
                    if not A or not B:
                        continue
                    n, j = P.located_join(cond, A, B, limit=CAP - tot)
                    tot += n
                    if tot > CAP:
                        break
                    joined.extend(j)
                if tot <= CAP:
                    chosen = (tier, tot, joined, space)
                    break
            if chosen is None:
                cnt["skipped cells", name] += 1
                skipped.append((name, form, L, a, phi))
                continue
            tier, tot, joined, space = chosen
            cnt["cells", name, tier] += 1
            cnt["space", name, tier] += space
            cnt["solved", name] += tot
            cnt["tested"] += space
            for la, lb in joined:
                for A in la:
                    for B in lb:
                        key = P.key_string(form, A, B)
                        r = P.solve_located(T, li, key, phi)
                        if r:
                            hits.append(((name, None, "R", key, phi, r[0], r[1]), (form, A, B)))
        # ---------- numeric models: common x common, else theme x common, under the same cap
        for mi in G["numeric"]:
            fs = P.numeric_forms(T, mi)
            name = T.num[mi][0].name
            for kind in NUM_KINDS:
                wts = P.numeric_weights(fs, tm, phi, kind)
                if any(not wa and not wb and tgt for wa, wb, tgt, _ in wts):
                    cnt["dead cells", name, kind] += 2
                    continue
                for vn in ("AZ", "KR"):
                    vals = H.VAL[vn]
                    chosen = None
                    for tier, parts in (("common", [("common", "common")]),
                                        ("theme", [("theme", "common"), ("common-theme", "theme")])):
                        joined, tot, space = [], 0, 0
                        for la, lb in parts:
                            A, B = words(la, a, 0), words(lb, b, 1)
                            space += len(A) * len(B)
                            if A and B:
                                j = P.numeric_join(wts, vals, A, B)
                                tot += sum(len(m) for _, m in j)
                                joined.extend(j)
                        if tot <= CAP_NUM:
                            chosen = (tier, tot, joined, space)
                            break
                    if chosen is None:
                        cnt["skipped cells", name, kind] += 1
                        skipped.append(("%s/%s/%s" % (name, vn, kind), form, L, a, phi))
                        continue
                    tier, tot, joined, space = chosen
                    cnt["cells", "%s/%s" % (name, kind), tier] += 1
                    cnt["space", name, kind] += space
                    cnt["tested"] += space
                    cnt["solved", name, kind] += tot
                    for wa, mb in joined:
                        for wb in mb:
                            k = P.numeric_key_values(form, wa, wb, phi, kind, vals)
                            sols, status = G["NS"][mi].solutions(k)
                            if sols or status == "many":
                                hits.append(((name, vn, kind, P.key_string(form, wa, wb), phi, sols, status),
                                             (form, wa, wb)))
    return cnt, hits, skipped


def cell_list(max_l=MAX_L):
    out = []
    for L in range(4, max_l + 1):
        for a in range(2, L // 2 + 1):
            for phi in range(L):
                out.append(("pair", L, a, L - a, phi))
    for a in range(2, 14):
        for b in range(2, 27):
            L = 2 * a + b
            if L <= max_l:
                for phi in range(L):
                    out.append(("sandwich", L, a, b, phi))
    random.Random(128).shuffle(out)          # spread heavy cells over the workers
    return out


def search(ct, cribs, cells, vocab=None, models=tuple(range(5)), numeric=NUM_IDX, thin=None, procs=None):
    cnt, hits, skipped = Counter(), [], []
    init_args = (ct, cribs, vocab, models, numeric, thin)
    if procs == 1:
        init(*init_args)
        res = [work(cells)]
    else:
        res = pmap(work, cells, init, init_args, chunk=4, procs=procs or PROCS)
    for c, h, s in res:
        cnt.update(c)
        hits.extend(h)
        skipped.extend(s)
    return cnt, hits, skipped


# ---------------------------------------------------------------- judging survivors

def read_score(pt, big):
    q = [pt[i:i + 4] for i in range(len(pt) - 3)
         if "?" not in pt[i:i + 4] and not all(j in CLUE for j in range(i, i + 4))]
    return (sum(big.logp.get(x, big.floor) for x in q) / len(q) if q else -99.0), len(q)


def judge(hits, ct, cribs, big):
    rows, unlisted = [], Counter()
    for h, meta in hits:
        if not h[5]:
            unlisted[h[0]] += 1
            continue
        best = None
        for pt, X, E in H.readings(h, ct, cribs):
            sc, nq = read_score(pt, big)
            key = (nq >= MIN_Q, sc if nq >= MIN_Q else nq)
            if best is None or key > best[0]:
                best = (key, sc, nq, pt, X, E)
        rows.append({"model": h[0], "key_values": h[1], "kind": h[2], "form": meta[0], "A": meta[1], "B": meta[2],
                     "key": h[3], "phase": h[4], "solutions": len(h[5]), "status": h[6],
                     "score": round(best[1], 3), "quadgrams": best[2], "reading": best[3]})
    rows.sort(key=lambda r: (r["quadgrams"] >= MIN_Q, r["score"]), reverse=True)
    return rows, unlisted


def summary(cnt, rows, unlisted, skipped):
    judged = [r for r in rows if r["quadgrams"] >= MIN_Q]
    tiers_used = {}
    for k, v in cnt.items():
        if isinstance(k, tuple) and k[0] == "cells":
            tiers_used.setdefault(k[1], {})[k[2]] = v
    return {"tested": cnt["tested"], "systems_solved": sum(v for k, v in cnt.items() if isinstance(k, tuple) and k[0] == "solved"),
            "survivors": len(rows), "undecided": sum(unlisted.values()),
            "judged": len(judged), "english": sum(r["score"] > ENGLISH for r in judged),
            "best": judged[0]["score"] if judged else None,
            "dead_cells": {"%s" % (k[1:],): v for k, v in cnt.items() if isinstance(k, tuple) and k[0] == "dead cells"},
            "cells_by_tier": tiers_used,
            "skipped_cells": dict(Counter(s[0] for s in skipped))}


# ---------------------------------------------------------------- planted answers

PLANTS = [  # (model kind, model index, valuation, kind, form, A, B)
    ("loc", 2, None, "R", "pair", "SHADOW", "FORCES"),           # Quagmire III, C = K - P
    ("loc", 0, None, "R", "pair", "BERLIN", "WALL"),             # Quagmire III, C = P + K
    ("loc", 3, None, "R", "sandwich", "EAST", "BERLIN"),         # Quagmire II on A-Z, EAST BERLIN EAST
    ("num", 0, "AZ", "S", "pair", "CLOCK", "WISE"),              # numeric C = P + k, sliding
    ("num", 1, "KR", "R", "sandwich", "LAYER", "TWO"),           # numeric C = k - P on KRYPTOS values
]


def planted_message(rng, spec):
    mk, idx, vn, kind, form, A, B = spec
    m = H.LOCATED[idx] if mk == "loc" else H.NUMERIC[idx]
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    pt = "".join(pt)
    alpha = "".join(rng.sample(AZ, 26))
    key = P.key_string(form, A, B)
    phi = rng.randrange(len(key))
    E = rng.randrange(1, 26) if (mk == "num" or not H.is_q3(m)) else 0
    ct = H.encrypt(m, kind, key, phi, H.VAL[vn] if vn else None, alpha, E, pt)
    return m, ct, pt, alpha, key, phi


def same_alphabet(X, alpha):
    true = {c: i for i, c in enumerate(alpha)}
    return any(all((u * true[c] + t) % 26 == v for c, v in X.items()) for u in H.UNITS for t in range(26))


def planted_case(rng, spec, decoys, big, procs=None):
    mk, idx, vn, kind, form, A, B = spec
    m, ct, pt, alpha, key, phi = planted_message(rng, spec)
    cribs = {i: pt[i] for i in CRIBS}
    L = len(key)
    vocab = {"big": decoys + [A, B], "common": decoys[: len(decoys) // 2] + [A, B], "theme": [A, B]}
    if form == "pair":
        cells = [("pair", L, a, L - a, f) for a in range(2, L // 2 + 1) for f in range(L)]
    else:
        cells = [("sandwich", L, a, L - 2 * a, f) for a in range(2, (L - 2) // 2 + 1) for f in range(L)]
    cnt, hits, _ = search(ct, cribs, cells, vocab, models=(idx,) if mk == "loc" else (),
                          numeric=(idx,) if mk == "num" else (), procs=procs)
    want_name = m.name
    mine = [(h, meta) for h, meta in hits if h[0] == want_name and h[3] == key and h[4] == phi and
            (mk == "loc" or (h[1] == vn and h[2] == kind))]
    # a pair can also be found as (B, A) at another phase: same cipher; accept any cyclic shift of the key
    if not mine:
        mine = [(h, meta) for h, meta in hits if h[0] == want_name and len(h[3]) == L and
                any(h[3] == key[s:] + key[:s] and (h[4] - phi + s) % L == 0 for s in range(L))]
    ok, right, sc = False, 0, None
    for h, meta in mine:
        for rd, X, E in H.readings(h, ct, cribs):
            good = sum(x == y for x, y in zip(rd, pt))
            wrong = sum(x != y and x != "?" for x, y in zip(rd, pt))
            if not wrong and good >= 60 and same_alphabet(X, alpha) and good > right:
                ok, right = True, good
                sc = read_score(rd, big)[0]
    print("planted %-34s %-8s %s %s+%s L %d phase %d -> found=%s, %d/97 read, English %s, alphabet recovered=%s, "
          "other survivors %d, systems solved %d"
          % (want_name, form, vn or "", A, B, L, phi, bool(mine), right, None if sc is None else round(sc, 2), ok,
             len(hits) - len(mine), sum(v for k, v in cnt.items() if isinstance(k, tuple) and k[0] == "solved")))
    return ok


def main():
    t0 = time.time()
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    cells = cell_list()
    if os.environ.get("IDEA128_SLICE"):           # timing runs only: K4 on every k-th cell
        sl = cells[::int(os.environ["IDEA128_SLICE"])]
        cnt, hits, sk = search(K4, CRIBS, sl)
        print(len(cells), len(sl), "cells; %.1f s" % (time.time() - t0), "hits", len(hits),
              "skipped", Counter(s[0] for s in sk))
        print({repr(k): v for k, v in cnt.items() if k[0] in ("solved", "cells", "skipped cells")})
        return
    decoys = random.Random(5).sample(wordkeys.vocabulary("common"), 600 if SMOKE else 3000)
    ok = sum(planted_case(random.Random(1280 + n), spec, decoys, big) for n, spec in enumerate(PLANTS))
    print("planted recovered: %d/%d  (%.1f min)" % (ok, len(PLANTS), (time.time() - t0) / 60), flush=True)
    with Experiment("two-word keys (A+B, A+B+A) on one hidden alphabet: forced key slots joined, exact solve",
                    puzzle="k4", cribs_forced=True,
                    notes="%d cells (pair L 4-%d, sandwich L <= %d, every phase); located Quagmire III/II with vocab "
                          "tiers big/mixed/common/theme under cap %d per cell; numeric one-alphabet models common/theme "
                          "tiers under cap %d, repeating and sliding" % (len(cells), MAX_L, MAX_L, CAP, CAP_NUM)) as ex:
        cnt, hits, skipped = search(K4, CRIBS, cells)
        rows, unlisted = judge(hits, K4, CRIBS, big)
        k4 = summary(cnt, rows, unlisted, skipped)
        ex.count(cnt["tested"])
        print("K4: %s  (%.1f min)" % (json.dumps(k4), (time.time() - t0) / 60), flush=True)
        for r in rows[:15]:
            print("   %6.2f over %2d quadgrams, word cover %.2f  %s %s %s %s+%s phase %d (%d sol, %s)\n          %s"
                  % (r["score"], r["quadgrams"], word_coverage(r["reading"].replace("?", "")), r["model"],
                     r["key_values"] or "", r["kind"], r["A"], r["B"], r["phase"], r["solutions"], r["status"],
                     r["reading"]))
            ex.add(r["reading"].replace("?", "X"), english_big=r["score"], model=r["model"], key=r["key"],
                   form=r["form"], phase=r["phase"], kind=r["kind"], key_values=r["key_values"])
        sk = Counter((s[0], s[2]) for s in skipped)
        print("skipped cells by (model, L):", json.dumps(sorted(("%s L%d" % k, v) for k, v in sk.items())))
        ctrl = []
        nctrl = 1 if SMOKE else 3
        for s in range(nctrl):
            sct = shuffled_control(12800 + s)
            ccnt, chits, csk = search(sct, CRIBS, cells[s::2 * nctrl])
            crows, cun = judge(chits, sct, CRIBS, big)
            ctrl.append(summary(ccnt, crows, cun, csk))
            print("shuffled K4 #%d (cells %d::%d): %s  (%.1f min)" % (s + 1, s, 2 * nctrl, json.dumps(ctrl[-1]),
                                                                      (time.time() - t0) / 60), flush=True)
            for r in crows[:3]:
                print("   %6.2f over %2d quadgrams  %s %s %s+%s  %s" % (r["score"], r["quadgrams"], r["model"],
                                                                   r["kind"], r["A"], r["B"], r["reading"]))
        cbest = [c["best"] for c in ctrl if c["best"] is not None]
        signal = k4["english"] > 0 and (not cbest or k4["best"] > max(cbest) + 0.3)
        verdict = ("K4 has a survivor that reads better than every control - inspect by eye" if signal else
                   "no two-word key fits one hidden alphabet: %d survivors, %d readable (controls: %s survivors, %s readable)"
                   % (k4["survivors"], k4["english"], [c["survivors"] for c in ctrl], [c["english"] for c in ctrl]))
        print("RESULT " + json.dumps({"k4": k4, "controls": ctrl, "planted": "%d/%d" % (ok, len(PLANTS)),
                                      "minutes": round((time.time() - t0) / 60, 1)}))
        print("VERDICT:", verdict)
        ex.notes += "; " + verdict + "; planted %d/%d" % (ok, len(PLANTS))
        out = Path(os.environ.get("KRYPTOS_SMOKE") or ".") / "results" if SMOKE else Path("results")
        out.mkdir(parents=True, exist_ok=True)
        (out / "idea128_detail.json").write_text(json.dumps(
            {"k4": k4, "controls": ctrl, "k4_rows": rows[:50], "skipped": skipped,
             "counts": {repr(k): v for k, v in cnt.items()}}, indent=1))


if __name__ == "__main__":
    main()
