"""Idea 93: real word keys on a fully hidden tableau.

Scheidt: K4 runs "with the correct key word/s". The open-gaps list keeps "hidden alphabet, key of 23+
letters" as open, but only because the key letters were treated as unknowns too. If the key is a real word,
a phrase or a reading of the sculpture, the key letters are KNOWN, and one hidden alphabet (26 unknown
positions) is decided exactly by the 24 clue letters at every key length.

Key sources
  words      264,828 words and phrases (theme words, 22k common words, /usr/share/dict, every 4-26 letter
             window of the K1-K3 plaintexts), each at every phase
  streams    attack 58's readings of the sculpture (rows, columns, back-and-forth, diagonals of both panels,
             K1-K3 plaintext grids, the Morse text; every d-th letter, d = 1-60), as a running key at
             every offset
How a word makes a key (kind)
  R  repeating        S  sliding: the key is the running sum of the word
  G  progressive: the word, moved one step further at every pass
Models (X = the hidden alphabet, k = key letter as a number on A-Z or KRYPTOS)
  a  one hidden alphabet on both sides, numeric key:   X[C] = X[P] + k + c   and   X[C] = k + c - X[P]
  b  true Quagmire III: the key letter is found on the hidden alphabet too:
     X[C] = X[P] + X[K],  X[C] = X[P] - X[K],  X[C] = X[K] - X[P]; sliding = running sum of X[K] with a free
     start; progressive = X[K] + t per pass with ANY step t
  c  hidden alphabet on one side, A-Z or KRYPTOS on the other, numeric key (plain or cipher side hidden,
     key added or subtracted); and true Quagmire II (hidden cipher alphabet that also holds the key letter)
Every constant offset is free. In true Quagmire III the fixed points S->S (33) and K->K (74) force the key
letters there to be the same letter, and R->P twice (28, 66) does the same: filters no earlier test used.

A setting survives only if the 24 equations have a solution mod 26 in which the letters sit in different
places (all-letters-in-one-place solves every such system). Survivors are decrypted where the solution
forces a letter and scored on the big English model. Controls: 3 shuffled K4s. Planted: 9 messages.

  python attacks/93_word_keys_hidden_tableau.py
"""
import importlib.util
import json
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea93_hidden as H  # noqa: E402
from kryptos import wordkeys  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE") and not os.environ.get("IDEA93_SLICE")
PROCS = int(os.environ.get("IDEA93_PROCS", "4" if SMOKE else "10"))
MAX_SKIP = 3 if SMOKE else 60
ENGLISH = -5.1          # big-model score per quadgram a reading must beat (planted readings: about -4.3)
MIN_Q = 15              # quadgrams outside the clues needed before a reading can be judged
CLUE = set(CRIBS)
G = {}


def attack58():
    spec = importlib.util.spec_from_file_location("a58", Path(__file__).resolve().parent / "58_sculpture_readings.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def vocabulary():
    return wordkeys.vocabulary("big")


def sculpture_streams():
    """[(name, string)]: every distinct reading of attack 58's grids that can hold the two clues."""
    a = attack58()
    seen, out = set(), []
    for gname, rows in a.grids().items():
        for rname, s in a.readings(rows):
            if len(s) >= 53 and s not in seen:
                seen.add(s)
                out.append(("%s: %s" % (gname, rname), s))
    return out


def init(ct, cribs):
    G["T"] = H.Tables(ct, cribs)


def work_words(words):
    cnt, hits = Counter(), []
    H.scan_words(G["T"], words, cnt, hits)
    return cnt, hits


def work_streams(items):
    cnt, hits = Counter(), []
    for name, s in items:
        for d in range(1, MAX_SKIP + 1):
            if len(s) // d < 53:
                break
            for a in range(d):
                t = s[a::d]
                if len(t) >= 53:
                    cnt["streams"] += 1
                    H.scan_stream(G["T"], t, cnt, hits, "%s, every %d from %d" % (name, d, a))
    return cnt, hits


def search(ct, cribs, words, streams, chunk=400):
    cnt, hits = Counter(), []
    for work, items, ch in ((work_words, words, chunk), (work_streams, streams, 1)):
        if not items:
            continue
        for c, h in pmap(work, items, init, (ct, cribs), chunk=ch, procs=PROCS):
            cnt.update(c)
            hits.extend(h)
    return cnt, hits


def read_score(pt, big):
    """(big-model score per quadgram, number of quadgrams) over fully forced quadgrams that are not
    wholly inside the clues."""
    q = [pt[i:i + 4] for i in range(len(pt) - 3)
         if "?" not in pt[i:i + 4] and not all(j in CLUE for j in range(i, i + 4))]
    return (sum(big.logp.get(x, big.floor) for x in q) / len(q) if q else -99.0), len(q)


def judge(hits, ct, cribs, big):
    """One line per surviving setting: its best reading. Returns (rows, number that cannot be listed)."""
    rows, unlisted = [], Counter()
    for h in hits:
        if not h[5]:
            unlisted["%s / %s" % (h[0].split(",")[0], h[2])] += 1
            continue
        best = None
        for pt, X, E in H.readings(h, ct, cribs):
            sc, nq = read_score(pt, big)
            key = (nq >= MIN_Q, sc if nq >= MIN_Q else nq)
            if best is None or key > best[0]:
                best = (key, sc, nq, pt, X, E)
        word = h[3] if h[2] != "run" else h[3][0]
        rows.append({"model": h[0], "key_values": h[1], "kind": h[2], "key": word, "phase": h[4],
                     "solutions": len(h[5]), "status": h[6], "score": round(best[1], 3), "quadgrams": best[2],
                     "reading": best[3], "X": best[4], "E": best[5]})
    rows.sort(key=lambda r: (r["quadgrams"] >= MIN_Q, r["score"]), reverse=True)
    return rows, unlisted


def summary(rows, unlisted, cnt):
    judged = [r for r in rows if r["quadgrams"] >= MIN_Q]
    by = Counter("%s / %s" % (r["model"].split(",")[0], r["kind"]) for r in rows)
    return {"tested": cnt["tested"], "streams": cnt["streams"], "survivors": len(rows),
            "undecided": dict(sorted(unlisted.items())), "by_model": dict(sorted(by.items())),
            "judged": len(judged), "english": sum(r["score"] > ENGLISH for r in judged),
            "best": judged[0]["score"] if judged else None, "best_quadgrams": judged[0]["quadgrams"] if judged else 0,
            "systems_solved": sum(v for k, v in cnt.items() if k[0] == "solved")}


# ---------------------------------------------------------------- planted answers

PLANTS = [  # (model name, key values, kind, key)
    ("Quagmire III, C = P + K", None, "R", "SCULPTURE"),
    ("Quagmire III, C = K - P", None, "R", "UNDERGROUNDTRANSMISSIONS"),
    ("one hidden alphabet, C = P + k", "AZ", "S", "KRYPTOS"),
    ("Quagmire III, C = P - K", None, "S", "ILLUSION"),
    ("Quagmire III, C = P + K", None, "G", "ABSCISSA"),
    ("Quagmire II, plain on KR", None, "R", "PALIMPSEST"),
    ("one hidden alphabet, C = k - P", "KR", "R", "SHADOW"),
    ("hidden plain alphabet, cipher on AZ, P = C + k", "AZ", "G-", "BERLIN"),
    ("Quagmire III, C = K - P", None, "run", None),
]


def plant(rng, name, vn, kind, word, streams):
    """A 97-letter English message that carries the real clue words, under a random 26-letter alphabet."""
    m = H.model_by_name(name)
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    pt = "".join(pt)
    alpha = "".join(rng.sample(AZ, 26))
    E = rng.randrange(1, 26)
    if kind == "run":
        long = [x for x in streams if len(x[1]) >= 400]
        tag, s = long[rng.randrange(len(long))]
        t = s[1::3] if len(s) >= 3 * 120 else s
        word, phi = t, rng.randrange(0, len(t) - 97)
    else:
        phi = rng.randrange(len(word))
    ct = H.encrypt(m, kind, word, phi, H.VAL[vn] if vn else None, alpha, E, pt)
    return ct, pt, alpha, word, phi


def same_alphabet(X, alpha):
    """Recovered positions equal the true ones up to sliding / decimating the whole alphabet."""
    true = {c: i for i, c in enumerate(alpha)}
    return any(all((u * true[c] + t) % 26 == v for c, v in X.items()) for u in H.UNITS for t in range(26))


def planted_case(rng, spec, words, streams, big):
    name, vn, kind, word = spec
    ct, pt, alpha, word, phi = plant(rng, name, vn, kind, word, streams)
    cribs = {i: pt[i] for i in CRIBS}
    if kind == "run":
        cnt, hits = search(ct, cribs, [], [("planted stream", word)])
        mine = [h for h in hits if h[0] == name and h[2] == "run" and h[3][1][h[4] + 21:h[4] + 74] == word[phi + 21:phi + 74]]
        label = "a reading of the sculpture, 97 letters from offset %d" % phi
    else:
        cnt, hits = search(ct, cribs, words + [word], [], chunk=100)
        mine = [h for h in hits if h[:5] == (name, vn, kind, word, phi)]
        label = word
    rows, _ = judge(mine, ct, cribs, big)
    ok, right, sc = False, 0, None
    for h in mine:
        for rd, X, E in H.readings(h, ct, cribs):
            good = sum(a == b for a, b in zip(rd, pt))
            wrong = sum(a != b and a != "?" for a, b in zip(rd, pt))
            if not wrong and good >= 60 and same_alphabet(X, alpha) and good > right:
                ok, right = True, good
                sc = read_score(rd, big)[0]
    print("planted %-48s %-3s key %-28s -> found=%s, %d/97 letters read, English %s, alphabet recovered=%s, "
          "other survivors %d" % (name, kind, label[:28], bool(mine), right, None if sc is None else round(sc, 2), ok,
                                  len(hits) - len(mine)))
    return ok


if __name__ == "__main__":
    t0 = time.time()
    words = vocabulary()
    streams = sculpture_streams()
    if SMOKE:
        words, streams = words[::400], streams[::12]
    if os.environ.get("IDEA93_SLICE"):          # timing runs only
        k = int(os.environ["IDEA93_SLICE"])
        words, streams = words[::k], streams[::k]
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    with Experiment("word keys and sculpture readings on a fully hidden tableau (exact, distinct positions)",
                    puzzle="k4", cribs_forced=True,
                    notes="%d words x every phase x repeating/sliding/progressive, %d sculpture readings x skips 1-%d as "
                          "running keys; one hidden alphabet with numeric key, true Quagmire III and II, hidden "
                          "alphabet on one side" % (len(words), len(streams), MAX_SKIP)) as ex:
        cnt, hits = search(K4, CRIBS, words, streams)
        rows, unlisted = judge(hits, K4, CRIBS, big)
        k4 = summary(rows, unlisted, cnt)
        ex.count(cnt["tested"])
        print("K4: %s  (%.1f min)" % (json.dumps(k4), (time.time() - t0) / 60))
        for r in rows[:12]:
            cov = word_coverage(r["reading"].replace("?", ""))
            print("   %6.2f over %2d quadgrams, word cover %.2f  %s | %s%s %s key %s phase %d (%d solutions, %s)\n"
                  "          %s" % (r["score"], r["quadgrams"], cov, r["model"], r["key_values"] or "", "", r["kind"],
                                    r["key"][:60], r["phase"], r["solutions"], r["status"], r["reading"]))
            ex.add(r["reading"].replace("?", "X"), english_big=r["score"], model=r["model"], kind=r["kind"],
                   key=r["key"][:60], phase=r["phase"], key_values=r["key_values"])
        ctrl = []
        nctrl = 1 if SMOKE else 3
        for s in range(nctrl):
            sct = shuffled_control(9300 + s)
            ccnt, chits = search(sct, CRIBS, words[s::nctrl], streams)
            crows, cun = judge(chits, sct, CRIBS, big)
            ctrl.append(summary(crows, cun, ccnt))
            print("shuffled K4 #%d (words %d::%d, all streams): %s  (%.1f min)"
                  % (s + 1, s, nctrl, json.dumps(ctrl[-1]), (time.time() - t0) / 60))
            for r in crows[:3]:
                print("   %6.2f over %2d quadgrams  %s %s key %s" % (r["score"], r["quadgrams"], r["model"], r["kind"], r["key"][:40]))
        rng = random.Random(93)
        decoys = random.Random(5).sample(words, min(len(words), 300 if SMOKE else 2000))
        ok = sum(planted_case(rng, spec, decoys, streams, big) for spec in PLANTS)
        print("planted recovered: %d/%d" % (ok, len(PLANTS)))
        cbest = [c["best"] for c in ctrl if c["best"] is not None]
        signal = k4["english"] > 0 and (not cbest or k4["best"] > max(cbest) + 0.3)
        verdict = ("K4 has a survivor that reads better than every control - inspect by eye" if signal else
                   "no word key or sculpture reading fits a hidden tableau: %d survivors, %d readable as English "
                   "(controls: %s survivors, %s English)" % (k4["survivors"], k4["english"],
                                                             [c["survivors"] for c in ctrl], [c["english"] for c in ctrl]))
        print("RESULT " + json.dumps({"k4": k4, "controls": ctrl, "planted": "%d/%d" % (ok, len(PLANTS)),
                                      "minutes": round((time.time() - t0) / 60, 1)}))
        print("VERDICT:", verdict)
        ex.notes += "; " + verdict + "; planted %d/%d" % (ok, len(PLANTS))
