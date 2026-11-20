"""Idea 158: a recited list as the key.

Scheidt: the method is simple, can be remembered and run years later. The longest keys anyone carries in the
head are recited lists: ONE TWO THREE ..., NORTH NORTH-BY-EAST NORTH-NORTH-EAST ... (EASTNORTHEAST is itself a
point of that list), the hours, the months, the planets that turn on top of the World Clock, EINS ZWEI DREI.
Earlier text keys were sculpture texts, single words, or unknown English judged by a score. No named list was
ever run as an exact key.

Keys (kryptos/idea158_lists.py, all built in code): number words and ordinals in English and German (0-120,
short rounds such as 1-12 and 1-24, evens, odds, fives, tens; up and down), the 32/16/8/4 compass points in
both turning directions (long and short, English and German), hours and clock phrases, Roman numerals,
months, days, planets, zodiac, NATO / Able-Baker / Greek letter names, the alphabet, and the World Clock's
city ring facet by facet (data/weltzeituhr_1989.json). German is written both ways (FUENF, FUNF). Each list
is used at EVERY start letter as a running key, forwards and with its letters reversed.

Tests, all exact on the 24 clue letters
  1 gate     any tableau with distinct rows and columns: R->P at letters 28 and 66 needs the same key letter
             there, and 22 other pairs (EAST/EAST with different cipher letters, and so on) need different
             ones. Free, and it holds for every tableau at once.
  2 join     666,993 keyword tableaux (A-Z, KRYPTOS, dictionary words, transposition-mixed) x 5 layouts x
             Vigenere / Beaufort / variant (and Beaufort with the key negated) x key letter valued on A-Z,
             KRYPTOS or the tableau's own alphabet x all 26 shifts: 24 of 24 or nothing (hash join).
  3 hidden   one fully hidden alphabet (idea 93's models: numeric key, true Quagmire III and II, hidden
             alphabet on one side): 24 linear equations mod 26, a solution with distinct places required.
  4 near     how close any list comes on plain A-Z / KRYPTOS tableaux (most clue letters right at once, any
             shift), to compare K4 with shuffled K4s even when nothing passes.
A hit would be decrypted over all 97 letters and scored on the big English model and word coverage.
Controls: the same on 20 shuffled K4s. Planted: 5 messages, one keyed by the boxed compass from ENE on a
dictionary tableau and one by the same key on a hidden alphabet.

  python attacks/158_recited_list_keys.py
"""
import json
import os
import random
import sys
import time
from collections import Counter
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea158_lists as L  # noqa: E402
from kryptos import idea93_hidden as H  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA158_PROCS", "4" if SMOKE else "16"))
NCTRL = 3 if SMOKE else 20
ENGLISH = -5.1          # big-model score per quadgram that English reaches (planted readings: about -4.3)
CLUE = set(CRIBS)
G = {}


# ---------------------------------------------------------------- one ciphertext: gate, near misses, hidden alphabet

def hidden_scan(strs, ct, cribs):
    """Idea 93's scan with every list as a running key. Returns (offsets, hits, systems solved); a hit is
    (model, key valuation, stream index, start, solutions, status). Only starts inside the list count."""
    T = H.Tables(ct, cribs)
    cnt, out, n = Counter(), [], 0
    for si, (_, t) in enumerate(strs):
        hits = []
        H.scan_stream(T, t, cnt, hits, si)
        n += len(t) - L.SPAN + 1
        for name, vn, _, _, phi, sols, status in hits:
            if 0 <= phi <= len(t) - L.SPAN:
                out.append((name, vn, si, phi, sols, status))
    return n, out, sum(v for k, v in cnt.items() if k[0] == "solved")


def light(job):
    """Everything for one ciphertext except the dictionary join."""
    ct, cribs, strs, near = job
    wins, counts = L.gated_windows(strs, ct, cribs)
    out = {"gate": counts, "distinct": len({w[2] for w in wins})}
    if near:
        best, hist, ex = L.near_miss(strs, ct, cribs)
        out["near"] = (best, sorted(hist.items())[-4:], ex)
    out["hidden"] = hidden_scan(strs, ct, cribs)
    return out


def init_join(indexes, cts, cribs):
    G["ix"], G["cts"], G["cribs"] = indexes, cts, cribs


def work_join(alphabets):
    return len(alphabets), L.join(G["ix"], G["cts"], G["cribs"], alphabets)


def run_join(strs, cts, cribs, alphabets, procs=PROCS):
    indexes = [L.build_index(L.gated_windows(strs, ct, cribs)[0]) for ct in cts]
    hits = []
    if procs == 1:
        return L.join(indexes, cts, cribs, alphabets)
    for _, h in pmap(work_join, alphabets, init_join, (indexes, cts, cribs), chunk=2000, procs=procs):
        hits.extend(h)
    return hits


# ---------------------------------------------------------------- reading a hit

def read_score(pt, big):
    """(big-model score per quadgram, number of quadgrams) over known quadgrams not wholly inside the clues."""
    q = [pt[i:i + 4] for i in range(len(pt) - 3)
         if "?" not in pt[i:i + 4] and not all(j in CLUE for j in range(i, i + 4))]
    return (sum(big.logp.get(x, big.floor) for x in q) / len(q) if q else -99.0), len(q)


def read_tableau(hit, ct, strs):
    _, name, m, lay, form, sign, kn, shift, si, s = hit
    return L.decrypt(ct, strs[si][1][s:s + L.SPAN], m, lay, form, sign, kn, shift)


def read_hidden(hit, ct, cribs, strs):
    """[(reading with '?', positions)] for a hidden-alphabet hit."""
    name, vn, si, phi, sols, status = hit
    return [(pt, X) for pt, X, _ in H.readings((name, vn, "run", (si, strs[si][1]), phi, sols, status), ct, cribs)]


def describe(hit, strs):
    _, name, m, lay, form, sign, kn, shift, si, s = hit
    f = {("vig", 1): "Vigenere", ("vig", -1): "variant", ("beau", 1): "Beaufort", ("beau", -1): "Beaufort, key negated"}
    return "%s from letter %d | alphabet %s (%s), %s, %s, key valued on %s, shift %d" % (
        strs[si][0], s, name, m, lay, f[form, sign], kn, shift)


def judge(ct, cribs, strs, thits, hhits, big):
    """Best readings of every hit: [(score, quadgrams, word cover, reading, what)], best first."""
    rows = []
    for h in thits:
        pt = read_tableau(h, ct, strs)
        assert all(pt[i] == c for i, c in cribs.items()), h
        sc, nq = read_score(pt, big)
        rows.append((sc, nq, word_coverage(pt), pt, describe(h, strs)))
    for h in hhits:
        if not h[4]:
            continue
        best = max(read_hidden(h, ct, cribs, strs), key=lambda r: read_score(r[0], big))
        sc, nq = read_score(best[0], big)
        rows.append((sc, nq, word_coverage(best[0].replace("?", "")), best[0],
                     "%s from letter %d | hidden alphabet, %s%s" % (strs[h[2]][0], h[3], h[0],
                                                                  ", key on " + h[1] if h[1] else "")))
    rows.sort(key=lambda r: (r[1] >= 15, r[0]), reverse=True)
    return rows


# ---------------------------------------------------------------- planted answers

def start_of(strs, name, word):
    """(stream index, first start where `word` begins) in the stream called `name`."""
    si = next(i for i, (n, _) in enumerate(strs) if n == name)
    return si, strs[si][1].index(word)


def planted_text(rng):
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


def plants(strs, alphabets, rng):
    """[(label, ct, pt, kind, truth)]. kind 'tableau': truth = the hit tuple's tail; 'hidden': (model, vn, si, s)."""
    out = []
    pick = [a for a in alphabets if a[1] != AZ and len(a[0]) >= 6]

    def tab(label, name, word, alph, lay, form, sign, kn, shift):
        pt = planted_text(rng)
        si, s = start_of(strs, name, word)
        ct = L.encrypt(pt, strs[si][1][s:s + L.SPAN], alph[1], lay, form, sign, kn, shift)
        out.append((label, ct, pt, "tableau", (alph[1], lay, form, sign, kn, shift, si, s)))

    def hid(label, name, word, model, vn):
        pt = planted_text(rng)
        si, s = start_of(strs, name, word)
        alpha = "".join(rng.sample(AZ, 26))
        ct = H.encrypt(H.model_by_name(model), "run", strs[si][1], s, H.VAL[vn] if vn else None, alpha,
                       rng.randrange(1, 26), pt)
        out.append((label, ct, pt, "hidden", (model, vn, si, s, alpha)))

    a1, a2 = rng.choice(pick), rng.choice(pick)
    tab("boxed compass from ENE, Quagmire III on dictionary alphabet %s" % a1[0],
        "compass 32 points, English long", "EASTNORTHEASTEASTBYNORTH", a1, "M/M", "vig", 1, "M", 0)
    hid("boxed compass from ENE, hidden alphabet (Quagmire III)",
        "compass 32 points, English long", "EASTNORTHEASTEASTBYNORTH", "Quagmire III, C = P + K", None)
    tab("EINS ZWEI DREI ..., Beaufort on the KRYPTOS tableau, key on A-Z, shift 3",
        "German numbers 0-120", "EINSZWEI", ("KRYPTOS", L.KRYPTOS_ALPHABET), "M/M", "beau", 1, "AZ", 3)
    tab("months with letters reversed, variant on alphabet %s, key on KRYPTOS, shift 11" % a2[0],
        "months, letters reversed", "REBOTCO", a2, "AZ/M", "vig", -1, "KR", 11)
    hid("World Clock ring from BERLIN, hidden alphabet, key valued on A-Z",
        "World Clock ring, best 1989 state, all plates", "BERLIN", "one hidden alphabet, C = P + k", "AZ")
    return out


def same_alphabet(X, alpha):
    true = {c: i for i, c in enumerate(alpha)}
    return any(all((u * true[c] + t) % 26 == v for c, v in X.items()) for u in H.UNITS for t in range(26))


def planted_case(job):
    label, ct, pt, kind, truth, strs, alphabets = job
    cribs = {i: pt[i] for i in CRIBS}
    if kind == "tableau":
        hits = run_join(strs, [ct], cribs, alphabets, procs=1)
        mine = [h for h in hits if h[2:] == truth]
        ok = bool(mine) and read_tableau(mine[0], ct, strs) == pt
        return label, ok, "%d hits in all, true setting %s, all 97 letters read back %s" % (
            len({h[2:] for h in hits}), bool(mine), ok)
    model, vn, si, s, alpha = truth
    n, hits, _ = hidden_scan(strs, ct, cribs)
    mine = [h for h in hits if h[:4] == (model, vn, si, s)]
    right, ok = 0, False
    for h in mine:
        for rd, X in read_hidden(h, ct, cribs, strs):
            good = sum(a == b for a, b in zip(rd, pt))
            if all(a == b or a == "?" for a, b in zip(rd, pt)) and good >= 60 and same_alphabet(X, alpha):
                ok, right = True, max(right, good)
    return label, ok, "%d survivors in all over %d starts, true setting %s, %d/97 letters read back" % (
        len(hits), n, bool(mine), right)


def run_planted(strs, alphabets, pool, seed=158):
    rng = random.Random(seed)
    sample = rng.sample(alphabets, min(len(alphabets), 3000))
    jobs = []
    for label, ct, pt, kind, truth in plants(strs, sample, rng):
        al = sample
        if kind == "tableau" and not any(a[1] == truth[0] for a in al):
            al = sample + [("planted", truth[0])]
        jobs.append((label, ct, pt, kind, truth, strs, al))
    return pool.map(planted_case, jobs, chunksize=1)


# ---------------------------------------------------------------- main

if __name__ == "__main__":
    t0 = time.time()
    strs = L.streams(smoke=bool(SMOKE))
    full = L.streams()
    alphabets = dictionary_alphabets(mixed=True)
    nwin = L.n_windows(strs)
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    cts = [K4] + [shuffled_control(15800 + s) for s in range(NCTRL)]
    print("%d lists -> %d key texts, %d start letters; %d alphabets; %d ciphertexts (K4 + %d shuffled)"
          % (len(L.all_lists()), len(strs), nwin, len(alphabets), len(cts), NCTRL))
    with Experiment("recited lists (numbers, compass, hours, months, planets, letter names, World Clock ring) as "
                    "exact running keys", puzzle="k4", cribs_forced=True,
                    notes="%d key texts, %d starts; any-tableau gate; hash join on %d keyword alphabets x 5 "
                          "layouts x 4 forms x 3 key valuations x 26 shifts; one hidden alphabet (idea 93 models)"
                          % (len(strs), nwin, len(alphabets))) as ex:
        with Pool(PROCS) as pool:
            lights = pool.map(light, [(ct, CRIBS, strs, True) for ct in cts], chunksize=1)
            print("gate, near misses, hidden alphabet done (%.1f min)" % ((time.time() - t0) / 60))
            # the planted lists must be present even in the smoke slice
            planted = run_planted(full, alphabets, pool)
        for label, ok, note in planted:
            print("planted %-78s -> %s (%s)" % (label, "FOUND" if ok else "MISSED", note))
        nok = sum(p[1] for p in planted)
        print("planted recovered: %d/%d (%.1f min)" % (nok, len(planted), (time.time() - t0) / 60))

        hits = run_join(strs, cts, CRIBS, alphabets)
        print("dictionary join done (%.1f min)" % ((time.time() - t0) / 60))
        per = [[h for h in hits if h[0] == j] for j in range(len(cts))]
        per = [list({h[2:]: h for h in hs}.values()) for hs in per]        # the same tableau under two names

        res = []
        for j, ct in enumerate(cts):
            lt = lights[j]
            n, hh, solved = lt["hidden"]
            rows = judge(ct, CRIBS, strs, per[j], hh, big)
            judged = [r for r in rows if r[1] >= 15]
            res.append({"gate_all": lt["gate"][0], "gate_equal_ok": lt["gate"][1], "gate_pass": lt["gate"][2],
                        "gate_pass_distinct": lt["distinct"], "near_best": lt["near"][0],
                        "near_top": lt["near"][1], "tableau_hits": len(per[j]),
                        "hidden_survivors": sum(1 for h in hh if h[4]),
                        "hidden_undecided": sum(1 for h in hh if not h[4]), "hidden_systems_solved": solved,
                        "english": sum(r[0] > ENGLISH for r in judged),
                        "best": round(judged[0][0], 3) if judged else None})
            print("%-14s %s" % ("K4" if j == 0 else "shuffled #%d" % j, json.dumps(res[-1])))
            for r in rows[:5 if j == 0 else 2]:
                print("     %6.2f over %2d quadgrams, word cover %.2f  %s\n          %s" % (r[0], r[1], r[2], r[4], r[3]))
                if j == 0:
                    ex.add(r[3].replace("?", "X"), english_big=round(r[0], 3), setting=r[4][:100])
        k4, ctrl = res[0], res[1:]

        # K4's closest list on the plain tableaux, read in full (not a hit: for the record only)
        lay, form, sign, kn, shift, si, s = lights[0]["near"][2]
        near_pt = L.decrypt(K4, strs[si][1][s:s + L.SPAN], AZ, lay, form, sign, kn, shift)
        nright = sum(near_pt[i] == c for i, c in CRIBS.items())
        print("K4's closest list on A-Z/KRYPTOS tableaux: %d of 24 clue letters (%s from letter %d, %s %s sign %d, "
              "key on %s, shift %d), big model %.2f, word cover %.2f\n          %s"
              % (nright, strs[si][0], s, lay, form, sign, kn, shift, big.score(near_pt), word_coverage(near_pt),
                 near_pt))
        assert nright == k4["near_best"], (nright, k4["near_best"])
        ex.add(near_pt, note="closest list, not a hit", clue_letters=nright)

        joined = nwin * len(alphabets) * L.SETTINGS_PER_ALPHABET
        tested = joined + 25 * nwin + nwin
        ex.count(tested)
        cn = [c["near_best"] for c in ctrl]
        signal = (k4["english"] > 0 and all(c["best"] is None or k4["best"] > c["best"] + 0.3 for c in ctrl))
        verdict = ("K4 has a hit that reads better than every control - inspect by eye" if signal else
                   "no recited list fits: %d of %d starts pass the any-tableau gate, %d exact hits on keyword "
                   "tableaux, %d hidden-alphabet survivors, closest %d/24 (controls: hits %s, hidden %s, closest "
                   "%d-%d)" % (k4["gate_pass"], k4["gate_all"], k4["tableau_hits"], k4["hidden_survivors"],
                               k4["near_best"], sorted(Counter(c["tableau_hits"] for c in ctrl).items()),
                               sorted(Counter(c["hidden_survivors"] for c in ctrl).items()), min(cn), max(cn)))
        print("RESULT " + json.dumps({"k4": k4, "controls": ctrl, "planted": "%d/%d" % (nok, len(planted)),
                                      "tested": tested, "join_settings": joined, "key_texts": len(strs),
                                      "starts": nwin, "alphabets": len(alphabets),
                                      "minutes": round((time.time() - t0) / 60, 1)}))
        print("VERDICT:", verdict)
        ex.notes += "; " + verdict + "; planted %d/%d" % (nok, len(planted))
        if nok != len(planted):
            sys.exit("planted answers missed: the search proves nothing")
