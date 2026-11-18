"""Idea 125: misspelled keywords, and other ways to finish a keyword alphabet, through the whole
key-rule battery.

Sanborn misspells, on purpose and by accident: the K1 key header reads PALIMPCEST, the texts have
IQLUSION, UNDERGRUUND and DESPARATLY, and K2 lost a letter. A keyword alphabet built from a
misspelled word is in no dictionary, so every dictionary test would miss an otherwise ordinary
cipher. Idea 86 solved ANY keyword exactly, but only for repeating and sliding keys. The other key
rules (progressive, two stacked words, autokey, chain addition) were only ever run on dictionary
spellings, and always with the keyword first and the rest of the alphabet in A-Z order.

What this runs (helpers in kryptos/idea125_alphabets.py):

  part 1  every theme word and every one of the 22,000 common words, with every single spelling
          change (one letter replaced by any other, one dropped, one doubled, two neighbours
          swapped). Each gives its keyword alphabet and its two transposition-mixed forms.
          Alphabets already in the dictionary list are dropped: 8.1 million new ones.
  part 2  every vocabulary word (236k) with another way to build the alphabet: the rest in reverse
          order; the rest in A-Z order starting after the keyword's last letter; repeated letters
          kept at their LAST place; the keyword at the END; and the K1-K3 misspelling swaps (Q/L,
          U/O, A/E, C/S) applied to the finished keyword alphabet. 1.7 million new ones.

Both go through kryptos.idea120_layer.test_alphabet: repeating key 1-17, sliding 1-15, progressive
1-12, autokey lags 1-6 fed on M, chain addition, every stacked pair exactly, autokey numbered on
A-Z / KRYPTOS, progressive key moved on in another alphabet's order. Five layouts (M/M, M/AZ, AZ/M,
M/KR, KR/M), Vigenere and Beaufort, 7+ exact checks with the 24 clue letters forced.

  part 3  attack 63's exact hash join (Quagmire IV: plain alphabet, cipher alphabet, repeating key
          of length 1-20) with the part-2 alphabets added to the dictionary list on both sides; only
          pairs with at least one part-2 alphabet are new.

Survivors are read in full and scored on the big model and word coverage. Controls: 3 shuffled K4s,
each on a different slice of the part 1 + 2 alphabets (CTRL_SHARE), and the full join. Planted: six
messages (see PLANTS), each searched over the true alphabet plus a random sample, and the join
plant over the full join.

  python attacks/125_misspelled_keyword_alphabets.py            (--prefilter for the clue card)
"""
import collections
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea125_alphabets as A  # noqa: E402
from kryptos import idea120_layer as L  # noqa: E402
from kryptos import idea104_holes as H  # noqa: E402
from kryptos.ciphers.substitution import AZ, KRYPTOS_ALPHABET as KR  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, english97  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1
CTRL_SHARE = 3 if SMOKE else 6       # each control runs on every CTRL_SHARE-th new alphabet
SAMPLE = 300 if SMOKE else 3000      # decoy alphabets in each planted search
LAYS = ("M/M", "M/AZ", "AZ/M", "M/KR", "KR/M")


def log(*a):
    print(*a, flush=True)


def with_clues(pt):
    return pt[:21] + "EASTNORTHEAST" + pt[34:63] + "BERLINCLOCK" + pt[74:]


def describe(h):
    return "%d checks: %s %s %s, %s [%s]" % (h[0], h[1], h[2], h[3], h[4], h[5])


def readings(hits, by_name, ct, cribs, big, limit=400):
    out = []
    for h in sorted(hits, reverse=True)[:limit]:
        pt = A.read(h, by_name[h[1]], ct, cribs)
        sc, nq = H.read_score(pt, big)
        out.append((sc, nq, pt, h))
    return sorted(out, key=lambda r: (-r[0], -r[3][0]))


# ------------------------------------------------------------------ planted answers

def plant(kind, rng, p1, p2, dic):
    """(ct, plaintext, (name, m), rule prefix, layout, form)."""
    lay, form = rng.choice(LAYS), rng.choice(("vig", "beau"))
    pt = with_clues(english97(rng))
    n = len(pt)
    if kind == "sliding on PALIMPCEST":
        name, m = "PALIMPCEST", keyword_alphabet("PALIMPCEST")
        p, w, acc, key = 7, [rng.randrange(26) for _ in range(7)], rng.randrange(26), []
        for i in range(n):
            key.append(acc)
            acc = (acc + w[i % p]) % 26
        rule = "sliding p=%d" % p
    elif kind == "progressive on DESPARATLY":
        name, m = "DESPARATLY", keyword_alphabet("DESPARATLY")
        p, s = 8, rng.randrange(1, 26)
        w = [rng.randrange(26) for _ in range(p)]
        key = [(w[i % p] + s * (i // p)) % 26 for i in range(n)]
        rule = "progressive p=%d step=%d" % (p, s)
    elif kind == "plain autokey on KRYPTOS reversed tail":
        name, m = "KRYPTOS@rev", A.construct("KRYPTOS", "rev")
        lag, sg = rng.randrange(1, 7), rng.choice((1, -1))
        key = ("autokey", "plain", lag, sg, rng.randrange(26), [rng.randrange(26) for _ in range(lag)])
        rule = "autokey plain lag=%d sign=%+d" % (lag, sg)
    elif kind == "stacked pair on a wrap-tail alphabet":
        name, m = rng.choice([a for a in p2 if a[0].endswith("@wrap")])
        p, q = rng.choice(((4, 11), (5, 9), (5, 12), (6, 11), (3, 13)))
        a, b = [rng.randrange(26) for _ in range(p)], [rng.randrange(26) for _ in range(q)]
        key = [(a[i % p] + b[i % q]) % 26 for i in range(n)]
        rule = "two stacked keys p=%d q=%d" % (p, q)
    elif kind == "repeating 17 on a misspelt word":
        name, m = rng.choice([x for x in p1 if "~" not in x[0]])
        w = [rng.randrange(26) for _ in range(17)]
        key = [w[i % 17] for i in range(n)]
        rule = "repeating p=17"
    else:
        raise ValueError(kind)
    ct = L.layer2_encrypt(pt, m, lay, form, key)
    return ct, pt, (name, m), rule, lay, form


PLANTS = ("sliding on PALIMPCEST", "progressive on DESPARATLY", "plain autokey on KRYPTOS reversed tail",
          "stacked pair on a wrap-tail alphabet", "repeating 17 on a misspelt word")


def run_plants(rng, p1, p2, dic, big):
    pool = p1 + p2 + dic
    ok = 0
    for kind in PLANTS:
        ct, pt, (name, m), rule, lay, form = plant(kind, rng, p1, p2, dic)
        alphas = [a for a in rng.sample(pool, SAMPLE) if a[1] != m] + [(name, m)]
        by = dict(alphas)
        t0 = time.time()
        h = A.battery_search(ct, CRIBS, alphas, chunk=max(20, len(alphas) // 28))
        mine = [x for x in h if x[1] == name and x[2] == lay and x[3] == form and x[4].startswith(rule)]
        texts = {A.read(x, by[x[1]], ct, CRIBS) for x in h}
        wrong = [t for t in texts if any(a != "?" and a != b for a, b in zip(t, pt))]
        strays = [x for x in h if x[1] != name]
        good, right, sc = False, 0, -99.0
        if mine:
            text = A.read(mine[0], m, ct, CRIBS)
            right = sum(a == b for a, b in zip(text, pt))
            sc, _ = H.read_score(text, big)
            # sister settings on the true alphabet (nested key lengths) may extrapolate differently where
            # their own key is less fixed; they must have fewer checks than the true setting
            top = max(x[0] for x in h)
            good = right == 97 and not strays and \
                all(x[0] < top for x in h if any(a != "?" and a != b for a, b in zip(A.read(x, by[x[1]], ct, CRIBS), pt)))
        log("planted %-40s on %s %s %s %s -> %s; %d settings pass over %d alphabets (%d distinct readings, %d with a "
            "wrong letter, %d on another alphabet); read back %d/97, english %.2f; %.0f s"
            % (kind, name, lay, form, rule, "FOUND, only true reading" if good else ("NOT CLEAN" if mine else "MISSED"),
               len(h), len(alphas), len(texts), len(wrong), len(strays), right, sc, time.time() - t0))
        for x in h[:5]:
            log("      " + describe(x))
        ok += good
    return ok, len(PLANTS)


def join_plant(rng, dic, p2):
    """Quagmire IV: plain alphabet from part 2, cipher alphabet from the dictionary list, key of 14."""
    pt = with_clues(english97(rng))
    ia = rng.randrange(len(p2))
    ib = rng.randrange(1, len(dic))
    form = rng.choice(("vig", "beau"))
    key = [rng.randrange(26) for _ in range(14)]
    ct = A.quag4_encrypt(pt, p2[ia][1], dic[ib][1], key, form)
    return ct, pt, (len(dic) + ia, ib, form, 14)


def prefilter_encrypt(pt, rng):
    """For the clue pre-filter: a common word with one letter changed, its keyword alphabet, a
    progressive key of 3-12 letters on M/M; everything from rng."""
    from kryptos import wordkeys
    w = rng.choice(wordkeys.common_words()[:5000])
    w = rng.choice(A.edits(w) or [w])
    m = keyword_alphabet(w)
    p, s = rng.randrange(3, 13), rng.randrange(1, 26)
    k = [rng.randrange(26) for _ in range(p)]
    return L.layer2_encrypt(pt, m, "M/M", "vig", [(k[i % p] + s * (i // p)) % 26 for i in range(len(pt))])


# ------------------------------------------------------------------ main

if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("misspelled-keyword alphabet with the key-rule battery", encrypt=prefilter_encrypt)
        sys.exit(0)
    t_all = time.time()
    dic, p1, p2 = A.all_lists(2000 if SMOKE else None)
    new = p1 + p2
    by_name = dict(dic + new)
    chance = L.chance_per_alphabet()
    PLANTS_ONLY = "--plants-only" in sys.argv     # rerun of the planted checks alone (same seed, same plants, no ledger line)

    class _NoLog:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def count(self, n=1):
            pass

        def add(self, *a, **k):
            pass
    with ((lambda *a, **k: _NoLog()) if PLANTS_ONLY else Experiment)("misspelled keywords (one change, 22k common + theme words) and other alphabet constructions "
                    "(reverse/wrap tail, last-place repeats, keyword at end, K1-K3 swaps) through the key-rule battery "
                    "+ Quagmire IV join", puzzle="k4",
                    notes="part 1 %d alphabets, part 2 %d (after dropping %d dictionary alphabets and duplicates); "
                          "idea-120 battery (round-11 + idea-104 fixes), 5 layouts, vig/beau, 7+ checks; join of part 2 "
                          "against the dictionary list, key 1-%d; 3 shuffled K4s on a 1/%d slice each and the full join"
                          % (len(p1), len(p2), len(dic), A.MAX_P, CTRL_SHARE), cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        log("alphabets: dictionary list %d; part 1 (misspellings) %d new; part 2 (other constructions) %d new; %.0f s"
            % (len(dic), len(p1), len(p2), time.time() - t_all))
        log("   part 2 by construction: %s" % dict(collections.Counter(n.split("@")[1] for n, _ in p2)))
        log("chance passes with 7+ checks: %.3g per alphabet, %.3f expected over the %d new alphabets"
            % (chance, chance * len(new), len(new)))

        rng = random.Random(125)
        ok, nplants = run_plants(rng, p1, p2, dic, big)
        log("planted (battery) recovered: %d/%d" % (ok, nplants))

        # K4, battery
        t0 = time.time()
        hits = []
        for label, lst in () if PLANTS_ONLY else (("part 1", p1), ("part 2", p2)):
            t1 = time.time()
            h = A.battery_search(K4, CRIBS, lst, progress=lambda d: log("   ... %d alphabets, %.0f s" % (d, time.time() - t1)))
            log("K4 %s: %d alphabets, %d pass with 7+ checks (%d with 8+), chance %.2f; %.0f s"
                % (label, len(lst), len(h), sum(x[0] >= 8 for x in h), chance * len(lst), time.time() - t1))
            hits += h
        ex.count(len(new))
        log("   by rule and checks: %s" % dict(collections.Counter((x[4].split()[0], x[0]) for x in hits)))
        done = readings(hits, by_name, K4, CRIBS, big)
        for r in done[:30]:
            log("   english %.2f over %d new quadgrams, words %.2f; %s\n      %s"
                % (r[0], r[1], word_coverage(r[2].replace("?", "")), describe(r[3]), r[2]))
            ex.add(r[2].replace("?", "X"), english_big=round(r[0], 3), setting=describe(r[3]))
        k4_best = max((r[0] for r in done), default=-99.0)
        log("K4 battery: %d passes in %d alphabets (chance %.2f); best reading %.2f (English needs %.1f; -99 = nothing)"
            % (len(hits), len(new), chance * len(new), k4_best, ENGLISH))

        ctrl = []
        for seed in () if PLANTS_ONLY else (1, 2, 3):
            sct = shuffled_control(seed)
            t1 = time.time()
            sl = new[seed - 1::CTRL_SHARE]
            ch = A.battery_search(sct, CRIBS, sl)
            cd = readings(ch, by_name, sct, CRIBS, big)
            cb = max((r[0] for r in cd), default=-99.0)
            log("shuffled K4 seed %d: %d alphabets, %d pass with 7+ (%d with 8+), chance %.2f, best reading %.2f; %.0f s"
                % (seed, len(sl), len(ch), sum(x[0] >= 8 for x in ch), chance * len(sl), cb, time.time() - t1))
            for r in cd[:3]:
                log("      english %.2f; %s" % (r[0], describe(r[3])))
            ctrl.append((len(ch), len(sl), cb))

        # part 3: Quagmire IV join
        t1 = time.time()
        jct, jpt, jwant = join_plant(rng, dic, p2)
        alphas = [m for _, m in dic + p2]
        names = [n for n, _ in dic + p2]
        cts = ([] if PLANTS_ONLY else [("K4", K4)] + [("shuffled %d" % s, shuffled_control(s)) for s in (1, 2, 3)]) + \
            [("planted", jct)]
        if PLANTS_ONLY:
            log("planted (join): see below")
        jres = A.join_search(CRIBS, cts, alphas, len(dic), procs=7)
        npairs = 2 * (len(alphas) ** 2 - len(dic) ** 2)
        log("join: %d alphabets per side (%d dictionary + %d part 2), %.3g new (pair, form) per key length; %.0f s"
            % (len(alphas), len(dic), len(p2), npairs, time.time() - t1))
        jbest = {}
        jplant_ok = False
        for label, ct in cts:
            res = jres[label]
            tot, best, rows = 0, (-99.0, None), []
            for p in sorted(res):
                cnt, got = res[p]
                tot += cnt
                for form, a, b in got:
                    pt = A.join_decrypt(ct, CRIBS, p, form, alphas[a], alphas[b])
                    sc, nq = H.read_score(pt, big)
                    rows.append((sc, nq, p, form, names[a], names[b], pt, (a, b)))
            rows.sort(reverse=True)
            chk = {p: 24 - len({i % p for i in POS}) for p in res}
            log("join %s: %d matches; by key length (count / chance): %s" % (
                label, tot, ", ".join("%d: %d/%.2g" % (p, res[p][0], npairs * 26.0 ** -chk[p]) for p in sorted(res) if res[p][0] or p >= 13)))
            for r in rows[:5 if label != "K4" else 15]:
                log("      english %.2f over %d, p=%d %s plain %s / cipher %s\n         %s" % r[:7])
            jbest[label] = rows[0][0] if rows else -99.0
            if label == "K4":
                ex.count(npairs * A.MAX_P)
                for r in rows[:10]:
                    ex.add(r[6].replace("?", "X"), english_big=round(r[0], 3), setting="quag4 p=%d %s %s/%s" % (r[2], r[3], r[4], r[5]))
            if label == "planted":
                a, b, form, p = jwant
                top = rows[0] if rows else None
                mine = [r for r in rows if r[7] == (a, b) and r[3] == form and r[2] == p]
                right = sum(x == y for x, y in zip(mine[0][6], jpt)) if mine else 0
                wrongs = [r for r in rows if any(x != "?" and x != y for x, y in zip(r[6], jpt))]
                # chance matches at 7-8 checks read differently; the true pair must read best by a margin
                jplant_ok = bool(mine) and top is not None and top[6] == mine[0][6] and \
                    (len(rows) < 2 or rows[1][0] < top[0] - 1.0 or rows[1][6] == top[6])
                log("join planted: plain %s / cipher %s %s key 14 -> %s; %d matches (%d with a wrong letter); read back %d/97"
                    % (names[a], names[b], form, "FOUND, best reading" if jplant_ok else "NOT CLEAN", len(rows),
                       len(wrongs), right))
        if PLANTS_ONLY:
            log("planted recovered: %d/%d" % (ok + jplant_ok, nplants + 1))
            sys.exit(0)
        log("join: K4 best %.2f; shuffled %s" % (jbest["K4"], ["%.2f" % jbest["shuffled %d" % s] for s in (1, 2, 3)]))
        ok_all = ok + jplant_ok
        log("planted recovered: %d/%d" % (ok_all, nplants + 1))

        rate = len(hits) / float(max(1, len(new)))
        more = all(rate * c[1] > c[0] + 3 * (c[0] ** 0.5) + 3 for c in ctrl)
        reads = k4_best > ENGLISH and k4_best > max(c[2] for c in ctrl) + 0.3
        jreads = jbest["K4"] > ENGLISH and jbest["K4"] > max(jbest["shuffled %d" % s] for s in (1, 2, 3)) + 0.3
        log("VERDICT:", ("K4 beats every control - inspect; " if (more or reads or jreads) else "no signal; ") +
            "battery: K4 %d passes in %d alphabets (chance %.2f), best reading %.2f; controls %s passes in %s alphabets, "
            "best %s; join K4 best %.2f; planted %d/%d; total %.0f s"
            % (len(hits), len(new), chance * len(new), k4_best, [c[0] for c in ctrl], [c[1] for c in ctrl],
               ["%.2f" % c[2] for c in ctrl], jbest["K4"], ok_all, nplants + 1, time.time() - t_all))
