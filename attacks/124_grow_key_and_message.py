"""Idea 124: a sentence key on a keyword tableau, judged by growing key and message together.

Ideas 57, 65 and 89 tested an English sentence used as the key on a keyword tableau by scoring
only the 13 + 11 key letters the clues force. That score is weak: the true key sat inside the
noise in 1 of 4 planted runs (idea 89's K3 + Z-A alphabet ranked 7th).

A true setting has a property noise should not copy. Move one letter past a clue block: some plain
letter there makes BOTH the message and the key continue as English, and that keeps happening
letter after letter, all the way across the 29 unknown letters to the next clue block. For a wrong
setting, making one string English makes the other one gibberish.

  Stage 1  as attack 57: for every alphabet M (666,993 dictionary keyword alphabets with their two
           transposition-mixed forms, plus idea 89's 140,752 non-keyword alphabets), five layouts
           (M/A-Z, A-Z/M, M/M, M/KRYPTOS, KRYPTOS/M), four forms (Vigenere, Beaufort, variant,
           reversed DIANA table) and 78 key readings (A-Z[s+c], M[s+c], KRYPTOS[s+c], c = 0..25),
           score the 24 forced key letters on the big English model. Keep the best 20,000.
  Stage 2  for each kept setting, a beam search over plain letters (each plain letter fixes the
           key letter there): from block 1 across the gap 34..62 into block 2. Score = quadgrams
           of the plain string + quadgrams of the key string, 24 clue letters fixed. First a
           narrow beam (width 20) on all 20,000, then a wide beam (width 300) on the best 200,
           which also grows 12 letters left of block 1 and 12 right of block 2.
           A setting "bridges" if over 21..73 (53 letters) the plain AND the key both score above
           -5.1 per quadgram. The ranking is by the joint score (plain + key).

Controls: three shuffled K4s (each on a different third of the alphabets, 20,000 kept), and K4
with the kept list replaced by 20,000 random settings (how much English the beam makes alone).
Planted: attack 57's four sentence keys, idea 89's 7th-ranked key, and a key of rare dictionary
words. Each plant is run on a pool of 20,000 alphabets that holds its true one.

  python attacks/124_grow_key_and_message.py
"""
import importlib.util
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, dictionary_alphabets, english97  # noqa: E402
from kryptos.score import word_coverage  # noqa: E402
from kryptos import idea89_orders as o  # noqa: E402
from kryptos import idea124_grow as G  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
KEEP = 1500 if SMOKE else 20000
POOL = 1500 if SMOKE else 20000
NARROW, WIDTH = 20, 300
WIDE = 30 if SMOKE else 200


def load_attack(name):
    spec = importlib.util.spec_from_file_location("a" + name[:2], sorted((ROOT / "attacks").glob(name))[0])
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def all_alphabets():
    dic = dictionary_alphabets(mixed=True)
    new, _ = o.new_alphabets()
    if SMOKE:
        dic, new = dic[:3000], new[:1000]
    return dic + new


def run(ct, cribs, alist, settings=None, extra=()):
    """Stage 1 (unless settings given) then the narrow and wide beams.
    extra: settings (ai, vi, rc) always carried into both beams (a plant's truth).
    Returns (stage-1 list, narrow results, wide results)."""
    if settings is None:
        s1 = G.stage1(ct, cribs, alist, KEEP)
        settings = [(r, a, v, c) for r, (_, a, v, c) in enumerate(s1)]
    else:
        s1 = None
    have = {x[1:] for x in settings}
    settings = settings + [(-1, a, v, c) for a, v, c in extra if (a, v, c) not in have]
    narrow = G.stage2(ct, cribs, alist, settings, NARROW, sides=False)
    top = [x[1:5] for x in narrow[:WIDE]]
    have = {x[1:] for x in top}
    top += [x[1:5] for x in narrow if x[2:5] in set(extra) and x[2:5] not in have]
    wide = G.stage2(ct, cribs, alist, top, WIDTH, sides=True)
    return s1, narrow, wide


def describe(alist, r):
    joint, tag, ai, vi, rc, res = r
    name, m, lay, form, read, off = G.setting(alist, ai, vi, rc)
    return "%.3f (plain %.3f, key %.3f, bridges %s) | %s %s %s %s+%d | stage-1 rank %s" % (
        joint, res["plain_bridge"], res["key_bridge"], res["bridges"], name, lay, form, read, off, tag)


def strings(r):
    res = r[5]
    return "plain %s (word cover %.2f)\n      key   %s (word cover %.2f)" % (
        res["plain"], word_coverage(res["plain"]), res["key"], word_coverage(res["key"]))


# ---------------------------------------------------------------- planted messages

def plants(alphas):
    """[(label, ct, pt, key, m, lay, form, read, off)]."""
    out = []
    a57 = load_attack("57_*.py")
    al57 = a57.alphabets(limit=3000 if SMOKE else None)
    rng = random.Random(9)
    for kind in ("Q3", "Q1", "Q3", "Q1"):
        ct, cribs, w, key = a57.plant(rng, al57, kind)
        m = keyword_alphabet(w)
        lay, read = ("Q3", "M") if kind == "Q3" else ("Q1", "AZ")
        pt = None
        kt = G.key_table(ct, m, lay, "vig", read, 0)
        # recover the plaintext from ct and key (the plant does not return it)
        pt = "".join(next(G.AZ[p] for p in range(26) if kt[i][p] == ord(key[i]) - 65) for i in range(97))
        assert all(pt[i] == cribs[i] for i in CRIBS)
        out.append(("attack 57 %s on %s" % (kind, w), ct, pt, key, m, lay, "vig", read, 0))
    # idea 89's planted sentence key that ranked 7th (replay its random stream)
    rng = random.Random(8900)
    m_k2 = o.fill(o.first_seen("ITWASTOTALLYINVISIBLE"))
    m_k3 = o.fill(o.first_seen("SLOWLYDESPARATLYSLOWLY"), o.ZA)
    morse = dict(o.fixed_orders())["morse by length, dot first"]
    o.plant_sliding(rng, m_k2, 7)
    o.plant_sliding(rng, morse, 9)
    ct, pt, key = o.plant_running_key(rng, m_k3)
    out.append(("idea 89 K3 opening + Z-A (ranked 7th there)", ct, pt, key, m_k3, "Q3", "vig", "M", 0))
    # a key made of rare dictionary words, on a dictionary tableau, an unusual layout and reading
    rng = random.Random(12400)
    common = set(wordkeys.common_words())
    rare = [w for w in wordkeys.big_dictionary() if 7 <= len(w) <= 12 and w not in common and w.isalpha()]
    key = ""
    while len(key) < 97:
        key += rng.choice(rare)
    key = key[:97]
    pt = english97(rng)
    name, m = rng.choice([a for a in alphas[1:3000] if "~" not in a[0]])
    ct = G.encrypt(pt, key, m, "Q4a", "beau", "KR", 5)
    out.append(("rare-word key on %s, M/KRYPTOS Beaufort, KRYPTOS+5" % name, ct, pt, key, m, "Q4a", "beau", "KR", 5))
    return out


def run_plant(p, alphas, rng):
    label, ct, pt, key, m, lay, form, read, off = p
    cribs = {i: pt[i] for i in CRIBS}
    pool = [("TRUE", m)] + rng.sample([a for a in alphas if a[1] != m], POOL - 1)
    vi, rc = G.code(lay, form, read, off)
    truth = (0, vi, rc)
    s1, narrow, wide = run(ct, cribs, pool, extra=[truth])
    true_frag = G.frag(ct, cribs, m, lay, form, read, off)
    true_s1 = G.qmean(G.nums(true_frag.replace("|", "")[:13])) * 10 / 18 + G.qmean(G.nums(true_frag[14:])) * 8 / 18
    r1 = next((i for i, x in enumerate(s1) if x[1:] == truth), None)
    rn = next(i for i, x in enumerate(narrow) if x[2:5] == truth)
    rw = next(i for i, x in enumerate(wide) if x[2:5] == truth)
    best = wide[0]
    top_ok = best[2:5] == truth or G.frag(ct, cribs, *G.setting(pool, *best[2:5])[1:]) == true_frag
    tw = wide[rw]
    return {"label": label, "s1_rank": r1, "s1_score": true_s1, "s1_cut": s1[-1][0], "narrow_rank": rn,
            "wide_rank": rw, "joint": tw[0], "bridges": tw[5]["bridges"], "top_ok": top_ok and tw[5]["bridges"],
            "noise_best": next((x[0] for x in wide if x[2:5] != truth), None), "row": tw, "pool": pool,
            "true_bridge": (G.qmean(G.nums(pt[21:74])), G.qmean(G.nums(key[21:74])))}


def thirds(alphas):
    """Matched comparison: K4 on each third of the alphabets, the same third its shuffled control used."""
    with Experiment("sentence key grown outward: K4 on the three alphabet thirds (matched to the controls)",
                    puzzle="k4", cribs_forced=True,
                    notes="K4 on alphas[j::3], j=0..2, same KEEP/beams as the shuffled controls") as ex:
        for j in range(3):
            sub = alphas[j::3]
            s1, nw, wd = run(K4, CRIBS, sub)
            ex.count(len(sub) * G.NV * G.NR)
            print("K4 third %d (as shuffled #%d): stage-1 best %.3f cut %.3f; narrow best %.3f, bridging %d; wide best %s" % (
                j + 1, j + 1, s1[0][0], s1[-1][0], nw[0][0], sum(x[5]["bridges"] for x in nw), describe(sub, wd[0])))
            print("     ", strings(wd[0]))
            ex.add("X" * 9 + wd[0][5]["plain"] + "X" * 11, setting=describe(sub, wd[0]), key=wd[0][5]["key"])


if __name__ == "__main__" and "--thirds" in sys.argv:
    thirds(all_alphabets())
elif __name__ == "__main__":
    t0 = time.time()
    alphas = all_alphabets()
    N = len(alphas)
    n1 = N * G.NV * G.NR
    with Experiment("sentence key on keyword tableaux grown outward from the clues (beam on plain + key)",
                    puzzle="k4", cribs_forced=True,
                    notes="%d alphabets (dictionary + mixed + idea 89 non-keyword) x 5 layouts x 4 forms x 78 key "
                          "readings; forced key letters scored, best %d kept; beam width %d then %d on the best %d: "
                          "plain+key quadgrams over 9..85, bridge 21..73 both > -5.1" % (N, KEEP, NARROW, WIDTH, WIDE)) as ex:
        print("alphabets: %d; stage-1 settings per text: %s" % (N, "{:,}".format(n1)))
        s1, narrow, wide = run(K4, CRIBS, alphas)
        ex.count(n1)
        print("K4 stage 1: best %.3f %s, cut (rank %d) %.3f   (%.0f s)" % (
            s1[0][0], G.frag(K4, CRIBS, *G.setting(alphas, *s1[0][1:])[1:]), KEEP, s1[-1][0], time.time() - t0))
        print("K4 narrow beam best %.3f; bridging settings (narrow): %d of %d" % (
            narrow[0][0], sum(x[5]["bridges"] for x in narrow), len(narrow)))
        print("K4 wide beam, best 5:")
        for r in wide[:5]:
            print("  ", describe(alphas, r))
            print("     ", strings(r))
            ex.add("X" * 9 + r[5]["plain"] + "X" * 11, setting=describe(alphas, r), key=r[5]["key"])
        k4_best = wide[0][0]

        ctrl = []
        for seed in (1, 2, 3):
            sub = alphas[seed - 1::3]
            c1, cn, cw = run(shuffled_control(seed), CRIBS, sub)
            ctrl.append(cw[0][0])
            print("shuffled K4 #%d (1/3 of alphabets): stage-1 best %.3f cut %.3f; narrow best %.3f, bridging %d; "
                  "wide best %s" % (seed, c1[0][0], c1[-1][0], cn[0][0], sum(x[5]["bridges"] for x in cn),
                                    describe(sub, cw[0])))
            print("     ", strings(cw[0]))
            ex.count(len(sub) * G.NV * G.NR)
        rng = random.Random(124)
        rand = [(-2, a, v, c) for a, v, c in G.random_settings(rng, N, KEEP)]
        _, rn_, rw = run(K4, CRIBS, alphas, settings=rand)
        print("K4 with %d random settings: narrow best %.3f, bridging %d; wide best %s" % (
            KEEP, rn_[0][0], sum(x[5]["bridges"] for x in rn_), describe(alphas, rw[0])))
        print("     ", strings(rw[0]))
        rand_best = rw[0][0]
        print("   (%.0f s so far)" % (time.time() - t0))

        noise = max(ctrl + [rand_best, k4_best])
        ok = 0
        pl = plants(alphas)
        prng = random.Random(1240)
        for p in pl:
            r = run_plant(p, alphas, prng)
            full_rank = sum(x[0] > r["s1_score"] for x in s1)
            beats = r["joint"] > noise
            ok += r["top_ok"]
            print("planted %s:\n   true key letters %.3f (pool rank %s, cut %.3f; would be K4-run rank %d of %d kept);"
                  " narrow rank %d, wide rank %d; true joint %.3f (bridges %s; the true texts over 21..73 score %.3f/%.3f);"
                  " best wrong setting %s; first and bridges: %s; beats every K4/control best (%.3f): %s" % (
                      r["label"], r["s1_score"], r["s1_rank"], r["s1_cut"], full_rank, KEEP, r["narrow_rank"],
                      r["wide_rank"], r["joint"], r["bridges"], r["true_bridge"][0], r["true_bridge"][1],
                      "%.3f" % r["noise_best"] if r["noise_best"] is not None else "-", r["top_ok"], noise, beats))
            print("     ", strings(r["row"]))
        print("\nplanted recovered (first and bridging in its pool): %d/%d" % (ok, len(pl)))
        print("K4 best joint %.3f vs shuffled %s, random settings %.3f" % (
            k4_best, ", ".join("%.3f" % c for c in ctrl), rand_best))
        print("VERDICT:", "K4 above every control - read it" if k4_best > max(ctrl + [rand_best]) else
              "no signal (K4 inside the controls)")
        print("total %.0f s" % (time.time() - t0))
