"""Idea 95: two rotors in series, one wired from a keyword, one hidden.

Idea 82 tried two rotors with both wirings hidden and found that 24 clue letters cannot judge
52 unknown contacts. Here one rotor is a strip anyone could rebuild from a keyword and only the
other is secret (the chart Sanborn changed). That version CAN be judged.

    Y = R1[P + s] - s        first rotor, fast turn s
    C = R2[Y + t] - t        second rotor, slow turn t

  form A   hidden rotor first, keyword rotor second
  form B   keyword rotor first, hidden rotor second

With one wiring known the middle letter Y is known at every clue letter, so each clue letter
gives one wire of the hidden rotor. A real wiring never sends one contact to two places or two
contacts to one place. 24 wires on 26 contacts must meet again several times ("forced
coincidences"); a setting counts when all of them come out right and there are 7 or more
(settings with 5 or 6 are also listed and read, as a weaker second look).

  keyword wiring   KRYPTOS, the theme words and every dictionary keyword alphabet, as a strip
                   read against A-Z, both ways round. For KRYPTOS and the theme words also the
                   strip against itself, 1-25 places on. (A-Z itself as a wiring is no rotor
                   at all: that case is idea 72, already dead.)
  fast turn s      26 constant speeds; the previous cipher letter; the running sum of the cipher
                   text; every key of length 1-3; the theme words (plain and sliding = running
                   sum; A-Z or KRYPTOS numbering). In form B each with every start 0-25.
  slow turn t      constant inside each clue block, block 2 a further 0-25 on; one step per 26
                   letters (every offset). In form A with every start 0-25.
  faces            plain and cipher letters numbered A-Z or KRYPTOS (4 combinations)

Survivors: the forced part of the hidden wiring is built, all 97 letters are decrypted (? where
the wiring is not forced) and the reading is scored on the big English model.

  python attacks/95_keyword_rotor_plus_hidden_rotor.py
"""
import collections
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos import idea95_rotor as R  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402
from kryptos.wordkeys import theme_words  # noqa: E402

ENGLISH = -5.1      # big-model score per quadgram a reading must beat (planted texts read back near -4.5)
ALL_VIEWS = [v[0] for v in R.views(K4, CRIBS)]
_S = {}


def alphabets():
    """(small, big): KRYPTOS + theme-word alphabets, and the other dictionary keyword alphabets."""
    small, seen = [("KRYPTOS", KRYPTOS_ALPHABET)], {AZ, KRYPTOS_ALPHABET}
    for w in theme_words():
        m = keyword_alphabet(w)
        if m not in seen:
            seen.add(m)
            small.append((w, m))
    big = [(w, m) for w, m in dictionary_alphabets() if m not in seen]
    return small, big


def init(ct, cribs, theme, big_views, only=None):
    _S["rules"] = R.fast_rules(ct, theme)
    _S["shapes"] = R.slow_shapes()
    _S["views"] = R.views(ct, cribs, only)
    _S["big_views"] = big_views
    _S["pa"] = {vn: R.plan_a(_S["rules"], pv) for vn, pv, cv in _S["views"]}
    _S["pb"] = {vn: R.plan_b(_S["rules"], cv, _S["shapes"]) for vn, pv, cv in _S["views"]}


def work(chunk):
    """chunk of (word, alphabet, small). Returns (settings judged, hits)."""
    n, hits = 0, []
    rules, shapes = _S["rules"], _S["shapes"]
    for word, m, small in chunk:
        for form in R.forms(small):
            kw = R.wiring(m, form)
            kb = R.inverse(kw)
            for vn, pv, cv in _S["views"]:
                if not small and vn not in _S["big_views"]:
                    continue
                pa, pb = _S["pa"][vn], _S["pb"][vn]
                for k, ri, si, t0 in R.run_a(pa, cv, kb, shapes, small):
                    hits.append((k, "A", vn, word, m, form, rules[ri][0], 0, shapes[si][0], t0))
                n += len(pa["rec"]) * 26 * (len(shapes) if small else 26)
                for k, rid, si, t0 in R.run_b(pb, pv, kw):
                    hits.append((k, "B", vn, word, m, form, rules[rid // 26][0], rid % 26, shapes[si][0], 0))
                n += len(pb["s24"]) * pb["judged"]
    return n, hits


def search(ct, cribs, small, big, theme, big_views=None, chunk=300):
    """Returns (settings judged, hits). A hit is
    (coincidences, form, faces, keyword, alphabet, strip reading, fast rule, fast start, slow shape, slow start)."""
    args = (ct, cribs, theme, ALL_VIEWS if big_views is None else big_views)
    si = [(w, m, True) for w, m in small]
    bi = [(w, m, False) for w, m in big]
    n, hits = 0, []
    if len(si) + len(bi) <= 4:               # tests and tiny runs: no pool
        init(*args)
        return work(si + bi)
    for items, size in ((si, 3), (bi, chunk)):
        if items:
            for k, h in pmap(work, items, init, args, chunk=size):
                n += k
                hits += h
    return n, hits


def complete(hit, ct, cribs, big, rules=None):
    """Read the message for a hit: (english score, text with ? where the hidden wiring is not
    forced). Tries every place for the jump of the slow rotor between the clues."""
    k, cfg, vn, word, m, form, rule, c0, shape, t0 = hit
    a, b = R.NUM[vn[2:4]], R.NUM[vn[7:9]]
    rules = rules or dict(R.fast_rules(ct, theme_words()))
    s = [(x + c0) % 26 for x in rules[rule]]
    cn = [b.index(ch) for ch in ct]
    pn = {i: a.index(cribs[i]) for i in POS}
    kw = R.wiring(m, form)
    best = (-99.0, "")
    for t in R.slow_streams(shape, t0):
        out = R.read(cfg, kw, pn, cn, s, t)
        if out is not None:
            pt = "".join("?" if x is None else a[x] for x in out)
            best = max(best, (R.read_score(pt, big), pt))
    return best


def complete_all(hits, ct, cribs, big, theme):
    rules = dict(R.fast_rules(ct, theme))
    out = []
    for h in sorted(hits, reverse=True)[:5000]:
        sc, pt = complete(h, ct, cribs, big, rules)
        out.append((sc, pt, h))
    return sorted(out, reverse=True)


def same_text(got, pt, hit):
    """Every letter that was read is right (outside the stretch where the jump place is free)
    and at least half the message was read."""
    free = range(34, 63) if hit[8].startswith("block 2 is") and not hit[8].startswith("block 2 is 0 ") else ()
    return (len(got) == len(pt) and all(g in ("?", p) or i in free for i, (g, p) in enumerate(zip(got, pt)))
            and got.count("?") < len(pt) / 2)


# ---- planted messages and the power count ------------------------------------------------------

def draw(rng, pool, theme, cfg, kind, k4_clues=False, split=None):
    """One random true setting and its message. Returns (ct, cribs, hit without the count,
    coincidences, plaintext)."""
    word, m = rng.choice(pool)
    form = rng.choice(["strip/A-Z", "A-Z/strip"])
    kw = R.wiring(m, form)
    hidden = list(range(26))
    rng.shuffle(hidden)
    r1, r2 = (hidden, kw) if cfg == "A" else (kw, hidden)
    rules = [x for x in R.fast_rules(AZ * 4, theme) if "cipher" not in x[0]]
    pre = {"speed": "speed ", "key": "key ", "word": ("word ", "sliding word ")}[kind]
    name, base = rng.choice([x for x in rules if x[0].startswith(pre) and (kind != "key" or len(x[0]) == 7)])
    c0 = rng.randrange(26) if cfg == "B" else 0
    t0 = rng.randrange(26) if cfg == "A" else 0
    # a step inside a clue block: form A tries it only on the KRYPTOS/theme strips, so only plant it in form B
    split = (cfg == "B" and rng.random() < 0.25) if split is None else split
    shape = rng.choice(R.slow_shapes()[26:])[0] if split else "block 2 is %d on" % rng.randrange(26)
    s = [(x + c0) % 26 for x in base]
    t = rng.choice(R.slow_streams(shape, t0))
    pt = english97(rng)
    if k4_clues:
        pt = "".join(CRIBS.get(i, ch) for i, ch in enumerate(pt))
    cn = R.encrypt([AZ.index(ch) for ch in pt], r1, r2, s, t)
    ct = "".join(AZ[x] for x in cn)
    if cfg == "A":
        u = [(AZ.index(pt[i]) + s[i]) % 26 for i in POS]
    else:
        u = [(cn[i] + t[i]) % 26 for i in POS]
    k = 24 - len(set(u))
    return ct, {i: pt[i] for i in POS}, ("ptAZ/ctAZ", word, m, form, name, c0, shape, t0), k, pt


def plant(rng, pool, theme, cfg, kind, need=R.MIN):
    for tries in range(1, 100000):
        ct, cribs, want, k, pt = draw(rng, pool, theme, cfg, kind)
        if k >= need:
            return ct, cribs, (k, cfg) + want, pt, tries
    raise RuntimeError("no judgeable planted setting")


def power(rng, pool, theme, cfg, kind, n):
    """Share of random true settings (with K4's own clue words) that reach 7 / 5 coincidences."""
    ks = [draw(rng, pool, theme, cfg, kind, k4_clues=True)[3] for _ in range(n)]
    return sum(k >= R.MIN for k in ks) / n, sum(k >= R.MINREC for k in ks) / n


def encrypt(pt, rng):
    """For the clue pre-filter: keyword rotor + hidden rotor, key drawn from rng only."""
    m = keyword_alphabet("".join(rng.choice(AZ) for _ in range(8)))
    hidden = list(range(26))
    rng.shuffle(hidden)
    key = [rng.randrange(26) for _ in range(3)]
    d, n = rng.randrange(26), len(pt)
    cn = R.encrypt([AZ.index(ch) for ch in pt], hidden, R.wiring(m, "strip/A-Z"),
                   [key[i % 3] for i in range(n)], [0 if i < n // 2 else d for i in range(n)])
    return "".join(AZ[x] for x in cn)


def summary(hits):
    h7 = [h for h in hits if h[0] >= R.MIN]
    return len(h7), len(hits) - len(h7), max((h[0] for h in hits), default=0)


def judgeable(ct, cribs, theme):
    """What can be judged for this text: form A rules and form B slow shapes by coincidences."""
    rules, shapes = R.fast_rules(ct, theme), R.slow_shapes()
    out = []
    for vn, pv, cv in R.views(ct, cribs):
        pa, pb = R.plan_a(rules, pv), R.plan_b(rules, cv, shapes)
        ka = pa["kcount"]
        out.append((vn, len(rules), sum(v for k, v in ka.items() if k >= R.MIN),
                    sum(v for k, v in ka.items() if k >= R.MINREC), pa["nn"], len(pa["n1"]), len(pa["n2"]),
                    sum(k >= R.MIN for k in pb["kshape"].values()),
                    sum(k >= R.MINREC for k in pb["kshape"].values()), len(shapes), len(pb["groups"])))
    return out


if __name__ == "__main__":
    theme = theme_words()
    small, big_alpha = alphabets()
    if SMOKE:
        small, big_alpha = small[:12], big_alpha[:3000]
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    with Experiment("two rotors, one wired from a keyword and one hidden", puzzle="k4",
                    notes="wire-collision test on the hidden rotor; %d keyword alphabets (strip against A-Z both "
                          "ways; %d theme alphabets also against themselves); fast = speeds, cipher feeds, keys "
                          "1-3, theme words; slow = block 2 shifted 0-25, one step per 26; both orders; "
                          "A-Z/KRYPTOS faces" % (len(small) + len(big_alpha), len(small)), cribs_forced=True) as ex:
        print("keyword alphabets: %d (KRYPTOS + theme words, all strip readings) + %d dictionary" % (len(small), len(big_alpha)))
        print("what can be judged on K4 (form A: fast rules by coincidences; rules with no forced pair inside either "
              "clue block are dropped; rules with none in block 1 / 2 are not tried with a step inside the other block):")
        for row in judgeable(K4, CRIBS, theme):
            print("   %s: form A %d rules, %d reach 7, %d reach 5, %d dropped, %d / %d with no pair in block 1 / 2 "
                  "| form B %d shapes reach 7, %d reach 5, of %d (%d groups)" % row)
        n, hits = search(K4, CRIBS, small, big_alpha, theme)
        ex.count(n)
        n7, n5, kbest = summary(hits)
        print("settings judged on K4: %d" % n)
        print("K4: %d settings give a real hidden wiring with 7+ forced coincidences, %d more with 5-6; most %d"
              % (n7, n5, kbest))
        done = complete_all(hits, K4, CRIBS, big, theme)
        for sc, pt, h in done[:12]:
            print("   english %.2f words %.2f | %d coincidences, form %s, %s, %s (%s), %s +%d, %s, slow start %d\n      %s"
                  % ((sc, word_coverage(pt.replace("?", ""))) + h[:4] + h[5:] + (pt,)))
            ex.add(pt.replace("?", "X"), english_big=round(sc, 3), setting=" | ".join(str(x) for x in h[1:4] + h[5:]))
        kb = done[0][0] if done else -99.0
        ctrl, cbs = [], []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            # each shuffled K4 gets KRYPTOS and the theme alphabets in full and a different third of the dictionary
            sct = shuffled_control(seed)
            cn, chits = search(sct, CRIBS, small, big_alpha[seed % 3::3], theme)
            cdone = complete_all(chits, sct, CRIBS, big, theme)
            ctrl.append(summary(chits))
            cbs.append(cdone[0][0] if cdone else -99.0)
            print("shuffled K4 seed %d (%d settings): %d with 7+, %d with 5-6, most %d; best english %.2f"
                  % ((seed, cn) + ctrl[-1] + (cbs[-1],)))
        rng = random.Random(95)
        pool = small + big_alpha
        print("share of true settings (K4's clue words, random strip, wiring, rule) reaching 7 / 5 coincidences:")
        for cfg in "AB":
            for kind in ("speed", "key", "word"):
                p7, p5 = power(rng, pool, theme, cfg, kind, 200 if SMOKE else 1000)
                print("   form %s, %s: %.1f%% / %.1f%%" % (cfg, kind, 100 * p7, 100 * p5))
        ok = tot = 0
        for cfg in "AB":
            for kind in ("speed", "key", "word"):
                ct, cribs, want, pt, tries = plant(rng, pool, theme, cfg, kind)
                sample = [x for x in big_alpha[::25 if SMOKE else 60] if x[1] != want[4]]
                if want[4] not in [m for _, m in small[:10]]:
                    sample.append((want[3], want[4]))
                # the planted search: the strip that was used, every 60th dictionary strip, 10 theme strips
                phits = search(ct, cribs, small[:10], sample, theme, big_views=["ptAZ/ctAZ"])[1]
                pdone = complete_all(phits, ct, cribs, big, theme)
                # the planted setting must be among the survivors and its reading must be the planted
                # text and score as English; also say whether it is the best reading of all survivors
                wsc, wpt = complete(want, ct, cribs, big, dict(R.fast_rules(ct, theme)))
                right = same_text(wpt, pt, want)
                found = want in phits and right and wsc > ENGLISH
                top = bool(pdone) and (pdone[0][2] == want or same_text(pdone[0][1], pt, pdone[0][2]))
                ok += found
                tot += 1
                print("planted form %s, %s (%s) %s, %s +%d, %s, slow start %d; %d coincidences, draw %d -> found=%s; "
                      "%d settings pass; its reading english %.2f, %d of 97 letters read; best reading of all "
                      "survivors is the planted text: %s"
                      % ((cfg, kind) + want[3:4] + want[5:] + (want[0], tries, found, len(phits), wsc,
                         97 - wpt.count("?"), top)))
        print("planted recovered: %d/%d" % (ok, tot))
        beats = kb > ENGLISH and kb > max(cbs) + 0.3
        print("VERDICT:", ("K4 beats every control - inspect; " if beats else "no signal; ") +
              "K4 %d settings with 7+ coincidences, %d with 5-6, best english %.2f; shuffled (7+, 5-6, most) %s, "
              "best english %s (-99 = nothing to read; English needs %.1f)"
              % (n7, n5, kb, ctrl, ["%.2f" % x for x in cbs], ENGLISH))
