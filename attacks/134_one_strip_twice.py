"""Idea 134: one hidden paper strip used twice, in the same direction.

Idea 82 closed two rotors where the second is the first read backwards (form B), and showed that
two DIFFERENT hidden strips cannot be judged (form H). A hand encoder with one strip would more
likely just pass the letter through the same strip twice:

    C = R[ R[P + s] - s + t ] - t          (mod 26)

R is one hidden wiring (any permutation of 26 letters). The letter goes in at offset s, comes
out, goes in again at offset t. Nothing about R is guessed. With x = P + s, u = t - s and
z = C + t, every clue letter says "R sends x to some a, and R sends a + u to z". 24 clue letters
against 26 contacts: a random setting has about 26!/26^24 = 4e-8 wirings, so a true setting is
almost always decidable (kryptos/idea134_onestrip.py: an exact backtracking search over R,
after a fast weighted union-find pre-test that is blind to the slow offset's start).

One gauge: adding the same constant to s and t only renames the strip's contacts, so one start
position is pinned (key letter 1 = A, or the fast rule starts at 0).

Families (both offsets can be the fast one: "order"; faces A-Z or KRYPTOS on plain and cipher):

  small   fast: speed 0-25, previous cipher letter (A-Z/KR, either direction), running sum of the
          cipher text (A-Z/KR, either direction).  slow: start 0-25 plus constant per clue block
          with block 2 d = 0-25 on; a step every 2-26 letters at any offset, either direction;
          constant speed 0-25 (this includes both offsets at constant speed).
  keys    every key of 1-5 letters turning one offset, and a random sample of 1,002 x 26 = 26,052
          of the 11.9 million 6-letter keys (each shuffled K4: a third of the 5-letter keys and
          a different 334 x 26 sample of the 6-letter keys); the other offset is constant per clue block
          (start 0-25, d 0-25), steps once per pass of the key (either direction), or turns at a
          constant speed 0-25 (keys of 1-3 only for the speed).
  words   the 85 theme words and 21,425 common words (not the 236,000-word big dictionary; each
          shuffled K4 gets a different third) (repeating, sliding = running sum, word + 1 per letter; A-Z or KRYPTOS
          numbering) turning one offset; the other constant per clue block (start, d) or one step
          per pass of the word (either direction).

Survivors are listed with every wiring that fits (contacts not forced stay open), decrypted where
R is forced, and the open contacts completed by hill-climbing on the big English model.

  python attacks/134_one_strip_twice.py
"""
import collections
import itertools
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea134_onestrip import decrypt, encrypt as strip_encrypt, prefilter, solve_fast as solve, solve_shifts  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos import wordkeys  # noqa: E402
from kryptos.round11 import POS, SMOKE, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ALPH = (("AZ", AZ), ("KR", KRYPTOS_ALPHABET))
BLK = [0] * 13 + [1] * 11
B1 = list(range(13))
B2 = list(range(13, 24))
KMAX = 4 if SMOKE else 6
KSPEED = 2 if SMOKE else 3
ENGLISH = -5.1
_S = {}


# ---- the core test ----------------------------------------------------------------------------

def arrays(pv, cv, s, t, idx=None):
    idx = range(len(pv)) if idx is None else idx
    return ([(pv[i] + s[i]) % 26 for i in idx], [(t[i] - s[i]) % 26 for i in idx],
            [(cv[i] + t[i]) % 26 for i in idx])


def pre(pv, cv, f, g, order, idx=None):
    """The pre-test (blind to the slow start c). f = fast offsets, g = slow shape."""
    s, t = (f, g) if order == 0 else (g, f)
    return prefilter(*arrays(pv, cv, s, t, idx))


def judge(pv, cv, f, g, order, stats):
    """Slow offset = c + g for c = 0..25. Returns [(c, wiring)] for settings with a wiring."""
    s, t = (f, g) if order == 0 else (g, f)
    dx, du, dz = (0, 1, 1) if order == 0 else (1, -1, 0)
    out = []
    for c, sols, complete in solve_shifts(*arrays(pv, cv, s, t), dx, du, dz, limit=1, node_cap=20000):
        stats["solved"] += 1
        if not complete:
            stats["cap"] += 1
        if sols:
            out.append((c, sols[0]))
    return out


# ---- families ---------------------------------------------------------------------------------

def views(ct, cribs):
    return [("pt%s/ct%s" % (an, bn), [a.index(cribs[i]) for i in POS], [b.index(ct[i]) for i in POS])
            for an, a in ALPH for bn, b in ALPH]


def small_fasts(ct):
    out = [("speed %d" % a, [a * i % 26 for i in POS]) for a in range(26)]
    for nn, num in ALPH:
        cum, t = [], 0
        for ch in ct:
            cum.append(t % 26)
            t += num.index(ch)
        for e in (1, -1):
            out.append(("previous cipher letter %s x%+d" % (nn, e), [e * num.index(ct[i - 1]) % 26 for i in POS]))
            out.append(("running sum of cipher %s x%+d" % (nn, e), [e * cum[i] % 26 for i in POS]))
    return out


def small_slows():
    out = [("block 2 is %d on" % d, [d * b for b in BLK]) for d in range(26)]
    for L in range(2, 27):
        for off in range(L):
            for e in (1, -1):
                out.append(("step %+d every %d letters (offset %d)" % (e, L, off), [e * ((i + off) // L) % 26 for i in POS]))
    out += [("speed %d" % b, [b * i % 26 for i in POS]) for b in range(1, 26)]
    return out


def key_slows(p):
    out = [("per pass %+d" % e, [e * (i // p) % 26 for i in POS]) for e in (1, -1)]
    if p <= KSPEED:
        out += [("speed %d" % b, [b * i % 26 for i in POS]) for b in range(1, 26)]
    return out


def word_fasts(w):
    p, out = len(w), []
    for nn, num in ALPH:
        vals = [num.index(ch) for ch in w]
        run, t = [], 0
        for i in range(74):
            t = (t + vals[i % p]) % 26
            run.append(t)
        out.append(("word %s (%s)" % (w, nn), [vals[i % p] for i in POS]))
        out.append(("sliding word %s (%s)" % (w, nn), [run[i] for i in POS]))
        out.append(("word + 1 per letter %s (%s)" % (w, nn), [(vals[i % p] + i) % 26 for i in POS]))
    return out


def init(ct, cribs):
    _S["ct"], _S["v"] = ct, views(ct, cribs)
    _S["fasts"], _S["slows"] = small_fasts(ct), small_slows()


def new_stats():
    return collections.Counter()


def run_fixed(f_items, slows, blockwise, stats, hits, fam):
    """Every fixed fast sequence x slow shape x order x view. blockwise: the slow shape is
    'block 2 is d on' for d = 0..25 and the d-blind block pre-test runs first."""
    for vn, pv, cv in _S["v"]:
        for fname, f in f_items:
            for order in (0, 1):
                if blockwise:
                    z = [0] * 24
                    if not (pre(pv, cv, f, z, order, B1) and pre(pv, cv, f, z, order, B2)):
                        stats["settings"] += 26 * 26
                        continue
                    shapes = [("block 2 is %d on" % d, [d * b for b in BLK]) for d in range(26)]
                else:
                    shapes = slows
                for gname, g in shapes:
                    stats["settings"] += 26
                    if not pre(pv, cv, f, g, order):
                        continue
                    stats["pre"] += 1
                    for c, w in judge(pv, cv, f, g, order, stats):
                        hits.append((fam, vn, order, fname, gname, c, w))


def work_small(chunk):
    stats, hits = new_stats(), []
    for k in chunk:
        run_fixed([_S["fasts"][k]], _S["slows"], False, stats, hits, "small")
    return stats, hits


def work_words(chunk):
    stats, hits = new_stats(), []
    for w in chunk:
        fs = word_fasts(w)
        run_fixed(fs, None, True, stats, hits, "words")
        p = len(w)
        run_fixed(fs, [("per pass %+d" % e, [e * (i // p) % 26 for i in POS]) for e in (1, -1)], False,
                  stats, hits, "words")
    return stats, hits


def work_keys(chunk):
    """chunk: (p, head) jobs. The key starts with A (gauge) and `head`; the rest is searched
    letter by letter with the pre-test on the clues whose key letters are already chosen."""
    stats, hits = new_stats(), []
    for p, head in chunk:
        res = [i % p for i in POS]
        levels = [[j for j in range(24) if res[j] < m] for m in range(p + 1)]
        bl = [([j for j in lv if j < 13], [j for j in lv if j >= 13]) for lv in levels]
        n_tail = p - len(head)
        for vn, pv, cv in _S["v"]:
            for order in (0, 1):
                # slow shape: block constant (d-blind test while choosing the key), then the others
                for shape in [None] + key_slows(p):
                    z = [0] * 24
                    g = z if shape is None else shape[1]
                    if shape is None:
                        nset = 26 * 26
                    else:
                        nset = 26

                    def ok(key, m):
                        f = [key[r] if r < len(key) else 0 for r in res]
                        if shape is None:
                            a, b = bl[m]
                            return pre(pv, cv, f, g, order, a) and pre(pv, cv, f, g, order, b)
                        return pre(pv, cv, f, g, order, levels[m])

                    def leaf(key):
                        f = [key[r] for r in res]
                        shapes = ([("block 2 is %d on" % d, [d * b for b in BLK]) for d in range(26)]
                                  if shape is None else [shape])
                        for gname, gg in shapes:
                            if not pre(pv, cv, f, gg, order):
                                continue
                            stats["pre"] += 1
                            for c, w in judge(pv, cv, f, gg, order, stats):
                                hits.append(("keys", vn, order, "key " + "".join(AZ[x] for x in key), gname, c, w))

                    stats["settings"] += nset * 26 ** n_tail

                    def dfs(key):
                        m = len(key)
                        if not ok(key, m):
                            return
                        if m == p:
                            leaf(key)
                            return
                        for x in range(26):
                            dfs(key + (x,))
                    dfs(head)
    return stats, hits


P6_HEADS = 60 if SMOKE else 1002            # sampled 5-letter heads of 6-letter keys (26 keys each)


def key_jobs(maxp=KMAX, third=None, p6_heads=P6_HEADS, seed=0):
    """Keys of 1-5 letters: all of them (controls: a third of the 5-letter keys). Keys of 6 letters:
    a random sample of p6_heads heads A????, each with all 26 last letters."""
    jobs = []
    for p in range(1, min(maxp, 5) + 1):
        nh = min(p - 1, 2)                     # head letters after the pinned A
        js = [(p, (0,) + h) for h in itertools.product(range(26), repeat=nh)]
        if p == 5 and third is not None:
            js = js[third::3]
        jobs += js
    if maxp >= 6:
        rng = random.Random(600 + seed)
        heads = rng.sample(range(26 ** 4), p6_heads)
        for h in heads:
            jobs.append((6, (0, h // 17576, h // 676 % 26, h // 26 % 26, h % 26)))
    return jobs


def search(ct, cribs, words, parts=("small", "keys", "words"), maxp=KMAX, third=None, p6_heads=P6_HEADS, seed=0):
    stats, hits = new_stats(), []
    t0 = time.time()

    def take(name, results):
        t1 = time.time()
        st = new_stats()
        for s, h in results:
            st.update(s)
            hits.extend(h)
        stats.update(st)
        dt = time.time() - t1
        print("   %-6s %12d settings, %9d pass the pre-test, %9d searched for a wiring (%d capped), "
              "%d survive; %.0f s (%.2f us per setting)"
              % (name, st["settings"], st["pre"], st["solved"], st["cap"],
                 sum(1 for x in hits if x[0] == name), dt, 1e6 * dt / max(1, st["settings"])), flush=True)
    if "small" in parts:
        take("small", pmap(work_small, list(range(len(small_fasts(ct)))), init, (ct, cribs), chunk=1))
    if "keys" in parts:
        take("keys", pmap(work_keys, key_jobs(maxp, third, p6_heads, seed), init, (ct, cribs), chunk=1))
    if "words" in parts and words:
        take("words", pmap(work_words, words, init, (ct, cribs), chunk=200))
    print("   total %.0f s" % (time.time() - t0))
    return stats, hits


# ---- reading a survivor -----------------------------------------------------------------------

def full_streams(hit, ct):
    """s and t over all 97 places for a hit (None if the rule is not rebuilt)."""
    fam, vn, order, fname, gname, c, w = hit
    num = dict(ALPH)
    n = 97
    if fname.startswith("speed "):
        f = [int(fname[6:]) * i % 26 for i in range(n)]
    elif fname.startswith("previous cipher letter"):
        a, e = num[fname.split()[3]], int(fname[-2:])
        f = [e * a.index(ct[i - 1]) % 26 for i in range(n)]
    elif fname.startswith("running sum"):
        a, e = num[fname.split()[4]], int(fname[-2:])
        f, t = [], 0
        for ch in ct:
            f.append(e * t % 26)
            t += a.index(ch)
    elif fname.startswith("key "):
        k = [AZ.index(ch) for ch in fname[4:]]
        f = [k[i % len(k)] for i in range(n)]
    else:
        kind, word, nn = fname.rsplit(" ", 2)[0], fname.split()[-2], fname[-3:-1]
        vals = [num[nn].index(ch) for ch in word]
        p = len(vals)
        if kind == "word":
            f = [vals[i % p] for i in range(n)]
        elif kind == "sliding word":
            f, t = [], 0
            for i in range(n):
                t = (t + vals[i % p]) % 26
                f.append(t)
        else:
            f = [(vals[i % p] + i) % 26 for i in range(n)]
    p = len(fname) - 4 if fname.startswith("key ") else (len(fname.split()[-2]) if "word" in fname else 0)
    if gname.startswith("block 2 is"):
        d = int(gname.split()[3])
        gs = [[0] * j + [d] * (n - j) for j in range(34, 64)] if d else [[0] * n]
    elif gname.startswith("step"):
        e, L, off = int(gname.split()[1]), int(gname.split()[3]), int(gname.split()[-1][:-1])
        gs = [[e * ((i + off) // L) for i in range(n)]]
    elif gname.startswith("speed"):
        gs = [[int(gname.split()[1]) * i for i in range(n)]]
    elif gname.startswith("per pass"):
        e = int(gname.split()[2])
        gs = [[e * (i // p) for i in range(n)]]
    else:
        return None
    out = []
    for g in gs:
        gc = [(c + x) % 26 for x in g]
        out.append((f, gc) if order == 0 else (gc, f))
    return out


def read_score(pt, big):
    q = [pt[i:i + 4] for i in range(len(pt) - 3) if "?" not in pt[i:i + 4]]
    return sum(big.logp.get(x, big.floor) for x in q) / len(q) if len(q) >= 10 else -99.0


def all_wirings(hit, ct, cribs, limit=50):
    fam, vn, order, fname, gname, c, w = hit
    num = dict(ALPH)
    a, b = num[vn[2:4]], num[vn[7:9]]
    pv, cv = [a.index(cribs[i]) for i in POS], [b.index(ct[i]) for i in POS]
    out = []
    for s, t in full_streams(hit, ct) or []:
        sols = solve(*arrays(pv, cv, [s[i] for i in POS], [t[i] for i in POS]), limit=limit, node_cap=200000)[0]
        out.append((s, t, sols))
    return out


def climb(cvall, s, t, r, a, big, rng, rounds=3, steps=1500):
    """Fill the open contacts of r and hill-climb them (swaps among the open ones) on the big model."""
    free_d = [i for i in range(26) if r[i] is None]
    free_r = [y for y in range(26) if y not in r]
    best_sc, best_pt = -99.0, ""
    if not free_d:
        pt = "".join(a[x] for x in decrypt(cvall, r, s, t))
        return big.score(pt), pt
    for _ in range(rounds):
        img = list(free_r)
        rng.shuffle(img)
        cur = list(r)
        for d, y in zip(free_d, img):
            cur[d] = y
        sc = big.score("".join(a[x] for x in decrypt(cvall, cur, s, t)))
        for _ in range(steps):
            i, j = rng.sample(free_d, 2) if len(free_d) > 1 else (free_d[0], free_d[0])
            cur[i], cur[j] = cur[j], cur[i]
            n = big.score("".join(a[x] for x in decrypt(cvall, cur, s, t)))
            if n >= sc:
                sc = n
            else:
                cur[i], cur[j] = cur[j], cur[i]
        if sc > best_sc:
            best_sc, best_pt = sc, "".join(a[x] for x in decrypt(cvall, cur, s, t))
    return best_sc, best_pt


def complete(hit, ct, cribs, big, rng):
    """(forced-letter score, forced text, completed score, completed text, contacts fixed, wirings)."""
    num = dict(ALPH)
    a, b = num[hit[1][2:4]], num[hit[1][7:9]]
    cvall = [b.index(ch) for ch in ct]
    cands = []
    for s, t, sols in all_wirings(hit, ct, cribs):
        for r in sols[:10]:
            forced = "".join("?" if x is None else a[x] for x in decrypt(cvall, r, s, t))
            cands.append((read_score(forced, big), forced, s, t, r, len(sols)))
    cands.sort(key=lambda x: x[0], reverse=True)
    best = None
    for fs, forced, s, t, r, nsol in cands[:3]:
        cs, cpt = climb(cvall, s, t, r, a, big, rng)
        rec = (cs, fs, forced, cpt, sum(v is not None for v in r), nsol)
        if best is None or rec > best:
            best = rec
    return best


# ---- planted messages -------------------------------------------------------------------------

def plant(rng, kind):
    """A planted message: (ct, cribs, plaintext, wanted (order, fast name, slow name, c))."""
    pt = english97(rng)
    r = list(range(26))
    rng.shuffle(r)
    n = 97
    if kind == "key":
        key = [0] + [rng.randrange(26) for _ in range(2)]
        f = [key[i % 3] for i in range(n)]
        e = rng.choice((1, -1))
        g = [e * (i // 3) for i in range(n)]
        want = (0, "key " + "".join(AZ[x] for x in key), "per pass %+d" % e)
    elif kind == "key6":
        key = [0] + [rng.randrange(26) for _ in range(5)]
        f = [key[i % 6] for i in range(n)]
        d = rng.randrange(1, 26)
        g = [0] * 40 + [d] * 57
        want = (1, "key " + "".join(AZ[x] for x in key), "block 2 is %d on" % d)
    else:
        a, b = rng.randrange(1, 26), rng.randrange(1, 26)
        f = [a * i % 26 for i in range(n)]
        g = [b * i for i in range(n)]
        want = (rng.randrange(2), "speed %d" % a, "speed %d" % b)
    c = rng.randrange(26)
    gc = [(c + x) % 26 for x in g]
    s, t = (f, gc) if want[0] == 0 else (gc, f)
    cv = strip_encrypt([AZ.index(ch) for ch in pt], r, s, t)
    ct = "".join(AZ[x] for x in cv)
    return ct, {i: pt[i] for i in POS}, pt, want + (c,)


def planted_run(rng, kind, big):
    ct, cribs, pt, want = plant(rng, kind)
    part = "small" if kind == "speed" else "keys"
    maxp = 3 if kind == "key" else 6
    if kind == "key6":                            # the length-6 key search runs only the job with the true head
        init(ct, cribs)
        key = [AZ.index(ch) for ch in want[1][4:]]
        stats, hits = work_keys([(6, tuple(key[:5]))])
    else:
        stats, hits = search(ct, cribs, [], parts=(part,), maxp=maxp)
    found = [h for h in hits if h[1] == "ptAZ/ctAZ" and (h[2], h[3], h[4], h[5]) == want]
    ok, note = False, ""
    if found:
        res = complete(found[0], ct, cribs, big, random.Random(1))
        right = sum(1 for g, p in zip(res[2], pt) if g != "?" and g == p)
        read = sum(1 for g in res[2] if g != "?")
        ok = right == read and read >= 30
        note = "; read back %d of 97 letters (all right: %s), forced %d contacts, completed english %.2f" % (
            read, right == read, res[4], res[0])
    print("planted %s: %s -> found=%s, survivors %d%s" % (kind, want, bool(found), len(hits), note), flush=True)
    return ok


def encrypt(pt, rng):
    """For the clue pre-filter: one strip used twice, 5-letter key and a slow offset per block."""
    r = list(range(26))
    rng.shuffle(r)
    key = [rng.randrange(26) for _ in range(5)]
    d = rng.randrange(26)
    n = len(pt)
    cv = strip_encrypt([AZ.index(ch) for ch in pt], r, [key[i % 5] for i in range(n)],
                       [0 if i < n // 2 else d for i in range(n)])
    return "".join(AZ[x] for x in cv)


def summary(hits):
    return collections.Counter(h[0] for h in hits)


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter as clue_prefilter
        clue_prefilter("one hidden strip used twice", encrypt=encrypt)
        sys.exit()
    words = sorted(set(w for w in ["KRYPTOS"] + wordkeys.theme_words() + wordkeys.common_words()
                       if 3 <= len(w) <= 22))
    if SMOKE:
        words = words[:2000]
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    with Experiment("one hidden strip used twice in the same direction", puzzle="k4",
                    notes="exact backtracking over the wiring; small rules, keys 1-%d, %d words; "
                          "slow constant per block / per pass / speed; A-Z/KR faces; both orders"
                          % (KMAX, len(words)), cribs_forced=True) as ex:
        rng = random.Random(134)
        ok = 0
        kinds = ("key", "speed", "key6")
        for kind in kinds:
            ok += planted_run(rng, kind, big)
        print("planted recovered: %d/%d" % (ok, len(kinds)), flush=True)
        assert ok == len(kinds), "planted answers must be found"
        print("K4:", flush=True)
        stats, hits = search(K4, CRIBS, words)
        ex.count(stats["settings"])
        print("K4: %d settings, survivors by family %s" % (stats["settings"], dict(summary(hits))), flush=True)
        done = []
        for h in hits[:500]:
            res = complete(h, K4, CRIBS, big, random.Random(2))
            if res:
                done.append((res, h))
        done.sort(key=lambda x: x[0], reverse=True)
        for res, h in done[:15]:
            print("   completed %.2f (forced letters %.2f, %d contacts forced, %d wirings) words %.2f %s order %d %s | %s | c=%d\n"
                  "      forced:    %s\n      completed: %s"
                  % (res[0], res[1], res[4], res[5], word_coverage(res[3]), h[1], h[2], h[3], h[4], h[5], res[2], res[3]))
            ex.add(res[3], setting="%s order %d %s | %s | c=%d" % h[1:6], english_big=round(res[0], 3))
        kbest = done[0][0][0] if done else -99.0
        cbest = []
        for seed in (1, 2, 3):
            sct = shuffled_control(seed)
            print("shuffled K4 seed %d:" % seed, flush=True)
            cs, ch = search(sct, CRIBS, words[seed % 3::3], third=seed % 3, p6_heads=P6_HEADS // 3, seed=seed)
            cd = [complete(h, sct, CRIBS, big, random.Random(2)) for h in ch[:500]]
            cd = [x for x in cd if x]
            cbest.append(max((x[0] for x in cd), default=-99.0))
            print("shuffled K4 seed %d: %d settings, survivors %s, best completed english %.2f"
                  % (seed, cs["settings"], dict(summary(ch)), cbest[-1]), flush=True)
        beats = kbest > ENGLISH and kbest > max(cbest) + 0.3
        print("VERDICT:", "K4 beats every control - inspect" if beats else "no signal",
              "; K4 survivors %d, best completed %.2f; controls best %s (English needs %.1f)"
              % (len(hits), kbest, ["%.2f" % x for x in cbest], ENGLISH))
