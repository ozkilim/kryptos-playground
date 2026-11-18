"""Idea 140: the key steps with each repeat of the CIPHER letter (homophone cycling, cipher side).

Idea 109 gave every PLAIN letter its own counter into a key word and found the cipher hard to
undo. Put the counter on the cipher letter instead and decryption is easy, letter by letter:

    C_i = Tab(P_i, W[n_i mod L])     n_i = how many times the cipher letter C_i occurred before

n_i comes from the ciphertext alone. The count runs from K4's first letter, or (variant) from
some point of the K1-K3 ciphertext through to K4. Every start s = 0..768 in K1K2K3 is tried
(s = 0 is the start of K1, s = 768 is K4's first letter).

Proofs (any tableau, hidden ones too). A fixed key letter is a one-to-one map plain -> cipher.
So two clue positions with the same residue n mod L must have (same plain) == (same cipher).
  * Counting from K4's first letter: positions 22 (E -> F) and 31 (E -> G) both have n = 1
    (one F before 22, one G before 31). Same key letter, same plain letter, different cipher
    letters: impossible for every key length, word and tableau.
  * Counting from the start of K1: every L = 1..26 breaks the same way.
  * Other starts: the test leaves 3,478 (start, L) settings with 7+ checks (2,030 distinct
    groupings of the clue positions).

Exact search. For every keyword tableau (A-Z, KRYPTOS, every dictionary keyword alphabet and
its two transposition-mixed forms; 5 layouts; Vigenere and Beaufort; variant has Vigenere's
equalities) the 24 clue letters force 24 key values. A grouping passes when the key values agree
inside every group (7-20 checks). Survivors:
  * dictionary join: words and K1-K3 phrase windows of length L (any rotation) with the forced
    letters in the right places, key letter read in the plain, cipher or A-Z alphabet; decrypted
    in full and scored;
  * W free: consistent at all, unknown key letters filled by a hill climb on English.

Workability. A writer has to find a cipher letter c whose own next key letter turns P into c.
There may be none. The script measures how far English messages get with full backtracking.
Because ordinary English can (almost) never be enciphered, planted answers are made backwards:
random ciphertext, decrypted with a dictionary key; the search must name key, alphabet and
start and read the text back exactly.

Controls: 3 shuffled K4s, each on its own groupings and a third of the alphabets.

  python attacks/140_cipher_letter_counters.py              (--prefilter for the clue card)
"""
import collections
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea140_cipher import (counts, decrypt, encrypt, index_of, k13, keyvals, labels,  # noqa: E402
                                    layouts, settings)
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap, vocabulary  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1
MIN_CHECKS = 7
GAUGE = 5             # groupings with 5-6 checks are scanned too, as a near-miss gauge (not judged)
STARTS = range(769)
FORM_NAME = {"vig": "Vigenere", "beau": "Beaufort", "var": "variant Beaufort"}
_S = {}


def key_words():
    return sorted(set(w for w in vocabulary() if 3 <= len(w) <= 26) | set(wordkeys.phrase_windows()))


def by_length(words):
    out = collections.defaultdict(list)
    for w in words:
        out[len(w)].append(w)
    return out


# ---- proofs -------------------------------------------------------------------------------------

def proofs(ct=K4, cribs=CRIBS):
    pre = k13()
    n0 = counts(ct)
    k4_start = n0[21] == n0[30] and cribs[21] == cribs[30] and ct[21] != ct[30]
    pos = sorted(cribs)
    pl, cl = [cribs[i] for i in pos], [ct[i] for i in pos]
    from kryptos.idea140_cipher import residue_groups, tableau_free_ok
    dead_all = []
    for s in STARTS:
        n = counts(ct, pre[s:])
        if all(not tableau_free_ok(residue_groups(n, pos, L), pl, cl) for L in range(1, 27)):
            dead_all.append(s)
    return k4_start, dead_all


# ---- the scan (runs in the pool) ----------------------------------------------------------------

def init(ct, cribs, parts):
    pos = sorted(cribs)
    _S["pl"] = [cribs[i] for i in pos]
    _S["cl"] = [ct[i] for i in pos]
    first = collections.defaultdict(list)
    for part in parts:
        first[part[0][0], part[0][1]].append(part)
    _S["first"] = first


def work(chunk):
    pl, cl, first = _S["pl"], _S["cl"], _S["first"]
    nstream, hits = 0, []
    for name, m in chunk:
        for lay, a, b in layouts(m):
            ia, ib = index_of(a), index_of(b)
            pa, cb = [ia[c] for c in pl], [ib[c] for c in cl]
            for form in ("vig", "beau"):
                nstream += 1
                k = keyvals(pa, cb, form)
                g = {}
                for j, v in enumerate(k):
                    g.setdefault(v, []).append(j)
                for grp in g.values():
                    for x in range(len(grp)):
                        for y in range(x + 1, len(grp)):
                            for part in first.get((grp[x], grp[y]), ()):
                                if all(k[j] == k[gr[0]] for gr in part for j in gr):
                                    hits.append((name, m, lay, form, part))
    return nstream, hits


def scan(ct, cribs, alphabets, parts, pool=True):
    if pool:
        res = pmap(work, alphabets, init, (ct, cribs, parts), chunk=2000)
    else:
        init(ct, cribs, parts)
        res = [work(alphabets)]
    nstream, hits, seen = 0, [], set()
    for n, h in res:
        nstream += n
        for x in h:
            if (x[1], x[2], x[3], x[4]) not in seen:     # the same alphabet may come twice under two names
                seen.add((x[1], x[2], x[3], x[4]))
                hits.append(x)
    return nstream, hits


# ---- judging survivors --------------------------------------------------------------------------

def forced(ct, cribs, a, b, form, res, L):
    """Key value per residue the clue letters force (None where no clue letter falls)."""
    pos = sorted(cribs)
    ia, ib = index_of(a), index_of(b)
    k = keyvals([ia[cribs[i]] for i in pos], [ib[ct[i]] for i in pos], form)
    wv = [None] * L
    for v, r in zip(k, res):
        wv[r] = v
    return wv


def join(ct, cribs, hits, plans, wlen, big):
    """Dictionary key words for every surviving (tableau, start, L). Returns readings
    [(english, coverage, text, settings)] and the number of (word, setting) fits."""
    pre = k13()
    out, nfit = [], 0
    for name, m, lay, form, part in hits:
        a, b = next((x, y) for n, x, y in layouts(m) if n == lay)
        for s, L, res in plans[part]:
            for f in (("vig", "var") if form == "vig" else ("beau",)):
                wv = forced(ct, cribs, a, b, f, res, L)
                for ln, lab in labels(a, b):
                    need = [(r, lab[v]) for r, v in enumerate(wv) if v is not None]
                    il = index_of(lab)
                    for w in wlen.get(L, ()):
                        for rot in range(L):
                            if all(w[(r + rot) % L] == ch for r, ch in need):
                                nfit += 1
                                key = [il[w[(r + rot) % L]] for r in range(L)]
                                pt = decrypt(ct, a, b, f, key, pre[s:])
                                out.append((big.score(pt), word_coverage(pt), pt,
                                            "key word %s (rotation %d) on %s %s, %s, key letters in the %s "
                                            "alphabet, count from K1K2K3[%d:], L=%d" % (w, rot, name, lay,
                                                                                        FORM_NAME[f], ln, s, L)))
    out.sort(reverse=True)
    return out, nfit


def fill_free(ct, cribs, hits, plans, big, limit=300):
    """W free: fill the unknown key values by a hill climb on English. [(english, text, settings)]."""
    pre = k13()
    out = []
    for name, m, lay, form, part in hits[:limit]:
        a, b = next((x, y) for n, x, y in layouts(m) if n == lay)
        for s, L, res in plans[part][:5]:
            wv = forced(ct, cribs, a, b, form, res, L)
            free = [r for r in range(L) if wv[r] is None]
            cur = [v if v is not None else 0 for v in wv]
            best = big.score(decrypt(ct, a, b, form, cur, pre[s:]))
            for _ in range(2):
                for r in free:
                    for v in range(26):
                        t = cur[:]
                        t[r] = v
                        sc = big.score(decrypt(ct, a, b, form, t, pre[s:]))
                        if sc > best:
                            best, cur = sc, t
            out.append((best, decrypt(ct, a, b, form, cur, pre[s:]),
                        "W free on %s %s, %s, count from K1K2K3[%d:], L=%d, %d free key letters"
                        % (name, lay, FORM_NAME[form], s, L, len(free))))
    out.sort(reverse=True)
    return out


def run_all(label, ct, cribs, alphabets, wlen, big, pool=True, quiet=False):
    t0 = time.time()
    tested, dead, plans = settings(ct, cribs, STARTS, min_checks=GAUGE)
    parts = list(plans)
    ck = lambda part: sum(len(g) - 1 for g in part)  # noqa: E731
    expect, gexp = 0.0, 0.0
    nstream, allhits = scan(ct, cribs, alphabets, parts, pool)
    for part in parts:
        if ck(part) >= MIN_CHECKS:
            expect += 26.0 ** -ck(part)
        else:
            gexp += 26.0 ** -ck(part)
    expect *= nstream
    gexp *= nstream
    hits = [h for h in allhits if ck(h[4]) >= MIN_CHECKS]
    aidx = {x: n for n, x in enumerate(alphabets)}
    gbt = [0, 0, 0]
    for h in allhits:
        if ck(h[4]) < MIN_CHECKS and (h[0], h[1]) in aidx:
            gbt[aidx[h[0], h[1]] % 3] += 1
    gauge = len(allhits) - len(hits)
    plans_n = {p: v for p, v in plans.items() if ck(p) >= MIN_CHECKS}
    readings, nfit = join(ct, cribs, hits, plans_n, wlen, big)
    free = fill_free(ct, cribs, hits, plans_n, big)
    hist = collections.Counter(sum(len(g) - 1 for g in h[4]) for h in hits)
    s = {"label": label, "tested": tested, "dead": dead, "nset": sum(len(v) for v in plans_n.values()),
         "nparts": len(plans_n), "gauge": gauge, "gexp": gexp, "gauge_by_third": gbt, "nstream": nstream, "hits": hits, "hist": dict(hist), "expect": expect,
         "readings": readings, "nfit": nfit, "free": free,
         "best": readings[0][0] if readings else -99.0, "best_free": free[0][0] if free else -99.0}
    if not quiet:
        print("%s: %d (start, L) settings, %d broken by the tableau-free test, %d left with %d+ checks "
              "(%d distinct groupings); %d alphabets, %d key streams [%.0fs]"
              % (label, tested, dead, s["nset"], MIN_CHECKS, s["nparts"], len(alphabets), nstream, time.time() - t0))
        print("   near-miss gauge, tableaux consistent with a 5-6 check grouping: %d [chance predicts %.1f]"
              % (gauge, gexp))
        print("   tableaux consistent with a grouping (W free): %d, by checks %s [chance predicts %.3f]"
              % (len(hits), dict(sorted(hist.items())), expect))
        print("   dictionary key words that fit: %d; best reading %.2f (needs %.1f)%s"
              % (nfit, s["best"], ENGLISH, "  " + readings[0][2] + "  " + readings[0][3] if readings else ""))
        if free:
            print("   W free, best hill-climbed reading %.2f  %s  %s" % free[0])
    return s


# ---- workability and planted answers ------------------------------------------------------------

def workability(rng, alphabets, n=1000):
    """How far does an English message get? Full backtracking, random dictionary key of 5-12."""
    pre = k13()
    words = [w for w in vocabulary() if 5 <= len(w) <= 12]
    hist = collections.Counter()
    for t in range(n):
        name, m = alphabets[rng.randrange(len(alphabets))]
        lay, a, b = rng.choice(layouts(m))
        form = rng.choice(("vig", "beau", "var"))
        wv = [index_of(a)[c] for c in rng.choice(words)]
        s = rng.choice((768, 0, rng.randrange(769)))
        pt = english97(rng)
        got = 0
        for cut in (10, 20, 30, 40, 60, 80, 97):
            if encrypt(pt[:cut], a, b, form, wv, pre[s:], limit=50000) is None:
                break
            got = cut
        hist[got] += 1
    return dict(sorted(hist.items()))


def planted(rng, big, sample, wlen, start, alpha, pool=True):
    """Random ciphertext decrypted with a dictionary key word: the search must name it and read it back."""
    pre = k13()
    name, m = alpha
    lay, a, b = rng.choice(layouts(m))
    form = rng.choice(("vig", "beau", "var"))
    lab_name, lab = rng.choice(labels(a, b))
    word = rng.choice([w for L in range(5, 13) for w in wlen.get(L, ()) if w.isalpha()])
    wv = [index_of(lab)[c] for c in word]
    ct = "".join(rng.choice(AZ) for _ in range(97))
    pt = decrypt(ct, a, b, form, wv, pre[start:])
    cribs = {i: pt[i] for i in POS}
    s = run_all("planted", ct, cribs, sample + [alpha], wlen, big, pool=pool, quiet=True)
    want = "key word %s (rotation 0) on %s %s, %s, key letters in the %s alphabet, count from K1K2K3[%d:]" % (
        word, name, lay, FORM_NAME[form], lab_name, start)
    ok = any(r[3].startswith(want) and r[2] == pt for r in s["readings"])
    other = sum(1 for r in s["readings"] if r[2] != pt)
    print("planted: key %s (L=%d) on %s %s, %s, key letters in the %s alphabet, count from K1K2K3[%d:]; "
          "%d settings, %d tableaux consistent, %d word fits, planted setting named and read back exactly: %s; "
          "other readings %d (the plaintext is not English, so nothing can rank them) -> %s"
          % (word, len(word), name, lay, FORM_NAME[form], lab_name, start, s["nset"], len(s["hits"]), s["nfit"],
             ok, other, "ok" if ok else "MISSED"))
    return ok, s


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("cipher-letter counters into a key word", marks={
            "hand": ("pass", "paper tableau and a tally per cipher letter"),
            "cribs": ("fail", "dead by proof from K4's start and from K1's start; see the run"),
            "english": ("fail", "English messages almost never encipher (writer gets stuck)")})
        sys.exit(0)
    rng = random.Random(140)
    alphabets = dictionary_alphabets(mixed=True)
    words = key_words()
    if SMOKE:
        alphabets = alphabets[:3000]
        words = words[:40000] + ["PALIMPSEST", "ABSCISSA", "SHADOW", "LODESTONE"]
    wlen = by_length(words)
    with Experiment("cipher-letter counters into a key word (homophone cycling, cipher side)", puzzle="k4",
                    notes="C=Tab(P,W[n mod L]), n=earlier copies of the cipher letter, counted from K1K2K3[s:], "
                          "s=0..768; tableau-free proof + exact test on %d alphabets x 5 layouts x Vig/Beau "
                          "(variant), L=1..26; join with %d words; W free; 3 shuffled K4s on thirds; planted 4"
                          % (len(alphabets), len(words)), cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        k4_start, dead_all = proofs()
        print("proof, count from K4's first letter: positions 22 and 31 are E->F and E->G with n=1 both: "
              "impossible for every tableau: %s" % k4_start)
        print("starts where every L=1..26 is impossible for every tableau: %d of %d (K1 start s=0 among them: %s)"
              % (len(dead_all), len(STARTS), 0 in dead_all))
        wk = workability(random.Random(7), alphabets, n=200 if SMOKE else 1000)
        print("workability: English messages enciphered to at least N letters (full backtracking): %s" % wk)

        sample = [alphabets[0]] + random.Random(5).sample(alphabets, min(3000, len(alphabets) - 1))
        pl_ok = 0
        for start, alpha in ((768, ("KRYPTOS", alphabets[1][1]) if alphabets[1][0] == "KRYPTOS" else alphabets[1]),
                             (0, alphabets[rng.randrange(len(alphabets))]),
                             (rng.randrange(1, 768), alphabets[rng.randrange(len(alphabets))]),
                             (rng.randrange(1, 768), ("(A-Z)", AZ))):
            ok, _ = planted(rng, big, sample, wlen, start, alpha)
            pl_ok += ok
        print("planted: %d/4" % pl_ok)
        if pl_ok < 4:
            sys.exit("planted answers missed: the search is broken")

        k4 = run_all("K4", K4, CRIBS, alphabets, wlen, big)
        ex.count(k4["nstream"] * k4["nparts"])
        for r in k4["readings"][:20]:
            ex.add(r[2], how=r[3])
        for r in k4["free"][:20]:
            ex.add(r[1], how=r[2])
        thirds = []
        for seed in (1, 2, 3):
            sh = shuffled_control(seed)
            third = alphabets[seed - 1::3]
            c = run_all("shuffled K4 seed %d (third %d of the alphabets)" % (seed, seed), sh, CRIBS, third, wlen, big)
            k4t = sum(1 for h in k4["hits"] if alphabets.index((h[0], h[1])) % 3 == seed - 1) if k4["hits"] else 0
            k4g = k4["gauge_by_third"][seed - 1]
            thirds.append((seed, c["nset"], len(c["hits"]), c["nfit"], c["best"], k4t, c["gauge"], c["gexp"], k4g))
        print("\nSUMMARY")
        print("K4: %d settings left by the tableau-free test, %d groupings; %d key streams; %d tableaux consistent "
              "(chance %.3f); %d word fits; best word reading %.2f; best W-free reading %.2f"
              % (k4["nset"], k4["nparts"], k4["nstream"], len(k4["hits"]), k4["expect"], k4["nfit"], k4["best"],
                 k4["best_free"]))
        print("K4 near-miss gauge (5-6 checks): %d [chance %.1f]" % (k4["gauge"], k4["gexp"]))
        for seed, nset, nh, nf, best, k4t, g, ge, k4g in thirds:
            print("control seed %d: %d settings left; %d tableaux consistent (K4 on the same third: %d); "
                  "%d word fits; best %.2f; gauge %d [chance %.1f] (K4 on the same third %d)"
                  % (seed, nset, nh, k4t, nf, best, g, ge, k4g))
        print("planted %d/4; workability %s" % (pl_ok, wk))
