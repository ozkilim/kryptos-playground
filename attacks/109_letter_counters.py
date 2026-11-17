"""Idea 109: each plain letter keeps its own place in the key word (homophone cycling on the tableau).

Scheidt: "I masked the English language", and the cipher is simple, remembered, run with the
correct key word(s). The classic hand way to flatten letter counts and stay letter-for-letter is
to give every plain letter its own counter: the first E takes key letter 1, the second E key
letter 2, and so on.

    C = Tab(P, W[n mod L])       n = how many times THIS plain letter has occurred before

The key letter depends on the letter's own count, not on the position. No earlier test models
this (idea 83 had one shared state).

One-line proofs first (checked in code, they hold for every tableau and every alphabet):
  * a common numeric step per occurrence is impossible: T goes V then R, L goes V then Z, both one
    step on from V, so the step would have to lead to R and to Z;
  * counters that restart at each word are impossible: EAST is FLRV and then GKSS, with E the
    first E of its word both times;
  * key words of 1 or 2 letters, and any 2 tableaux taken in turn (even hidden ones), are
    impossible: the T's at 25 and 34 are two occurrences apart and give V and S.

What the clues force. Inside a clue block the next occurrence of a letter is known: E 22-31,
A 23-32, S 24-33, T 25-29-34, L 67-71, C 70-73. For any key stream these are 7 ordered key-letter
pairs that must be neighbours in W, cyclically (T gives a triple).

  part 1  dictionary key words and every 4-26 letter window of K1-K3's plaintexts as a key phrase.
          Index them by their cyclic letter pairs; for every key
          stream (A-Z, KRYPTOS, every dictionary keyword alphabet and its two transposition-mixed
          forms; 5 layouts; Vigenere, Beaufort, variant; key letter read in the plain, cipher or
          A-Z alphabet) look up the words that hold all 7 pairs. Survivors are decrypted exactly:
          start all counters at 0 (and at every rotation of the word), follow the tree of plain
          letters whose own next key letter gives the cipher letter, force the clue letters.
          Extra check, reported only: E 31-65, R 28-66, N 26-69, O 27-72 lie 1-8 key places apart.
          The "chance predicts" figure assumes independent, uniform key values. Keyword alphabets
          are near copies of each other, so real counts are clumpy; the shuffled K4s are the
          fair comparison.
          Note: the cipher is ambiguous by nature (two letters whose next key letters lead to the
          same cipher letter can swap), so a planted text comes back with a few letters swapped.
  part 2  keys of ANY letters, length 1-5 (the counter picks one of up to 5 rows): the 7 pairs
          must fit a ring of 5. Same decryption.
  part 3  counters restart at each row: rows of every width 2-48 with every first-row length (the
          carved rows are width 31, first row 4). A restart inside a clue block makes the counts
          known outright, so whole groups of clue letters must share one key value. Tests with 6+
          checks; any key letters. Survivors: every dictionary word that fits, decrypted.
  part 4  the counter picks one of 3 or 4 DIFFERENT fixed alphabets (each a keyword alphabet at
          some shift, direct or reversed). For 3: the three T's need three alphabets that explain
          all 24 clue letters between them, so two of them explain 16+; exact join. For 4: only
          the bound (best three T alphabets + best fourth < 24) on A-Z, KRYPTOS and theme words.
          Hidden alphabets: 3 or 4 always fit the clues, so that cannot be decided.

Controls: 3 shuffled K4s, every alphabet each (the plan said a third; the test is cheap). Planted: English texts carrying K4's
own clue words, enciphered with this model, found and read back.

  python attacks/109_letter_counters.py              (--prefilter for the clue card)
"""
import collections
import itertools
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea109_cycling import (FORMS, bit_ids, build_index, chain_fits, chains, chance_per_reading,  # noqa: E402
                                     clue_keyvals, encrypt as cyc_encrypt, hidden_tableaux_possible, index_of,
                                     keyvals, label_alphabet, labels, layout, layouts, near_pairs, near_runs,
                                     readings, restart_fit, restart_plans, row_starts, short_keys, word_values)
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap, vocabulary  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1          # big-model score per quadgram a reading must beat (planted texts: about -4.3)
LMAX = 5                # part 2: any-letter keys up to this length
ROW_CHECKS = 6          # part 3: fewest checks a row test must have (the carved rows have exactly 6)
ANCH_MIN = 6            # part 4: smallest alphabet (clue letters explained) kept for the join
FORM_NAME = {"vig": "Vigenere", "beau": "Beaufort", "var": "variant Beaufort"}
_S = {}


def key_words():
    """Dictionary and theme words of 3+ letters, plus every 4-26 letter window of K1-K3's plaintexts."""
    return sorted(set(w for w in vocabulary() if len(w) >= 3) | set(wordkeys.phrase_windows()))


def small_alphabets():
    out, seen = [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)], {AZ, KRYPTOS_ALPHABET}
    for w in wordkeys.theme_words():
        m = keyword_alphabet(w)
        if m not in seen:
            seen.add(m)
            out.append((w, m))
    return out


# ---- the scan (runs in the pool) ----------------------------------------------------------------

def init(ct, cribs, words, need=None):
    pos = sorted(cribs)
    chs = chains(cribs)
    _S["pl"] = [cribs[i] for i in pos]
    _S["cl"] = [ct[i] for i in pos]
    _S["near"] = near_pairs(chs)
    _S["bits"], _S["cnts"] = build_index(words) if words else ([0] * 676, [0] * 676)
    plans = restart_plans(cribs, len(ct), min_checks=ROW_CHECKS)
    first = {}
    for eqs in plans:
        first.setdefault(eqs[0], []).append(eqs)
    _S["first"] = first
    tri = [r for r in near_runs(chs) if len(r) >= 3]
    _S["anchors"] = tri[0][:3] if tri else []
    _S["need"] = need


def work(chunk):
    """One pass over a list of (name, alphabet). Returns counts and everything that passed a test."""
    pl, cl, near, bits, cnts = _S["pl"], _S["cl"], _S["near"], _S["bits"], _S["cnts"]
    first, anchors, need = _S["first"], _S["anchors"], _S["need"]
    nread = nstream = 0
    word_hits, short, rows, anch, third = [], [], [], [], []
    hist = [0] * (len(pl) + 1)
    amax = [0] * len(anchors)
    for name, m in chunk:
        for lay, a, b in layouts(m):
            ia, ib = index_of(a), index_of(b)
            pa, cb = [ia[c] for c in pl], [ib[c] for c in cl]
            tabs = [(ln, [ord(c) - 65 for c in la]) for ln, la in labels(a, b)]
            for form in FORMS:
                k = keyvals(pa, cb, form)
                if need is None and near:
                    for ln, tab in tabs:                    # part 1: dictionary words holding all the pairs
                        nread += 1
                        codes = sorted((tab[k[i]] * 26 + tab[k[j]] for i, j in near), key=cnts.__getitem__)
                        x = bits[codes[0]]
                        for c in codes[1:]:
                            if not x:
                                break
                            x &= bits[c]
                        if x:
                            word_hits.append((name, m, lay, form, ln, bit_ids(x)))
                if form == "var":                           # same equalities as vig
                    continue
                nstream += 1
                g = {}
                for j, v in enumerate(k):
                    g.setdefault(v, []).append(j)
                if need is not None:                        # part 4, second pass: the third alphabet
                    for an, mask in need:
                        got = sum(1 << j for j in g[k[anchors[an]]])
                        if got & mask == mask:
                            third.append((an, mask, name, lay, form, k[anchors[an]]))
                    continue
                hist[max(len(x) for x in g.values())] += 1
                for an, t in enumerate(anchors):            # part 4: one fixed alphabet through each T
                    grp = g[k[t]]
                    if len(grp) > amax[an]:
                        amax[an] = len(grp)
                    if len(grp) >= ANCH_MIN:
                        anch.append((an, sum(1 << j for j in grp), len(grp), name, lay, form, k[t]))
                eq = set()
                for grp in g.values():
                    if len(grp) > 1:
                        eq.update(itertools.combinations(grp, 2))
                for e in eq:                                # part 3: restarts
                    for eqs in first.get(e, ()):
                        if all(x in eq for x in eqs):
                            rows.append((name, m, lay, form, k, eqs))
                if near and len(set((k[i], k[j]) for i, j in near)) <= LMAX:
                    short.append((name, m, lay, form, k))   # part 2: candidates for a short ring
    return nread, nstream, word_hits, short, rows, anch, hist, amax, third


def search(ct, cribs, alphabets, words, need=None, pool=True):
    out = {"nread": 0, "nstream": 0, "word_hits": [], "short": [], "rows": [], "anch": [],
           "hist": collections.Counter(), "amax": [0, 0, 0], "third": []}
    if pool:
        results = pmap(work, alphabets, init, (ct, cribs, words, need), chunk=1000)
    else:
        init(ct, cribs, words, need)
        results = [work(alphabets)]
    for nread, nstream, wh, sh, rw, an, hist, amax, third in results:
        out["nread"] += nread
        out["nstream"] += nstream
        out["word_hits"] += wh
        out["short"] += sh
        out["rows"] += rw
        out["anch"] += an
        out["third"] += third
        for n, c in enumerate(hist):
            if c:
                out["hist"][n] += c
        out["amax"] = [max(x, y) for x, y in zip(out["amax"], list(amax) + [0, 0, 0])]
    return out


# ---- judging the survivors (main process) -------------------------------------------------------

def best_reading(ct, cribs, a, b, form, wv, big, starts=(), rotate=True):
    """Best (english, text, rotation) over the rotations of the key, or None if no text holds the clues."""
    best, seen = None, set()
    for r in range(len(wv) if rotate else 1):
        w = tuple(wv[r:] + wv[:r])
        if w in seen:
            continue
        seen.add(w)
        got = readings(ct, a, b, form, list(w), cribs, big.logp, big.floor, starts)
        if got and (best is None or got[0][0] > best[0]):
            best = (got[0][0], got[0][1], r)
    return best


def judge_words(res, ct, cribs, words, big):
    """Part 1. Returns (counts, [(english, text, description)])."""
    chs = chains(cribs)
    c = collections.Counter()
    out = []
    for name, m, lay, form, lab, ids in res["word_hits"]:
        a, b = layout(m, lay)
        la = label_alphabet(a, b, lab)
        k = clue_keyvals(ct, cribs, a, b, form)
        for wid in ids:
            c["pairs"] += 1
            wv = word_values(words[wid], la)
            if not chain_fits(wv, k, chs, far=False):
                continue
            c["chains"] += 1
            far = chain_fits(wv, k, chs, far=True)
            c["far"] += far
            got = best_reading(ct, cribs, a, b, form, wv, big)
            if got:
                c["read"] += 1
                out.append((got[0], got[1], "key word %s (start at letter %d) on %s %s, %s, key letters in the %s "
                            "alphabet; gap check %s" % (words[wid], got[2] + 1, name, lay, FORM_NAME[form], lab,
                                                        "ok" if far else "fails")))
    return c, sorted(out, reverse=True)


def judge_short(res, ct, cribs, big):
    """Part 2: keys of any letters, length <= LMAX."""
    chs = chains(cribs)
    c = collections.Counter()
    out = []
    for name, m, lay, form, k in res["short"]:
        a, b = layout(m, lay)
        keys = short_keys(k, chs, LMAX)
        c["streams"] += bool(keys)
        for w in keys:
            c["keys"] += 1
            holes = [i for i, v in enumerate(w) if v is None]
            if len(holes) > 2:
                c["unread"] += 1
                continue
            for fill in itertools.product(range(26), repeat=len(holes)):
                wv = list(w)
                for i, v in zip(holes, fill):
                    wv[i] = v
                got = best_reading(ct, cribs, a, b, form, wv, big)
                if got:
                    c["read"] += 1
                    out.append((got[0], got[1], "key values %s (length %d, any letters, start %d) on %s %s, %s"
                                % (wv, len(wv), got[2] + 1, name, lay, FORM_NAME[form])))
    return c, sorted(out, reverse=True)


def judge_rows(res, ct, cribs, words, big, plans):
    """Part 3: counters restart at each row. Returns (counts by checks, [(english, text, description)])."""
    c = collections.Counter()
    out = []
    for name, m, lay, form, k, eqs in res["rows"]:
        checks, groups, widths = plans[eqs]
        c[checks] += 1
        a, b = layout(m, lay)
        for f, kk in ((form, k),) + ((("var", [(-v) % 26 for v in k]),) if form == "vig" else ()):
            for ln, la in labels(a, b):
                known = [(n, la[kk[g[0]]]) for n, g in groups.items()]
                for w in words:
                    L = len(w)
                    if all(w[n % L] == ch for n, ch in known):
                        c["words"] += 1
                        wv = word_values(w, la)
                        for width, o in widths:
                            st = row_starts(width, o, len(ct))
                            if not restart_fit(wv, kk, cribs, st):
                                continue
                            c["fit"] += 1
                            got = best_reading(ct, cribs, a, b, f, wv, big, st, False)
                            if got:
                                c["read"] += 1
                                out.append((got[0], got[1], "key word %s, counters restart every %d letters "
                                            "(first row %d), on %s %s, %s, key letters in the %s alphabet"
                                            % (w, width, o or width, name, lay, FORM_NAME[f], ln)))
    return c, sorted(out, reverse=True)


def join_three(anch, full):
    """Part 4: pairs of fixed alphabets through two different T's that explain 16+ of the 24 clue
    letters between them. Three alphabets that explain all 24 must hold such a pair: the largest
    explains 8+, the smallest at most 8, so the other two explain 16+ together; and the second
    explains ANCH_MIN+ as long as none explains 13+ (the caller checks that)."""
    out = []
    big = [x for x in anch if x[2] >= 8]
    for x in big:
        for y in anch:
            if y[0] != x[0] and (y[2] < 8 or x < y) and bin(x[1] | y[1]).count("1") >= 16:
                rest = full & ~(x[1] | y[1])
                out.append((x, y, ({0, 1, 2} - {x[0], y[0]}).pop(), rest))
    return out


def judge_three(res, ct, cribs, alphabets, words, pool=True):
    """Returns (pairs found, full sets of three found)."""
    full = (1 << len(cribs)) - 1
    pairs = join_three(res["anch"], full)
    if not pairs:
        return 0, []
    need = sorted(set((an, rest) for _, _, an, rest in pairs))
    got = search(ct, cribs, alphabets, None, need=need, pool=pool)["third"]
    have = collections.defaultdict(list)
    for t in got:
        have[t[0], t[1]].append(t[2:])
    return len(pairs), [(x[3:], y[3:], z) for x, y, an, rest in pairs for z in have.get((an, rest), ())]


def run_all(label, ct, cribs, alphabets, words, big, plans, per_reading, quiet=False, pool=True):
    """Every part on one ciphertext. Returns a summary dict (and prints it)."""
    res = search(ct, cribs, alphabets, words, pool=pool)
    wc, wout = judge_words(res, ct, cribs, words, big)
    sc, sout = judge_short(res, ct, cribs, big)
    rc, rout = judge_rows(res, ct, cribs, words, big, plans)
    npairs, threes = judge_three(res, ct, cribs, alphabets, words, pool)
    allr = sorted(wout + sout + rout, reverse=True)
    lo = ROW_CHECKS
    row_by = {"%d" % lo: rc[lo], "%d+" % (lo + 1): sum(v for n, v in rc.items() if isinstance(n, int) and n > lo)}
    row_exp = {"%d" % lo: res["nstream"] * sum(26.0 ** -p[0] for p in plans.values() if p[0] == lo),
               "%d+" % (lo + 1): res["nstream"] * sum(26.0 ** -p[0] for p in plans.values() if p[0] > lo)}
    s = {"label": label, "res": res, "nread": res["nread"], "nstream": res["nstream"],
         "pairs": wc["pairs"], "chains": wc["chains"], "far": wc["far"], "read_words": wc["read"],
         "expect": res["nread"] * per_reading, "short_streams": sc["streams"], "short_keys": sc["keys"],
         "short_read": sc["read"], "short_unread": sc["unread"], "rows": row_by, "rows_expect": row_exp,
         "row_words": rc["fit"], "row_read": rc["read"], "three_pairs": npairs, "threes": threes,
         "amax": res["amax"], "gmax": max(res["hist"]) if res["hist"] else 0,
         "readings": allr, "best": allr[0][0] if allr else -99.0,
         "wout": wout, "sout": sout, "rout": rout}
    if not quiet:
        print("%s: %d alphabets, %d key-stream readings (each against %d words), %d key streams"
              % (label, len(alphabets), s["nread"], len(words), s["nstream"]))
        print("   part 1 word keys: %d (word, reading) hold all the neighbour pairs; %d hold the chains exactly "
              "[chance predicts %.1f]; %d of those pass the 1-8 gap check; %d give a text that holds the clues"
              % (s["pairs"], s["chains"], s["expect"], s["far"], s["read_words"]))
        print("   part 2 any-letter keys up to %d: %d key streams fit a ring (%d keys); %d give a text that holds "
              "the clues%s" % (LMAX, s["short_streams"], s["short_keys"], s["short_read"],
                               "; %d with 3+ free letters not read" % s["short_unread"] if s["short_unread"] else ""))
        print("   part 3 row restarts: passes by checks %s [chance predicts %s]; %d (word, row width) fit the clue letters; "
              "%d give a text that holds the clues"
              % (" ".join("%s:%d" % x for x in row_by.items()),
                 " ".join("%s:%.2f" % x for x in row_exp.items()), s["row_words"], s["row_read"]))
        print("   part 4 fixed alphabets: most clue letters one alphabet explains through each T %s, anywhere %d; "
              "pairs explaining 16+: %d; full sets of three: %d"
              % (s["amax"], s["gmax"], npairs, len(threes)))
        print("   texts that hold all 24 clue letters: %d; best english %.2f (needs %.1f)"
              % (len(allr), s["best"], ENGLISH))
    return s


def agree(x, y):
    return len(x) == len(y) and sum(a == b for a, b in zip(x, y))


def same_text(x, y):
    """The cipher is ambiguous by nature (two letters whose next key letters lead to the same cipher
    letter can swap), so a reading counts as the planted text when 85+ of 97 letters agree."""
    return agree(x, y) >= 0.875 * len(y)


# ---- planted messages ---------------------------------------------------------------------------

def spliced(rng):
    """English text carrying K4's own clue words at K4's places."""
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


def planted_word(rng, big, words, sample, plans, per_reading, label, name, m, lay, form, lab, word, natural=False):
    """Plant a dictionary key word, run the whole search, read back. Found = the best text is the
    planted one, it reads as English, and it came from the planted word."""
    a, b = layout(m, lay)
    if natural:
        while True:
            pt = english97(rng)
            cribs = {i: pt[i] for i in POS}
            if len(near_pairs(chains(cribs))) >= 5:
                break
    else:
        pt, cribs = spliced(rng), dict(CRIBS)
    ct = cyc_encrypt(pt, a, b, form, word_values(word, label_alphabet(a, b, lab)))
    pl = plans if not natural else restart_plans(cribs, len(ct), min_checks=ROW_CHECKS)
    per = per_reading if not natural else chance_per_reading(words, chains(cribs))
    s = run_all("planted " + label, ct, cribs, sample + [(name, m)], words, big, pl, per, quiet=True)
    top = s["wout"][0] if s["wout"] else (-99.0, "", "")
    other = sum(1 for r in s["readings"] if not same_text(r[1], pt))
    ok = same_text(top[1], pt) and top[0] > ENGLISH and ("key word %s " % word) in top[2] and s["best"] == top[0]
    print("planted %s: key word %s on %s %s, %s, key letters in the %s alphabet; %d alphabets, %d readings; "
          "%d (word, reading) hold the pairs, %d the chains [chance %.1f], %d give a text holding the clues; "
          "best english %.2f, agrees with the planted text on %d of %d letters; texts reading something else: %d -> %s"
          % (label, word, name, lay, FORM_NAME[form], lab, len(sample) + 1, s["nread"], s["pairs"], s["chains"],
             s["expect"], s["read_words"], top[0], agree(top[1], pt), len(pt), other, "ok" if ok else "MISSED"))
    return ok


def planted_short(rng, big, words, sample, plans, per_reading, name, m, lay, form, wv):
    a, b = layout(m, lay)
    pt = spliced(rng)
    ct = cyc_encrypt(pt, a, b, form, wv)
    s = run_all("planted short", ct, CRIBS, sample + [(name, m)], words, big, plans, per_reading, quiet=True)
    top = s["sout"][0] if s["sout"] else (-99.0, "", "")
    ok = same_text(top[1], pt) and top[0] > ENGLISH and s["best"] == top[0]
    print("planted any-letter key %s (length %d, not a word) on %s %s, %s: %d key streams fit a ring, %d give a "
          "text holding the clues; best english %.2f, agrees with the planted text on %d of %d letters -> %s"
          % (wv, len(wv), name, lay, FORM_NAME[form], s["short_streams"], s["short_read"], top[0],
             agree(top[1], pt), len(pt), "ok" if ok else "MISSED"))
    return ok


def planted_rows(rng, big, words, sample, plans, per_reading, name, m, lay, form, lab, word, width, o):
    a, b = layout(m, lay)
    pt = spliced(rng)
    ct = cyc_encrypt(pt, a, b, form, word_values(word, label_alphabet(a, b, lab)), row_starts(width, o))
    s = run_all("planted rows", ct, CRIBS, sample + [(name, m)], words, big, plans, per_reading, quiet=True)
    top = s["rout"][0] if s["rout"] else (-99.0, "", "")
    ok = (same_text(top[1], pt) and top[0] > ENGLISH and s["best"] == top[0]
          and any(("key word %s," % word) in r[2] and same_text(r[1], pt) for r in s["rout"])
          and all(same_text(r[1], pt) for r in s["readings"]))
    print("planted row restart: key word %s, rows of %d (first row %d), on %s %s, %s: row tests passed %s, %d "
          "(word, width) fit, %d give a text holding the clues (all the planted text; short rows use only the "
          "first letters of the word); best english %.2f, agrees with the planted text on %d of %d letters -> %s"
          % (word, width, o or width, name, lay, FORM_NAME[form], dict((k, v) for k, v in s["rows"].items() if v),
             s["row_words"], s["row_read"], top[0], agree(top[1], pt), len(pt), "ok" if ok else "MISSED"))
    return ok


def planted_three(rng, sample, words, tabs):
    """Three different fixed alphabets taken in turn by the letter's own counter. Found = the join
    names the three planted alphabets. tabs: [(name, alphabet, layout, form, key value)] x 3."""
    pt = spliced(rng)
    cnt, out = {}, []
    for ch in pt:
        n = cnt.get(ch, 0)
        cnt[ch] = n + 1
        name, m, lay, form, kv = tabs[n % 3]
        a, b = layout(m, lay)
        out.append(cyc_encrypt(ch, a, b, form, [kv]))
    ct = "".join(out)
    alphabets = sample + [(t[0], t[1]) for t in tabs]
    res = search(ct, CRIBS, alphabets, None)
    npairs, threes = judge_three(res, ct, CRIBS, alphabets, None)
    want = set((t[0], t[2], t[3], t[4]) for t in tabs)
    ok = any(set(tuple(x) for x in t) == want for t in threes)
    print("planted three fixed alphabets (%s): %d pairs explain 16+, %d full sets of three, the planted set "
          "among them: %s -> %s" % (", ".join("%s %s %s" % (t[0], t[2], t[3]) for t in tabs), npairs, len(threes),
                                    ok, "ok" if ok else "MISSED"))
    return ok


# ---- proofs -------------------------------------------------------------------------------------

def proofs(ct=K4, cribs=CRIBS):
    """The one-line impossibilities, checked on the letters. Returns {name: True if impossible}."""
    c = lambda i: ct[i - 1]                                   # noqa: E731  (1-based, as in the text above)
    return {
        "common numeric step per occurrence": c(25) == c(67) and c(29) != c(71),
        "counters restart at each word": c(22) != c(31),
        "key of 1 or 2 letters / 2 tableaux in turn": c(25) != c(34)
        and not hidden_tableaux_possible(1, ct, cribs) and not hidden_tableaux_possible(2, ct, cribs),
        "3 hidden tableaux": not hidden_tableaux_possible(3, ct, cribs),
        "4 hidden tableaux": not hidden_tableaux_possible(4, ct, cribs),
    }


def encrypt(pt, rng):
    """For the clue pre-filter: a key word on the KRYPTOS tableau, each letter with its own counter."""
    word = rng.choice(["PALIMPSEST", "ABSCISSA", "SHADOW", "BERLINCLOCK", "LODESTONE", "ILLUSION"])
    form = rng.choice(FORMS)
    return cyc_encrypt(pt, KRYPTOS_ALPHABET, KRYPTOS_ALPHABET, form, word_values(word, KRYPTOS_ALPHABET))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("each plain letter keeps its own place in the key word", encrypt=encrypt,
                  marks={"hand": ("pass", "paper tableau, a key word and a tally per letter")})
        sys.exit(0)
    words = key_words()
    alphabets = dictionary_alphabets(mixed=True)
    small = small_alphabets()
    if SMOKE:
        alphabets = alphabets[:6000]
    plans = restart_plans(CRIBS, len(K4), min_checks=ROW_CHECKS)
    chs = chains(CRIBS)
    per_reading = chance_per_reading(words, chs)
    carved = next(e for e, p in plans.items() if (31, 4) in p[2])
    with Experiment("each plain letter keeps its own place in the key word (homophone cycling)", puzzle="k4",
                    notes="exact tests on the clue letters; %d alphabets (A-Z, KRYPTOS, dictionary keyword + 2 mixed "
                          "forms) x 5 layouts x Vig/Beau/variant x key-letter alphabet; %d key words and K1-K3 phrases by a "
                          "cyclic-pair index; any-letter keys to length %d; row restarts (%d tests, widths 2-48); "
                          "3 or 4 fixed alphabets in turn; 3 shuffled K4s on every alphabet"
                          % (len(alphabets), len(words), LMAX, len(plans)), cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        pr = proofs()
        print("proofs (True = impossible for every tableau):")
        for name, dead in pr.items():
            print("   %-46s %s" % (name, dead))
        print("neighbour pairs the clues force: %d (%s); key words: %d; chance per reading that some word holds "
              "the chains: %.3g" % (len(near_pairs(chs)), " ".join("-".join(str(POS[j] + 1) for j in r)
                                                                   for r in near_runs(chs)), len(words), per_reading))
        print("row-restart tests: %d distinct with %d+ checks (the carved rows 4+31+31+31 have %d)"
              % (len(plans), ROW_CHECKS, plans[carved][0]))
        k4 = run_all("K4", K4, CRIBS, alphabets, words, big, plans, per_reading)
        ex.count(k4["nread"] * len(words))
        for sc, pt, how in k4["readings"][:12]:
            print("   english %.2f words %.2f  %s\n      %s" % (sc, word_coverage(pt), how, pt))
            ex.add(pt, english_big=round(sc, 3), setting=how)
        carved_k4 = sum(1 for r in k4["res"]["rows"] if r[5] == carved)
        sm = search(K4, CRIBS, small, None, pool=False)
        bound4 = sum(sm["amax"]) + max(sm["hist"])
        print("4 fixed alphabets from A-Z, KRYPTOS and %d theme alphabets: the best through each T explain %s clue "
              "letters, the best anywhere %d: at most %d of 24 -> %s"
              % (len(small) - 2, sm["amax"], max(sm["hist"]), bound4, "impossible" if bound4 < 24 else "not decided"))
        ctrl = []
        for seed in (1, 2, 3):                              # cheap enough to give each control every alphabet
            ctrl.append(run_all("shuffled K4 seed %d" % seed, shuffled_control(seed), CRIBS, alphabets, words, big,
                                plans, per_reading))
        rng = random.Random(109)
        sample = alphabets[2::10 if SMOKE else 40]
        names = dict(alphabets)
        pick = [x for x in alphabets if "~" not in x[0] and len(x[0]) >= 6]
        d1, d2, d3 = pick[len(pick) // 3], pick[len(pick) // 2], pick[2 * len(pick) // 3]
        mixed = next(x for x in alphabets[len(alphabets) // 2:] if x[0].endswith("~keyed"))
        ok = tot = 0
        for case in (("7-letter word, dictionary tableau", d1[0], d1[1], "M/M", "vig", "plain", "COMPASS"),
                     ("10-letter word, mixed dictionary tableau", mixed[0], mixed[1], "AZ/M", "beau", "plain",
                      "PALIMPSEST"),
                     ("8-letter word, KRYPTOS tableau, natural text", "KRYPTOS", KRYPTOS_ALPHABET, "KR/KR", "var",
                      "plain", "ABSCISSA", True)):
            ok += planted_word(rng, big, words, sample, plans, per_reading, *case)
            tot += 1
        ok += planted_short(rng, big, words, sample, plans, per_reading, d2[0], d2[1], "M/KR", "vig", [7, 19, 2, 24])
        ok += planted_rows(rng, big, words, sample, plans, per_reading, d3[0], d3[1], "M/M", "beau", "plain",
                           "SHADOW", 31, 4)
        ok += planted_three(rng, sample, words, [(d1[0], d1[1], "M/M", "vig", 5), (d2[0], d2[1], "AZ/M", "beau", 11),
                                                 ("KRYPTOS", KRYPTOS_ALPHABET, "KR/KR", "vig", 20)])
        tot += 3
        print("planted recovered: %d/%d" % (ok, tot))
        cbest = max(c["best"] for c in ctrl)
        beats = k4["best"] > ENGLISH and k4["best"] > cbest + 0.3
        print("VERDICT:", ("K4 beats every control - inspect; " if beats else "no signal; ") +
              "K4: %d word keys hold the chains (chance %.1f), %d any-letter rings, row tests %s (carved rows %d), "
              "%d sets of three alphabets, %d texts hold the clues, best english %.2f; shuffled K4s: word keys %s "
              "(chance %s), rings %s, row tests %s, sets of three %s, texts %s, best english %s (English needs %.1f; "
              "-99 = nothing to read)"
              % (k4["chains"], k4["expect"], k4["short_streams"], dict((a, b) for a, b in k4["rows"].items() if b),
                 carved_k4, len(k4["threes"]), len(k4["readings"]), k4["best"], [c["chains"] for c in ctrl],
                 ["%.1f" % c["expect"] for c in ctrl], [c["short_streams"] for c in ctrl],
                 [dict((a, b) for a, b in c["rows"].items() if b) for c in ctrl], [len(c["threes"]) for c in ctrl],
                 [len(c["readings"]) for c in ctrl], ["%.2f" % c["best"] for c in ctrl], ENGLISH))
