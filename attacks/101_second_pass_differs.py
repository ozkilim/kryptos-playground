"""Idea 101: the key word comes round a second time, but the second pass differs.

K1's key PALIMPSEST is a sheet written over a second time; K2 ends LAYER TWO; Sanborn said the
lower half uses two separate systems. A hand encoder who changes something each time the key
word comes round gives a key that repeats only after TWO passes. A repeating-key test at the
word's own length sees nothing, and the doubled length (28-48 for a word of 14-24) has too few
clue letters per key slot for the plain test. But the rule that links the two passes halves the
unknowns again, so the clue letters still give 7 or more exact checks.

What is tested, on every keyword tableau (A-Z, KRYPTOS, the dictionary keyword alphabets and
their two transposition-mixed forms; five layouts M/M, M/AZ, AZ/M, M/KR, KR/M):

  mirror   the word is read forwards, then backwards: key stream u[x] = u[(c - x) mod T].
           T = 16..52 with EVERY c (so every start letter, and all three ways to turn round:
           ABCDDCBA, ABCDCB, ABCDDCB), also with the count restarting at each carved row, and
           T = none: one fold over the whole text (a long key written out and then back).
  slide    the same for a strip that is moved on by the word (the steps mirror, not the values).
  period   plain repeating key of length 18..52, the baseline the mirror rule halves.
  alt      the same word every pass, the form alternates by pass: Vigenere/Beaufort,
           Vigenere/variant, Beaufort/variant, Beaufort/minus-Beaufort; word length 2..52,
           every start letter, either form first; also restarting at each carved row.
  shift    odd passes use the word moved along the alphabet by one free constant (1..25).
  tab      the same word every pass, the tableau alternates by pass between the keyword tableau
           and A-Z or KRYPTOS (key letter found on each tableau's own alphabet, or by its A-Z row
           label), every pairing of Vigenere/Beaufort/variant on the two tableaux.

The test (kryptos/idea101_passes.py). Each setting says which clue letters must show the same
key letter. Checks = clue letters tied - key slots they touch (one less for "shift": the
constant is free). Only settings with 7+ checks count; 5-6 checks are kept as a chance gauge
(a setting with n checks passes by chance about 26^-n of the time). Settings that tie the clue
letters in exactly the same way are one test; all of them are read when it passes.

Survivors: the forced key letters are filled in, all 97 letters are decrypted ('?' where the key
is not reached) and the letters OUTSIDE the clues are scored on the big English model.

  python attacks/101_second_pass_differs.py            (--prefilter for the clue card)
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
from kryptos import idea101_passes as ip  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

MIN_CHECKS = 7          # the headline bar (as in rounds 9-11)
GAUGE = 5               # 5-6 checks: counted only, to compare with chance
ENGLISH = -5.1          # big-model score per quadgram a reading must beat (planted texts: about -4.3)
MIN_NEW = 10            # quadgrams outside the clue words needed before a reading is judged
FAMS = ("mirror", "slide", "period", "alt", "shift", "tab")
FORM = {"V": "Vigenere", "B": "Beaufort", "N": "variant", "O": "minus-Beaufort"}
INBLOCK = set(POS)
_S = {}


def tests():
    if "tests" not in _S:
        _S["tests"] = ip.catalogue(GAUGE)
    return _S["tests"]


def init(ct, cribs):
    _S["pl"] = [cribs[i] for i in POS]
    _S["cl"] = [ct[i] for i in POS]
    _S["ea"] = ip.EngineA(tests())
    _S["ec"] = ip.EngineC(tests(), _S["pl"], _S["cl"])


def work(chunk):
    """-> (alphabets, layouts scanned, [(checks, name, alphabet, layout or "tab", test index)])."""
    tt, pl, cl, ea, ec, hits, nl = tests(), _S["pl"], _S["cl"], _S["ea"], _S["ec"], [], 0
    for name, m in chunk:
        nl += len(ip.layouts(m))
        for lay, tid in ip.scan_alphabet(m, pl, cl, ea, ec, tt):
            hits.append((tt[tid].checks, name, m, lay, tid))
    return len(chunk), nl, hits


def search(ct, cribs, alphabets):
    n, nl, hits = 0, 0, []
    for k, l, h in pmap(work, alphabets, init, (ct, cribs), chunk=1000):
        n += k
        nl += l
        hits.extend(h)
    return n, nl, sorted(hits, key=lambda h: (-h[0], h[1], h[3], h[4]))


def headline(hits):
    return [h for h in hits if h[0] >= MIN_CHECKS]


def sizes():
    """Tests per layout (engine A) and per alphabet (tableau alternation), at 7+ checks and in the gauge."""
    tt = tests()
    return {"A7": sum(t.eng == "A" and t.checks >= MIN_CHECKS for t in tt),
            "C7": sum(t.eng == "C" and t.checks >= MIN_CHECKS for t in tt),
            "Ag": sum(t.eng == "A" and t.checks < MIN_CHECKS for t in tt),
            "Cg": sum(t.eng == "C" and t.checks < MIN_CHECKS for t in tt)}


def chance(n, nl):
    """Passes chance predicts if every check were an independent 1-in-26: {checks: count} for 5, 6, 7
    and 8 (= 8 or more). A rough guide; the shuffled K4s are the real yardstick."""
    out = collections.Counter()
    for t in tests():
        out[min(t.checks, 8)] += (nl if t.eng == "A" else n) * 26.0 ** -t.checks
    return out


def by_checks(hits):
    c = collections.Counter(h[0] for h in hits)
    return " ".join("%d:%d" % (k, c[k]) for k in sorted(c)) or "none"


def ctx_of(hit, st):
    return ("tab", hit[2], st[1]) if st[0] == "tab" else ip.layout_ctx(hit[2], hit[3])


def read_score(pt, big):
    """(big-model score per quadgram, quadgrams) over the fully known quadgrams that are not
    wholly inside the clue words; -99 if fewer than MIN_NEW of them."""
    q = [pt[i:i + 4] for i in range(len(pt) - 3)
         if "?" not in pt[i:i + 4] and not all(j in INBLOCK for j in range(i, i + 4))]
    return (sum(big.logp.get(x, big.floor) for x in q) / len(q) if len(q) >= MIN_NEW else -99.0), len(q)


def complete(hit, ct, cribs, big):
    """A survivor -> [(english, new quadgrams, text, key, setting)] for every setting it stands for."""
    out = []
    for st in tests()[hit[4]].aliases:
        ctx = ctx_of(hit, st)
        sol = ip.solve(st, ctx, ct, cribs)
        assert sol is not None, ("fast and slow test disagree", hit[:2], hit[3], st)
        pt = ip.decrypt(st, ctx, ct, sol)
        assert all(pt[i] == cribs[i] for i in cribs)
        sc, nq = read_score(pt, big)
        out.append((sc, nq, pt, ip.key_text(st, sol), st))
    return out


def complete_all(hits, ct, cribs, big, limit=3000):
    out = []
    for h in hits[:limit]:
        for sc, nq, pt, key, st in complete(h, ct, cribs, big):
            out.append((sc, nq, pt, key, st, h))
    return sorted(out, key=lambda r: (-r[0], -r[5][0], r[2]))


def start_of(T, c):
    """(letters of the word, end letters written twice, a letter count where a forward word starts)."""
    if T % 2:
        return (T + 1) // 2, 1, (c * (T + 1) // 2) % T
    if c % 2:
        return T // 2, 2, ((c + 1) // 2) % (T // 2)
    return T // 2 + 1, 0, (c // 2) % (T // 2)


def describe(st, hit):
    fam = st[0]
    where = "tableau %s" % hit[1] if fam == "tab" else "%s, layout %s" % (hit[1], hit[3])
    rows = lambda lp: "count restarts at each carved row" if lp else "counted through the whole text"  # noqa: E731
    if fam in ("mirror", "slide"):
        _, f, lp, T, c = st
        what = "key read back and forth" if fam == "mirror" else "strip moved by a word read back and forth"
        if not T:
            return "%s, one fold over the text: letter x pairs with letter %d - x; %s; %s" % (what, c + 2, FORM[f], where)
        L, ends, o = start_of(T, c)
        return ("%s: word of %d, %d end letter(s) doubled, period %d, a forward word starts at count %d, %s; %s; %s"
                % (what, L, ends, T, o + 1, rows(lp), FORM[f], where))
    if fam == "period":
        return "plain repeating key of length %d; %s; %s" % (st[2], FORM[st[1]], where)
    lp, L, o = st[-3:]
    pos = "word of %d, first pass starts at count %d, %s" % (L, o + 1, rows(lp))
    if fam == "alt":
        return "form alternates by pass, %s then %s: %s; %s" % (FORM[st[1][0]], FORM[st[1][1]], pos, where)
    if fam == "shift":
        return "odd passes use the word moved by a constant: %s; %s; %s" % (pos, FORM[st[1]], where)
    return ("tableau alternates by pass, keyword tableau (%s) then %s (%s), key letter by %s: %s; %s"
            % (FORM[st[3][0]], st[2], FORM[st[3][1]], "its own alphabet" if st[1] == "own" else "A-Z row label",
               pos, where))


# ---- planted messages -------------------------------------------------------------------------

def nums(word, alpha):
    return [alpha.index(ch) for ch in word]


def planted_cases(rng, dic):
    """[(label, plaintext, ciphertext, true alphabet (name, m), layout or "tab", true setting)]."""
    pick = lambda: dic[rng.randrange(2, len(dic))]  # noqa: E731
    out = []
    # 1. a 16-letter phrase read back and forth (ABCDDCBA, period 32) on a dictionary tableau
    n, m = pick()
    ks, T, c = ip.mirror_stream(nums("SHADOWSANDLIGHTS", m), 2, 0)
    pt = english97(rng)
    out.append(("16-letter phrase SHADOWSANDLIGHTS read back and forth (period 32), Vigenere, dictionary tableau",
                pt, ip.encrypt_stream(pt, m, m, "V", ks), (n, m), "M/M", ("mirror", "V", 0, T, c)))
    # 2. an 11-letter word alternating Vigenere and Beaufort on the KRYPTOS tableau
    pt = english97(rng)
    out.append(("11-letter word PALIMPSESTS, Vigenere and Beaufort by turns, KRYPTOS tableau",
                pt, ip.encrypt_alt(pt, KRYPTOS_ALPHABET, KRYPTOS_ALPHABET, "VB", nums("PALIMPSESTS", KRYPTOS_ALPHABET), 0),
                ("KRYPTOS", KRYPTOS_ALPHABET), "M/M", ("alt", ("V", "B"), 0, 11, 0)))
    # 3. a 9-letter word alternating between a dictionary tableau and A-Z
    n, m = pick()
    pt = english97(rng)
    out.append(("9-letter word LODESTONE, dictionary tableau and A-Z by turns (Vigenere both, key letter on its own alphabet)",
                pt, ip.encrypt_tab(pt, m, "AZ", "own", "VV", "LODESTONE", 0), (n, m), "tab",
                ("tab", "own", "AZ", ("V", "V"), 0, 9, 0)))
    # 4. a strip moved by a 10-letter word read back and forth without doubled ends (period 18)
    n, m = pick()
    ks, T, c = ip.mirror_stream(nums("BERLINWALL", AZ), 0, 5)
    pt = english97(rng)
    out.append(("strip moved by 10-letter word BERLINWALL read back and forth (period 18, from letter 6), Beaufort, "
                "dictionary plain alphabet against A-Z", pt, ip.encrypt_slide(pt, m, AZ, "B", ks, 3), (n, m), "M/AZ",
                ("slide", "B", 0, T, c)))
    # 5. an 8-letter word, odd passes moved by 7, count restarting at each carved row
    n, m = pick()
    pt = english97(rng)
    out.append(("8-letter word ILLUSION, odd passes moved 7 along, restart at carved rows, KRYPTOS plain against a "
                "dictionary cipher alphabet", pt, ip.encrypt_shift(pt, KRYPTOS_ALPHABET, m, "V", nums("ILLUSION", m), 7, 0, 1),
                (n, m), "KR/M", ("shift", "V", 1, 8, 0)))
    # 6. a 13-letter word read back and forth without doubled ends (period 24), restart at carved rows
    n, m = pick()
    ks, T, c = ip.mirror_stream(nums("UNDERGRUENDIG"[:13], m), 0, 0, 1)
    pt = english97(rng)
    out.append(("13-letter word read back and forth (period 24), restart at carved rows, Beaufort, dictionary tableau",
                pt, ip.encrypt_stream(pt, m, m, "B", ks), (n, m), "M/M", ("mirror", "B", 1, T, c)))
    # 7. a 49-letter random key written out and then back: one fold in the middle of the text
    w = [rng.randrange(26) for _ in range(49)]
    ks = [w[min(i, 96 - i)] for i in range(97)]
    pt = english97(rng)
    out.append(("49 random key letters written out and then back (one fold at the middle letter), Vigenere, KRYPTOS "
                "plain against A-Z", pt, ip.encrypt_stream(pt, KRYPTOS_ALPHABET, AZ, "V", ks), ("KRYPTOS", KRYPTOS_ALPHABET),
                "M/AZ", ("mirror", "V", 0, 0, 96)))
    return out


def planted_case(case, sample, big):
    """Found = the true setting is a survivor, no survivor has more checks, every reading that
    scores as well or better is the planted text letter for letter, and the true reading scores
    as English (where there is enough new text to read). Other survivors are listed: settings
    the same key also satisfies pass too (a word of 8 with every other pass shifted is also a
    key of length 16), so the true setting is not always alone."""
    label, pt, ct, (name, m), lay, st = case
    cribs = {i: pt[i] for i in POS}
    alph = [x for x in sample if x[1] != m] + [(name, m)]
    n, nl, hits = search(ct, cribs, alph)
    hits = headline(hits)
    done = complete_all(hits, ct, cribs, big)
    true = [r for r in done if r[4] == st and r[5][2] == m and r[5][3] == lay]
    other = [h for h in hits if (h[2], h[3]) != (m, lay)]
    good = lambda r: all(a == b for a, b in zip(r[2], pt) if a != "?")  # noqa: E731
    known = sum(ch != "?" for ch in true[0][2]) if true else 0
    readable = bool(true) and true[0][0] > -99
    wrong_above = [r for r in done if readable and r[0] >= true[0][0] and not good(r)]
    ok = (bool(true) and good(true[0]) and true[0][5][0] == hits[0][0] and not wrong_above
          and (true[0][0] > ENGLISH or not readable))
    print("planted: %s\n   %d alphabets searched -> true setting found=%s with %d checks (most of any survivor: %d); "
          "survivors at %d+ checks: %d, of them on other tableaux/layouts: %d; letters read back %d of 97, all "
          "correct=%s; english %.2f over %d new quadgrams%s; wrong readings scoring as well: %d; key %s -> %s"
          % (label, n, bool(true), true[0][5][0] if true else 0, hits[0][0] if hits else 0, MIN_CHECKS, len(hits),
             len(other), known, bool(true) and good(true[0]), true[0][0] if true else -99, true[0][1] if true else 0,
             "" if readable else " (too few to judge: the exact checks decide alone)", len(wrong_above),
             true[0][3] if true else "-", "ok" if ok else "MISSED"))
    return ok


def prefilter_encrypt(pt, rng):
    """For the clue pre-filter: a word of 9-24 read back and forth on the KRYPTOS tableau; key from rng only."""
    word = [rng.randrange(26) for _ in range(rng.randrange(9, 25))]
    ks, _, _ = ip.mirror_stream(word, rng.choice((0, 2)), 0)
    return ip.encrypt_stream(pt, KRYPTOS_ALPHABET, KRYPTOS_ALPHABET, "V", ks[:len(pt)] if len(pt) <= 97 else
                             [ks[i % len(ks)] for i in range(len(pt))])


def report(tag, n, nl, hits):
    ch = chance(n, nl)
    c = collections.Counter(min(h[0], 8) for h in hits)
    print("%s: %d alphabets, %d layouts; passes at 5 / 6 / 7 / 8+ checks: %d / %d / %d / %d   [chance predicts about "
          "%.0f / %.1f / %.2f / %.3f]" % (tag, n, nl, c[5], c[6], c[7], c[8], ch[5], ch[6], ch[7], ch[8]))
    return c


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("key word read back and forth / second pass differs", encrypt=prefilter_encrypt)
        sys.exit(0)
    dic = dictionary_alphabets(mixed=True)
    if SMOKE:
        dic = dic[:3000]
    sz = sizes()
    with Experiment("second pass of the key word differs: read backwards, other form, other tableau", puzzle="k4",
                    notes="exact equal-key-letter tests on the 24 clue letters, 7+ checks: key read back and forth "
                          "(period 16-52, every start and turn, one fold, carved-row restart), its sliding form, "
                          "plain period 18-52, form alternating by pass (word 2-52), odd passes shifted by a "
                          "constant, tableau alternating by pass with A-Z/KRYPTOS; %d keyword alphabets incl. "
                          "transposition-mixed, 5 layouts; 3 shuffled K4s on a third of the alphabets each"
                          % len(dic), cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        tt = tests()
        fam = collections.Counter((t.fam, t.checks >= MIN_CHECKS) for t in tt)
        ali = collections.Counter(t.fam for t in tt for _ in t.aliases if t.checks >= MIN_CHECKS)
        print("distinct tests with %d+ checks (settings they stand for) / gauge tests with %d-%d checks:" % (MIN_CHECKS, GAUGE, MIN_CHECKS - 1))
        for f in FAMS:
            print("   %-7s %6d (%6d) / %5d   per %s" % (f, fam[f, True], ali[f], fam[f, False],
                                                       "alphabet" if f == "tab" else "layout and Vigenere/Beaufort view pair"))
        n, nl, hits = search(K4, CRIBS, dic)
        tested = nl * sz["A7"] + n * sz["C7"]
        ex.count(tested)
        print("K4: %d tests with %d+ checks (%d per layout, %d per alphabet for the tableau alternation)"
              % (tested, MIN_CHECKS, sz["A7"], sz["C7"]))
        k4c = report("K4", n, nl, hits)
        k4_head = headline(hits)
        done = complete_all(k4_head, K4, CRIBS, big)
        for r in done[:40]:
            cover = word_coverage(r[2].replace("?", ""))
            print("   english %.2f over %d new quadgrams, words %.2f, %d checks: %s\n      key %s\n      %s"
                  % (r[0], r[1], cover, r[5][0], describe(r[4], r[5]), r[3], r[2]))
            ex.add(r[2].replace("?", "X"), english_big=round(r[0], 3), setting=describe(r[4], r[5]), key=r[3])
        k4_best = done[0][0] if done else -99.0
        k4_unread = sum(r[0] == -99.0 for r in done)
        print("K4: %d survivors with %d+ checks stand for %d settings; best reading %.2f (English needs %.1f); %d "
              "settings leave fewer than %d new quadgrams to read" % (len(k4_head), MIN_CHECKS, len(done), k4_best,
                                                                      ENGLISH, k4_unread, MIN_NEW))
        ctrl = []
        for seed in (1, 2, 3):
            sct = shuffled_control(seed)
            part = dic[:2] + dic[2:][seed - 1::3]
            cn, cnl, chits = search(sct, CRIBS, part)
            cc = report("shuffled K4 seed %d" % seed, cn, cnl, chits)
            ch = headline(chits)
            cdone = complete_all(ch, sct, CRIBS, big)
            ctrl.append((len(ch), cc[8], cdone[0][0] if cdone else -99.0, cn, cc[5] + cc[6]))
            print("   %d survivors with %d+ checks (%d with 8+), best reading %.2f" % (len(ch), MIN_CHECKS, cc[8], ctrl[-1][2]))
        rng = random.Random(101)
        sample = dic[::5 if SMOKE else 40]
        cases = planted_cases(rng, dic)
        ok = sum(planted_case(c, sample, big) for c in cases)
        print("planted recovered: %d/%d" % (ok, len(cases)))
        share = [c[3] / float(n) for c in ctrl]
        more = all(len(k4_head) * sh > c[0] + 3 * (c[0] ** 0.5) + 3 for sh, c in zip(share, ctrl))
        reads = k4_best > ENGLISH and k4_best > max(c[2] for c in ctrl) + 0.3
        print("VERDICT:", ("K4 beats every control - inspect; " if (more or reads) else "no signal; ") +
              "K4 %d tests pass with %d+ checks (%d with 8+), best reading english %.2f; shuffled K4s on %s of the "
              "alphabets: %s pass with %d+ (%s with 8+), best readings %s (English needs %.1f; -99 = nothing to read). "
              "Gauge at 5-6 checks: K4 %d, shuffled %s"
              % (len(k4_head), MIN_CHECKS, k4c[8], k4_best, ["%.2f" % s for s in share], [c[0] for c in ctrl],
                 MIN_CHECKS, [c[1] for c in ctrl], ["%.2f" % c[2] for c in ctrl], ENGLISH, k4c[5] + k4c[6],
                 [c[4] for c in ctrl]))
