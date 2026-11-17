"""Idea 111: vowels and consonants take their key letters from two separate words (or the key holds).

Sanborn (1990) spoke of two separate systems; Scheidt masked the English language and explains
the problem as "the E against the Z". A hand way to do both: two key words, one used up by the
vowels and one by the consonants, each moving on only when it is used. The key place of a letter
then depends on the text before it, so every position-based key test of rounds 9-11 fails on such
a message, even with short words. Idea 60 split letters by position, never by kind of letter.

  Model A   key letter = V[vowels so far mod p] for a vowel, W[consonants so far mod q] for a
            consonant. EASTNORTHEAST has 5 vowels and 8 consonants, BERLINCLOCK 3 and 8. Inside a
            clue the counters are known; the phase of both words at BERLINCLOCK is free (29 unknown
            letters lie between). Test: the key letters repeat inside each class, p = 1..8,
            q = 1..16, all p x q phases. checks = coincidences - log26(p q); 7 needed.
  Model B   one repeating key of length L = 2..16 that holds (does not move on) or moves two, at
            or after the letters of a set S. S = vowels, consonants, the letters of KRYPTOS, each
            single clue letter (plain or cipher side), a cipher letter equal to the one before it.
            On A-Z, KRYPTOS and the theme-word alphabets also every subset of the 13 distinct clue
            plaintext letters (8,191 sets), L = 2..12.
  Model C   the class is read from the cipher letter (with or without Y as a vowel) in Model A;
            vowels in Vigenere and consonants in Beaufort (or the reverse) in Models A and B.
            Y as a plain vowel changes nothing inside the clues (they hold no Y); it is tried when
            a survivor is read.

Key streams: A-Z, KRYPTOS, every dictionary keyword alphabet and its two transposition-mixed
forms, five layouts, Vigenere and Beaufort (variant Beaufort has the same equal pairs as
Vigenere). Every test is exact. The expected number of chance passes is printed beside the counts.
Survivors are read left to right with every start phase and scored on the big English model.

Pre-filter (--prefilter): FLAG, on the K5 clue only (a shared word comes out the same in 14% of
message pairs, because the key place depends on the text before it). Built all the same: the
K5 statement is firm, not a fact, the same flag stands on every text-dependent key (ideas 83,
94), and no earlier test could see this family at all.

  python attacks/111_vowel_and_consonant_keys.py            (--prefilter for the clue card)
"""
import math
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea111_classes as C  # noqa: E402
from kryptos import wordkeys  # noqa: E402
from kryptos.ciphers.substitution import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea90_rowkey import extra_score  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap, streams  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1          # big-model score per quadgram that English reaches; noise sits near -6.5
CLUESET = set(POS)
MIXES = (("vig", "beau"), ("beau", "vig"))
_S = {}


def init(ct, cribs):
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    ia, tabs, cha, na = C.build_a(pl, cl)
    ib, pats, chb, nb = C.build_b(pl, cl, ct)
    vecs = C.class_vectors(pl, cl)
    _S.update(pl=pl, cl=cl, ia=ia, free=C.free_a(ia), ib=ib, pats=pats, vec=vecs["plain"],
              one_sided={n for n, v in vecs.items() if len(set(v)) < 2},
              chance=(cha, chb), settings=(na, nb))


def test_alphabet(name, m):
    """Every hit of one alphabet: [(checks, model, alphabet, layout, form, detail)], and raw pass counts."""
    S = _S
    ia, ib, free, vec, one = S["ia"], S["ib"], S["free"], S["vec"], S["one_sided"]
    hits, raw_a, raw_b, near = [], 0, 0, 0
    st = list(streams(m, S["pl"], S["cl"]))
    for j in range(0, len(st), 2):
        lay, kv, kb = st[j][0], st[j][2], st[j + 1][2]
        ev, pv = C.eq_mask(kv)
        eb, pb = C.eq_mask(kb)
        gv = ia.query(ev, pv) if pv else []
        gb = ia.query(eb, pb) if pb else []
        if gv or gb:
            for fv, fc, a_, b_ in (("vig", "vig", gv, gv), ("beau", "beau", gb, gb), ("vig", "beau", gv, gb),
                                   ("beau", "vig", gb, gv)):
                got = C.combine_a(a_, b_, free)
                if fv != fc:
                    got = [h for h in got if h[1] not in one]
                if not got:
                    continue
                n_all = len(got)
                got = [h for h in got if h[0] >= C.MIN_CHECKS - C.EPS]
                near += n_all - len(got)
                raw_a += len(got)
                for h in C.minimal_a(got):
                    hits.append((h[0], "A", name, lay, fv + "/" + fc, h[1:]))
        for form, k, e, p in (("vig", kv, ev, pv), ("beau", kb, eb, pb)) + tuple(
                ("%s/%s" % mx, C.mixed_stream(kv, kb, vec, mx[0]), None, None) for mx in MIXES):
            if e is None:
                e, p = C.eq_mask(k)
            got = ib.query(e, p) if p else []
            raw_b += len(got)
            for n, L, d, c in C.minimal_b(got):
                hits.append((c - math.log(L) / C.LOG26, "B", name, lay, form, (n, L, d, c)))
    return hits, raw_a, raw_b, near


def work(chunk):
    hits, ra, rb, nr = [], 0, 0, 0
    for name, m in chunk:
        h, a, b, n = test_alphabet(name, m)
        hits += h
        ra += a
        rb += b
        nr += n
    return hits, ra, rb, nr


def search(ct, cribs, alphas):
    """(best hit per key stream, model A settings passing, model B settings passing, model A near misses)."""
    hits, ra, rb, nr = [], 0, 0, 0
    for h, a, b, n in pmap(work, alphas, init, (ct, cribs), chunk=800):
        hits += h
        ra += a
        rb += b
        nr += n
    return best_per_stream(sorted(hits, key=lambda h: (-h[0], h[1:5]))), ra, rb, nr


def best_per_stream(hits):
    """One hit per (model, alphabet, layout, form): the one with most checks. The others on the same key
    stream are weaker echoes of it (longer words, fewer coincidences)."""
    best = {}
    for h in hits:
        if h[1:5] not in best:
            best[h[1:5]] = h
    return list(best.values())


def theme_alphabets():
    seen, out = set(), []
    for name, m in [("(A-Z)", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)] + [
            (w, keyword_alphabet(w)) for w in wordkeys.theme_words() if len(w) >= 3]:
        if m not in seen:
            seen.add(m)
            out.append((name, m))
    return out


def subset_search(ct, cribs, alphas):
    """Model B with every subset of the clue plaintext letters, on the small alphabet list (one process)."""
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    vec = [0 if c in C.VOWELS else 1 for c in pl]
    hits = []
    for name, m in alphas:
        st = list(streams(m, pl, cl))
        for j in range(0, len(st), 2):
            lay, kv, kb = st[j][0], st[j][2], st[j + 1][2]
            for form, k in (("vig", kv), ("beau", kb)) + tuple(
                    ("%s/%s" % mx, C.mixed_stream(kv, kb, vec, mx[0])) for mx in MIXES):
                for n, L, d, c in C.minimal_b(C.subset_hits(k, pl)):
                    hits.append((c - math.log(L) / C.LOG26, "S", name, lay, form, (n, L, d, c)))
    return best_per_stream(sorted(hits, key=lambda h: (-h[0], h[1:5])))


def stream_of(m, lay, form, pl, cl, vec):
    ks = {(la, f): k for la, f, k, _, _ in streams(m, pl, cl)}
    if "/" in form:
        fv, fc = form.split("/")
        return C.mixed_stream(ks[lay, "vig"], ks[lay, "beau"], vec, "vig" if fv == "vig" else "beau"), (fv, fc)
    return ks[lay, form], None


def describe(h, ct=K4, cribs=CRIBS):
    checks, model, name, lay, form, det = h
    if model == "A":
        cl_, p, dp, q, dq, cv, cc = det
        what = "two words, class by %s: vowel word %d (phase %d, %d coincidences), consonant word %d (phase %d, %d)" % (
            cl_, p, dp, cv, q, dq, cc)
    else:
        n, L, d, c = det
        if model == "B":
            pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
            lab = " | ".join(x[0] for x in C.build_b(pl, cl, ct)[1][n][1][:3])
        else:
            specs = C.build_subsets([cribs[i] for i in POS])[1][n][1]
            lab = "set {%s} %s%s" % ("".join(sorted(specs[0][0])), specs[0][1],
                                     " (+%d equal sets)" % (len(specs) - 1) if len(specs) > 1 else "")
        what = "one key of %d (phase %d, %d coincidences), %s" % (L, d, c, lab)
    return "checks=%.2f model %s %s %s %s: %s" % (checks, model, name, lay, form, what)


def readings(h, ct, cribs, m, big):
    """Every left-to-right reading of a hit that agrees with the clues."""
    _, model, name, lay, form, det = h
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    out = []
    if model == "A":
        cl_, p, dp, q, dq, _, _ = det
        vec = C.class_vectors(pl, cl)[cl_]
        fv, fc = form.split("/")
        ks = {(la, f): k for la, f, k, _, _ in streams(m, pl, cl)}
        vw, ww = C.words_a(ks[lay, fv], ks[lay, fc], vec, p, dp, q, dq)
        for vs in ((C.VOWELS, C.VOWELS_Y) if cl_ == "plain" else (C.VOWELS,)):
            out += C.decrypt_a(ct, m, lay, fv, fc, vw, ww, cl_, vs, cribs, big)
        return out
    n, L, d, _ = det
    if model == "B":
        off, specs = C.build_b(pl, cl, ct)[1][n]
        specs = [(sp, v) for _, sp, v in specs]
    else:
        off, specs = C.build_subsets(pl)[1][n]
        specs = [(("pt", s), v) for s, v in specs[:40]]
    vec = [0 if c in C.VOWELS else 1 for c in pl]
    k, mix = stream_of(m, lay, form, pl, cl, vec)
    key = C.key_b(k, off, L, d)
    for sp, v in specs:
        out += C.decrypt_b(ct, m, lay, form, key, sp, v, mix, cribs, big)
    return out


def read(hits, ct, cribs, by_name, big, limit=40):
    """[(english outside the clues, word coverage, text, hit)] for the first hits, best English first."""
    rows = []
    for h in hits[:limit]:
        for pt in set(readings(h, ct, cribs, by_name[h[2]], big)):
            sc, cnt = extra_score(pt.replace("?", "."), big, CLUESET)
            rows.append((sc if sc is not None else -99.0, word_coverage(pt.replace("?", "")), pt, h))
    return sorted(rows, key=lambda r: -r[0])


def show(rows, ct=K4, cribs=CRIBS, limit=8):
    for sc, cov, pt, h in rows[:limit]:
        print("    " + describe(h, ct, cribs))
        print("      %s   english %.2f outside the clues, word coverage %.2f" % (pt, sc, cov))


def agree(a, b):
    return sum(x == y for x, y in zip(a, b))


def planted_text(rng):
    pt = list(english97(rng))
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


def word(rng, n):
    w = rng.sample(range(26), n)
    return w


def plant(rng, alphas, kind):
    """(ciphertext, plaintext, test(hit) -> is this the planted setting, label)."""
    pt = planted_text(rng)
    name, m = rng.choice(alphas)
    lay = rng.choice(["M/M", "M/AZ", "AZ/M", "M/KR", "KR/M"]) if m != AZ else "AZ/KR"
    f = rng.choice(["vig", "beau"])
    if kind in ("A", "C"):
        p, q = (3, 6) if kind == "A" else (2, 5)
        fv, fc = (f, f) if kind == "A" else rng.choice(MIXES)
        ct = C.encrypt_a(pt, m, lay, fv, fc, word(rng, p), word(rng, q), rng.randrange(p), rng.randrange(q))
        want = lambda h: h[1:5] == ("A", name, lay, fv + "/" + fc) and h[5][0] == "plain" and (h[5][1], h[5][3]) == (p, q)  # noqa: E731
        label = "vowel word of %d and consonant word of %d, %s %s %s/%s" % (p, q, name, lay, fv, fc)
    elif kind == "B":
        ct = C.encrypt_b(pt, m, lay, f, word(rng, 7), "hold-after", C.VOWELS, rng.randrange(7))
        want = lambda h: h[1:5] == ("B", name, lay, f) and h[5][1] == 7  # noqa: E731
        label = "key of 7 that holds after a vowel, %s %s %s" % (name, lay, f)
    else:
        s = frozenset(rng.sample(sorted(set(CRIBS.values())), 3))
        ct = C.encrypt_b(pt, m, lay, f, word(rng, 6), "skip-at", s, rng.randrange(6))
        want = lambda h: h[1:5] == ("S", name, lay, f) and h[5][1] == 6  # noqa: E731
        label = "key of 6 that moves two onto %s, %s %s %s" % ("".join(sorted(s)), name, lay, f)
    return ct, pt, want, label


def prefilter_encrypt(pt, rng):
    """Model A on a keyword tableau; the key comes from rng only."""
    m = keyword_alphabet(rng.choice(["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN", "LODESTONE"]))
    return C.encrypt_a(pt, m, "M/M", "vig", "vig", word(rng, rng.randrange(2, 5)), word(rng, rng.randrange(3, 8)))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("vowels and consonants take key letters from two separate words", encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "paper tableau and two key words, one finger on each")})
        sys.exit(0)
    alphas = dictionary_alphabets(mixed=True)
    by_name = dict(alphas)
    themes = theme_alphabets()
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    init(K4, CRIBS)
    ((cha, chlow), chb), (na, nb) = _S["chance"], _S["settings"]
    lays = len(alphas) * 5 - 1
    sub = C.build_subsets(_S["pl"])
    sub_streams = (len(themes) * 5 - 1) * 4
    n_main = lays * 4 * (na + nb)
    n_sub = sub_streams * sub[3]
    with Experiment("vowels and consonants keyed by two separate words; a key that holds or skips on a letter set",
                    puzzle="k4",
                    notes="%d alphabets (A-Z, KRYPTOS, dictionary keyword + 2 transposition-mixed forms) x 5 layouts x "
                          "Vig/Beau and the two mixed forms; model A p<=%d q<=%d all phases, class by plain or cipher "
                          "letter; model B %d hold/skip patterns L<=%d; all subsets of the clue plaintext letters on "
                          "%d theme alphabets L<=%d; exact, >=%d checks; 3 shuffled controls on a third of the "
                          "alphabets each" % (len(alphas), C.P_MAX, C.Q_MAX, len(_S["pats"]), C.L_MAX, len(themes),
                                              C.L_MAX_SUBSETS, C.MIN_CHECKS),
                    cribs_forced=True) as ex:
        print("alphabets: %d; layouts: %d; theme alphabets for the subset search: %d" % (len(alphas), lays, len(themes)))
        print("settings per layout: model A/C %d x 4 forms, model B %d x 4 forms (%d distinct hold/skip patterns); "
              "total %d" % (na, nb, len(_S["pats"]), n_main))
        print("subset search: %d distinct patterns from %d sets x 4 variants, %d settings per key stream, %d key "
              "streams; total %d" % (len(sub[1]), 2 ** sub[4] - 1, sub[3], sub_streams, n_sub))
        print("chance, uniformly random key values: model A/C %.3g passes expected per ciphertext, model B %.3g, "
              "subsets %.3g" % (cha * lays * 4, chb * lays * 4, sub[2] * sub_streams))

        print("model A/C near misses (%d to under %d checks): %.3g settings expected by chance per ciphertext on all "
              "alphabets, %.3g on a third; model B has none (a key of %d or less always leaves 8 coincidences)"
              % (C.LOW, C.MIN_CHECKS, (chlow - cha) * lays * 4, (chlow - cha) * lays * 4 / 3, C.L_MAX))
        hits, ra, rb, near = search(K4, CRIBS, alphas)
        shits = subset_search(K4, CRIBS, themes)
        ex.count(n_main + n_sub)
        k4n = (sum(1 for h in hits if h[1] == "A"), sum(1 for h in hits if h[1] == "B"), len(shits))
        print("K4: model A/C %d key streams with a setting of >= %d checks (%d settings), model B %d (%d), "
              "subsets %d" % (k4n[0], C.MIN_CHECKS, ra, k4n[1], rb, k4n[2]))
        print("K4: model A/C near misses with %d to under %d checks: %d settings" % (C.LOW, C.MIN_CHECKS, near))
        for h in (hits + shits)[:20]:
            print("   " + describe(h))
        k4rows = read(hits, K4, CRIBS, by_name, big) + read(shits, K4, CRIBS, dict(themes), big)
        k4rows.sort(key=lambda r: -r[0])
        for sc, cov, pt, h in k4rows[:8]:
            ex.add(pt.replace("?", "X"), hit=describe(h))
        show(k4rows)
        k4best = k4rows[0][0] if k4rows else None

        ctrl, cbest, cnear = [], [], []
        for seed in (1, 2, 3):
            sc_ct = shuffled_control(seed)
            part = alphas[seed - 1::3]
            h, a, b, nr = search(sc_ct, CRIBS, part)
            cnear.append(nr)
            sh = subset_search(sc_ct, CRIBS, themes)
            ctrl.append((sum(1 for x in h if x[1] == "A"), sum(1 for x in h if x[1] == "B"), len(sh)))
            rows = read(h, sc_ct, CRIBS, by_name, big) + read(sh, sc_ct, CRIBS, dict(themes), big)
            cbest.append(max((r[0] for r in rows), default=None))
            for x in (h + sh)[:5]:
                print("   shuffled %d: %s" % (seed, describe(x, sc_ct)))
        print("shuffled K4s, a third of the alphabets each (model A/C, model B, subsets on all theme alphabets):", ctrl,
              "best English of a reading:", cbest)
        print("shuffled K4s, model A/C near misses on a third of the alphabets each: %s (K4 on all alphabets: %d, a "
              "third of that: %.1f)" % (cnear, near, near / 3.0))

        rng = random.Random(111)
        ok = 0
        for kind in ("A", "B", "C", "S"):
            ct, pt, want, label = plant(rng, themes if kind == "S" else alphas, kind)
            cribs = {i: pt[i] for i in POS}
            if kind == "S":
                h, names = subset_search(ct, cribs, themes), dict(themes)
            else:
                h, names = search(ct, cribs, alphas)[0], by_name
            mine = [x for x in h if want(x)]
            rows = read(mine, ct, cribs, names, big)
            same = max((agree(r[2], pt) for r in rows), default=0)
            back = same >= 90
            ok += bool(mine) and back
            print("planted %s -> found=%s, letters read back: %d/97, key streams passing in all: %d%s" % (
                label, bool(mine), same, len(h),
                "" if len(h) == len(mine) else " (others: %s)" % "; ".join(
                    describe(x, ct, cribs) for x in h if not want(x))[:600]))
            if mine:
                print("   " + describe(mine[0], ct, cribs))
                if back:
                    r = max(rows, key=lambda r: agree(r[2], pt))
                    print("   %s   english %.2f, word coverage %.2f" % (r[2], r[0], r[1]))
        print("planted recovered: %d/4" % ok)

        total = sum(k4n)
        cmax = max(sum(c) for c in ctrl)
        english = k4best is not None and k4best > ENGLISH - 0.3
        if total and total > cmax and english:
            print("VERDICT: K4 has %d passing settings, more than every control, and a reading near English "
                  "(%.2f) - INSPECT BY HAND" % (total, k4best))
        else:
            print("VERDICT: no signal (K4 passing settings: model A/C %d, model B %d, subsets %d; shuffled %s; "
                  "best English of a K4 reading: %s, English needs %.1f)"
                  % (k4n + (ctrl, "%.2f" % k4best if k4best is not None else "none", ENGLISH)))
