"""Idea 114: a chart with a flaw - one extra or missing letter in a tableau header, row or strip.

The carved tableau is not perfect: row N has one letter more than the others (the extra L).
Sanborn said the K1 worksheet tableau was slightly different from the carved one and was used like
a mileage chart, and his K1 key header was misspelled. Every earlier tableau test assumed a perfect
square of shifted alphabets. If the K4 chart had one letter too many or too few somewhere, every
lookup past the flaw lands one cell off, and an ordinary method fails all those tests.

Model (see kryptos/idea114_flaw.py): the strip cell is v = a + k (Vigenere) or v = k - a
(Beaufort), a = plaintext letter's place in the header, k = key row. One flaw, past cell t
(t = 1..25), one cell off (d = +1 extra letter, d = -1 missing letter):

  col    in the header:      a -> a + d when a >= t
  row    in the row labels:  k -> k + d when k >= t
  body   in the strip:       v -> v + d when v >= t
  cell   the carved chart literally: only row rho is off, past header column t (row N, rho = 13,
         has 31 letters to the others' 30, so a reader going by physical column drifts by one)

For every tableau (A-Z, KRYPTOS and every plain dictionary keyword alphabet, five layouts,
Vigenere and Beaufort) and every flaw, the 24 clue letters give the corrected key values; where the
flaw makes two key values possible, both are tried. These go through the round-11 battery:
repeating key (1-17; column and body flaws only, a row flaw is absorbed by a repeating key),
sliding key (1-15), progressive key (1-12), autokey plain/cipher lags 1-6. 7+ checks count.
The single-row flaw runs on the A-Z and KRYPTOS alphabets (Vigenere form, every rho), the
literal carved chart being layouts AZ/KR and KR/KR with rho = 13.

Survivors are decrypted in full with the flaw applied and scored on the big quadgram model.
Controls: 3 shuffled K4s, each on a third of the alphabets. Planted: a 7-letter repeating key
with a column flaw at cell 12, a sliding key with a row flaw, a progressive key with a body flaw
(each on a random dictionary tableau), and a repeating key on the carved chart with row N off.

  python attacks/114_flawed_chart.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea114_flaw as F  # noqa: E402
from kryptos.ciphers.substitution import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, battery, dictionary_alphabets, english97, pmap, streams  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

KR = KRYPTOS_ALPHABET
_S = {}


def layout_alphabets(lay, m):
    """(header alphabet, strip alphabet) of a layout name from round11.streams."""
    pick = {"M": m, "AZ": AZ, "KR": KR}
    a, b = lay.split("/")
    return pick[a], pick[b]


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]


def test_alphabet(name, m, pl, cl, kinds=("col", "row", "body")):
    """Hits [(checks, name, lay, form, flaw, rule, stream)] and variant counts {rep/norep/over}."""
    hits, cnt = [], {"rep": 0, "norep": 0, "over": 0}
    for lay, form, k, xp, xc in streams(m, pl, cl):
        aa, bb = layout_alphabets(lay, m)
        ia = {c: i for i, c in enumerate(aa)}
        ib = {c: i for i, c in enumerate(bb)}
        a, b = [ia[c] for c in pl], [ib[c] for c in cl]
        for flaw, v in F.variants(k, a, b, form, kinds):
            if v is None:
                cnt["over"] += 1
                continue
            rep = flaw[0] != "row"
            cnt["rep" if rep else "norep"] += 1
            for ck, rule in F.check(v, xp, xc, rep):
                hits.append((ck, name, lay, form, flaw, rule, tuple(v)))
    return hits, cnt


def test_cell(name, m, pl, cl, rhos=range(26)):
    """The single-row flaw, Vigenere form, every layout of alphabet m."""
    hits, cnt = [], {"rep": 0, "norep": 0, "over": 0}
    for lay, form, k, xp, xc in streams(m, pl, cl):
        if form != "vig":
            continue
        aa, _ = layout_alphabets(lay, m)
        ia = {c: i for i, c in enumerate(aa)}
        a = [ia[c] for c in pl]
        for flaw, v in F.cell_variants(k, a, rhos):
            if v is None:
                cnt["over"] += 1
                continue
            cnt["rep"] += 1
            for ck, rule in F.check(v, xp, xc, True):
                hits.append((ck, name, lay, form, flaw, rule, tuple(v)))
    return hits, cnt


def work(chunk):
    hits, cnt = [], {"rep": 0, "norep": 0, "over": 0}
    for name, m in chunk:
        h, c = test_alphabet(name, m, _S["p"], _S["c"])
        hits += h
        for x in cnt:
            cnt[x] += c[x]
    return hits, cnt


def search(ct, cribs, alphas):
    hits, cnt = [], {"rep": 0, "norep": 0, "over": 0}
    for h, c in pmap(work, alphas, init, (ct, cribs), chunk=300):
        hits += h
        for x in cnt:
            cnt[x] += c[x]
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    for name, m in (("(A-Z)", AZ), ("KRYPTOS", KR)):
        h, c = test_cell(name, m, pl, cl)
        hits += h
        for x in cnt:
            cnt[x] += c[x]
    return sorted(hits, reverse=True), cnt


def flaw_str(fl):
    s = "%s flaw t=%s d=%+d" % (fl[0], fl[1] if fl[1] == fl[2] else "%d..%d" % (fl[1], fl[2]), fl[3])
    return s + (" row=%d" % fl[4] if fl[0] == "cell" else "")


def show(h):
    ck, name, lay, form, fl, rule, _ = h
    return "checks=%d %s %s %s [%s] %s" % (ck, name, lay, form, flaw_str(fl), rule)


def segment_score(q, text):
    """Mean log10 quadgram probability over quadgrams lying wholly in known ('?'-free) stretches."""
    tot, n = 0.0, 0
    for seg in text.split("?"):
        for i in range(len(seg) - 3):
            tot += q.logp.get(seg[i:i + 4], q.floor)
            n += 1
    return (tot / n if n else q.floor), n


def decrypt_hit(h, ct, cribs, alphas_by_name):
    ck, name, lay, form, fl, rule, v = h
    m = alphas_by_name[name]
    aa, bb = layout_alphabets(lay, m)
    flaw = (fl[0], fl[1], fl[3]) if fl[0] != "cell" else ("cell", fl[1], fl[3], fl[4])
    return F.decrypt(ct, cribs, m, aa, bb, form, flaw, rule, list(v))


# ------------------------------------------------------------------ planted answers

def plant(rng, alphas, kind):
    """(ct, cribs, truth). truth = (alphabet name, layout, form, flaw kind, t, d, rule prefix[, rho])."""
    while True:
        pt = english97(rng)
        pt = pt[:21] + "EASTNORTHEAST" + pt[34:63] + "BERLINCLOCK" + pt[74:]
        if kind == "cell":
            # the carved chart: header A-Z over KRYPTOS rows (AZ/M), or KRYPTOS both ways (M/M)
            name, m, lay, form = "KRYPTOS", KR, rng.choice(("AZ/M", "M/M")), "vig"
            aa, bb = layout_alphabets(lay, m)
            t, d, rho = rng.randrange(8, 20), rng.choice((1, -1)), 13
            flaw = ("cell", t, d, rho)
        else:
            name, m = rng.choice(alphas[1:])
            lay, form = rng.choice(("M/M", "M/AZ", "AZ/M", "M/KR", "KR/M")), rng.choice(("vig", "beau"))
            aa, bb = layout_alphabets(lay, m)
            t, d = (12 if kind == "col" else rng.randrange(5, 22)), rng.choice((1, -1))
            flaw = (kind, t, d)
        ia, im = {c: i for i, c in enumerate(aa)}, {c: i for i, c in enumerate(m)}
        if kind in ("col", "cell"):
            p = 7 if kind == "col" else 8
            w = [rng.randrange(26) for _ in range(p)]
            if kind == "cell":
                w[rng.randrange(p)] = rho
            key, rp = [w[i % p] for i in range(97)], "repeating p=%d" % p
        elif kind == "row":
            p = rng.randrange(5, 9)
            w = [rng.randrange(26) for _ in range(p)]
            key, acc = [], rng.randrange(26)
            for i in range(97):
                acc = (acc + w[i % p]) % 26
                key.append(acc)
            rp = "sliding p=%d" % p
        else:
            p, s = rng.randrange(4, 8), rng.randrange(1, 26)
            w = [rng.randrange(26) for _ in range(p)]
            key, rp = [(w[i % p] + s * (i // p)) % 26 for i in range(97)], "progressive p=%d step=%d" % (p, s)
        ct = "".join(bb[F.enc_index(ia[ch], kv, form, flaw)] for ch, kv in zip(pt, key))
        cribs = {i: pt[i] for i in POS}
        # the flaw must matter: the plain battery on the uncorrected stream must not find the rule
        plain_hit = False
        for l2, f2, k, xp, xc in streams(m, [cribs[i] for i in POS], [ct[i] for i in POS]):
            if (l2, f2) == (lay, form):
                plain_hit = any(r.startswith(rp) for _, r in battery(k, POS, xp=xp, xc=xc, skip=F.NEVER))
        if not plain_hit:
            truth = (name, lay, form, kind, t, d, rp) + ((rho,) if kind == "cell" else ())
            return ct, cribs, truth, pt


def found(hits, truth):
    for h in hits:
        ck, name, lay, form, fl, rule, _ = h
        if (name, lay, form, fl[0], fl[3]) == truth[:4] + (truth[5],) and fl[1] <= truth[4] <= fl[2] \
                and rule.startswith(truth[6]) and ck >= F.MIN_CHECKS and (fl[0] != "cell" or fl[4] == truth[7]):
            return h
    return None


if __name__ == "__main__":
    alphas = dictionary_alphabets(mixed=False)
    by_name = dict(alphas)
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    with Experiment("flawed chart: one extra or missing letter in a tableau header, row or strip", puzzle="k4",
                    notes="%d alphabets x 5 layouts x Vig/Beau; col/row/body flaw t=1..25 d=+-1; single-row flaw "
                          "on A-Z/KRYPTOS (Vig); repeating(not row)/sliding/progressive/autokey; >=%d checks"
                          % (len(alphas), F.MIN_CHECKS), cribs_forced=True) as ex:
        hits, cnt = search(K4, CRIBS, alphas)
        n_var = cnt["rep"] + cnt["norep"]
        ex.count(n_var)
        c_all, c_norep = F.chance_per_stream(), F.chance_per_stream(("sliding", "progressive", "autokey"))
        exp = cnt["rep"] * c_all + cnt["norep"] * c_norep
        n_plain = len(alphas) * 10 - 2
        print("alphabets: %d; unflawed key streams: %d; corrected streams tested: %d (%d with repeating, %d "
              "without; %d skipped with > %d key combinations)" % (len(alphas), n_plain, n_var, cnt["rep"],
                                                                    cnt["norep"], cnt["over"], F.MAX_COMBOS))
        print("chance: %.3g passes expected for K4 with the flaws (%.0f times the unflawed search, which "
              "expects %.3g)" % (exp, n_var / n_plain, n_plain * c_all))
        print("K4: %d settings with >= %d checks" % (len(hits), F.MIN_CHECKS))
        best = None
        for h in hits[:30]:
            txt = decrypt_hit(h, K4, CRIBS, by_name)
            sc, nq = segment_score(big, txt)
            ex.add(txt.replace("?", ""), flaw=show(h))
            print("   %s\n      %s  big=%.2f over %d quadgrams" % (show(h), txt, sc, nq))
            if nq >= 20 and (best is None or sc > best):
                best = sc
        print("K4 best full decrypt score (>= 20 quadgrams): %s" % ("none" if best is None else "%.2f" % best))
        ctrl = []
        for seed in (1, 2, 3):
            part = alphas[seed - 1::3]
            h, c = search(shuffled_control(seed), CRIBS, part)
            nv = c["rep"] + c["norep"]
            ctrl.append((len(h), nv, c["rep"] * c_all + c["norep"] * c_norep))
            for x in h[:5]:
                print("   shuffled %d: %s" % (seed, show(x)))
        print("shuffled K4s (passes, streams tested, chance expects):",
              ", ".join("%d / %d / %.2g" % x for x in ctrl))
        rng = random.Random(114)
        ok = 0
        for kind in ("col", "row", "body", "cell"):
            ct, cribs, truth, pt = plant(rng, alphas, kind)
            sample = [a for a in alphas if a[0] == truth[0]] + rng.sample(alphas, 2000 if SMOKE else 20000)
            h, _ = search(ct, cribs, sample)
            f = found(h, truth)
            ok += f is not None
            if f:
                txt = decrypt_hit(f, ct, cribs, dict(sample))
                wrong = sum(1 for x, y in zip(txt, pt) if x != "?" and x != y)
                print("planted %s: found %s; decrypt %s (%d wrong letters; big=%.2f); passes in all %d"
                      % (truth, show(f), txt, wrong, segment_score(big, txt)[0], len(h)))
            else:
                print("planted %s: NOT FOUND (passes %d)" % (truth, len(h)))
        print("planted recovered: %d/4" % ok)
        cmax = max(x[0] for x in ctrl)
        print("VERDICT:", "K4 beats every control - inspect" if len(hits) > 3 * max(1, cmax) and best and best > -4.6
              else "no signal (K4 %d passes; shuffled %s)" % (len(hits), [x[0] for x in ctrl]))
