"""Idea 120: the K1/K2 machine as a known layer, then every key rule on a second tableau.

K2 ends LAYER TWO. Scheidt said two of the four processes are similar, and the Cyrillic Projector
shows Sanborn reusing the K1/K2 machine. Suppose K4 went through the K1 or K2 chart (the KRYPTOS
tableau with key PALIMPSEST or ABSCISSA) and ALSO through a second, different chart. Then the
letters that the second chart turned into the carved cipher are not EASTNORTHEAST / BERLINCLOCK but
those words after (or before) the known K1/K2 step. Every earlier key-rule test was run on the clue
words themselves, so it never saw the right letters. Idea 84 tested two layers, but only with two
repeating keys; a known first layer with a sliding, progressive or autokey second layer is new.

Known layer (kryptos/idea120_layer.py): tableau KRYPTOS (as K1/K2; this reproduces both carved
texts) or plain A-Z; key ABSCISSA, PALIMPSEST, PALIMPCEST (the misspelling) or KRYPTOS; enciphering
or deciphering direction; every phase of the key at K4 letter 1 (so a key running on from the end
of K2 or K3, or restarting, is included). Two orders:

  first  P -> known layer -> layer two -> C : the clue plain letters are replaced by their
         known-layer letters, and layer two is tested as their cipher.
  last   P -> layer two -> known layer -> C : the known layer is stripped from all of K4 first.

2 tableaux x (8+10+10+7 phases) x 2 directions x 2 orders = 280 variants. Each variant is just a
new set of 24 clue letter pairs, which goes through the full key-rule battery with both hole fixes:
repeating key 1-17, sliding 1-15, progressive 1-12, autokey lags 1-6 fed on M (round-11 battery),
chain addition, every stacked pair exactly, autokey with the fed letter numbered on A-Z / KRYPTOS,
progressive key moved on in another alphabet's order (idea 104). Five layouts, Vigenere and
Beaufort, 7+ exact checks.

  part 1  all 280 variants on A-Z, KRYPTOS, the 84 theme alphabets and the common-word keyword
          alphabets
  part 2  the 16 variants with the key starting at K4 letter 1 on the KRYPTOS tableau, on all
          666,993 dictionary alphabets (plain keyword and transposition-mixed)

Layer two on the KRYPTOS alphabet itself is kept on purpose: a repeating key there is absorbed
into the known key, but autokey and progressive are not.

Survivors are read through both layers and scored on the big English model. Controls: 3 shuffled
K4s, the same variants, each on a different slice of the alphabets (see CTRL_SHARE). Planted: three
two-layer messages, searched over all 280 variants on an alphabet sample.

  python attacks/120_known_first_layer.py            (--prefilter for the clue card)
"""
import collections
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea120_layer as L  # noqa: E402
from kryptos import idea104_holes as H  # noqa: E402
from kryptos import wordkeys  # noqa: E402
from kryptos.ciphers.substitution import AZ, KRYPTOS_ALPHABET as KR  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1
CTRL_SHARE = 9           # each control runs on every CTRL_SHARE-th alphabet (a different slice per seed)


def small_alphabets():
    seen, out = {AZ}, [("(A-Z)", AZ)]
    for w in ["KRYPTOS"] + wordkeys.theme_words() + wordkeys.common_words():
        if 3 <= len(w) <= 22:
            m = keyword_alphabet(w)
            if m not in seen:
                seen.add(m)
                out.append((w, m))
    return out


def describe(h, vs):
    return "%d checks: [%s] layer two on %s %s %s, %s [%s]" % (h[0], vs[h[7]]["label"], h[1], h[2], h[3], h[4], h[5])


def readings(hits, vs, by_name, ct, cribs, big, limit=300):
    out = []
    for h in sorted(hits, reverse=True)[:limit]:
        pt = L.read(h, vs[h[7]], by_name[h[1]], ct, cribs)
        sc, nq = H.read_score(pt, big)
        out.append((sc, nq, pt, h))
    return sorted(out, key=lambda r: (-r[0], -r[3][0]))


def run(ct, cribs, vs, small, full, full_idx):
    """Both parts. Returns (hits, alphabet-variant pairs tested)."""
    hits = L.search(vs, ct, cribs, small) if small else []
    n = len(vs) * len(small)
    if full and full_idx:
        hits += L.search([vs[j] for j in full_idx], ct, cribs, full, idx=full_idx)
        n += len(full_idx) * len(full)
    return hits, n


# ------------------------------------------------------------------ planted answers

def with_clues(pt):
    return pt[:21] + "EASTNORTHEAST" + pt[34:63] + "BERLINCLOCK" + pt[74:]


def plant(kind, rng, alphas, vs):
    """(ct, cribs, plaintext, variant index, alphabet (name, m), rule prefix, layout, form)."""
    name, m = rng.choice([a for a in alphas[2:]])
    lay = rng.choice(("M/M", "M/AZ", "AZ/M", "M/KR", "KR/M"))
    form = rng.choice(("vig", "beau"))
    pt = with_clues(english97(rng))
    if kind == "ABSCISSA then sliding":
        want = dict(tname="KR", word="ABSCISSA", e=1, phase=rng.randrange(8), order="first")
        p = 5
        w = [rng.randrange(26) for _ in range(p)]
        key, acc = [], rng.randrange(26)
        for i in range(97):
            key.append(acc)
            acc = (acc + w[i % p]) % 26
        rule = "sliding p=%d" % p
    elif kind == "progressive then PALIMPSEST":
        want = dict(tname="KR", word="PALIMPSEST", e=1, phase=4, order="last")
        p, s = 7, rng.randrange(1, 26)
        w = [rng.randrange(26) for _ in range(p)]
        key = [(w[i % p] + s * (i // p)) % 26 for i in range(97)]
        rule = "progressive p=%d step=%d" % (p, s)
    else:   # plain autokey lag 2 under ABSCISSA (A-Z chart, deciphering direction, phase 5)
        want = dict(tname="AZ", word="ABSCISSA", e=-1, phase=5, order="first")
        sg = rng.choice((1, -1))
        key = ("autokey", "plain", 2, sg, rng.randrange(26), [rng.randrange(26) for _ in range(2)])
        rule = "autokey plain lag=2 sign=%+d" % sg
    vi = next(j for j, v in enumerate(vs) if all(v[k] == want[k] for k in want))
    ct = L.encrypt(pt, vs[vi], m, lay, form, key)
    cribs = {i: pt[i] for i in POS}
    return ct, cribs, pt, vi, (name, m), rule, lay, form


def prefilter_encrypt(pt, rng):
    """For the clue pre-filter: ABSCISSA on the KRYPTOS tableau at a random phase, then a sliding key
    on a random alphabet; everything drawn from rng."""
    f = rng.randrange(8)
    y = L.layer(pt, KR, "ABSCISSA", 1, f)
    m = list(AZ)
    rng.shuffle(m)
    m = "".join(m)
    w = [rng.randrange(26) for _ in range(5)]
    key, acc = [], rng.randrange(26)
    for i in range(len(pt)):
        key.append(acc)
        acc = (acc + w[i % 5]) % 26
    return L.layer2_encrypt(y, m, "M/M", "vig", key)


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("known K1/K2 layer (ABSCISSA/PALIMPSEST/KRYPTOS) then a key rule on a second tableau",
                  encrypt=prefilter_encrypt)
        sys.exit(0)
    vs = L.variants()
    full_idx = [j for j, v in enumerate(vs) if v["tname"] == "KR" and v["phase"] == 0]
    small = small_alphabets()
    sset = {m for _, m in small}
    mixed_only = "--mixed-only" in sys.argv     # part 2 on the transposition-mixed alphabets alone (second run)
    plain_dic = dictionary_alphabets(mixed=False)
    if mixed_only:
        pset = {m for _, m in plain_dic}
        full = [a for a in dictionary_alphabets(mixed=True) if a[1] not in pset]
    else:
        full = [a for a in plain_dic if a[1] not in sset]
    by_small = small
    if mixed_only:
        small = []
    if SMOKE:
        small, full = small[:60], full[:300]
    by_name = dict(by_small + full)
    chance1 = L.chance_per_alphabet()
    with Experiment("known K1/K2 layer (ABSCISSA/PALIMPSEST/PALIMPCEST/KRYPTOS on KRYPTOS or A-Z, every phase, "
                    "both directions, both orders) then the key-rule battery on a second tableau", puzzle="k4",
                    notes=("PART 2 ON TRANSPOSITION-MIXED ALPHABETS ONLY; " if mixed_only else "") + "%d variants on %d alphabets (A-Z, KRYPTOS, theme, common words); the %d phase-0 KRYPTOS "
                          "variants also on %d more dictionary alphabets; battery: repeating/sliding/progressive/"
                          "autokey/chain + idea-104 stacked exact, autokey numbered A-Z/KR, progressive other order; "
                          "7+ checks; 3 shuffled K4s on a 1/%d slice each"
                          % (len(vs), len(small), len(full_idx), len(full), CTRL_SHARE), cribs_forced=True) as ex:
        big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        print("variants: %d (%d with the key at K4 letter 1 on the KRYPTOS tableau); alphabets: part 1 %d, part 2 %d more"
              % (len(vs), len(full_idx), len(small), len(full)))
        print("chance passes with 7+ checks per alphabet and variant: %.3g" % chance1)

        # planted answers first: the search must find them
        rng = random.Random(120)
        sample = (small[:2] + rng.sample(small[2:] + full, 60 if SMOKE else 300)) if small else []
        ok = 0
        for kind in () if mixed_only else ("ABSCISSA then sliding", "progressive then PALIMPSEST",
                                           "plain autokey lag 2 under ABSCISSA"):
            ct, cribs, pt, vi, (name, m), rule, lay, form = plant(kind, rng, small + full, vs)
            alphas = sample if (name, m) in sample else sample + [(name, m)]
            t0 = time.time()
            h = L.search(vs, ct, cribs, alphas)
            h = [x for x in h if x[0] >= L.MIN_CHECKS]
            mine = [x for x in h if x[7] == vi and x[1] == name and x[2] == lay and x[3] == form and x[4].startswith(rule)]
            texts = {L.read(x, vs[x[7]], dict(alphas)[x[1]], ct, cribs) for x in h}
            good = False
            if mine:
                text = L.read(mine[0], vs[vi], m, ct, cribs)
                right = sum(a == b for a, b in zip(text, pt))
                sc, nq = H.read_score(text, big)
                wrong = [t for t in texts if any(a != "?" and a != b for a, b in zip(t, pt))]
                strays = [x for x in h if (x[7], x[1]) != (vi, name)]
                good = right == 97 and not wrong and not strays
                print("planted %-36s [%s] on %s %s %s %s -> %s; %d settings pass over %d variants x %d alphabets "
                      "(%d distinct readings, %d with a wrong letter, %d settings of another variant or alphabet); "
                      "read back %d/97, english %.2f; %.0f s"
                      % (kind, vs[vi]["label"], name, lay, form, rule, "FOUND, only true reading" if good else "NOT CLEAN",
                         len(h), len(vs), len(alphas), len(texts), len(wrong), len(strays), right, sc, time.time() - t0))
                for x in h[:6]:
                    print("      " + describe(x, vs))
            else:
                print("planted %-36s [%s] -> MISSED (%d settings pass)" % (kind, vs[vi]["label"], len(h)))
            ok += good
        print("planted recovered: %d/3" % ok)

        # K4
        t0 = time.time()
        hits, n = run(K4, CRIBS, vs, small, full, full_idx)
        ex.count(n)
        exp = n * chance1
        print("K4: %d alphabet-variant pairs (%.0fx the %d alphabet tests of one plain run), %.0f s"
              % (n, n / float(len(small) + len(full)), len(small) + len(full), time.time() - t0))
        print("K4: %d settings pass with 7+ checks (%d with 8+); chance expects %.2f over this %.0f-fold larger search"
              % (len(hits), sum(h[0] >= 8 for h in hits), exp, n / float(len(small) + len(full))))
        by_rule = collections.Counter((h[4].split()[0], h[0]) for h in hits)
        print("   by rule and checks:", dict(by_rule))
        done = readings(hits, vs, by_name, K4, CRIBS, big)
        for r in done[:30]:
            print("   english %.2f over %d new quadgrams, words %.2f; %s\n      %s"
                  % (r[0], r[1], word_coverage(r[2].replace("?", "")), describe(r[3], vs), r[2]))
            ex.add(r[2].replace("?", "X"), english_big=round(r[0], 3), setting=describe(r[3], vs))
        k4_best = max((r[0] for r in done), default=-99.0)
        print("K4 best reading %.2f (English needs %.1f; -99 = nothing to read)" % (k4_best, ENGLISH))

        ctrl = []
        for seed in (1, 2, 3):
            sct = shuffled_control(seed)
            t0 = time.time()
            ch, cn = run(sct, CRIBS, vs, small[seed - 1::CTRL_SHARE], full[seed - 1::CTRL_SHARE], full_idx)
            cd = readings(ch, vs, by_name, sct, CRIBS, big)
            cb = max((r[0] for r in cd), default=-99.0)
            print("shuffled K4 seed %d: %d pairs, %d pass with 7+ (%d with 8+), chance expects %.2f, best reading %.2f; %.0f s"
                  % (seed, cn, len(ch), sum(h[0] >= 8 for h in ch), cn * chance1, cb, time.time() - t0))
            for r in cd[:3]:
                print("      english %.2f; %s" % (r[0], describe(r[3], vs)))
            ctrl.append((len(ch), cn, cb))

        rate = len(hits) / float(n)
        more = all(rate * c[1] > c[0] + 3 * (c[0] ** 0.5) + 3 for c in ctrl)
        reads = k4_best > ENGLISH and k4_best > max(c[2] for c in ctrl) + 0.3
        print("VERDICT:", ("K4 beats every control - inspect; " if (more or reads) else "no signal; ") +
              "K4 %d passes in %d pairs (chance %.2f), best reading %.2f; controls %s passes in %s pairs, best %s; "
              "planted %d/3" % (len(hits), n, exp, k4_best, [c[0] for c in ctrl], [c[1] for c in ctrl],
                                ["%.2f" % c[2] for c in ctrl], ok))
