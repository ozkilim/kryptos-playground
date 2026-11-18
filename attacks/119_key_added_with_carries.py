"""Idea 119: the key is added like a number: long addition with carries instead of mod 26 per letter.

Scheidt said he could have moved to a different math base and that the cipher is simple enough to
remember. Every exact test so far adds key and text letter by letter with no carry. Suppose instead
the message and the repeated key were added as two long numbers in base 26 (letters A=0..Z=25 on
the tableau alphabet) or base 27 (letters 1..26). Then each cipher letter is plain + key + a carry
of 0 or 1 that depends on the neighbouring digit. The key values the clues force are off by one in
an irregular pattern and every repeating-key test fails, even with a short word.

Exact reduction (see kryptos/idea119_carry.py). Inside a clue block the plain and cipher letters
are known. Fix the one carry that enters the block: then the key digit at the first letter worked
is forced, so its sum and the next carry are known, and so on along the block. Each block gives
two key vectors, so the two blocks give at most four 24-value vectors per stream. Each is tested
exactly against repeating, sliding and progressive keys (L = 1..12, 7 or more independent checks),
and for A-Z, KRYPTOS and the theme alphabets also against the rest of the round-11 battery (autokey,
two stacked keys combined before the carry pass, chain addition).

Settings: forms add (C = P + K), sub (C = P - K, borrows) and beau (C = K - P, borrows); carries
right to left (written sum) and left to right; bases 26 (from 0) and 27 (from 1). Models: one long
number; the number restarted at each carved row (4+31+31+31) or each row of 7, 14, 21, 31, 42, with
the key running on or restarting with the row.

Key streams: A-Z, KRYPTOS, every keyword alphabet of the theme words, the 21k common words and the
236k-word dictionary, each plain and in two transposition-mixed forms (666,993 alphabets), five
layouts. Tiers to fit the time box: row-restart models on A-Z/KRYPTOS/theme/common-word alphabets
(tiers 0-1); one long number (no restarts) on all of them (tier 2 = the big dictionary). The extra
battery rules on tier 0 only.

Every hit is decrypted from the far end (carry 0 there; unique once the key is known), up to two
unknown key letters filled by best English score, and must give back all 24 clue letters.

Controls: 3 shuffled K4s on a third of the alphabets each; 200 shuffled K4s on A-Z and KRYPTOS
(all models, full battery) to measure the real pass rate against the n^-checks estimate.
Planted: 12 English texts, key words of 5, 8, 11 letters on KRYPTOS (any model) and on a
dictionary tableau (one long number), both carry directions.

  python attacks/119_key_added_with_carries.py            (--prefilter for the clue card)
"""
import itertools
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea119_carry as Q  # noqa: E402
from kryptos import wordkeys  # noqa: E402
from kryptos.ciphers.substitution import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control, keyword_alphabet  # noqa: E402
from kryptos.round11 import POS, SMOKE, battery, dictionary_alphabets, english97, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

ENGLISH = -5.1
_S = {}
FULL = Q.models(True)
PLAIN = Q.models(False)


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]


def run_one(name, m, tier, pl, cl):
    mods = PLAIN if tier == 2 else FULL
    return Q.test_alphabet(name, m, pl, cl, mods, battery if tier == 0 else None)


def work(chunk):
    hits, tested, exp = [], 0, 0.0
    for name, m, tier in chunk:
        h, t, e = run_one(name, m, tier, _S["p"], _S["c"])
        hits += h
        tested += t
        exp += e
    return hits, tested, exp


def search(ct, cribs, items, chunk=400):
    hits, tested, exp = [], 0, 0.0
    for h, t, e in pmap(work, items, init, (ct, cribs), chunk=chunk):
        hits += h
        tested += t
        exp += e
    return sorted(hits, key=lambda x: -x[0]), tested, exp


def tiers(alphas):
    small = set(["(A-Z)", "KRYPTOS"] + wordkeys.theme_words())
    common = set(wordkeys.common_words())
    out = []
    for name, m in alphas:
        base = name.split("~")[0]
        out.append((name, m, 0 if base in small else (1 if base in common else 2)))
    return out


def model_of(name):
    for md in FULL:
        if md[0] == name:
            return md
    raise KeyError(name)


def read_hit(h, ct, cribs, by_name, big):
    """Decrypt a hit: (score, words, text, clue letters matched, unknown key letters)."""
    ck, name, lay, n, form, d, rule, mnames, es, k = h
    md = model_of(mnames[0])
    _, r, restart = md
    o = 1 if n == 27 else 0
    ia, ib = Q.layout_maps(by_name[name], lay)
    kp = [i - Q.row_start(i, Q.ROWS[r]) if restart else i for i in range(97)]
    if rule.split()[0] in ("repeating", "sliding", "progressive"):
        keys = Q.key_stream(list(k), kp, rule, n, Q.key_index(md))
        Lr = int(rule.split("p=")[1].split()[0])
        unknown = sorted(set(kp[i] % Lr for i in range(97) if keys[i] is None))
    else:                                   # battery rules: no decryption, judged on checks alone
        keys, unknown = [None] * 97, list(range(99))
    best = None
    if rule.startswith("repeating") and 0 < len(unknown) <= 2:
        L = int(rule.split("p=")[1].split()[0])
        for vals in itertools.product(range(n), repeat=len(unknown)):
            fill = dict(zip(unknown, vals))
            ks = [v if v is not None else fill[kp[i] % L] for i, v in enumerate(keys)]
            t = Q.decrypt(ct, ia, ib, n, o, form, d, ks, r)
            s = big.score(t.replace("?", "").replace("#", ""))
            if best is None or s > best[0]:
                best = (s, t)
        text = best[1]
    else:
        text = Q.decrypt(ct, ia, ib, n, o, form, d, keys, r)
    clean = text.replace("?", "").replace("#", "")
    match = sum(1 for i in POS if text[i] == cribs[i])
    return (big.score(clean) if len(clean) > 4 else -9.0, word_coverage(clean) if clean else 0.0,
            text, match, len(unknown) if not (best and len(unknown) <= 2) else 0)


def survivors(hits, ct, cribs, by_name, big, limit=400):
    rows = []
    for h in hits[:limit]:
        sc, cov, text, match, unk = read_hit(h, ct, cribs, by_name, big)
        rows.append((match == 24, sc, cov, text, match, unk, h))
    rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
    return rows


def tableau(name, lay, by_name):
    """The two alphabets a stream really uses (A-Z on KR/KR and KRYPTOS on M/M are one tableau)."""
    ia, ib = Q.layout_maps(by_name[name], lay)
    return tuple("".join(sorted(x, key=x.get)) for x in (ia, ib))


def describe(h):
    ck, name, lay, n, form, d, rule, mnames, es, k = h
    return "%s %s base %d %s %s | %s, %d checks | models %s | entering carries %s" % (
        name, lay, n, form, d, rule, ck, ",".join(mnames[:3]) + ("..." if len(mnames) > 3 else ""), es[0])


def plant(rng, alphas, kind, L, d):
    """A planted message: (ct, cribs, pt, setting)."""
    while True:
        pt = english97(rng)
        if kind == "KR":
            name, m, lay = "KRYPTOS", KRYPTOS_ALPHABET, "M/M"
            md = rng.choice(FULL)
        else:
            name, m = rng.choice([a for a in alphas[len(alphas) // 2:] if "~" not in a[0]])
            lay, md = rng.choice(["M/M", "M/AZ", "AZ/M"]), PLAIN[0]
        n, o = rng.choice(Q.BASES)
        form = rng.choice(Q.FORMS)
        _, r, restart = md
        w = [rng.randrange(26) + o for _ in range(L)]
        kp = [i - Q.row_start(i, Q.ROWS[r]) if restart else i for i in range(97)]
        ia, ib = Q.layout_maps(m, lay)
        ct = Q.encrypt(pt, ia, ib, n, o, form, d, [w[t % L] for t in kp], r)
        if ct is not None:
            return ct, {i: pt[i] for i in POS}, pt, (name, lay, n, form, d, "repeating p=%d" % L, md[0])


def prefilter_encrypt(pt, rng):
    """Repeating key word of 4-12 letters on the KRYPTOS tableau, added as a long base-26 number."""
    L = rng.randrange(4, 13)
    w = [rng.randrange(26) for _ in range(L)]
    im = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    return Q.encrypt(pt, im, im, 26, 0, "add", "RL", [w[i % L] for i in range(len(pt))])


def tally(rows):
    raw = len(rows)
    full = [r for r in rows if r[0]]
    return raw, len(full), max((r[1] for r in rows), default=-9.0)


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("repeating key added to the message as a long base-26 number (carries)",
                  encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "long addition by hand on paper"),
                         "math_base": ("pass", "a different math base: carries in base 26/27")})
        sys.exit(0)
    alphas = dictionary_alphabets(mixed=True, smoke_limit=10 ** 7)
    if SMOKE:
        alphas = alphas[:2400] + alphas[-600:]
    items = tiers(alphas)
    by_name = dict(alphas)
    index = {name: i for i, (name, _) in enumerate(alphas)}
    big = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    nt = [sum(1 for x in items if x[2] == t) for t in range(3)]
    with Experiment("key added like a number: long addition with carries, base 26/27, both directions",
                    puzzle="k4",
                    notes="%d alphabets (tiers %s) x 5 layouts x add/sub/beau x carries RL/LR x base 26/27; "
                          "entering carry per block free (4 exact key vectors); repeating/sliding/progressive "
                          "L 1-12 >= 7 checks; row restarts (carved, 7,14,21,31,42; key on or restarted) on "
                          "tiers 0-1; full battery tier 0" % (len(alphas), nt),
                    cribs_forced=True) as ex:
        print("alphabets: %d (tier 0 battery+rows %d, tier 1 rows %d, tier 2 plain %d)" % ((len(alphas),) + tuple(nt)))
        hits, tested, exp = search(K4, CRIBS, items)
        ex.count(tested)
        rows = survivors(hits, K4, CRIBS, by_name, big)
        k4 = tally(rows)
        print("K4: %d key vectors tested; %d passes with >= %d checks (chance expects %.3g for the repeating/"
              "sliding/progressive rules); %d decrypt back to all 24 clue letters; best score %.2f"
              % (tested, k4[0], Q.MIN_CHECKS, exp, k4[1], k4[2]))
        for full, sc, cov, text, match, unk, h in rows[:8]:
            print("   %s\n      clue letters %d/24, score %.2f, words %.2f, unknown key letters %d  %s"
                  % (describe(h), match, sc, cov, unk, text))
            ex.add(text, setting=describe(h), clue_letters=match)

        # controls 1: three shuffled K4s on a third of the alphabets each
        ctrl, k4_third = [], []
        for seed in (1, 2, 3):
            part = [x for x in items if index[x[0]] % 3 == seed - 1]
            ct = shuffled_control(seed)
            h, t, e = search(ct, CRIBS, part)
            rws = survivors(h, ct, CRIBS, by_name, big)
            ctrl.append(tally(rws) + (t, e))
            k4_third.append(tally([r for r in rows if index[r[6][1]] % 3 == seed - 1]))
            for full, sc, cov, text, match, unk, hh in rws[:1]:
                print("   shuffled %d best: %s | clue letters %d, score %.2f  %s" % (seed, describe(hh), match, sc, text))
        print("shuffled K4s, a third of the alphabets each (passes, 24/24 decrypts, best score, vectors, expected):")
        for c in ctrl:
            print("   %d, %d, %.2f, %d, %.3g" % c)
        print("K4 on the same thirds (passes, 24/24, best):", k4_third)

        # controls 2: 200 shuffled K4s on A-Z and KRYPTOS, all models, full battery
        nsh = 20 if SMOKE else 200
        base_items = [x for x in items if x[0] in ("(A-Z)", "KRYPTOS")]
        k4_small = [h for h in hits if h[1] in ("(A-Z)", "KRYPTOS")]
        sh_pass, sh_vec, sh_exp, sh_full = 0, 0, 0.0, 0
        for seed in range(1000, 1000 + nsh):
            ct = shuffled_control(seed)
            pl, cl = [CRIBS[i] for i in POS], [ct[i] for i in POS]
            for name, m, tier in base_items:
                h, t, e = run_one(name, m, 0, pl, cl)
                sh_pass += len(h)
                sh_vec += t
                sh_exp += e
                sh_full += sum(1 for r in survivors(h, ct, CRIBS, by_name, big) if r[0])
        print("A-Z/KRYPTOS: %d shuffled K4s, %d key vectors: %d passes (chance for the repeating/sliding/"
              "progressive rules %.3g; the battery rules add their own), %d decrypt back to 24/24; rate %.3g per vector "
              "(26^-7 = %.3g). K4 on the same: %d passes"
              % (nsh, sh_vec, sh_pass, sh_exp, sh_full, sh_pass / max(sh_vec, 1), 26.0 ** -7, len(k4_small)))

        # planted answers
        rng = random.Random(119)
        ok, nplant = 0, 0
        for kind in ("KR", "DICT"):
            for L in (5, 8, 11):
                for d in Q.DIRS:
                    nplant += 1
                    ct, cribs, pt, want = plant(rng, alphas, kind, L, d)
                    part = [x for x in items if index[x[0]] % 60 == index[want[0]] % 60]
                    if SMOKE:
                        part = [x for x in part if x[0] == want[0]] + part[:60]
                    h, t, e = search(ct, cribs, part, chunk=100)
                    rws = survivors(h, ct, cribs, by_name, big)
                    found = [r for r in rws if r[0] and (r[6][1], r[6][2], r[6][3], r[6][4], r[6][5], r[6][6])
                             == want[:6] and want[6] in r[6][7]]
                    good = max((sum(a == b for a, b in zip(r[3], pt)) for r in found), default=0)
                    # a survivor from another stream that reads the planted text is the same answer in an
                    # equivalent form (A-Z on KR/KR is the KRYPTOS tableau; subtracting a key is adding its
                    # complement); only a different reading counts against the test
                    me = tableau(want[0], want[1], by_name) + (want[2], want[4])
                    others = [r for r in rws if r[0] and tableau(r[6][1], r[6][2], by_name) + (r[6][3], r[6][5]) != me
                              and sum(a == b for a, b in zip(r[3], pt)) < 90]
                    top = sum(a == b for a, b in zip(rws[0][3], pt)) if rws else 0
                    passed = bool(found) and good == 97 and top >= 96 and not others
                    ok += passed
                    print("planted %s L=%d %s: %s -> found=%s, %d/97 read back (best-scoring survivor %d/97), "
                          "survivors with a different reading %d, passes %d (alphabets searched %d)"
                          % (kind, L, d, want, bool(found), good, top, len(others), len(h), len(part)))
        print("planted recovered: %d/%d" % (ok, nplant))
        signal = k4[1] > 0 and all(c[1] == 0 for c in ctrl) and k4[2] > ENGLISH
        print("VERDICT:", "K4 survivor reads as English and controls have none - inspect" if signal else
              "no signal (K4: %d passes, %d full 24/24 decrypts, best score %.2f; controls %s)"
              % (k4[0], k4[1], k4[2], [c[:3] for c in ctrl]))
