"""Idea 117: tests that need no alphabet. Which fed-key models clash on every possible tableau?

Almost every negative so far assumed the tableau is built from a keyword. Idea 94 found a test that needs no
alphabet at all. On any tableau whose rows are all different and whose columns are all different (a Latin
square), the same key letter with the same plain letter must give the same cipher letter; the same key and
cipher letter must come from the same plain letter; the same plain and cipher letter must have the same key
letter. Two clue letters that agree in two of (plain, key, cipher) and differ in the third are a CLASH, and a
clash kills the model on every tableau at once, hidden ones included, with any constant added to the key.

This works wherever the key letter at a clue position is itself a known letter:

  plain autokey     key = plaintext L back or L ahead; known when both letters are in the clues
                    (L 1-12 inside a block, L 30-52 across the blocks; every L 1-60 is listed)
  cipher autokey    key = ciphertext L back or ahead, L 1-68 (all 24 clue letters known)
  rows of width w   key = the letter above = autokey at lag w (w 7-48 is the same list)
  lag patterns      idea 74: key = letter L[i mod p] back, p 2-7, plain L 1-8, cipher L 1-20 (counted)
  running keys      every reading of the sculpture in attack 58 (grids x walks x every d-th letter) and the
                    K1, K2, K3 plaintexts straight and reversed, at every offset
  second clue       BERLINCLOCK moved by -3..+3 (0 is the true place)

Part B narrows the tableau to one hidden alphabet on all three sides, X[C] = a X[P] + b X[K] + E
(four forms), and solves it mod 26 with all letters in different places (round 9 / idea 93 solver). Plain
autokey lags 15-26 add the two-step chains of idea 100, which drop the unknown middle letter.
Part C reads the key letter as a number on A-Z or KRYPTOS: X[C] = a X[P] + b k + E.

Controls: 50 shuffled K4s (clue plaintext stays put). Planted: plain autokey lag 3, cipher autokey lag 11 and
the K2 plaintext as running key, on a random 26 x 26 Latin square and on a random hidden alphabet.

  python attacks/117_clash_on_every_tableau.py              (--prefilter for the clue card)
"""
import importlib.util
import random
import sys
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, load  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR, letters  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, pmap  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402
from kryptos import idea117_clash as C  # noqa: E402

N_CTRL = 4 if SMOKE else 50
N_CTRL_FULL = 1 if SMOKE else 5        # controls that also get Part B on every sculpture reading
SHIFTS = (0, 1) if SMOKE else C.SHIFTS
PATTERN_P = range(2, 8)
SAMPLE7 = 20000 if SMOKE else 200000     # cipher-feed patterns of period 7 are sampled (20^7 = 1.28e9)
MAX_SKIP = 6 if SMOKE else 60
CTRL_SAMPLE = 300 if SMOKE else 3000     # sculpture-reading survivors per control that go to Part B
NUMS = (("AZ", C.IZ), ("KR", C.IK))
ENGLISH = -5.1                          # big-model score per quadgram that English reaches
_A58 = None


def a58():
    global _A58
    if _A58 is None:
        spec = importlib.util.spec_from_file_location("a58", str(Path(__file__).parent / "58_sculpture_readings.py"))
        _A58 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_A58)
    return _A58


def texts():
    """Straight texts: K1-K3 plaintexts, K2 corrected, all three joined; each also reversed."""
    k = {n: letters(load(n)["plaintext"]) for n in ("k1", "k2", "k3")}
    base = {"K1 plaintext": k["k1"], "K2 plaintext": k["k2"], "K3 plaintext": k["k3"],
            "K2 plaintext corrected": letters(load("k2")["plaintext_corrected"]),
            "K1-K3 plaintext": k["k1"] + k["k2"] + k["k3"]}
    out = {}
    for n, s in base.items():
        out[n] = s
        out[n + " reversed"] = s[::-1]
    return out


def streams():
    """(name, stream) for every sculpture reading of attack 58 with every d-th letter, then the straight texts."""
    m = a58()
    for gname, rows in m.grids().items():
        for rname, s in m.readings(rows):
            for d in range(1, MAX_SKIP + 1):
                if len(s) // d < 20:
                    break
                for a in range(d):
                    yield "%s | %s | every %d from %d" % (gname, rname, d, a), s[a::d]


# ---------------------------------------------------------------- one ciphertext, one clue placement: Part A

def part_a_job(job):
    label, ct, shift, full = job
    res = {"label": label, "shift": shift}
    res["fixed"] = C.part_a(ct, shift)
    pats = {}
    for feed in ("plain", "cipher"):
        for p in PATTERN_P:
            sample = SAMPLE7 if feed == "cipher" and p == 7 else None
            pats[feed, p] = C.pattern_survivors(ct, feed, p, shift, sample, random.Random(p))
    res["patterns"] = pats
    rules, span = C.pair_rules(ct, shift)
    n_off = alive = 0
    surv = []
    for name, s in streams():
        m, n = C.running_survivors(s, rules, span)
        n_off += n
        alive += bin(m).count("1")
        if full and m:
            surv.append((name, [u for u in C.bits(m)]))
    txt_off = txt_alive = 0
    tsurv = []
    for name, s in texts().items():
        m, n = C.running_survivors(s, rules, span)
        txt_off += n
        txt_alive += bin(m).count("1")
        if m:
            tsurv.append((name, C.bits(m)))
    res["running"] = (n_off, alive, txt_off, txt_alive)
    if label != "K4" and surv:
        # controls keep 3 in 4 offsets alive (K4 about 1 in 60): Part B on a random sample of them
        flat = [(name, u) for name, us in surv for u in us]
        pick = random.Random(shift * 1000 + len(flat)).sample(flat, min(CTRL_SAMPLE, len(flat)))
        by = {}
        for name, u in pick:
            by.setdefault(name, []).append(u)
        surv = sorted(by.items())
    res["run_surv"] = surv
    res["text_surv"] = tsurv
    return res


# ---------------------------------------------------------------- Part B / Part C systems

def systems(ct, shift, run_surv, text_surv):
    """Yield (family, name, triples or None, model) for every model with known key letters."""
    pos, pt = C.clue_plain(shift)
    for fam, name, spec in C.fixed_models(shift):
        kind, dn, L = name.split()
        yield fam, name, C.triples(spec, ct, pt), (kind, int(L) * (-1 if dn == "ahead" else 1))
    for fam, src in (("text running key", text_surv), ("sculpture running key", run_surv)):
        lookup = dict(texts()) if fam == "text running key" else None
        for name, us in src:
            s = lookup[name] if lookup else stream_by_name(name)
            for u in us:
                yield fam, "%s @%d" % (name, u - 21), C.running_triples(s, u, ct, shift), ("run", s, u - 21)


_SB = {}


def stream_by_name(name):
    if not _SB:
        for n, s in streams():
            _SB[n] = s
    return _SB[name]


def decrypt(ct, model, sol, E, a, b, kidx=None, shift=0):
    """Fill in what one solution decrypts (outward from the clues for plain feed); '.' where unknown."""
    X = sol
    inv = {v: k for k, v in X.items()}
    pos, pt0 = C.clue_plain(shift)
    pt = dict(pt0)
    kind = model[0]

    def kval(letter):
        if kidx is not None:
            return kidx[letter]
        return X.get(letter)

    def kletter(v):
        if kidx is not None:
            return (KRYPTOS_ALPHABET if kidx is C.IK else AZ)[v % 26]
        return inv.get(v % 26)

    def plain_from(i, kv):
        if ct[i] not in X or kv is None:
            return None
        return inv.get((a * (X[ct[i]] - b * kv - E)) % 26)

    if kind in ("cipher", "run"):
        for i in range(97):
            if i in pt:
                continue
            if kind == "cipher":
                s = i - model[1]
                if not 0 <= s < 97:
                    continue
                kl = ct[s]
            else:
                j = model[2] + i
                if not 0 <= j < len(model[1]):
                    continue
                kl = model[1][j]
            v = plain_from(i, kval(kl))
            if v:
                pt[i] = v
    else:
        L = model[1]
        changed = True
        while changed:
            changed = False
            for i in range(97):
                s = i - L
                if not 0 <= s < 97:
                    continue
                if i not in pt and s in pt:
                    v = plain_from(i, kval(pt[s]))
                    if v:
                        pt[i] = v
                        changed = True
                elif s not in pt and i in pt and ct[i] in X and pt[i] in X:
                    v = kletter(b * (X[ct[i]] - a * X[pt[i]] - E))
                    if v:
                        pt[s] = v
                        changed = True
    return "".join(pt.get(i, ".") for i in range(97))


def run_score(q, text, shift=0):
    """Mean big-model log10 per quadgram over runs of known letters outside the clues; (score, quadgrams)."""
    pos = set(C.clue_positions(shift))
    s = "".join("." if i in pos else ch for i, ch in enumerate(text))
    tot = cnt = 0
    for run in s.split("."):
        for i in range(len(run) - 3):
            tot += q.logp.get(run[i:i + 4], q.floor)
            cnt += 1
    return (tot / cnt if cnt else None), cnt


def bc_job(job):
    """Part B and Part C for one ciphertext / placement over a list of systems. Returns status counters and the
    decrypted texts of every listed solution (with enough letters to read)."""
    label, ct, shift, run_surv, text_surv, which = job
    stat = Counter()
    listed = []
    for fam, name, tr, model in systems(ct, shift, run_surv, text_surv):
        if which == "sculpture" and fam != "sculpture running key":
            continue
        if which == "main" and fam == "sculpture running key":
            continue
        for fn, a, b in C.FORMS:
            rows, rhs = C.rows_hidden(tr, a, b)
            st, sols = C.decide(rows, rhs, tr)
            stat["B", fam, st] += 1
            if st in ("ok", "capped"):
                listed.append(("B", fam, name, fn, len(sols), [decrypt(ct, model, s, E, a, b, None, shift)
                                                               for s, E in sols]))
            for kn, kidx in NUMS:
                rows, rhs = C.rows_numeric(tr, a, b, kidx)
                st2, sols = ("tableau", []) if st == "tableau" else C.decide(rows, rhs)
                stat["C" + kn, fam, st2] += 1
                if st2 in ("ok", "capped"):
                    listed.append(("C" + kn, fam, name, fn, len(sols), [decrypt(ct, model, s, E, a, b, kidx, shift)
                                                                         for s, E in sols]))
    if which == "main":
        for L in C.CHAIN_LAGS:
            for dn in ("back", "ahead"):
                for fn, a, b in C.FORMS:
                    rows, rhs = C.chain_rows(ct, L, a, b, shift, dn)
                    st, sols = C.decide(rows, rhs)
                    stat["chain", "%s %d" % (dn, L), st] += 1
                    stat["chain", "all", st] += 1
                    if st in ("ok", "capped"):
                        listed.append(("chain", "plain chain", "%s %d" % (dn, L), fn, len(sols), []))
    return label, shift, which, stat, listed


def part_a_chunk(chunk):
    return [part_a_job(j) for j in chunk]


def bc_chunk(chunk):
    return [bc_job(j) for j in chunk]


# ---------------------------------------------------------------- planted answers

def planted(rng):
    """Returns (ok, lines). Plain autokey lag 3, cipher autokey lag 11, K2 plaintext running key; each on a random
    Latin square (no clash for the true model) and on a random hidden alphabet (true alphabet among Part B
    solutions or, if the system is too loose to list, satisfying it; Part C likewise with the key on A-Z)."""
    ok, lines = True, []
    k2 = letters(load("k2")["plaintext"])
    for trial in range(2):
        pt = C.plant_text(rng)
        off = rng.randrange(len(k2) - 97)
        primer = "".join(rng.choice(AZ) for _ in range(97))
        models = (("plain autokey lag 3", ("plain", 3)), ("cipher autokey lag 11", ("cipher", 11)),
                  ("K2 running key @%d" % off, ("run", k2[off:off + 97])))
        sq = C.latin_square(rng)
        assert C.is_latin(sq)
        for mname, model in models:
            ct = C.encrypt_square(pt, model, sq, primer)
            if model[0] == "run":
                rules, span = C.pair_rules(ct)
                m, n = C.running_survivors(k2, rules, span)
                good = bool(m >> (off + 21) & 1)
                killed = n - bin(m).count("1")
                lines.append("  Latin square, %s: true offset survives %s; %d of %d other K2 offsets clash" % (
                    mname, good, killed, n - 1))
            else:
                tr = C.triples(C.model_spec(model), ct, C.clue_plain()[1])
                good = not C.clashes(tr)
                A = C.part_a(ct)
                killed = sum(1 for v in A.values() if v[2])
                lines.append("  Latin square, %s: true model clash-free %s; %d of %d other fixed models clash" % (
                    mname, good, killed, len(A) - 1))
            ok &= good
        for mname, model in models:
            fn, a, b = rng.choice(C.FORMS)
            alpha = "".join(rng.sample(AZ, 26))
            E = rng.randrange(26)
            for part, kidx in (("B", None), ("C", C.IZ)):
                ct = C.encrypt_hidden(pt, model, alpha, a, b, E, primer, kidx)
                if model[0] == "run":
                    tr = C.running_triples(model[1], 21, ct)
                else:
                    tr = C.triples(C.model_spec(model), ct, C.clue_plain()[1])
                rows, rhs = (C.rows_hidden(tr, a, b) if kidx is None else C.rows_numeric(tr, a, b, kidx))
                st, sols = C.decide(rows, rhs, tr, max_points=200000)
                sat = C.satisfies(rows, rhs, alpha, E)
                letters_used = {ch for t in tr for ch in t[:3]}
                found = any(C.same_alphabet(s, alpha, letters_used) for s, _ in sols) if kidx is None else any(
                    len({(s[ch] - alpha.index(ch)) % 26 for ch in s}) == 1 for s, _ in sols)
                good = sat and st not in ("tableau", "none") and (found or st == "open")
                if st == "capped" and not found:
                    good = sat          # listed only the first 64; the true alphabet satisfies the system
                lines.append("  hidden alphabet (Part %s, %s), %s: status %s, %d listed, true alphabet listed %s, "
                             "satisfies %s" % (part, fn, mname, st, len(sols), found, sat))
                ok &= good
    return ok, lines


def prefilter_encrypt(pt, rng):
    """Ciphertext autokey 11 back on a random hidden alphabet, C = P + K; alphabet, constant, primer from rng."""
    alpha = "".join(rng.sample(AZ, 26))
    primer = "".join(rng.choice(AZ) for _ in range(len(pt)))
    return C.encrypt_hidden(pt, ("cipher", 11), alpha, 1, 1, rng.randrange(26), primer)


# ---------------------------------------------------------------- report

def summarise_a(res):
    fx = res["fixed"]
    dead = [n for n, v in fx.items() if v[2]]
    fam = Counter(v[0] for n, v in fx.items() if v[2])
    fragile = [n for n, v in fx.items() if v[3]]
    return dead, fam, fragile


def main():
    t0 = time.time()
    rng = random.Random(117)
    ok, lines = planted(rng)
    print("PLANTED ANSWERS")
    print("\n".join(lines))
    if not ok:
        print("planted test FAILED")
        sys.exit(1)
    q = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")

    with Experiment("117 clash on every tableau: fed-key models (autokey, lag patterns, running keys) on any Latin "
                    "square, one hidden alphabet, and key on A-Z/KR", puzzle="k4",
                    notes="Part A Latin-square clash test; Part B one hidden alphabet X[C]=aX[P]+bX[K]+E; Part C "
                          "key numbered on AZ/KR; plain lags 1-60, cipher lags 1-68 back/ahead, idea-74 patterns "
                          "p2-7, attack-58 sculpture readings + K1-K3 texts at every offset, clue 2 moved -3..+3, "
                          "plain chains 15-26; 50 shuffled controls", cribs_forced=True) as ex:
        cts = [("K4", K4)] + [("shuffled %d" % s, shuffled_control(s)) for s in range(1, N_CTRL + 1)]
        jobs = [(lab, ct, sh, lab == "K4" or k <= N_CTRL_FULL) for k, (lab, ct) in enumerate(cts) for sh in SHIFTS]
        A = {}
        for r in pmap(part_a_chunk, jobs, None, (), chunk=1, procs=6):
            for res in r:
                A[res["label"], res["shift"]] = res
        print("\nPart A done in %.0f s" % (time.time() - t0))
        tested = 0

        # ---- Part A report
        for sh in SHIFTS:
            k = A["K4", sh]
            dead, fam, fragile = summarise_a(k)
            nfix = len(k["fixed"])
            ctrl = [summarise_a(A["shuffled %d" % s, sh]) for s in range(1, N_CTRL + 1)]
            cd = sorted(len(c[0]) for c in ctrl)
            print("\nPART A, second clue moved by %+d: %d fixed models with known key letters" % (sh, nfix))
            print("  K4: %d impossible on every tableau (plain autokey %d, cipher autokey %d); of these %d would be "
                  "saved by one wrong letter" % (len(dead), fam["plain autokey"], fam["cipher autokey"],
                                                 len([n for n in dead if k["fixed"][n][3]])))
            print("  controls: impossible min %d, median %d, max %d; K4 rank (controls with fewer) %d of %d" % (
                cd[0], cd[len(cd) // 2], cd[-1], sum(1 for c in cd if c < len(dead)), len(cd)))
            for famname in ("plain autokey", "cipher autokey"):
                cf = sorted(c[1][famname] for c in ctrl)
                print("    %s: K4 %d, controls %d-%d (median %d)" % (famname, fam[famname], cf[0], cf[-1],
                                                                     cf[len(cf) // 2]))
            rules, _ = C.pair_rules(K4, sh)
            must = [(a + 21, b + 21) for a, b, m in rules if m]
            print("  K4 clue pairs with the same plain AND cipher letter (key letters there must be equal on every "
                  "tableau): %s; pairs where the key letters must differ: %d" % (must, len(rules) - len(must)))
            cm = sorted(sum(1 for r in C.pair_rules(shuffled_control(s), sh)[0] if r[2]) for s in range(1, N_CTRL + 1))
            print("  controls: such equal pairs per shuffle %s" % dict(Counter(cm)))
            if sh == 0:
                print("  K4 survivors (model: triples, testable pairs):")
                surv = [(n, v) for n, v in k["fixed"].items() if not v[2]]
                print("   ", ", ".join("%s (%d, %d)" % (n, v[1], v[4]) for n, v in surv))
                print("  K4 impossible (model: clashes, fragile):")
                print("   ", ", ".join("%s (%d%s)" % (n, k["fixed"][n][2], "*" if k["fixed"][n][3] else "")
                                       for n in dead))
            tested += nfix * (N_CTRL + 1)
            for feed in ("plain", "cipher"):
                for p in PATTERN_P:
                    tot, sv, samp = k["patterns"][feed, p]
                    cs = sorted(A["shuffled %d" % s, sh]["patterns"][feed, p][1] for s in range(1, N_CTRL + 1))
                    print("  lag patterns %s feed p=%d: %d patterns, K4 clash-free %d%s (%.2f%%); controls %d-%d "
                          "(median %d)" % (feed, p, tot, sv, " (sampled)" if samp else "", 100.0 * sv / tot, cs[0],
                                           cs[-1], cs[len(cs) // 2]))
                    tested += tot * (N_CTRL + 1)
            n_off, alive, t_off, t_alive = k["running"]
            ca = sorted(A["shuffled %d" % s, sh]["running"][1] for s in range(1, N_CTRL + 1))
            ta = sorted(A["shuffled %d" % s, sh]["running"][3] for s in range(1, N_CTRL + 1))
            print("  running keys, sculpture readings: %d offsets, K4 clash-free %d (%.2f%%); controls %d-%d "
                  "(median %d)" % (n_off, alive, 100.0 * alive / n_off, ca[0], ca[-1], ca[len(ca) // 2]))
            print("  running keys, K1-K3 texts: %d offsets, K4 clash-free %d; controls %d-%d (median %d)" % (
                t_off, t_alive, ta[0], ta[-1], ta[len(ta) // 2]))
            tested += (n_off + t_off) * (N_CTRL + 1)

        # ---- Part B / C
        t1 = time.time()
        bc = []
        for (lab, sh), res in A.items():
            if lab == "K4" or sh == 0:
                bc.append((lab, dict(cts)[lab], sh, [], res["text_surv"], "main"))
            if sh == 0 and res["run_surv"]:
                # split the sculpture survivors into chunks for the pool
                surv = res["run_surv"]
                for i in range(0, len(surv), 400):
                    bc.append((lab, dict(cts)[lab], sh, surv[i:i + 400], [], "sculpture"))
        stats = {}
        listed = []
        for r in pmap(bc_chunk, bc, None, (), chunk=1, procs=6):
            for lab, sh, which, stat, lst in r:
                stats.setdefault((lab, sh), Counter()).update(stat)
                for item in lst:
                    listed.append((lab, sh) + item)
        print("\nParts B and C done in %.0f s" % (time.time() - t1))
        report_bc(stats, listed, q, ex, cts)
        tested += sum(sum(v.values()) for v in stats.values())
        ex.count(tested)
        print("\ntotal models x forms tested (K4 and controls): %d; %.0f s" % (tested, time.time() - t0))


def report_bc(stats, listed, q, ex, cts):
    parts = ("B", "CAZ", "CKR")
    fams = ("plain autokey", "cipher autokey", "text running key", "sculpture running key")
    for sh in SHIFTS:
        k = stats.get(("K4", sh), Counter())
        print("\nPARTS B/C, second clue moved by %+d (K4; controls at shift 0 only)" % sh)
        for part in parts:
            for fam in fams:
                row = {st: k[part, fam, st] for st in ("tableau", "none", "ok", "capped", "open")}
                if not sum(row.values()):
                    continue
                line = "  %-4s %-22s K4: impossible %d (clash %d, no distinct solution %d), solutions listed %d, " \
                       "undecided %d" % (part, fam, row["tableau"] + row["none"], row["tableau"], row["none"],
                                         row["ok"] + row["capped"], row["open"])
                if sh == 0:
                    labs = ["shuffled %d" % s for s in range(1, N_CTRL + 1)]
                    if fam == "sculpture running key":
                        labs = labs[:N_CTRL_FULL]
                    cl = sorted(stats[lab, 0][part, fam, "ok"] + stats[lab, 0][part, fam, "capped"] for lab in labs)
                    co = sorted(stats[lab, 0][part, fam, "open"] for lab in labs)
                    line += "; controls listed %d-%d (median %d), undecided %d-%d" % (
                        cl[0], cl[-1], cl[len(cl) // 2], co[0], co[-1])
                    if fam == "sculpture running key":
                        tot = lambda lab: max(1, sum(stats[lab, 0][part, fam, st] for st in
                                                     ("tableau", "none", "ok", "capped", "open")))
                        fr = ["%.1f%%" % (100.0 * (stats[lab, 0][part, fam, "ok"] + stats[lab, 0][part, fam, "capped"])
                                          / tot(lab)) for lab in labs]
                        line += "\n         (controls sample %d clash-free offsets each) listed share: K4 %.1f%%, " \
                                "controls %s" % (CTRL_SAMPLE, 100.0 * (row["ok"] + row["capped"]) / sum(row.values()),
                                                 ", ".join(fr))
                print(line)
        row = {st: k["chain", "all", st] for st in ("tableau", "none", "ok", "capped", "open")}
        if sum(row.values()):
            print("  chains plain autokey lags %d-%d (x back/ahead x 4 forms): impossible %d, listed %d, undecided %d"
                  % (C.CHAIN_LAGS[0], C.CHAIN_LAGS[-1], row["none"], row["ok"] + row["capped"], row["open"]))
            for L in range(19, 23):
                for dn in ("back", "ahead"):
                    r2 = {st: k["chain", "%s %d" % (dn, L), st] for st in ("none", "ok", "capped", "open")}
                    print("    lag %d %s: impossible %d, listed %d, undecided %d" % (
                        L, dn, r2["none"], r2["ok"] + r2["capped"], r2["open"]))
            if sh == 0:
                cl = sorted(stats["shuffled %d" % s, 0]["chain", "all", "none"] for s in range(1, N_CTRL + 1))
                print("    controls: chains impossible %d-%d (median %d)" % (cl[0], cl[-1], cl[len(cl) // 2]))
    # fixed models with listed solutions on K4, and the readings they give
    print("\nK4 fixed models (shift 0) with 10+ clue letters and solutions listed in Part B/C:")
    big = {n: v[1] for n, v in C.part_a(K4).items()}
    for lab, sh, part, fam, name, fn, ns, texts_ in listed:
        if lab == "K4" and sh == 0 and fam in ("plain autokey", "cipher autokey") and big.get(name, 0) >= 10:
            print("  %s %s (%d letters) %s: %d solutions" % (part, name, big[name], fn, ns))
    best = []
    for lab, sh, part, fam, name, fn, ns, texts_ in listed:
        for t in texts_:
            sc, cnt = run_score(q, t, sh)
            if sc is None or cnt < 10:
                continue
            best.append((sc, cnt, lab, sh, part, fam, name, fn, t))
            if lab == "K4":
                ex.add(t.replace(".", "X"), part=part, family=fam, model=name, form=fn, shift=sh, big=round(sc, 3),
                       quadgrams=cnt)
    best.sort(reverse=True)
    for who in ("K4", "controls"):
        sel = [b for b in best if (b[2] == "K4") == (who == "K4")]
        print("\nbest readings from listed solutions, %s (%d readings with 10+ quadgrams outside the clues; English "
              "needs about %.1f):" % (who, len(sel), ENGLISH))
        for sc, cnt, lab, sh, part, fam, name, fn, t in sel[:6]:
            print("  %.3f over %d  %s shift %+d Part %s %s | %s | %s" % (sc, cnt, lab, sh, part, fam, name, fn))
            print("     %s   word coverage %.2f" % (t, word_coverage(t.replace(".", ""))))


if __name__ == "__main__":
    if "--prefilter" in sys.argv:
        from kryptos.clues import prefilter
        prefilter("cipher autokey (lag 11) on one hidden alphabet", encrypt=prefilter_encrypt,
                  marks={"hand": ("pass", "paper tableau; key = cipher letter 11 back")})
        sys.exit(0)
    main()
