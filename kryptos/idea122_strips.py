"""Idea 122: the sentences were enciphered one at a time, so the key's place at BERLINCLOCK is free.

Sanborn cut the plaintext into sentence strips and handled them out of order. If each sentence (or
strip) was enciphered on its own, or the sentences were enciphered in another order than they were
carved, the key runs on without a break inside each clue, but where it stands at the second clue
has nothing to do with the 42 letters between the clues. Every earlier joint test assumed it does.

So the two clue blocks are taken as separate runs (and, as a second split, EAST | NORTHEAST |
BERLINCLOCK as three runs). Run 0 is the reference; each later run gets a free phase g: the key
letter at clue position i of run r is the one the carved text would have used at i + g. g = 0 (the
carved gap) is left out: it was tested in rounds 9-11. Rules:

  rep      repeating key word of L letters (L 2..16; 17..20 as a gauge at 5-6 checks)
  slide    strip moved on by a word of L letters (first differences inside each run are a
           repeating word; the strip's place at each restart is free because differences across
           runs are never used)
  auto     plain or cipher autokey, lags 1-6, both signs, with a repeating word of L letters on top:
           k[b] - s * x[b - lag] = W[b + g]; feed pairs never cross a run boundary
  prog     progressive key: k = W[phi mod p] + step * (phi div p) (+ a free multiple of step in run 1:
           the pass count at the restart is unknown); 2 runs only, p 1..12, every g including 0
  stacked  two repeating words of p < q <= 9 letters added, each with its own free phase in run 1;
           exact loop test as in kryptos.idea104_holes (loops = clue letters - key letters + pieces)

Every test is exact: the key values the clue letters force must satisfy every equation. A setting
counts only with 7 or more independent checks. Expected chance passes = sum over settings of
26 ** -checks (each phase is its own setting, so the free phase is paid for in the sum).

A hit is (checks, alphabet name, layout, form, rule, split, phases).
"""
import os
from math import gcd
from operator import itemgetter

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET as KR
from .round11 import B1, B2, POS, pmap, streams

SMOKE = os.environ.get("KRYPTOS_SMOKE")
MIN_CHECKS = 7
GAUGE_MIN = 5
AUTO3_BAR = 8
SPLITS = {"2": [list(range(0, 13)), list(range(13, 24))],
          "3": [list(range(0, 4)), list(range(4, 13)), list(range(13, 24))]}
RUN_OF = {sp: {j: r for r, run in enumerate(runs) for j in run} for sp, runs in SPLITS.items()}
LMAX = {"2": 16, "3": 9}
GAUGE_L = {"rep": (17, 20), "slide": (16, 18)}       # 2 runs only; checks 5-6
LAGS = range(1, 7)
PQ_MAX = 9
P_PROG = 12


# ------------------------------------------------------------------ structure (same for every stream)

def _getter(idx):
    idx = list(idx)
    return itemgetter(*(idx + [idx[0]]))      # always a tuple, even for one index


def items_for(fam, split):
    """[(value index, run, position whose phase picks the word letter)] and a builder spec.

    fam: 'rep', 'slide', ('auto', feed, lag, sign)."""
    runof = RUN_OF[split]
    if fam == "rep":
        return [(j, runof[j], POS[j]) for j in range(24)], ("rep",)
    if fam == "slide":
        pairs = [(j, j + 1) for j in range(23) if runof[j] == runof[j + 1] and POS[j + 1] == POS[j] + 1]
        return [(t, runof[b], POS[b]) for t, (a, b) in enumerate(pairs)], ("slide", pairs)
    _, feed, lag, sg = fam
    pairs = [(j, j + lag) for j in range(24 - lag) if runof[j] == runof[j + lag] and POS[j + lag] == POS[j] + lag]
    return [(t, runof[b], POS[b]) for t, (a, b) in enumerate(pairs)], ("auto", pairs, feed, sg)


def values(spec, k, xp, xc):
    kind = spec[0]
    if kind == "rep":
        return k
    if kind == "slide":
        return [(k[b] - k[a]) % 26 for a, b in spec[1]]
    _, pairs, feed, sg = spec
    x = xp if feed == "plain" else xc
    return [(k[b] - sg * x[a]) % 26 for a, b in pairs]


def phase_tuples(nruns, L, with_zero=False):
    """Phases (g_1, .., g_{n-1}) for runs 1.. relative to run 0; the carved one (all zero) left out.
    With 3 runs, g_1 = 0 (EAST and NORTHEAST in step) is the 2-run test and is left out too."""
    if nruns == 2:
        return [(g,) for g in range(0 if with_zero else 1, L)]
    return [(g1, g2) for g1 in range(1, L) for g2 in range(L)]


def plan_single(items, nruns, L, min_checks):
    """Internal equality pairs (phase-free) and, per phase, the cross pairs and the checks."""
    groups = {}
    for idx, r, pos in items:
        groups.setdefault((r, pos % L), []).append(idx)
    ia, ib = [], []
    for g in groups.values():
        for a, b in zip(g, g[1:]):
            ia.append(a)
            ib.append(b)
    internal = (_getter(ia), _getter(ib)) if ia else None
    reps = {key: g[0] for key, g in groups.items()}
    out = []
    for ph in phase_tuples(nruns, L):
        glob, ca, cb = {}, [], []
        for (r, res), idx in sorted(reps.items()):
            gres = (res + (ph[r - 1] if r else 0)) % L
            if gres in glob:
                ca.append(glob[gres])
                cb.append(idx)
            else:
                glob[gres] = idx
        checks = len(items) - len(glob)
        if checks >= min_checks and ca:
            out.append((ph, checks, _getter(ca), _getter(cb)))
    return internal, out


def index_phases(items, nruns, L, ph):
    """A faster plan for the same phase entries (same answers, fewer comparisons).

    2 runs: one anchor letter of run 1; for each phase the run-0 letter it must equal. One C-level
    tuple fetch tells which phases can pass at all. 3 runs: test EAST against NORTHEAST once per g1."""
    reps = {}
    for idx, r, pos in items:
        reps.setdefault((r, pos % L), idx)
    if nruns == 2:
        r1 = sorted(res for r, res in reps if r == 1)
        best = None
        for r0 in r1:
            have = [e for e in ph if (0, (r0 + e[0][0]) % L) in reps]
            if best is None or len(have) > len(best[1]):
                best = (r0, have)
        r0, have = best
        rest = [e for e in ph if e not in have]
        partners = [reps[(0, (r0 + e[0][0]) % L)] for e in have]
        return ("2", reps[(1, r0)], _getter(partners) if partners else None, have, rest)
    groups = {}
    for e in ph:
        groups.setdefault(e[0][0], []).append(e)
    out = []
    for g1, entries in sorted(groups.items()):
        ca, cb = [], []
        for (r, res), idx in reps.items():
            if r == 1 and (0, (res + g1) % L) in reps:
                ca.append(reps[(0, (res + g1) % L)])
                cb.append(idx)
        out.append((_getter(ca) if ca else None, _getter(cb) if cb else None, entries))
    return ("3", out)


def loops(edges):
    """edges [(j, u, v)] meaning x_u - x_v = val_j. Returns ([(plus idx, minus idx)], nodes, pieces)."""
    adj = {}
    for j, u, v in edges:
        adj.setdefault(u, []).append((j, v, 1))
        adj.setdefault(v, []).append((j, u, -1))
    pot, used, out, pieces = {}, set(), [], 0
    for root in sorted(adj):
        if root in pot:
            continue
        pieces += 1
        pot[root] = {}
        queue = [root]
        for node in queue:
            for j, other, s in adj[node]:
                if j in used:
                    continue
                used.add(j)
                c = dict(pot[node])
                c[j] = c.get(j, 0) - s          # x_other = x_node - s * val_j
                if other not in pot:
                    pot[other] = c
                    queue.append(other)
                else:
                    d = {t: c.get(t, 0) - pot[other].get(t, 0) for t in set(c) | set(pot[other])}
                    plus = [t for t, w in d.items() for _ in range(max(w, 0))]
                    minus = [t for t, w in d.items() for _ in range(max(-w, 0))]
                    out.append((sorted(plus), sorted(minus)))
    return out, len(pot), pieces


def stacked_edges(p, q, ph=(0, 0), idx=range(24)):
    g1, g2 = ph
    return [(j, (0, (POS[j] + (g1 if j >= 13 else 0)) % p), (1, (POS[j] + (g2 if j >= 13 else 0)) % q)) for j in idx]


def _loop_getters(lps):
    out = []
    for plus, minus in sorted(lps, key=lambda t: len(t[0]) + len(t[1])):
        out.append((itemgetter(*plus, 24) if plus else None, itemgetter(*minus, 24) if minus else None))
    return out


def plan_stacked(min_checks=MIN_CHECKS):
    out = []
    for p in range(2, PQ_MAX):
        for q in range(p + 1, PQ_MAX + 1):
            internal = []
            for idx in (range(13), range(13, 24)):
                internal += loops(stacked_edges(p, q, (0, 0), idx))[0]
            phases = []
            for g1 in range(p):
                for g2 in range(q):
                    if (g1, g2) == (0, 0):
                        continue
                    lps = loops(stacked_edges(p, q, (g1, g2)))[0]
                    if len(lps) >= min_checks:
                        phases.append(((g1, g2), len(lps), _loop_getters(lps)))
            out.append((p, q, _loop_getters(internal), phases))
    return out


def _fits(getters, v):
    for P, M in getters:
        if ((sum(P(v)) if P else 0) - (sum(M(v)) if M else 0)) % 26:
            return False
    return True


def families():
    fams = ["rep", "slide"]
    for feed in ("plain", "cipher"):
        for lag in LAGS:
            for sg in (1, -1):
                fams.append(("auto", feed, lag, sg))
    return fams


def fam_name(fam):
    return fam if isinstance(fam, str) else "autokey %s lag=%d sign=%+d" % fam[1:]


_PLAN = {}


def plan():
    """Everything that does not depend on the stream, built once per process."""
    if _PLAN:
        return _PLAN
    single = []
    for split in ("2", "3"):
        nruns = len(SPLITS[split])
        for fam in families():
            items, spec = items_for(fam, split)
            rows = []
            for L in range(2, LMAX[split] + 1):
                internal, ph = plan_single(items, nruns, L, MIN_CHECKS)
                if ph:
                    rows.append((L, internal, ph, index_phases(items, nruns, L, ph)))
            if split == "2" and fam in GAUGE_L:
                lo, hi = GAUGE_L[fam]
                for L in range(lo, hi + 1):
                    internal, ph = plan_single(items, nruns, L, GAUGE_MIN)
                    ph = [x for x in ph if x[1] < MIN_CHECKS]
                    if ph:
                        rows.append((L, internal, ph, index_phases(items, nruns, L, ph)))
            single.append((split, fam, spec, rows))
    _PLAN["single"] = single
    _PLAN["stacked"] = plan_stacked()
    # progressive: lag-p pairs per block, residues, phases
    prog = []
    for p in range(1, P_PROG + 1):
        lagpairs = [(j, j + p) for j in range(24 - p) if (j + p < 13 or j >= 13) and POS[j + p] == POS[j] + p]
        if not any(b < 13 for a, b in lagpairs):
            continue
        phases = []
        for g in range(p):
            res1 = {POS[j] % p for j in range(13)}
            res2 = {(POS[j] + g) % p for j in range(13, 24)}
            checks = 24 - len(res1 | res2) - 2
            if checks >= MIN_CHECKS and res1 & res2:
                phases.append((g, checks))
        if phases:
            prog.append((p, lagpairs, phases))
    _PLAN["prog"] = prog
    return _PLAN


def sizes():
    """Settings per key stream, chance passes per key stream at >= 7 checks, and in the 5-6 gauge."""
    pl = plan()
    n, chance, n_g, chance_g = 0, 0.0, 0, 0.0
    by = {}
    for split, fam, spec, rows in pl["single"]:
        name = "%s/%s" % (split, fam if isinstance(fam, str) else "auto")
        for L, internal, ph, fast in rows:
            for x in ph:
                if x[1] >= (AUTO3_BAR if split == "3" and name.endswith("auto") else MIN_CHECKS):
                    n += 1
                    chance += 26.0 ** -x[1]
                    by[name] = by.get(name, 0) + 1
                else:
                    n_g += 1
                    chance_g += 26.0 ** -x[1]
    for p, q, internal, ph in pl["stacked"]:
        for x in ph:
            n += 1
            chance += 26.0 ** -x[1]
            by["2/stacked"] = by.get("2/stacked", 0) + 1
    for p, lp, ph in pl["prog"]:
        for g, ck in ph:
            n += 1
            chance += 26.0 ** -ck
            by["2/prog"] = by.get("2/prog", 0) + 1
    return n, chance, n_g, chance_g, by


# ------------------------------------------------------------------ the test of one key stream

def test_stream(k, xp, xc, pl=None):
    """[(checks, rule, split, phases)] for every free-phase setting the key values satisfy."""
    pl = pl or plan()
    out = []
    for split, fam, spec, rows in pl["single"]:
        v = values(spec, k, xp, xc)
        for L, internal, ph, fast in rows:
            if internal and internal[0](v) != internal[1](v):
                continue
            cand = []
            if fast[0] == "2":
                _, anchor, P, have, rest = fast
                cand = rest
                if P is not None:
                    tup, val = P(v)[:-1], v[anchor]
                    if val in tup:
                        cand = rest + [e for e, x in zip(have, tup) if x == val]
            else:
                for A, B, entries in fast[1]:
                    if A is None or A(v) == B(v):
                        cand += entries
            for phs, ck, A, B in cand:
                if A(v) == B(v):
                    out.append((ck, "%s L=%d" % (fam_name(fam), L), split, phs))
    kz = list(k) + [0]
    for p, q, internal, ph in pl["stacked"]:
        if not _fits(internal, kz):
            continue
        for phs, ck, getters in ph:
            if _fits(getters, kz):
                out.append((ck, "two stacked keys p=%d q=%d" % (p, q), "2", phs))
    for p, lagpairs, ph in pl["prog"]:
        d = {(k[b] - k[a]) % 26 for a, b in lagpairs}
        if len(d) != 1:
            continue
        s = d.pop()
        if s == 0:
            continue                          # a plain repeating key: tested under rep
        w = {}
        for j in range(13):
            w[POS[j] % p] = (k[j] - s * (POS[j] // p)) % 26
        step = gcd(s, 26)
        for g, ck in ph:
            D = None
            for j in range(13, 24):
                phi = POS[j] + g
                r = phi % p
                if r in w:
                    dd = (k[j] - s * (phi // p) - w[r]) % 26
                    if D is None:
                        D = dd
                    elif dd != D:
                        break
            else:
                if D is not None and D % step == 0:
                    out.append((ck, "progressive p=%d step=%d" % (p, s), "2", (g, D)))
    return out


_S = {}


def init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]
    plan()


def bar(rule, split):
    """Checks a pass needs to count. Autokey with a word on top over three runs has so many settings
    (2,868 per key stream) that 7 checks would let in about 0.26 chance passes; it needs 8 there."""
    return AUTO3_BAR if split == "3" and rule.startswith("autokey") else MIN_CHECKS


def is_main(hit):
    return hit[0] >= bar(hit[4], hit[5])


def work(chunk):
    hits, n = [], 0
    pl = plan()
    for name, m in chunk:
        for lay, form, k, xp, xc in streams(m, _S["p"], _S["c"]):
            n += 1
            for ck, rule, split, phs in test_stream(k, xp, xc, pl):
                hits.append((ck, name, lay, form, rule, split, phs))
    return n, hits


def search(ct, cribs, alphas, chunk=1500, procs=None):
    hits, n = [], 0
    for c, h in pmap(work, alphas, init, (ct, cribs), chunk=chunk, procs=procs):
        n += c
        hits += h
    return n, hits


def search_serial(ct, cribs, alphas):
    init(ct, cribs)
    return work(alphas)


# ------------------------------------------------------------------ reading a hit

def faces(lay, m):
    f = {"AZ": AZ, "KR": KR, "M": m}
    a, b = lay.split("/")
    return f.get(a, m), f.get(b, m)


def read(hit, m, ct, cribs, brk):
    """All 97 letters under a hit, run 1 starting at `brk` (a sentence start between the clues:
    34..63; run 2 of the 3-run split starts at 25). '?' where the clue letters fix no key."""
    _, _, lay, form, rule, split, phs = hit
    plain, cipher = faces(lay, m)
    ia = {c: i for i, c in enumerate(plain)}
    ib = {c: i for i, c in enumerate(cipher)}
    im = {c: i for i, c in enumerate(m)}
    beau = form == "beau"
    n = len(ct)

    def kval(i, p_letter):
        x, y = ia[p_letter], ib[ct[i]]
        return (y + x) % 26 if beau else (y - x) % 26

    def plain_of(i, kk):
        y = ib[ct[i]]
        return plain[(kk - y) % 26 if beau else (y - kk) % 26]

    starts = [0, brk] if split == "2" else [0, 25, brk]
    run_at = [max(r for r, s in enumerate(starts) if i >= s) for i in range(n)]
    shift = [0] + list(phs if split == "3" or not rule.startswith("progressive") else phs[:1])
    if rule.startswith("two stacked"):
        shift = [(0, 0), phs]
    known = {i: kval(i, cribs[i]) for i in cribs}
    out = ["?"] * n
    for i in cribs:
        out[i] = cribs[i]
    words = rule.split()
    if rule.startswith("two stacked"):
        p, q = int(words[3][2:]), int(words[4][2:])
        edges = [(i, (0, (i + shift[run_at[i]][0]) % p), (1, (i + shift[run_at[i]][1]) % q)) for i in sorted(cribs)]
        x = _solve_potentials(edges, known)
        for i in range(n):
            u = (0, (i + shift[run_at[i]][0]) % p)
            v = (1, (i + shift[run_at[i]][1]) % q)
            if i not in cribs and u in x and v in x and x[u][1] == x[v][1]:
                out[i] = plain_of(i, (x[u][0] - x[v][0]) % 26)
        return "".join(out)
    if rule.startswith("progressive"):
        p, s = int(words[1][2:]), int(words[2][5:])
        g, D = phs
        w = {i % p: (known[i] - s * (i // p)) % 26 for i in sorted(cribs) if i < 63}
        for i in range(n):
            phi = i + (g if run_at[i] else 0)
            if i not in cribs and phi % p in w:
                out[i] = plain_of(i, (w[phi % p] + s * (phi // p) + (D if run_at[i] else 0)) % 26)
        return "".join(out)
    L = int(words[-1][2:])

    def ph(i):
        return (i + shift[run_at[i]]) % L
    if rule.startswith("rep"):
        w = {ph(i): known[i] for i in cribs}
        for i in range(n):
            if i not in cribs and ph(i) in w:
                out[i] = plain_of(i, w[ph(i)])
        return "".join(out)
    if rule.startswith("slide"):
        w = {ph(i): (known[i] - known[i - 1]) % 26 for i in cribs if i - 1 in cribs and run_at[i] == run_at[i - 1]}
        kk = dict(known)
        for i in sorted(cribs):                    # forwards inside the run
            j = i
            while j + 1 < n and run_at[j + 1] == run_at[i] and j + 1 not in kk and ph(j + 1) in w:
                kk[j + 1] = (kk[j] + w[ph(j + 1)]) % 26
                j += 1
        for i in sorted(cribs, reverse=True):      # backwards inside the run
            j = i
            while j - 1 >= 0 and run_at[j - 1] == run_at[i] and j - 1 not in kk and ph(j) in w:
                kk[j - 1] = (kk[j] - w[ph(j)]) % 26
                j -= 1
        for i, v in kk.items():
            if i not in cribs:
                out[i] = plain_of(i, v)
        return "".join(out)
    # autokey with a word on top
    feed, lag, sg = words[1], int(words[2][4:]), int(words[3][5:])

    def xnum(i):
        return im[ct[i]] if feed == "cipher" else im[out[i]]
    w = {}
    for i in cribs:
        if i - lag in cribs and run_at[i] == run_at[i - lag]:
            w[ph(i)] = (known[i] - sg * xnum(i - lag)) % 26
    if feed == "cipher":
        for i in range(lag, n):
            if i not in cribs and run_at[i] == run_at[i - lag] and ph(i) in w:
                out[i] = plain_of(i, (w[ph(i)] + sg * im[ct[i - lag]]) % 26)
        return "".join(out)
    todo = sorted(cribs)
    while todo:
        i = todo.pop()
        b = i + lag                                # forwards: letter i feeds letter b
        if b < n and out[b] == "?" and run_at[b] == run_at[i] and ph(b) in w:
            out[b] = plain_of(b, (w[ph(b)] + sg * im[out[i]]) % 26)
            todo.append(b)
        a = i - lag                                # backwards: letter a fed letter i
        if a >= 0 and out[a] == "?" and run_at[a] == run_at[i] and ph(i) in w:
            out[a] = m[(sg * (kval(i, out[i]) - w[ph(i)])) % 26]
            todo.append(a)
    return "".join(out)


def _solve_potentials(edges, known):
    """x_u - x_v = known[j]; returns node -> (value, piece)."""
    adj = {}
    for j, u, v in edges:
        adj.setdefault(u, []).append((j, v, 1))
        adj.setdefault(v, []).append((j, u, -1))
    x = {}
    for root in sorted(adj):
        if root in x:
            continue
        x[root] = (0, root)
        queue = [root]
        for node in queue:
            for j, other, s in adj[node]:
                if other not in x:
                    x[other] = ((x[node][0] - s * known[j]) % 26, root)
                    queue.append(other)
    return x


def best_reading(hit, m, ct, cribs, big, score):
    """Try every break point 34..63 for the start of the run holding BERLINCLOCK; best by score."""
    best = None
    for brk in range(34, 64):
        pt = read(hit, m, ct, cribs, brk)
        sc, nq = score(pt, big)
        if best is None or sc > best[0]:
            best = (sc, nq, brk, pt)
    return best
