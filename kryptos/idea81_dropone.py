"""Helpers for idea 81: the round 9-11 exact tests with one clue letter left out.

If one of the 24 clue letters is deliberately wrong (as IQLUSION, UNDERGRUUND and DESPARATLY
are), every exact test fails on the true method. Leaving that one position out repairs the
test. We do not know which position, so each of the 24 is left out in turn.

Three tests, each on the 23 remaining letters:

  battery   kryptos.round11.battery (repeating, sliding, progressive, autokey, two stacked
            keys, chain addition) on every keyword alphabet, five layouts, Vigenere/Beaufort
  pairs     attack 71 part A: C = A[i mod p] * P + B[i mod q], exact solve for every p, q
  rotor     attack 72: hidden rotor wiring turned by a dictionary word (three schemes)
"""
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import CRIBS
from .round9 import solve_mod_p
from .round11 import POS, battery, english97, pmap, streams

ALPH = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
MIN_CHECKS = 7          # battery and pairs
ROTOR_MIN = 5           # rotor hits are kept from 5 checks (as attack 72); 7+ is the headline
DROPS = [(j, POS[j], POS[:j] + POS[j + 1:]) for j in range(len(POS))]
_S = {}


def cut(v, j):
    return v[:j] + v[j + 1:]


# ------------------------------------------------------------------ battery, one letter dropped

def battery_alphabet(name, m, pl, cl, drops=DROPS, min_checks=MIN_CHECKS):
    """[(checks, name, layout, form, rule, dropped position)] for one keyword alphabet."""
    hits = []
    for lay, form, k, xp, xc in streams(m, pl, cl):
        for j, dropped, pos in drops:
            for ck, rule in battery(cut(k, j), pos, 26, cut(xp, j), cut(xc, j), min_checks):
                hits.append((ck, name, lay, form, rule, dropped))
    return hits


def _init(ct, cribs):
    _S["p"] = [cribs[i] for i in POS]
    _S["c"] = [ct[i] for i in POS]
    _S["v"] = views(ct, cribs)


def _work_battery(chunk):
    hits = []
    for name, m in chunk:
        hits += battery_alphabet(name, m, _S["p"], _S["c"])
    return hits


def battery_search(ct, cribs, alphas, chunk=400):
    hits = []
    for h in pmap(_work_battery, alphas, _init, (ct, cribs), chunk=chunk):
        hits += h
    return hits


# ------------------------------------------------------------------ multiplier word + adder word

def pair_fit(p, q, pos, pv, cv):
    """Checks if C = A[i%p]*P + B[i%q] fits the letters at pos, else -1 (attack 71, any positions)."""
    seen = {}
    for i, x, y in zip(pos, pv, cv):          # mod 2: A is odd, so C - P repeats with period q
        if seen.setdefault(i % q, (y - x) % 2) != (y - x) % 2:
            return -1
    rows = []
    for i, x in zip(pos, pv):
        v = [0] * (p + q)
        v[i % p] = x % 13
        v[p + i % q] = 1
        rows.append(v)
    s = solve_mod_p(rows, cv, 13)
    if s is None:
        return -1
    part, basis = s
    for j in range(p):                        # a multiplier forced to 0 mod 13 is not usable
        if part[j] == 0 and all(b[j] == 0 for b in basis):
            return -1
    return len(pos) - (p + q - len(basis))


def views(ct, cribs):
    out = []
    for an, a in ALPH.items():
        for bn, b in ALPH.items():
            out.append(("pt%s/ct%s" % (an, bn), [a.index(cribs[i]) for i in POS], [b.index(ct[i]) for i in POS]))
    return out


def pairs_search(ct, cribs, pmax=17, drops=DROPS, min_checks=MIN_CHECKS):
    """(systems tried, [(checks, view, rule, dropped position)])."""
    hits, n = [], 0
    for vn, pv, cv in views(ct, cribs):
        for j, dropped, pos in drops:
            pj, cj = cut(pv, j), cut(cv, j)
            for p in range(1, pmax + 1):
                for q in range(1, pmax + 1):
                    n += 1
                    ck = pair_fit(p, q, pos, pj, cj)
                    if ck >= min_checks:
                        hits.append((ck, vn, "multiplier word %d + adder word %d" % (p, q), dropped))
    return n, hits


# ------------------------------------------------------------------ rotor, one wire dropped

def wires(pv, cv, s, sign):
    """Forced coincidences if the wires (P+s -> C+sign*s) form a real wiring, else -1 (attack 72)."""
    f, g = {}, {}
    for x, y, t in zip(pv, cv, s):
        u, v = (x + t) % 26, (y + sign * t) % 26
        if f.setdefault(u, v) != v or g.setdefault(v, u) != u:
            return -1
    return len(pv) - len(f)


def wires_drop_one(pv, cv, s, sign, min_checks=ROTOR_MIN):
    """[(checks on the 23 kept wires, index dropped)] for every single wire whose removal leaves
    a real wiring with at least min_checks coincidences.

    Only the wires in the first collision can be the one to drop: the later wire, or the single
    earlier wire it collides with on the input side or on the output side."""
    f, g, cand = {}, {}, None
    for j, (x, y, t) in enumerate(zip(pv, cv, s)):
        u, v = (x + t) % 26, (y + sign * t) % 26
        a, b = f.setdefault(u, (v, j)), g.setdefault(v, (u, j))
        if a[0] != v or b[0] != u:
            cand = {j}
            if a[0] != v:
                cand.add(a[1])
            if b[0] != u:
                cand.add(b[1])
            break
    if cand is None:                           # fits with no letter dropped
        if len(pv) - len(f) < min_checks:
            return []
        cand = range(len(pv))
    out = []
    for j in cand:
        ck = wires(cut(pv, j), cut(cv, j), cut(s, j), sign)
        if ck >= min_checks:
            out.append((ck, j))
    return out


def word_schemes(w, num):
    """The three turning schemes of attack 72 for a key word, as turn values at the clue positions."""
    p = len(w)
    vals = [num.index(ch) for ch in w]
    run, t, at = {}, 0, set(POS)
    for i in range(74):
        t += vals[i % p]
        if i in at:
            run[i] = t
    return (("word", [vals[i % p] for i in POS]), ("sliding word", [run[i] for i in POS]),
            ("word + 1 per letter", [vals[i % p] + i for i in POS]))


def rotor_word(w, vws, min_checks=ROTOR_MIN):
    hits = []
    for nn, num in ALPH.items():
        for sn, s in word_schemes(w, num):
            for vn, pv, cv in vws:
                for sign in (1, -1):
                    for ck, j in wires_drop_one(pv, cv, s, sign, min_checks):
                        hits.append((ck, vn, "%s %s (%s numbering), out %+d" % (sn, w, nn, sign), POS[j]))
    return hits


def _work_rotor(chunk):
    hits = []
    for w in chunk:
        hits += rotor_word(w, _S["v"])
    return hits


def rotor_search(ct, cribs, words, chunk=3000):
    hits = []
    for h in pmap(_work_rotor, words, _init, (ct, cribs), chunk=chunk):
        hits += h
    return hits


# ------------------------------------------------------------------ planted answers

def wrong_letter(rng, pt, avoid=()):
    """The 24 clue letters of pt with one changed to a different letter: (cribs, position changed)."""
    cribs = {i: pt[i] for i in CRIBS}
    j = rng.choice([i for i in POS if i not in avoid])
    cribs[j] = rng.choice([c for c in AZ if c != pt[j]])
    return cribs, j


def plant_sliding(rng, alphas):
    """A sliding-key message on a keyword alphabet; one clue letter is then given wrongly."""
    pt = english97(rng)
    name, m = rng.choice(alphas)
    p = rng.randrange(5, 9)
    word = [rng.randrange(26) for _ in range(p)]
    ct, k = [], 0
    for i, ch in enumerate(pt):
        k = (k + word[i % p]) % 26
        ct.append(m[(m.index(ch) + k) % 26])
    cribs, j = wrong_letter(rng, pt)
    return "".join(ct), cribs, (name, "M/M", "vig", "sliding p=%d" % p, j)


def plant_pair(rng):
    """Multiplier word + adder word on A-Z; one clue letter is then given wrongly."""
    pt = english97(rng)
    p, q = rng.randrange(3, 7), rng.randrange(3, 7)
    units = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    a, b = [rng.choice(units) for _ in range(p)], [rng.randrange(26) for _ in range(q)]
    ct = "".join(AZ[(a[i % p] * AZ.index(ch) + b[i % q]) % 26] for i, ch in enumerate(pt))
    cribs, j = wrong_letter(rng, pt)
    return ct, cribs, ("ptAZ/ctAZ", "multiplier word %d + adder word %d" % (p, q), j)


def plant_rotor(rng, words):
    """A rotor with random wiring turned by a dictionary word; one clue letter is then given wrongly."""
    pt = english97(rng)
    wiring = list(range(26))
    rng.shuffle(wiring)
    w = rng.choice([x for x in words if 5 <= len(x) <= 9])
    ct = "".join(AZ[(wiring[(AZ.index(ch) + AZ.index(w[i % len(w)])) % 26] - AZ.index(w[i % len(w)])) % 26]
                 for i, ch in enumerate(pt))
    cribs, j = wrong_letter(rng, pt)
    return ct, cribs, ("ptAZ/ctAZ", "word %s (AZ numbering), out +1" % w, j)
