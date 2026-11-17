"""Idea 83: the S,S and R,R repeats as a test of ANY state machine, not just Wheatstone's clock.

Idea 75 killed the Wheatstone cryptograph with one observation about repeated cipher letters.
This asks how far that reaches. Take any device with a hidden state that moves on after each
letter by an amount that depends only on that letter, and a hidden table F that turns a value
into the cipher letter:

    moore        C = F(state after the move),        state += g(plain letter)   mod m
    mealy        C = F(state + h(plain letter)),      state += g(plain letter)   mod m
    cipher-fed   C = F(state + h(plain letter)),      state += g(cipher letter)  mod m

g, h and F are unknown tables; m is anything from 2 to 60.

The answer turned out to be one line, and it needs no modulus. In the moore and mealy devices
the step from one F-input to the next depends only on the two plain letters involved
(g(first) + h(second) - h(first)). So if F is one-to-one, a plain pair that gives a DOUBLED
cipher letter once gives a doubled letter every time. The clues hold the pair S,T twice:

    letters 32-33   plain S,T -> cipher S,S   (doubled)
    letters 23-24   plain S,T -> cipher R,V   (not doubled)

So no such device with a one-to-one F fits, for any m, any tables, any group in place of Z_m.
Wheatstone's clock with ANY two ring sizes is a special case (its hand turns by an amount fixed
by the two plain letters), so idea 75's result extends from rings of 27-38 cells to all rings.

What the script does:
  1. checks the rule on K4, then solves the full equations for every m = 2..60 as an
     independent check (same letter = same value, different letters = different values, and
     different plain letters read differently), for moore, mealy and cipher-fed devices;
  2. the same with a many-to-one F (several values show the same letter, m = 27..60), where the
     rule does not apply;
  3. the same devices on KNOWN alphabets (every dictionary keyword alphabet, five layouts,
     Vigenere and Beaufort; plain and transposition-mixed keyword alphabets), where only the step table g is hidden: the key must move by the same
     amount after the same letter, 10 exact checks (plain-fed) or 8 (cipher-fed);
  4. shuffled K4s through all of it for the base rate, and planted devices that must be found.

  python attacks/83_repeats_any_state_machine.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.idea83_devices import (FEEDS, additive_encrypt, digram_rule, drift_checks, drift_encrypt,  # noqa: E402
                                    drift_table, moduli, ring_encrypt)
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import POS, SMOKE, dictionary_alphabets, english97, pmap, streams  # noqa: E402

MS = [2, 13, 14, 20, 26, 27, 31, 40, 60] if SMOKE else list(range(2, 61))
MS_MANY = [m for m in MS if m >= 27]          # many-to-one F needs more values than letters
N_CONTROLS = 12 if SMOKE else 200
MIN_CHECKS = 7
SYMS = [chr(65 + i) for i in range(60)]     # up to 60 different cipher symbols for test devices
# (label, kind, flags, moduli)
MODELS = (
    ("moore, equations only", "moore", dict(differ=False, decipherable=False), MS),
    ("moore, F one-to-one", "moore", dict(decipherable=False), MS),
    ("moore, F one-to-one, decipherable", "moore", {}, MS),
    ("mealy, F one-to-one", "tables", {}, MS),
    ("cipher-fed, F one-to-one", "tables-cipher", {}, MS),
    ("moore, F many-to-one", "moore", dict(same_state=False), MS_MANY),
    ("mealy, F many-to-one", "mealy", dict(same_state=False), MS_MANY),
)
_S = {}


def sweep(ct, cribs, models=MODELS, cap=None):
    """{label: {m: status}} for one text."""
    cap = cap or (20000 if SMOKE else 100000)
    return {label: moduli(ct, cribs, ms, kind, cap=cap, **flags) for label, kind, flags, ms in models}


def line(res):
    yes = [m for m, s in res.items() if s == "yes"]
    cap = [m for m, s in res.items() if s == "cap"]
    return "fits %d of %d moduli%s%s" % (len(yes), len(res), (" " + compact(yes)) if yes else "",
                                         ("; undecided " + compact(cap)) if cap else "")


def compact(ms):
    out, i = [], 0
    while i < len(ms):
        j = i
        while j + 1 < len(ms) and ms[j + 1] == ms[j] + 1:
            j += 1
        out.append(str(ms[i]) if i == j else "%d-%d" % (ms[i], ms[j]))
        i = j + 1
    return "[" + ",".join(out) + "]"


def control_work(seeds):
    out = []
    for seed in seeds:
        ct = shuffled_control(seed)
        out.append((seed, bool(digram_rule(ct, CRIBS)), sweep(ct, CRIBS, MODELS[1:5])))
    return out


def no_init():
    pass


# ---------------------------------------------------------------- known alphabets, hidden step table

def judged(ct, cribs):
    """How many checks each feed gets on this text (it depends only on which letters repeat)."""
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    out = {}
    for name, letters, off in ((FEEDS[0], pl, 0), (FEEDS[1], pl, 1), (FEEDS[2], cl, 0), (FEEDS[3], cl, 1)):
        fed = [letters[x + off] for a, b in ((0, 13), (13, 24)) for x in range(a, b - 1)]
        out[name] = len(fed) - len(set(fed))
    return out


def drift_init(ct, cribs):
    _S["pl"], _S["cl"] = [cribs[i] for i in POS], [ct[i] for i in POS]


def drift_work(chunk):
    hits, n = [], 0
    pl, cl = _S["pl"], _S["cl"]
    for name, alpha in chunk:
        for lay, form, k, _, _ in streams(alpha, pl, cl):
            n += 1
            for feed, checks in drift_checks(k, pl, cl).items():
                if checks >= MIN_CHECKS:
                    hits.append((checks, name, lay, form, feed))
    return n, hits


def drift_search(ct, cribs, alphas):
    hits, n = [], 0
    for c, h in pmap(drift_work, alphas, drift_init, (ct, cribs), chunk=3000):
        n += c
        hits += h
    feeds = [f for f, c in judged(ct, cribs).items() if c >= MIN_CHECKS]
    return n * len(feeds), hits, feeds


def plant_drift(rng, alphas, feed, form):
    """An English text through a known keyword alphabet (both sides) with a hidden step table."""
    while True:                                  # redraw until the text has enough repeats to be judged
        name, alpha = rng.choice(alphas)
        pt = english97(rng)
        ct = drift_encrypt(pt, alpha, alpha, drift_table(rng, alpha, feed), feed, beaufort=(form == "beau"),
                           start=rng.randrange(26))
        cribs = {i: pt[i] for i in CRIBS}
        if judged(ct, cribs)[feed] >= MIN_CHECKS:
            return ct, cribs, (name, "M/M" if alpha != AZ else "AZ/AZ", form, feed)


# ---------------------------------------------------------------- planted devices

def plant_device(rng, kind, m=26):
    """An English text through a moore / mealy / cipher-fed device with random tables (F one-to-one)."""
    pt = english97(rng)
    g = {c: v for c, v in zip(AZ, rng.sample(range(m), 26))}
    f = rng.sample(AZ, 26) + ["?"] * (m - 26)
    if kind == "moore":
        return additive_encrypt(pt, m, g, f), {i: pt[i] for i in CRIBS}
    h = {c: v for c, v in zip(AZ, rng.sample(range(26), 26))}      # values 0..25 only, so F never shows "?"
    if m > 26:
        g = {c: 0 for c in AZ}
    else:
        g = {c: rng.randrange(m) for c in AZ}
    return additive_encrypt(pt, m, g, f, h, feed="cipher" if kind == "cipher-fed" else "plain"), {i: pt[i] for i in CRIBS}


def rule_on_devices(rng, n_texts):
    """The digram rule over whole 97-letter texts from random devices. Returns
    (texts from one-to-one devices that break the rule [must be 0], texts from many-to-one devices
    that break it [may be > 0: the rule does not bind them])."""
    bad, bad_many = 0, 0
    for t in range(n_texts):
        pt = english97(rng)
        known = dict(enumerate(pt))
        which = t % 4
        if which == 0:                                           # moore, any m >= 26, tables random
            m = rng.randrange(26, 61)
            f = rng.sample(SYMS[:m], m)                           # m distinct symbols
            g = {c: rng.randrange(m) for c in AZ}
            ct = [f[x] for x in _values(pt, m, g, None)]
        elif which == 1:                                         # mealy
            m = rng.randrange(26, 61)
            f = rng.sample(SYMS[:m], m)
            g, h = {c: rng.randrange(m) for c in AZ}, {c: rng.randrange(m) for c in AZ}
            ct = [f[x] for x in _values(pt, m, g, h)]
        elif which == 2:                                         # the clock, any two rings
            n, m = rng.randrange(27, 61), rng.randrange(26, 61)
            pos = dict(zip(AZ, rng.sample(range(n), 26)))
            ct = ring_encrypt(pt, pos, n, rng.sample(SYMS[:m], m))
        else:                                                    # many-to-one F: 26 letters on m > 26 values
            m = rng.randrange(27, 61)
            f = [rng.choice(AZ) for _ in range(m)]
            g, h = {c: rng.randrange(m) for c in AZ}, {c: rng.randrange(m) for c in AZ}
            ct = [f[x] for x in _values(pt, m, g, h)]
            bad_many += bool(digram_rule(ct, known))
            continue
        bad += bool(digram_rule(ct, known))
    return bad, bad_many


def _values(pt, m, g, h):
    s, out = 0, []
    for ch in pt:
        if h is None:
            s = (s + g[ch]) % m
            out.append(s)
        else:
            out.append((s + h[ch]) % m)
            s = (s + g[ch]) % m
    return out


if __name__ == "__main__":
    alphas = [("KRYPTOS", KRYPTOS_ALPHABET)] + dictionary_alphabets(mixed=True)
    with Experiment("Any state machine moved by a hidden table of the letter (moore, mealy, cipher-fed), m = 2..60",
                    puzzle="k4",
                    notes="digram rule (plain S,T doubled at 32-33, not at 23-24) + exact solve of the clue equations for "
                          "every modulus; known-alphabet version over %d dictionary alphabets x 10 views x 4 feeds; "
                          "%d shuffled K4s" % (len(alphas), N_CONTROLS),
                    cribs_forced=True) as ex:
        rng = random.Random(83)
        # 1. the rule
        broken = digram_rule(K4, CRIBS)
        print("digram rule on K4's clues, broken by:", broken or "nothing")
        # 2. every modulus
        k4 = sweep(K4, CRIBS)
        n_solved = 0
        for label, _, _, ms in MODELS:
            n_solved += len(ms)
            print("K4  %-36s %s" % (label, line(k4[label])))
        # 3. controls
        seeds = list(range(1, N_CONTROLS + 1))
        ctrl = []
        for part in pmap(control_work, seeds, no_init, (), chunk=2):
            ctrl += part
        n_solved += sum(len(v) for _, _, r in ctrl for v in r.values())
        print("shuffled K4s: %d; break the digram rule: %d" % (len(ctrl), sum(b for _, b, _ in ctrl)))
        summary = {}
        for label, _, _, ms in MODELS[1:5]:
            dead = sum(1 for _, _, r in ctrl if all(s == "no" for s in r[label].values()))
            alive = sum(1 for _, _, r in ctrl if any(s == "yes" for s in r[label].values()))
            at26 = sum(1 for _, _, r in ctrl if r[label].get(26) == "yes")
            und26 = sum(1 for _, _, r in ctrl if r[label].get(26) == "cap")
            summary[label] = (dead, alive, len(ctrl) - dead - alive, at26, und26)
            print("   %-36s no modulus fits: %d; some modulus fits: %d; undecided: %d; fits at m=26: %d (undecided %d)"
                  % ((label,) + summary[label]))
        many = [sweep(shuffled_control(s), CRIBS, MODELS[5:]) for s in (1, 2, 3)]
        n_solved += sum(len(v) for r in many for v in r.values())
        for label, _, _, ms in MODELS[5:]:
            print("   %-36s 3 shuffled K4s: %s" % (label, "; ".join(line(r[label]) for r in many)))
        # 4. known alphabets, hidden step table
        n, hits, feeds = drift_search(K4, CRIBS, alphas)
        print("known alphabets: %d settings judged (feeds with %d+ checks: %s); K4 passes: %d"
              % (n, MIN_CHECKS, ", ".join("%s=%d" % (f, c) for f, c in judged(K4, CRIBS).items()), len(hits)))
        for h in sorted(hits, reverse=True)[:10]:
            print("   checks=%d alphabet %s layout %s %s feed %s" % h)
        drift_ctrl = []
        for seed in (1, 2, 3):
            c = shuffled_control(seed)
            cn, ch, cf = drift_search(c, CRIBS, alphas)
            drift_ctrl.append((cn, len(ch)))
        print("   shuffled K4s (settings judged, passes):", drift_ctrl)
        # 5. planted answers
        ok, total = 0, 0
        for kind, label, m in (("moore", "moore, F one-to-one, decipherable", 26), ("mealy", "mealy, F one-to-one", 26),
                               ("cipher-fed", "cipher-fed, F one-to-one", 26), ("mealy", "mealy, F one-to-one", 29)):
            ct, cribs = plant_device(rng, kind, m)
            model = [x for x in MODELS if x[0] == label][0]
            res = moduli(ct, cribs, [m], model[1], cap=400000, tries=8, **model[2])
            found = res[m] == "yes" and (kind == "cipher-fed" or not digram_rule(ct, cribs))
            ok += found
            total += 1
            print("planted %s device, m=%d -> solver says %s at m=%d, found=%s" % (kind, m, res[m], m, found))
        for feed, form in zip(FEEDS, ("vig", "beau", "vig", "beau")):
            ct, cribs, want = plant_drift(rng, alphas, feed, form)
            h = drift_search(ct, cribs, alphas)[1]
            found = any(x[1:] == want for x in h)
            ok += found
            total += 1
            print("planted drift on %s (%s, %s, feed %s) -> found=%s (passes %d)" % (want + (found, len(h))))
        n_dev = 80 if SMOKE else 2000
        bad, bad_many = rule_on_devices(rng, n_dev)
        print("digram rule over whole texts from %d random one-to-one devices (moore, mealy, clock): broken by %d (must be 0)"
              % (n_dev - n_dev // 4, bad))
        print("   and from %d many-to-one devices: broken by %d (the rule does not bind these)" % (n_dev // 4, bad_many))
        ok += bad == 0
        total += 1
        print("planted recovered: %d/%d" % (ok, total))
        ex.count(n_solved + n + sum(c for c, _ in drift_ctrl))
        one = [k4[label] for label, _, _, _ in MODELS[1:5]]
        fits = sum(1 for r in one[:3] for s in r.values() if s == "yes")
        print("VERDICT:", ("dead: K4 breaks the digram rule (%s); 0 moduli fit a plain-fed device with a one-to-one F; "
                           % broken[0][0] if broken and not fits else "CHECK: plain-fed one-to-one device fits %d moduli; " % fits)
              + "cipher-fed one-to-one: %s; known alphabets: %d passes" % (line(one[3]), len(hits)))
