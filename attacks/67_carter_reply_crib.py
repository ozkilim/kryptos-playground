"""Idea 67: a guessed third clue. K3 ends with a question; is K4's opening the answer?

K3's plaintext ends "CAN YOU SEE ANYTHING Q". In Howard Carter's account the reply is
"Yes, wonderful things" (his diary: "Yes, it is wonderful"). Sanborn says the answers to K1-K3
hold clues to K4, and K4 starts straight after K3's question mark. If K4 opens with the reply we
would hold 40-42 plaintext letters instead of 24.

A guess cannot be proved by itself, and anything the 24 real clues already contradict stays
contradicted. But the models the 24 clues could NOT decide become decidable with 16-18 more
letters. So for each guess we re-run exactly those:

  repeating key          lengths 27-60        (24 clues: undecidable above 26)
  two stacked keys       every pair p < q <= 26 by exact linear solve (was open at long pairs)
  sliding key            key = running sum of a repeating word, lengths 1-40
  autokey, both alphabets hidden   lags 1-8  (24 clues: decided at lag 1 only)

A pass here would support the guess and the method together. Controls: the same guess on
shuffled K4s, and planted messages that really do start with the guess.

  python attacks/67_carter_reply_crib.py
"""
import os
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control, solutions_mod26, solve_mod_p  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
ALPH = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
GUESSES = ["YESWONDERFULTHINGS", "YESITISWONDERFUL", "WONDERFULTHINGS", "YESXWONDERFULTHINGS", "ITISWONDERFUL"]
MIN_CHECKS = 6


def with_guess(guess, cribs=CRIBS):
    c = dict(cribs)
    c.update({i: ch for i, ch in enumerate(guess)})
    return c


def views(ct, cribs):
    pos = sorted(cribs)
    for an, a in ALPH.items():
        for bn, b in ALPH.items():
            for m, mn in ((1, "vig"), (-1, "beau")):
                yield "%s/%s/%s" % (an, bn, mn), {i: (b.index(ct[i]) - m * a.index(cribs[i])) % 26 for i in pos}


def fit(rows, rhs):
    s13, s2 = solve_mod_p(rows, rhs, 13), solve_mod_p(rows, rhs, 2)
    if s13 is None or s2 is None:
        return -1
    return len(rows) - (len(rows[0]) - len(s13[1]))


def slots_ok(vals):
    """vals: [(slot, value)] -> checks, or -1 on a clash."""
    seen = {}
    for s, v in vals:
        if seen.setdefault(s, v) != v:
            return -1
    return len(vals) - len(seen)


def search(ct, cribs):
    hits, tried = [], 0
    pos = sorted(cribs)
    for name, key in views(ct, cribs):
        for p in range(1, 61):
            tried += 1
            ck = slots_ok([(i % p, key[i]) for i in pos])
            if ck >= MIN_CHECKS:
                hits.append((ck, name, "repeating p=%d" % p))
        d = [(i, (key[i] - key[i - 1]) % 26) for i in pos if i - 1 in key]
        for p in range(1, 41):
            tried += 1
            ck = slots_ok([(i % p, v) for i, v in d])
            if ck >= MIN_CHECKS:
                hits.append((ck, name, "sliding p=%d" % p))
        for q in range(3, 27):
            for p in range(2, q):
                if q % p == 0:
                    continue
                tried += 1
                rows = []
                for i in pos:
                    v = [0] * (p + q)
                    v[i % p] = 1
                    v[p + i % q] = 1
                    rows.append(v)
                ck = fit(rows, [key[i] for i in pos])
                if ck >= MIN_CHECKS:
                    hits.append((ck, name, "two stacked keys p=%d q=%d" % (p, q)))
    # autokey with one hidden alphabet on both sides: x[C_i] = a*x[P_i] + b*x[U_i] + c
    letters = sorted(set(cribs.values()) | {ct[i] for i in cribs})
    col = {ch: k for k, ch in enumerate(letters)}
    n = len(letters) + 1
    for src in "PC":
        for lag in range(1, 9):
            for a in (1, -1):
                for b in (1, -1):
                    rows = []
                    for i in pos:
                        if i - lag not in cribs:
                            continue
                        v = [0] * n
                        v[col[ct[i]]] += 1
                        v[col[cribs[i]]] -= a
                        v[col[cribs[i - lag] if src == "P" else ct[i - lag]]] -= b
                        v[n - 1] = -1
                        rows.append(v)
                    tried += 1
                    if len(rows) <= MIN_CHECKS:
                        continue
                    ck = fit(rows, [0] * len(rows))
                    if ck < MIN_CHECKS:
                        continue
                    # x = 0 always solves these equations, so "consistent" means nothing by itself:
                    # a real alphabet must put the letters in different places.
                    sols = solutions_mod26(rows, [0] * len(rows), 200000)
                    if sols == "many" or sols is None:
                        continue
                    if any(len(set(v[:-1])) == len(letters) for v in sols):
                        hits.append((ck, "hidden alphabet", "autokey src=%s lag=%d a=%+d b=%+d" % (src, lag, a, b)))
    return tried, hits


def plant(rng, guess, kind):
    from kryptos import load
    from kryptos.data import letters
    text = letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = list(text[o:o + 97])
    pt[:len(guess)] = guess
    for i, ch in CRIBS.items():
        pt[i] = ch
    pt = "".join(pt)
    k = KRYPTOS_ALPHABET
    if kind == "long repeating":
        p = rng.randrange(27, 34)
        key = [rng.randrange(26) for _ in range(p)]
        ct = "".join(k[(k.index(ch) + key[i % p]) % 26] for i, ch in enumerate(pt))
        want = ("KR/KR/vig", "repeating p=%d" % p)
    elif kind == "stacked":
        p, q = rng.choice([(11, 13), (9, 14), (12, 17)])
        a, b = [rng.randrange(26) for _ in range(p)], [rng.randrange(26) for _ in range(q)]
        ct = "".join(k[(k.index(ch) + a[i % p] + b[i % q]) % 26] for i, ch in enumerate(pt))
        want = ("KR/KR/vig", "two stacked keys p=%d q=%d" % (p, q))
    else:
        alpha = list(AZ)
        rng.shuffle(alpha)
        x = {c: i for i, c in enumerate(alpha)}
        out = []
        for i, ch in enumerate(pt):
            u = x[pt[i - 3]] if i >= 3 else rng.randrange(26)
            out.append(alpha[(x[ch] + u + 5) % 26])
        ct = "".join(out)
        want = ("hidden alphabet", "autokey src=P lag=3 a=+1 b=+1")
    return ct, with_guess(guess, {i: pt[i] for i in CRIBS}), want


if __name__ == "__main__":
    with Experiment("guessed third clue: Carter's reply at the start of K4, undecided models re-run", puzzle="k4",
                    notes="guesses %s at position 1; repeating 1-60, sliding 1-40, two stacked keys p<q<=26 (exact), "
                          "hidden-alphabet autokey lags 1-8" % GUESSES, cribs_forced=True) as ex:
        signal = False
        for g in GUESSES:
            cribs = with_guess(g)
            tried, hits = search(K4, cribs)
            ex.count(tried)
            ctrl = []
            for seed in range(1, 4 if SMOKE else 11):
                _, h = search(shuffled_control(seed), cribs)
                ctrl.append(len(h))
            best = max((h[0] for h in hits), default=0)
            print("%-20s K4: %d settings fit with >= %d checks (best %d) | shuffled K4s: %s" % (g, len(hits), MIN_CHECKS, best, ctrl))
            for h in sorted(hits, reverse=True)[:6]:
                print("      checks=%d %s %s" % h)
            signal |= len(hits) > max(ctrl)
        rng = random.Random(17)
        ok = 0
        for kind in ("long repeating", "stacked", "hidden autokey"):
            ct, cribs, want = plant(rng, GUESSES[0], kind)
            _, h = search(ct, cribs)
            found = any(x[1:] == want for x in h)
            ok += found
            print("planted %s %s -> found=%s (settings %d)" % (kind, want, found, len(h)))
        print("planted recovered: %d/3" % ok)
        print("VERDICT:", "a guess makes something fit - inspect" if signal else
              "no guess makes any undecided model fit")
