"""Idea 55: autokey ciphers (and their cousins Condi and Ragbaby) with a HIDDEN alphabet.

Autokey is "the message keys itself": the shift for each letter comes from an earlier
plaintext or ciphertext letter. That is a natural reading of Scheidt's "masking" and gives
flat statistics from a short hand rule. Everyone has ruled out autokey on the A-Z and KRYPTOS
alphabets and a few keyword alphabets. Nobody could test it on an arbitrary scrambled
alphabet, because the alphabet has 26! settings.

The trick: write x[L] for the unknown position of letter L in the hidden alphabet. Then

    x[C_i] = a*x[P_i] + b*x[U_i] + c        (U_i = an earlier plaintext or ciphertext letter)

is LINEAR in the unknown positions. Inside the clues we know P, C and U, so the whole hidden
alphabet drops out of a linear system mod 26 (solved mod 13 and mod 2). A real alphabet must
also put different letters in different places, which random solutions almost never do.

Scope. With the alphabet hidden on both sides the clues give 22 equations for ~22 unknowns at
lag 1 (3-4 real checks) and too few beyond that, so only lag 1 is decided. With one side on
A-Z or KRYPTOS, lags 1-6 are decided. Everything else is reported as undecidable, not dead.

Models (all exact, no search):
  autokey    U = P[i-L] or C[i-L], L = 1..8, a,b = +-1 (Vigenere / Beaufort / variant),
             alphabet hidden on both sides, or hidden on one side with A-Z / KRYPTOS on the other
  Condi      the ACA cipher: shift = position of the previous plaintext letter (+ constant)
  Ragbaby    shift = word start value + letter number inside the word (hidden alphabet)

  python attacks/55_hidden_alphabet_autokey.py
"""
import os
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import BLOCKS, WORDS, shuffled_control, solutions_mod26, solve_mod_p  # noqa: E402
from kryptos.score import quadgram_score  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
KNOWN = {"AZ": AZ, "KR": KRYPTOS_ALPHABET}
# alphabet modes: (plain side, cipher side); "?" = hidden. With "?/?" both sides share one alphabet.
MODES = [("?", "?"), ("?", "AZ"), ("?", "KR"), ("AZ", "?"), ("KR", "?")]


class System:
    def __init__(self):
        self.vars, self.rows, self.rhs = {}, [], []

    def col(self, name):
        return self.vars.setdefault(name, len(self.vars))

    def add(self, terms, const=0):
        """terms: list of (coef, ('var', name) | ('num', value)). Sum of terms = const (mod 26)."""
        row, c = {}, const
        for coef, (kind, v) in terms:
            if kind == "num":
                c -= coef * v
            else:
                j = self.col(v)
                row[j] = row.get(j, 0) + coef
        self.rows.append(row)
        self.rhs.append(c % 26)

    def dense(self):
        n = len(self.vars)
        return [[r.get(j, 0) % 26 for j in range(n)] for r in self.rows]

    def solve(self, limit=60000):
        return solutions_mod26(self.dense(), self.rhs, limit)

    def checks(self):
        """Independent clue equations the model had to satisfy by luck (mod 13): equations - rank."""
        s13 = solve_mod_p(self.dense(), self.rhs, 13)
        return len(self.rows) - (len(self.vars) - len(s13[1]))


def term(side, letter):
    """Position of `letter` in the alphabet of that side: a known number or an unknown."""
    if side == "?":
        return ("var", "x" + letter)
    return ("num", KNOWN[side].index(letter))


def injective(sol, names):
    vals = [sol[j] for n, j in names.items() if n.startswith("x")]
    return len(set(vals)) == len(vals)


def autokey_system(ct, cribs, mode, src, lag, a, b):
    ps, cs = mode
    s = System()
    s.col("c0")
    for blk in BLOCKS:
        for i in blk:
            j = i - lag
            if j not in cribs:
                continue
            u = term(ps, cribs[j]) if src == "P" else term(cs, ct[j])
            # x[C_i] - a*x[P_i] - b*x[U_i] - c0 = 0
            s.add([(1, term(cs, ct[i])), (-a, term(ps, cribs[i])), (-b, u), (-1, ("var", "c0"))])
    return s


def ragbaby_system(ct, cribs, mode, per_word):
    """x[C_i] - x[P_i] = base(word) + step * (letter number in word). per_word: free base per word,
    else base = b0 + u * (word number), with the two clue blocks' word numbers unknown but
    consecutive inside a block."""
    ps, cs = mode
    s = System()
    s.col("step")
    for wn, word in enumerate(WORDS):
        blk = 0 if wn < 2 else 1
        for jn, i in enumerate(word):
            terms = [(1, term(cs, ct[i])), (-1, term(ps, cribs[i])), (-jn, ("var", "step"))]
            if per_word:
                terms.append((-1, ("var", "base%d" % wn)))
            else:
                terms.append((-1, ("var", "blk%d" % blk)))
                if wn % 2:
                    terms.append((-1, ("var", "wstep")))
            s.add(terms)
    return s


def models(ct, cribs):
    lags = (1, 2) if SMOKE else range(1, 9)
    for mode in MODES:
        for src in "PC":
            for lag in lags:
                for a in (1, -1):
                    for b in (1, -1):
                        name = "autokey %s/%s src=%s lag=%d a=%+d b=%+d" % (mode[0], mode[1], src, lag, a, b)
                        yield name, autokey_system(ct, cribs, mode, src, lag, a, b)
        for per_word in (False, True):
            yield "ragbaby %s/%s per_word=%s" % (mode[0], mode[1], per_word), ragbaby_system(ct, cribs, mode, per_word)


MIN_CHECKS = 3


def survivors(ct, cribs):
    """(models tried, [(name, n equations, n unknowns, checks, n valid alphabets | 'many')]).

    A model survives if the clue equations are consistent mod 26 and (when the solutions can be
    listed) at least one puts different letters in different places. `checks` counts the
    independent equations it had to pass; with fewer than MIN_CHECKS the clues cannot decide it."""
    out, tried = [], 0
    for name, s in models(ct, cribs):
        tried += 1
        sols = s.solve()
        if sols is None:
            continue
        if sols == "many":
            out.append((name, len(s.rows), len(s.vars), s.checks(), "many"))
            continue
        good = [v for v in sols if injective(v, s.vars)]
        if good:
            out.append((name, len(s.rows), len(s.vars), s.checks(), len(good)))
    return tried, out


def strong(surv):
    return [x for x in surv if x[3] >= MIN_CHECKS]


# ------------------------------------------------------------------ planted answers

def plant_autokey(rng, src="P", lag=1, a=1, b=1, text=None):
    from kryptos import load
    from kryptos.data import letters
    text = text or letters(load("k2")["plaintext"])
    o = rng.randrange(len(text) - 97)
    pt = text[o:o + 97]
    alpha = list(AZ)
    rng.shuffle(alpha)
    x = {c: i for i, c in enumerate(alpha)}
    c0 = rng.randrange(26)
    ct = []
    for i, p in enumerate(pt):
        if i < lag:
            u = rng.randrange(26)
        else:
            u = x[pt[i - lag]] if src == "P" else x[ct[i - lag]]
        ct.append(alpha[(a * x[p] + b * u + c0) % 26])
    return "".join(ct), {i: pt[i] for i in CRIBS}, pt


if __name__ == "__main__":
    with Experiment("autokey / Condi / Ragbaby with a hidden alphabet (exact linear solve)", puzzle="k4",
                    notes="x[C]=a*x[P]+b*x[U]+c mod 26 solved for the hidden alphabet; lags 1-8, P or C source, "
                          "5 alphabet modes; Ragbaby word-progressive", cribs_forced=True) as ex:
        tried, surv = survivors(K4, CRIBS)
        ex.count(tried)
        st = strong(surv)
        print("K4: %d models. Consistent with >= %d checks: %d. Consistent but undecidable (< %d checks): %d. "
              "Contradicted: %d" % (tried, MIN_CHECKS, len(st), MIN_CHECKS, len(surv) - len(st), tried - len(surv)))
        for name, ne, nv, ck, ng in st:
            print("   SURVIVOR %-46s equations %2d unknowns %2d checks %d alphabets %s" % (name, ne, nv, ck, ng))
        und = sorted(set(n.split(" a=")[0] for n, _, _, ck, _ in surv if ck < MIN_CHECKS))
        print("   undecidable:", "; ".join(und))
        ctrl = []
        for seed in range(1, 4 if SMOKE else 21):
            _, sv = survivors(shuffled_control(seed), CRIBS)
            ctrl.append(len(strong(sv)))
        print("shuffled K4s: survivors with >= %d checks, per control:" % MIN_CHECKS, ctrl)
        rng = random.Random(5)
        ok = 0
        cases = [("P", 1, 1, 1), ("C", 1, 1, 1), ("P", 1, -1, 1), ("C", 1, 1, -1), ("P", 1, 1, -1), ("C", 1, -1, 1)]
        for src, lag, a, b in cases:
            ct, cribs, pt = plant_autokey(rng, src, lag, a, b)
            _, sv = survivors(ct, cribs)
            want = "autokey ?/? src=%s lag=%d a=%+d b=%+d" % (src, lag, a, b)
            hit = [x for x in strong(sv) if x[0] == want]
            ok += bool(hit)
            print("planted %-34s found=%s checks=%s (strong survivors in all: %d)" % (
                want, bool(hit), hit[0][3] if hit else "-", len(strong(sv))))
        print("planted recovered: %d/%d" % (ok, len(cases)))
        print("VERDICT:", "K4 has MORE strong survivors than controls - inspect" if len(st) > max(ctrl) else
              "no signal (K4 %d strong survivors; shuffled mean %.1f, max %d)" % (len(st), sum(ctrl) / len(ctrl), max(ctrl)))
