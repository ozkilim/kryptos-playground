"""Idea 105: the independent-encryptor audit of idea 91, carried to the attacks it did not reach.

Messages are made by the textbook encryptors (kryptos/idea91_textbook.py and
kryptos/idea105_textbook.py, which share no code with the attacks) and handed to each attack's own
test function, the way K4 is. Every message is K4-shaped: 97 letters of English with
EASTNORTHEAST at 22-34 and BERLINCLOCK at 64-74 (unless the attack itself moves the second clue).

A planted message ends as in idea 91:
  found   the attack lists the planted setting
  limit   not listed, but the planted setting leaves fewer independent checks than the attack's
          own threshold (counted here, independently), so the attack never claimed to judge it
  HOLE    not listed although it has enough checks: the attack's scope is smaller than stated

Attacks audited here: 54, 56, 57 (conventions only), 59, 60, 61, 62, 65, 68, 69, 70, 73, 74 (edge settings), 78 (tests 68
and 70), 79, 81, 84, 86, 88, 89, 90.
"""
import glob
import importlib.util
import random
from pathlib import Path

from . import idea91_audit as A91
from . import idea91_textbook as T
from . import idea105_textbook as X
from .data import CRIBS

ROOT = Path(__file__).resolve().parent.parent
A2Z, KR, FACES, LAYOUTS, strips = T.A2Z, A91.KR, A91.FACES, A91.LAYOUTS, A91.strips
CLUE_POS = sorted(T.clue_map())
B1, B2 = [i for i in CLUE_POS if i < 40], [i for i in CLUE_POS if i > 40]
GAPS = (-3, -2, -1, 1, 2, 3)
# two stacked keys: the length pairs idea 91 found inside the pre-filter of the battery
STACK_OK = ((2, 3), (2, 5), (2, 7), (2, 9), (2, 11), (2, 13), (3, 4), (3, 5), (3, 7), (3, 8), (3, 10), (4, 5), (4, 6),
            (4, 7), (4, 9), (4, 10), (5, 6), (5, 7), (5, 8), (6, 7), (6, 8))
PI = "3" + "1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679" + "8214808651"
PARSE1 = (("EASTNORTHEAST",), ("EAST", "NORTHEAST"), ("EAST", "NORTH", "EAST"))
PARSE2 = (("BERLINCLOCK",), ("BERLIN", "CLOCK"))
_MODS = {}


def attack(key):
    """An attack script loaded by path, once per process, with its smoke-mode shortcuts switched off
    (the audit always wants the full-run scope)."""
    if key not in _MODS:
        path = glob.glob(str(ROOT / "attacks" / (key + "_*.py")))[0]
        spec = importlib.util.spec_from_file_location("idea105_attack_" + key, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, "SMOKE"):
            mod.SMOKE = None
        _MODS[key] = mod
    return _MODS[key]


# ---------------------------------------------------------------- independent counts of checks

def lag_pairs(pos, lag):
    """Index pairs (j, j + lag) inside one unbroken run of positions."""
    out = []
    for j in range(len(pos) - lag):
        if all(pos[j + t + 1] == pos[j + t] + 1 for t in range(lag)):
            out.append((j, j + lag))
    return out


def rule_checks(spec, pos):
    """Independent coincidences a key rule leaves on the clue letters at key positions `pos`."""
    kind = spec[0]
    if kind == "repeating":
        return len(pos) - len({i % spec[1] for i in pos})
    if kind == "sliding":
        pairs = lag_pairs(pos, 1)
        return len(pairs) - len({pos[j] % spec[1] for j, _ in pairs})
    if kind == "progressive":
        return len(pos) - len({i % spec[1] for i in pos}) - 1
    if kind == "autokey":
        return len(lag_pairs(pos, spec[1])) - 1
    if kind == "stacked":
        p, q = spec[1], spec[2]
        rows = [[int(j == i % p) for j in range(p)] + [int(j == i % q) for j in range(q)] for i in pos]
        return len(pos) - T.rank_mod(rows, 13)
    if kind == "chain":
        return len(lag_pairs(pos, spec[2]))
    raise ValueError(kind)


def primes(n):
    out, k = [], 2
    while len(out) < n:
        if all(k % d for d in range(2, int(k ** 0.5) + 1)):
            out.append(k)
        k += 1
    return out


def minimal_keyword_length(alpha):
    """Letters of a keyword alphabet that are not already the A-Z ordered tail."""
    m = 26
    while m > 0 and "".join(sorted(alpha[m - 1:])) == alpha[m - 1:]:
        m -= 1
    return m


class Audit(A91.Audit):
    """Plants for the attacks idea 91 did not reach. One record per message (see idea91_audit.Audit)."""

    def __init__(self, rng, english="", n_decoys=40, offset=0):
        A91.Audit.__init__(self, rng, english, n_decoys, offset)
        self.turn = 0

    # -- helpers
    def message_at(self, second=64, length=97):
        pt = X.k4_like_at(self.rng, self.english, second, length)
        return pt[len(pt) - self.offset:] + pt[:len(pt) - self.offset]

    def cycle(self, choices):
        """Take the choices in turn, so 12 messages cover every edge value."""
        self.turn += 1
        return choices[(self.turn - 1) % len(choices)]

    def some(self, true, mixed=None, n=8):
        taken = {m for _, m in true}
        pool = [a for a in A91.all_forms(mixed) if a[1] not in taken]
        return list(true) + self.rng.sample(pool, min(n, self.n_decoys, len(pool)))

    def key_rule(self, rule, pt, plain, cipher, beaufort, pmax=None, syms=None, pair=None):
        """Encipher with one key rule of the round-11 battery, by the textbook encryptors.
        Returns (cipher text, the rule as the battery prints it, settings as text, spec for rule_checks).
        syms: the sheet with its word spaces, if the key is to run on over the spaces."""
        rng = self.rng
        n = len(syms) if syms is not None else len(pt)
        index = rng.choice(plain)
        if rule == "sliding":
            p = rng.randrange(1, (pmax or 15) + 1)
            moves = T.random_numbers(rng, p)
            ct = (X.sliding_over_spaces(syms, plain, cipher, moves, beaufort) if syms is not None
                  else T.sliding_encrypt(pt, plain, cipher, moves, beaufort))
            return ct, "sliding p=%d" % p, "moves %s" % moves, ("sliding", p)
        if rule.startswith("autokey"):
            lag, feed = rng.randrange(1, (pmax or 5) + 1), rule.split()[1]
            primer = T.random_word(rng, lag)
            ct = T.autokey_encrypt(pt, plain, cipher, primer, feed, "cipher", beaufort)
            return ct, "autokey %s lag=%d sign=+1" % (feed, lag), "primer %s" % primer, ("autokey", lag)
        if rule == "repeating":
            p = rng.randrange(1, (pmax or 17) + 1)
            key = T.random_word(rng, p)
            keys, want, par, spec = T.repeating_key(key, n), "repeating p=%d" % p, "key %s" % key, ("repeating", p)
        elif rule == "progressive":
            p, step = (pair or (rng.randrange(1, (pmax or 12) + 1),))[0], rng.randrange(1, 26)
            key = T.random_word(rng, p)
            keys = T.progressive_key(key, step, cipher, n)
            want, par, spec = "progressive p=%d step=%d" % (p, step), "key %s step %d" % (key, step), ("progressive", p)
        elif rule == "stacked":
            p, q = pair or rng.choice(STACK_OK)
            a, b = T.random_word(rng, p), T.random_word(rng, q)
            keys = T.stacked_key(a, b, cipher, n)
            want, par, spec = "two stacked keys p=%d q=%d" % (p, q), "keys %s + %s" % (a, b), ("stacked", p, q)
        else:   # chain addition of key numbers (counted along the cipher strip, key set under its first letter)
            m = rng.randrange(2, (pmax or 6) + 1)
            t = rng.randrange(1, m)
            nums = X.chain_key([rng.randrange(26) for _ in range(m)], n, t, m)
            keys, index = [cipher[v] for v in nums], plain[0]
            want, par, spec = "chain taps %d,%d" % (t, m), "start %s" % nums[:m], ("chain", t, m)
        if syms is not None:
            ct = X.encrypt_over_spaces(syms, plain, cipher, keys, index, beaufort)
        else:
            ct = T.tableau_encrypt(pt, plain, cipher, keys, index, beaufort)
        return ct, want, par + " index %s" % index, spec

    def noise(self, pt, plain, cipher):
        return T.tableau_encrypt(pt, plain, cipher, T.repeating_key(T.random_word(self.rng, 23), len(pt)))

    # -- attack 59: autokey stacked with a repeating key, A-Z / KRYPTOS
    def plant_59(self, feed, lo, hi):
        rng = self.rng
        an, bn, un = (rng.choice(["AZ", "KR"]) for _ in range(3))
        beaufort = rng.random() < 0.5
        lag, p = rng.randrange(lo, hi + 1), self.cycle((1, 2, 3, 4, 5, 7, 10, 14, 19, 26))
        b = rng.choice([1, 1, 25, 25, rng.randrange(2, 25)])
        word = T.random_numbers(rng, p)
        ct = X.fed_key_encrypt(self.message(), FACES[an], FACES[bn], FACES[un], lag, feed, b, word, rng, beaufort)
        clue = T.clue_map()
        use = [i for i in CLUE_POS if (i - lag >= 0 if feed == "cipher" else i - lag in clue)]
        checks = len(use) - len({i % p for i in use})
        hits = attack("59").search(ct, CRIBS)[1]
        want = ("pt%s/ct%s/u%s" % (an, bn, un), feed[0].upper(), lag, -1 if beaufort else 1, b, p)
        return self.record("59", "autokey + repeating key, %s feed, %d-%d letters back" % (feed, lo, hi),
                           "%s lag %d a=%+d b=%d key length %d: %d clue letters usable" % (want[0], lag, want[3], b, p, len(use)),
                           want in [h[1:] for h in hits], checks, 6, None)

    # -- attack 68 (and 78's test 68): each clue alone, gap slack
    def plant_68(self, part, rule, via78=False, layout=None, pair=None, gap=None, decoys=True):
        rng = self.rng
        name, m = self.alphabet(mixed=bool(via78))
        layout = layout or ("M/M" if rule.startswith("autokey") else rng.choice(LAYOUTS))
        beaufort = rng.random() < 0.5
        plain, cipher = strips(layout, m)
        if part == "gap":
            g = gap or self.cycle(GAPS)
            pt = self.message_at(64 + g, 97 + g)
            pos, pmax, tag = B1 + [i + g for i in B2], None, "gap %+d" % g
        else:
            g, pt, tag = 0, self.message(), part
            pos = B1 if part == "clue 1 alone" else B2
            first = part == "clue 1 alone"
            pmax = {"repeating": 6 if first else 4, "sliding": 5 if first else 3, "progressive": 5 if first else 3,
                    "chain": 6 if first else 4}.get(rule, 5 if first else 3)
            if rule == "stacked":
                pair = pair or rng.choice(((2, 3), (2, 5), (3, 4)) if first else ((2, 3),))
        ct, want_rule, par, spec = self.key_rule(rule, pt, plain, cipher, beaufort, pmax, pair=pair)
        if part == "gap":
            ct = X.lose_or_add(ct, g, rng)
        elif part == "clue 1 alone":
            ct = ct[:48] + self.noise(pt, plain, cipher)[48:]
        else:
            ct = self.noise(pt, plain, cipher)[:48] + ct[48:]
        assert len(ct) == 97
        chunk = self.chunk([(name, m)], mixed=bool(via78)) if decoys else [(name, m)]
        if via78:
            from . import idea78_mixed as i78
            i78.init(ct, CRIBS, ("68",))
            hits = i78.work(chunk)["68"]
        else:
            mod = attack("68")
            mod.init(ct, CRIBS)
            hits = mod.work(chunk)
        form = "beau" if beaufort else "vig"
        want = (name, layout, form, tag, want_rule)
        what = part if part != "gap" else "gap off by 1-3"
        return self.record("78/68" if via78 else "68", "%s, %s key%s" % (what, rule, " [column-mixed]" if via78 else ""),
                           "%s %s %s %s: %s; %s" % (name, layout, form, tag, want_rule, par),
                           any(h[1:] == want for h in hits), rule_checks(spec, pos), 7,
                           sum(h[1] != name for h in hits), [m])

    # -- attack 70 (and 78's test 70): a wheel of 27-31 cells
    def plant_70(self, rule, via78=False, pair=None, cells=None, decoys=True):
        rng = self.rng
        n = cells or self.cycle((27, 28, 29, 30, 31) if rule != "multiply" else (29, 31))
        layout = "M/M" if rule.startswith("autokey") or rule == "multiply" else rng.choice(LAYOUTS)
        for _ in range(5000):        # redrawn until every clue place holds a letter, not an extra cell
            name, m = self.alphabet(mixed=bool(via78))
            beaufort = rng.random() < 0.5 and rule != "multiply"
            plain, cipher = strips(layout, m)
            wp, wc = X.wheel_strip(plain, n), X.wheel_strip(cipher, n)
            pt = self.message()
            if rule == "repeating":
                p = rng.randrange(1, 18)
                key = T.random_word(rng, p, wc)
                ct = X.wheel_encrypt(pt, wp, wc, T.repeating_key(key, 97), rng.choice(wp), beaufort)
                want, par, spec = "repeating p=%d" % p, "key %s" % key, ("repeating", p)
            elif rule == "sliding":
                p = rng.randrange(1, 16)
                moves = [rng.randrange(n) for _ in range(p)]
                ct = X.wheel_sliding(pt, wp, wc, moves, beaufort)
                want, par, spec = "sliding p=%d" % p, "moves %s" % moves, ("sliding", p)
            elif rule == "progressive":
                p, step = rng.randrange(1, 13), rng.randrange(1, n)
                key = T.random_word(rng, p, wc)
                keys = [wc[(wc.index(key[i % p]) + (i // p) * step) % n] for i in range(97)]
                ct = X.wheel_encrypt(pt, wp, wc, keys, rng.choice(wp), beaufort)
                want, par, spec = "progressive p=%d step=%d" % (p, step), "key %s" % key, ("progressive", p)
            elif rule.startswith("autokey"):
                lag, feed = rng.randrange(1, 7), rule.split()[1]
                out = []
                for i, ch in enumerate(pt):
                    k = rng.choice(wc) if i < lag else (pt if feed == "plain" else out)[i - lag]
                    out.append(X.wheel_encrypt(ch, wp, wc, [k], None, beaufort))
                ct = "".join(out)
                want, par, spec = "autokey %s lag=%d sign=+1" % (feed, lag), "", ("autokey", lag)
            elif rule == "stacked":
                p, q = pair or rng.choice(STACK_OK)
                a, b = T.random_word(rng, p, wc), T.random_word(rng, q, wc)
                keys = [wc[(wc.index(a[i % p]) + wc.index(b[i % q])) % n] for i in range(97)]
                ct = X.wheel_encrypt(pt, wp, wc, keys, rng.choice(wp), beaufort)
                want, par, spec = "two stacked keys p=%d q=%d (necessary test)" % (p, q), "keys %s + %s" % (a, b), ("stacked", p, q)
            elif rule == "chain":
                mm = rng.randrange(2, 7)
                t = rng.randrange(1, mm)
                nums = X.chain_key([rng.randrange(n) for _ in range(mm)], 97, t, mm, modulus=n)
                ct = X.wheel_encrypt(pt, wp, wc, [wc[v] for v in nums], wp[0], beaufort)
                want, par, spec = "chain taps %d,%d" % (t, mm), "start %s" % nums[:mm], ("chain", t, mm)
            else:   # multiplying key on a prime wheel
                p = rng.randrange(1, 18)
                mults = [rng.randrange(1, n) for _ in range(p)]
                while p > 1 and any(all(mults[i] == mults[i % d] for i in range(p)) for d in range(1, p)):
                    mults = [rng.randrange(1, n) for _ in range(p)]
                ct = X.wheel_multiply(pt, m, n, mults)
                want, par, spec = "repeating p=%d" % p, "multipliers %s" % mults, ("repeating", p)
            if all(ct[i] in A2Z for i in CLUE_POS):
                break
        else:
            raise RuntimeError("no message with letters at every clue place")
        ct = "".join(c if c in A2Z else "?" for c in ct)
        chunk = self.chunk([(name, m)], mixed=bool(via78)) if decoys else [(name, m)]
        if via78:
            from . import idea78_mixed as i78
            i78.init(ct, CRIBS, ("70",))
            hits = i78.work(chunk)["70"]
        else:
            mod = attack("70")
            mod.init(ct, CRIBS)
            hits = mod.work(chunk)
        form = "multiply" if rule == "multiply" else "beau" if beaufort else "vig"
        full = (name, n, layout, form, want)
        return self.record("78/70" if via78 else "70", "wheel of 27-31 cells, %s key%s" % (rule, " [column-mixed]" if via78 else ""),
                           "%s N=%d %s %s: %s; %s" % (name, n, layout, form, want, par),
                           any(h[1:] == full for h in hits), rule_checks(spec, CLUE_POS), 7,
                           sum(h[1] != name for h in hits), [m])

    # -- attack 74: the edges idea 91 did not draw
    def plant_74e(self, feed, kind):
        rng = self.rng
        p, lo, hi = {"period 13": (13, 1, 20), "distances 17-20": (rng.randrange(1, 14), 17, 20),
                     "periods 7-13": (rng.randrange(7, 14), 1, 8), "distances 7-8": (rng.randrange(1, 4), 7, 8)}[kind]
        mod = attack("74")
        dictionary = rng.random() < 0.5
        if dictionary:
            name, m = self.alphabet(mixed=False)
            plain = cipher = numbering = m
        else:
            an, bn, nn = (rng.choice(["AZ", "KR"]) for _ in range(3))
            name = "pt%s/ct%s feed on %s" % (an, bn, nn)
            plain, cipher, numbering = FACES[an], FACES[bn], FACES[nn]
        lags = [rng.randrange(lo, hi + 1) for _ in range(p)]
        const, beaufort, subtract = rng.randrange(26), rng.random() < 0.5, rng.random() < 0.5
        ct = T.keyed_lag_autokey_encrypt(self.message(), plain, lags, const, feed, rng, beaufort, subtract, cipher, numbering)
        clue = T.clue_map()
        seen = [i for i in CLUE_POS if feed == "cipher" or i - lags[i % p] in clue]
        checks = len(seen) - p - 1 if len(seen) >= 9 else 0
        if dictionary:
            mod.init(ct, CRIBS)
            hits = mod.work(self.chunk([(name, m)], mixed=False))
        else:
            ix = {k: {c: i for i, c in enumerate(v)} for k, v in FACES.items()}
            hits = mod.test_view(name, ix[an], ix[bn], ix[nn], ct, CRIBS)
        mine = [h for h in hits if h[1] == name and h[2] == ("beau" if beaufort else "vig")
                and h[3] == "%s feed %+d" % (feed, -1 if subtract else 1)]
        return self.record("74", "keyed-lag autokey, %s feed, edge: %s" % (feed, kind),
                           "%s period %d lags %s const %d; %d clue letters checked" % (name, p, lags, const, len(seen)),
                           any(h[4].startswith("period %d " % p) for h in mine), checks, 7,
                           sum(h[1] != name for h in hits))

    # -- attack 81: one wrong clue letter
    def _wrong(self, ct, wrong):
        """One clue letter spoiled: the plaintext letter we are told, or the cipher letter as carved."""
        rng = self.rng
        j = rng.randrange(24)
        at, cribs = CLUE_POS[j], dict(CRIBS)
        if wrong == "plain":
            cribs[at] = rng.choice([c for c in A2Z if c != cribs[at]])
        else:
            ct = ct[:at] + rng.choice([c for c in A2Z if c != ct[at]]) + ct[at + 1:]
        return ct, cribs, j, at

    def plant_81(self, rule, wrong, pair=None, decoys=True):
        from . import idea81_dropone as D
        rng = self.rng
        name, m = self.alphabet(mixed=False)
        layout = "M/M" if rule.startswith("autokey") else rng.choice(LAYOUTS)
        beaufort = rng.random() < 0.5
        plain, cipher = strips(layout, m)
        ct, want_rule, par, spec = self.key_rule(rule, self.message(), plain, cipher, beaufort, pair=pair)
        ct, cribs, j, at = self._wrong(ct, wrong)
        pl, cl = [cribs[i] for i in CLUE_POS], [ct[i] for i in CLUE_POS]
        hits = []
        for nm, mm in (self.some([(name, m)], mixed=False) if decoys else [(name, m)]):
            hits += D.battery_alphabet(nm, mm, pl, cl)
        want = (name, layout, "beau" if beaufort else "vig", want_rule, at)
        return self.record("81", "battery with one wrong %s letter, %s key" % (wrong, rule),
                           "%s %s %s: %s; wrong letter at %d; %s" % (want[:4] + (at + 1, par)),
                           any(h[1:] == want for h in hits), rule_checks(spec, CLUE_POS[:j] + CLUE_POS[j + 1:]), 7,
                           sum(h[1] != name for h in hits), [m])

    def plant_81_pairs(self, wrong):
        from . import idea81_dropone as D
        rng = self.rng
        an, bn = rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"])
        p, q = rng.randrange(1, 10), rng.randrange(1, 10)
        mults = [rng.choice([1, 25] + A91.MULTS) for _ in range(p)]
        adds = [rng.randrange(26) for _ in range(q)]
        pt = self.message()
        ct = T.multiplier_adder_encrypt(pt, FACES[an], FACES[bn], mults, adds)
        ct, cribs, j, at = self._wrong(ct, wrong)
        kept = CLUE_POS[:j] + CLUE_POS[j + 1:]
        rows = [[FACES[an].index(pt[i]) * (k == i % p) for k in range(p)] + [int(k == i % q) for k in range(q)] for i in kept]
        others = rng.sample([d for d in D.DROPS if d[0] != j], 2)
        hits = D.pairs_search(ct, cribs, 17, drops=[D.DROPS[j]] + others)[1]
        want = ("pt%s/ct%s" % (an, bn), "multiplier word %d + adder word %d" % (p, q), at)
        return self.record("81", "multiplier word + adder word with one wrong %s letter" % wrong,
                           "%s %s; wrong letter at %d" % (want[0], want[1], at + 1),
                           any(h[1:] == want for h in hits), 23 - T.rank_mod(rows, 13), 7, sum(h[3] != at for h in hits))

    def plant_81_rotor(self, wrong):
        from . import idea81_dropone as D
        rng = self.rng
        an, bn, nn = (rng.choice(["AZ", "KR"]) for _ in range(3))
        sign, kind = rng.choice([1, -1]), rng.choice(["word", "sliding word", "word + 1 per letter"])
        wiring = list(range(26))
        rng.shuffle(wiring)
        w = rng.choice(T.WORDS)
        vals = [FACES[nn].index(ch) for ch in w]
        seq, t = [], 0
        for i in range(97):
            t += vals[i % len(w)]
            seq.append(vals[i % len(w)] if kind == "word" else t if kind == "sliding word" else vals[i % len(w)] + i)
        pt = self.message()
        ct = T.rotor_encrypt(pt, wiring, seq, [sign * x for x in seq], FACES[an], FACES[bn])
        ct, cribs, j, at = self._wrong(ct, wrong)
        kept = CLUE_POS[:j] + CLUE_POS[j + 1:]
        checks = 23 - len({(FACES[an].index(pt[i]) + seq[i]) % 26 for i in kept})
        vws, hits = D.views(ct, cribs), []
        for word in [w] + rng.sample([x for x in T.WORDS if x != w], 6):
            hits += D.rotor_word(word, vws)
        want = ("pt%s/ct%s" % (an, bn), "%s %s (%s numbering), out %+d" % (kind, w, nn, sign), at)
        return self.record("81", "word-turned rotor with one wrong %s letter" % wrong,
                           "%s %s; wrong letter at %d" % (want[0], want[1], at + 1),
                           any(h[1:] == want for h in hits), checks, 5, sum(w not in h[2] for h in hits))

    # -- attack 88: the key runs on over the word spaces
    def plant_88(self, rule, p1=None, p2=None, pmin=None, pmax=None, pair=None, decoys=True):
        rng = self.rng
        p1_asked = p1
        p1 = rng.randrange(3) if p1 is None else p1
        p2 = rng.randrange(2) if p2 is None else p2
        words = X.spaced_k4(rng, PARSE1[p1], PARSE2[p2])
        first = next(n for n, w in enumerate(words) if w == PARSE1[p1][0] and sum(len(x) for x in words[:n]) == 21)
        second = next(n for n, w in enumerate(words) if w == PARSE2[p2][0] and sum(len(x) for x in words[:n]) == 63)
        double = rng.randrange(first + len(PARSE1[p1]), second - 1) if rng.random() < 0.5 else None
        syms = X.symbols(words, double)
        stream = [u for u, ch in enumerate(syms) if ch is not X.SPACE]
        pt = "".join(words)
        name, m = self.alphabet(mixed=False)
        layout, beaufort = rng.choice(LAYOUTS), rng.random() < 0.5
        plain, cipher = strips(layout, m)
        if rule == "progressive":
            pair = (rng.randrange(pmin or 1, (pmax or 12) + 1),)
        if rule == "chain":
            pmax = 3 if p1 else 6
        ct, want_rule, par, spec = self.key_rule(rule, pt, plain, cipher, beaufort, pmax, syms=syms, pair=pair)
        a = stream[21] - 21
        x = stream[63] - 63 - a - (len(PARSE1[p1]) - 1)
        if rule == "progressive":
            want_rule += " start+%d" % (a % spec[1])
        want = (name, layout, "beau" if beaufort else "vig", p1, p2, -1 if rule == "chain" else x, want_rule)
        mod = attack("88")
        mod.init(ct, CRIBS)
        pl, cl = [CRIBS[i] for i in CLUE_POS], [ct[i] for i in CLUE_POS]
        hits = []
        for nm, mm in (self.chunk([(name, m)], mixed=False) if decoys else [(name, m)]):
            hits += mod.test_alphabet(nm, mm, pl, cl)
        pos = [stream[i] for i in CLUE_POS]
        how = "%s + %s" % ("|".join(PARSE1[p1]), "|".join(PARSE2[p2]))
        model = "key runs over the spaces, %s key" % rule
        if pmin:
            model += ", lengths %d-%d, %s" % (pmin, pmax, "clues written " + how if p1_asked is not None else
                                              "BERLINCLOCK written as one word")
        return self.record("88", model, "%s %s %s [%s, %d breaks before EAST, offset +%d%s] %s; %s" % (
            name, layout, want[2], how, a, x, ", one double space" if double is not None else "", want_rule, par),
            any(h[1:] == want and h[0] >= 7 for h in hits), rule_checks(spec, pos), 7,
            sum(h[1] != name and h[0] >= 7 for h in hits), [m])

    # -- attack 90: a worksheet row keys the next row
    def plant_90(self, feed, lo, hi, shifted=False):
        from . import idea90_rowkey as R
        rng = self.rng
        name, m = self.alphabet()
        layout, beaufort = rng.choice(LAYOUTS), rng.random() < 0.5
        plain, cipher = strips(layout, m)
        fn, sg, p = self.cycle(["M", "AZ", "KR"]), rng.choice([1, -1]), self.cycle([1, 1, 2, 3, 4])
        s = self.cycle([-3, -2, -1, 1, 2, 3]) if shifted else 0
        lag = rng.randrange(lo, hi + 1)
        word = rng.sample(range(26), p)
        numbering = {"M": m, "AZ": A2Z, "KR": KR}[fn]
        ct = X.fed_key_encrypt(self.message_at(64 + s), plain, cipher, numbering, lag, feed, sg, word, rng, beaufort)
        pos = B1 + [i + s for i in B2]
        pairs = [i for i in pos if (i - lag in pos if feed == "plain" else i - lag >= 0)]
        checks = len(pairs) - len({i % p for i in pairs})
        hits = []
        for nm, mm in self.chunk([(name, m)]):
            hits += R.test_alphabet(nm, mm, ct, CRIBS)
        want = (name, layout, "beau" if beaufort else "vig", fn, sg, feed, lag, s, p)
        return self.record("90", "row keys the next row, %s feed %d-%d back%s" % (feed, lo, hi, ", second clue moved 1-3" if shifted else ""),
                           "%s %s %s fed letter numbered in %s sign %+d lag %d shift %+d word of %d; %d pairs" % (
                               name, layout, want[2], fn, sg, lag, s, p, len(pairs)),
                           any(h[1:10] == want for h in hits), checks, 7, sum(h[1] != name for h in hits), [m])

    # -- attack 56: interrupted key
    def plant_56(self, when):
        from . import wordkeys
        rng = self.rng
        mod = attack("56")
        theme = [w for w in T.WORDS if w in set(wordkeys.theme_words()) and T.keyword_alphabet(w) not in (A2Z, KR)]
        pairs = [("%s/%s" % (a, b), FACES[a], FACES[b]) for a in FACES for b in FACES]
        pairs += [("%s/%s" % (w, w), T.keyword_alphabet(w), T.keyword_alphabet(w)) for w in theme]
        aname, plain, cipher = rng.choice(pairs[:4]) if rng.random() < 0.5 else rng.choice(pairs[4:])
        beaufort = rng.random() < 0.5
        size = rng.randrange(1, 27)
        key = T.random_word(rng, size)
        index = rng.choice(plain)
        clue = T.clue_map()
        if when == "word starts":
            words = X.spaced_k4(rng, PARSE1[1], PARSE2[1])
            syms, pt = X.symbols(words), "".join(words)
            slots = X.interrupted_key(syms, list(range(size)), "word")
            ct = T.tableau_encrypt(pt, plain, cipher, X.interrupted_key(syms, key, "word"), index, beaufort)
            tname = "word starts"
        elif when in ("after plain", "at plain"):
            pt = self.message()
            trig = rng.choice("EASTNORHBLINC") if when == "at plain" else rng.choice("EASTNORHBLIC")
            slots = X.interrupted_key(pt, list(range(size)), when, trig)
            ct = T.tableau_encrypt(pt, plain, cipher, X.interrupted_key(pt, key, when, trig), index, beaufort)
            tname = "%s %s" % (when, trig)
        else:   # after a cipher letter: redraw until that letter turns up inside a clue
            for _ in range(500):
                pt, trig = self.message(), rng.choice(A2Z)
                ct = X.interrupted_cipher_encrypt(pt, plain, cipher, key, trig, index, beaufort)
                if any(ct[i] == trig and i + 1 in clue for i in CLUE_POS):
                    break
            slots, j = [], 0
            for c in ct:
                slots.append(j % size)
                j = 0 if c == trig else j + 1
            tname = "after cipher %s" % trig
        checks = 24 - len({slots[i] for i in CLUE_POS})
        decoys = rng.sample([pr for pr in pairs if pr[0] != aname], 4)
        mod.alphabet_pairs = lambda: iter([(aname, plain, cipher)] + decoys)
        hits = mod.search(ct, CRIBS)[1]
        want = (aname, "beau" if beaufort else "vig", tname, size)
        return self.record("56", "interrupted key, restart %s" % (when + " letter X" if when != "word starts" else "at each word"),
                           "%s %s %s key %s (length %d)" % (want[:3] + (key, size)),
                           any(h[1:] == want for h in hits), checks, 5, sum(h[1] != aname for h in hits))

    # -- attack 60: two systems in turn
    def plant_60_switch(self, k):
        rng = self.rng
        rows = []
        while len(rows) < k:
            row = (rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"]), rng.random() < 0.5, rng.choice(A2Z))
            if row not in rows:
                rows.append(row)
        pt, ct = self.message(), ""
        for ch in pt:
            an, bn, beaufort, key = rng.choice(rows)
            ct += T.tableau_encrypt(ch, FACES[an], FACES[bn], [key], FACES[an][0], beaufort)
        cover = attack("60").best_cover(ct, CRIBS, k)[0]
        return self.record("60A", "switching between %d fixed tableau rows" % k, "rows %s; cover %d of 24" % (rows, cover),
                           cover == 24, 1, 0, None)

    def plant_60_interleaved(self, k):
        rng = self.rng
        systems = [(rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"]), rng.random() < 0.5,
                    T.random_word(rng, rng.randrange(1, 14))) for _ in range(k)]
        pt, ct = self.message(), ""
        for i, ch in enumerate(pt):
            an, bn, beaufort, key = systems[i % k]
            ct += T.tableau_encrypt(ch, FACES[an], FACES[bn], [key[(i // k) % len(key)]], FACES[an][0], beaufort)
        per = []
        for r in range(k):
            use = [i for i in CLUE_POS if i % k == r]
            per.append(len(use) - len({(i // k) % len(systems[r][3]) for i in use}))
        total = attack("60").interleaved(ct, CRIBS, k)[0]
        return self.record("60B", "%d interleaved systems, each its own tableau and key (1-13)" % k,
                           "systems %s; true checks per stream %s; attack's best total %d" % (systems, per, total),
                           total >= sum(per), min(per), 2, None)

    def plant_60_slidefair(self, kind):
        rng = self.rng
        an, start = rng.choice(["AZ", "KR"]), rng.randrange(2)
        alpha, beaufort = FACES[an], kind == "Beaufort"
        key = T.random_word(rng, rng.randrange(3, 10))
        clue = T.clue_map()
        for _ in range(4000):
            pt = self.message()
            ct, same = X.slidefair_encrypt(pt, alpha, key, start, beaufort)
            inside = [i for i in same if i in clue and i + 1 in clue]
            if bool(inside) == (kind == "same-column rule inside a clue"):
                break
            key = T.random_word(rng, rng.randrange(3, 10))
        hits = attack("60").slidefair(ct, CRIBS)
        model = "Slidefair pairs, %s" % (kind + " kind" if kind in ("Vigenere", "Beaufort") else "Vigenere kind, " + kind)
        return self.record("60C", model, "%s pairs from letter %d key %s; same-column pairs inside the clues at %s" % (
            an, start + 1, key, [i + 1 for i in inside]), any(h[0] == an and h[1] == start for h in hits), 1, 0,
            sum(h[0] != an or h[1] != start for h in hits))

    # -- attack 61: the key itself is transposed
    def plant_61(self, kind):
        rng = self.rng
        mod = attack("61")
        an, bn = rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"])
        beaufort = rng.random() < 0.5
        p = rng.randrange(2, 27)
        key = T.random_word(rng, p)
        written, where = T.repeating_key(key, 97), list(range(97))
        loose = False
        if kind == "columnar":
            w = rng.randrange(2, 9)
            order = rng.sample(range(w), w)
            f = lambda s: X.columnar(s, order)
            others = [tuple(rng.sample(range(w), w)) for _ in range(5)]
            jobs, names = [("col", [tuple(order)] + others)], ["columnar %s" % (tuple(order),)]
        elif kind in ("quarter turn", "quarter turn the other way"):
            w = rng.randrange(2, 49)
            f = lambda s: X.quarter_turn(s, w, kind != "quarter turn")
            jobs, names = [("rot1", 0)], ["rotation w%d" % w]
            if kind != "quarter turn":
                jobs, loose = jobs + [("routes", w)], True
        elif kind == "two quarter turns":
            w, w2 = rng.randrange(2, 49), rng.randrange(2, 49)
            f = lambda s: X.quarter_turn(X.quarter_turn(s, w), w2)
            jobs, names = [("rot2", w)], ["rotations w%d then w%d" % (w, w2)]
        elif kind == "skip":
            a, b = rng.randrange(2, 97), rng.randrange(97)
            f = lambda s: X.skip_read(s, a, b)
            jobs, names = [("skip", a)], ["skip %d*i+%d" % (a, b)]
        else:
            w = rng.randrange(2, 49)
            f = lambda s: X.snake_rows(s, w)
            jobs, names = [("routes", w)], ["snake rows w%d" % w]
        ct = T.tableau_encrypt(self.message(), FACES[an], FACES[bn], f(written), rng.choice(FACES[an]), beaufort)
        checks = 24 - len({f(where)[i] % p for i in CLUE_POS})
        mod.init(ct, CRIBS)
        hits = []
        for job in jobs:
            hits += mod.work(job)[1]
        view = "%s/%s/%s" % (an, bn, "beau" if beaufort else "vig")
        names += [n + " (inverse)" for n in names]
        mine = [h for h in hits if h[2] == p and h[3] == view and (loose or h[1] in names)]
        return self.record("61", "repeating key scrambled by: %s" % kind, "%s key length %d %s%s" % (
            names[0], p, view, "; listed as " + mine[0][1] if loose and mine else ""),
            bool(mine), checks, 6, sum(h[1] not in names for h in hits))

    # -- attack 62: a key word that drifts
    def plant_62(self, lo, hi):
        rng = self.rng
        an, bn, beaufort = rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"]), rng.random() < 0.5
        w = rng.randrange(lo, hi + 1)
        key, steps = T.random_word(rng, w), [rng.randrange(26) for _ in range(w)]
        cipher = FACES[bn]
        keys = [cipher[(cipher.index(key[i % w]) + (i // w) * steps[i % w]) % 26] for i in range(97)]
        ct = T.tableau_encrypt(self.message(), FACES[an], cipher, keys, rng.choice(FACES[an]), beaufort)
        checks = 0
        for c in range(w):
            n = sum(i % w == c for i in CLUE_POS)
            checks += n - 2 if n >= 3 else 0
        hits = attack("62").search(ct, CRIBS)[1]
        want = ("%s/%s/%s" % (an, bn, "beau" if beaufort else "vig"), w)
        return self.record("62", "drifting key word, widths %d-%d" % (lo, hi), "%s width %d key %s steps %s" % (want + (key, steps)),
                           any(h[1:] == want for h in hits), checks, 4, sum(h[1:] != want for h in hits))

    # -- attack 65: chain addition, row word + column word
    def plant_65_chain(self, kind):
        rng = self.rng
        an, bn, beaufort = rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"]), rng.random() < 0.5
        m = rng.randrange(9, 11) if kind == "taps 9-10 back" else rng.randrange(2, 9)
        t = rng.randrange(1, m)
        a, b, c = (1, 1, 0) if kind != "any multipliers" else (rng.randrange(1, 26), rng.randrange(1, 26), rng.randrange(26))
        nums = X.chain_key([rng.randrange(26) for _ in range(m)], 97, t, m, a, b, c)
        cipher = FACES[bn]
        ct = T.tableau_encrypt(self.message(), FACES[an], cipher, [cipher[v] for v in nums], rng.choice(FACES[an]), beaufort)
        rows = sum(max(0, len(blk) - m) for blk in (B1, B2))
        hits = attack("65").search(ct, CRIBS)[1]
        want = ("%s/%s/%s" % (an, bn, "beau" if beaufort else "vig"), "taps %d,%d" % (t, m))
        return self.record("65", "chain addition of key letters, %s" % kind, "%s %s a=%d b=%d c=%d" % (want + (a, b, c)),
                           any(h[1:] == want for h in hits), rows - 3, 4, sum(h[1:] != want for h in hits))

    def plant_65_grid(self, qmark):
        rng = self.rng
        an, bn, beaufort = rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"]), rng.random() < 0.5
        w = rng.randrange(2, 49)
        off = 1 if qmark else 0
        cols, rws = T.random_word(rng, w), [rng.choice(A2Z) for _ in range(98 // w + 1)]
        cipher = FACES[bn]
        keys = [T.slide(cipher, cipher.index(cols[(i + off) % w]))[cipher.index(rws[(i + off) // w])] for i in range(97)]
        ct = T.tableau_encrypt(self.message(), FACES[an], cipher, keys, rng.choice(FACES[an]), beaufort)
        cs, rs = sorted({(i + off) % w for i in CLUE_POS}), sorted({(i + off) // w for i in CLUE_POS})
        rows = [[int((i + off) % w == c) for c in cs] + [int((i + off) // w == r) for r in rs] for i in CLUE_POS]
        hits = attack("65").search(ct, CRIBS)[1]
        want = ("%s/%s/%s" % (an, bn, "beau" if beaufort else "vig"), "width %d%s" % (w, " (? counted)" if off else ""))
        return self.record("65", "row word + column word%s" % (", the ? counted as a cell" if qmark else ""),
                           "%s %s" % want, any(h[1:] == want for h in hits), 24 - T.rank_mod(rows, 13), 4,
                           sum(h[1:] != want for h in hits))

    # -- attack 69: rows of 21
    def plant_69(self, kind):
        rng = self.rng
        mod = attack("69")
        n1, m1 = self.alphabet(mixed=False)
        n2, m2 = n1, m1
        lay1, bf1 = rng.choice(LAYOUTS), rng.random() < 0.5
        lay2, bf2, s = lay1, bf1, 0
        if kind == "one tableau":
            s = self.cycle(list(range(-5, 6)))
        else:
            while m2 == m1:
                n2, m2 = self.alphabet(mixed=False)
            if kind == "two tableaux, same cipher strip":
                lay1 = lay2 = rng.choice(["M/AZ", "M/KR"])
            elif kind == "two tableaux, key letters found on each row's own strip":
                lay1, lay2 = rng.choice(["M/M", "AZ/M", "KR/M"]), rng.choice(["M/M", "AZ/M", "KR/M"])
            else:
                lay2, bf2 = rng.choice(LAYOUTS), rng.random() < 0.5
        word = [rng.choice(A2Z) for _ in range(21)]
        start = [rng.randrange(21) for _ in range(5)]
        start[3] = start[1] + s
        const = [rng.randrange(26) for _ in range(5)]
        pt, ct = self.message(), ""
        for i, ch in enumerate(pt):
            r, c = i // 21, i % 21
            plain, cipher = strips(*((lay2, m2) if r >= 3 else (lay1, m1)))
            if kind == "two tableaux, key given as numbers":
                k = cipher[(A2Z.index(word[c]) + const[r]) % 26]       # the key says how many places to slide
            else:
                k = cipher[(cipher.index(word[(c + start[r]) % 21]) + const[r]) % 26]
            ct += T.tableau_encrypt(ch, plain, cipher, [k], plain[0], bf2 if r >= 3 else bf1)
        mod.init(ct, CRIBS)
        chunk = self.chunk([(n1, m1)] + ([(n2, m2)] if m2 != m1 else []), mixed=False)
        hits, s2, s4 = mod.work(chunk)
        f1, f2 = "beau" if bf1 else "vig", "beau" if bf2 else "vig"
        if kind == "one tableau":
            cs = [c for c in range(11) if 0 <= c + s < 13]
            want = (n1, lay1, f1, "row key moved %+d columns" % s)
            return self.record("69A", "rows of 21, one tableau, row key moved -5..5 columns", "%s %s %s %s" % want,
                               any(h[1:] == want for h in hits), len(cs) - 1, 7, sum(h[1] != n1 for h in hits), [m1])
        joined = set(s4) & set(s2)
        pairs = mod.name_join(ct, CRIBS, chunk, joined)
        want = ((n1, lay1, f1), (n2, lay2, f2))
        return self.record("69B", "rows of 21, %s" % kind, "rows 1-3 %s %s %s; rows 4-5 %s %s %s" % (want[0] + want[1]),
                           want in pairs, 10, 7, sum(pr != want for pr in pairs), [m1, m2])

    # -- attack 73: an alphabet that changes after every letter
    def plant_73(self, side):
        rng = self.rng
        mod = attack("73")
        name, m = self.alphabet(mixed=False)
        pt = self.message()
        if side == "Chaocipher":
            ln, rn = rng.choice([("M", "AZ"), ("AZ", "M"), ("M", "KR"), ("KR", "M"), ("M", "M"), ("M", "M reversed")])
            pick = {"M": m, "AZ": A2Z, "KR": KR, "M reversed": m[::-1]}
            ct = X.chaocipher_encrypt(pt, pick[ln], pick[rn])
            want = (name, "Chaocipher", "left " + ln, "right " + rn)
        else:
            change, driver = self.cycle(sorted(X.CHANGES)), rng.choice(["cipher", "plain"])
            arg = rng.randrange(1, 26) if side == "self" else rng.choice(["AZ", "KR"])
            ct = X.evolving_encrypt(pt, m, side, arg if side == "self" else FACES[arg], change, driver)
            want = (name, change, "driven by " + driver, "%s %s" % (side, arg))
        mod.init(ct, CRIBS)
        chunk = [(0, name, m)] + [(10 ** 6, dn, dm) for dn, dm in self.some([(name, m)], mixed=False, n=10)[1:]]
        best = mod.work(chunk)[1]
        model = "the real Chaocipher, six start pairs" if side == "Chaocipher" else \
            "changing alphabet, %s" % {"cipher": "S is the cipher alphabet", "plain": "S is the plain alphabet",
                                       "self": "S against itself, slid 1-25"}[side]
        return self.record("73", model, "%s %s %s %s; attack's best: %d of 24 %s" % (want + (best[0], best[1])),
                           best[0] == 24 and best[1][0] == name, 24, 0, None, [m], exact=best[1] == want)

    # -- attacks 54 and 79 (formula part): a short formula for the key
    def _formula(self, kind, pt, plain, cipher, beaufort):
        """Encipher with a key formula. Returns (cipher text, ingredient names as attack 54 calls them)."""
        rng = self.rng
        b = [rng.randrange(1, 26) for _ in range(3)]
        c = rng.randrange(26)
        un = rng.choice(["AZ", "KR"])
        num = FACES[un]
        w, lag, off = rng.randrange(2, 41), rng.randrange(1, 6), rng.randrange(2)
        pr = primes(110)
        names = {"position": ("i",), "grid row + column": ("col%d" % w, "row%d" % w),
                 "earlier plain letter": ("P[i-%d]%s" % (lag, un),), "earlier cipher letter": ("C[i-%d]%s" % (lag, un),),
                 "later plain letter": ("P[i+%d]%s" % (lag, un),), "digits of pi": ("pi_digit+%d" % off,),
                 "prime numbers": ("prime+%d" % off,),
                 "grid row + column + previous plain letter": ("col%d" % w, "row%d" % w, "P[i-1]%s" % un)}[kind]
        out = []
        for i, ch in enumerate(pt):
            if kind == "position":
                v = b[0] * i
            elif kind == "grid row + column":
                v = b[0] * (i % w) + b[1] * (i // w)
            elif kind == "earlier plain letter":
                v = b[0] * num.index(pt[i - lag]) if i >= lag else rng.randrange(26)
            elif kind == "earlier cipher letter":
                v = b[0] * num.index(out[i - lag]) if i >= lag else rng.randrange(26)
            elif kind == "later plain letter":
                v = b[0] * num.index(pt[i + lag]) if i + lag < len(pt) else rng.randrange(26)
            elif kind == "digits of pi":
                v = b[0] * int(PI[i + off])
            elif kind == "prime numbers":
                v = b[0] * pr[i + off]
            else:
                v = b[0] * (i % w) + b[1] * (i // w) + b[2] * (num.index(pt[i - 1]) if i else 0)
            out.append(T.tableau_encrypt(ch, plain, cipher, [cipher[(v + c) % 26]], plain[0], beaufort))
        rows = 24 - 2 * lag if "plain letter" in kind and "previous" not in kind else 22 if "previous" in kind else 24
        return "".join(out), names, rows - len(names) - 2

    def plant_54(self, kind, gap=False):
        rng = self.rng
        an, bn, beaufort = rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"]), rng.random() < 0.5
        g = self.cycle(GAPS) if gap else 0
        pt = self.message_at(64 + g, 97 + g)
        ct, names, checks = self._formula(kind, pt, FACES[an], FACES[bn], beaufort)
        view = "pt%s/ct%s" % (an, bn)
        if gap:
            from . import idea79_gap as G
            text, cribs = G.regap(X.lose_or_add(ct, g, rng), CRIBS, g)
            m54 = G.m54()
            lib = sorted(m54.library(text, cribs, False))
            G.formula_init({0: (text, cribs)}, False)
        else:
            m54 = attack("54")
            m54.init(ct, CRIBS, False)
            lib = sorted(m54._S["lib"])
        pool = sorted(set(names) | set(rng.sample(lib, 8)))
        hits = []
        for first in pool:
            hits += G.formula_work((0, first, pool, len(names)))[2] if gap else m54.work((first, pool, len(names)))[1]
        mine = [h for h in hits if h[0] == view and set(h[1]) == set(names) and h[3]]
        return self.record("79" if gap else "54", "key formula: %s%s" % (kind, ", gap off by 1-3" if gap else ""),
                           "%s %s %s%s" % (view, "+".join(names), "Beaufort" if beaufort else "Vigenere", " gap %+d" % g if gap else ""),
                           bool(mine), checks, 8, len(hits) - len(mine))

    def plant_79_join(self):
        from . import idea79_gap as G
        rng = self.rng
        (n1, m1), (n2, m2) = self.alphabet(), self.alphabet()
        while m2 == m1:
            n2, m2 = self.alphabet()
        g, beaufort, p = self.cycle(GAPS), rng.random() < 0.5, rng.randrange(1, 21)
        key = T.random_word(rng, p)
        ct = T.tableau_encrypt(self.message_at(64 + g, 97 + g), m1, m2, T.repeating_key(key, 97 + g), rng.choice(m1), beaufort)
        text, cribs = G.regap(X.lose_or_add(ct, g, rng), CRIBS, g)
        m63 = G.m63()
        m63.MAX_P = 20
        hits = m63.search(text, cribs, self.chunk([(n1, m1), (n2, m2)]))
        pos = B1 + [i + g for i in B2]
        return self.record("79", "three-keyword Quagmire IV join, gap off by 1-3",
                           "plain %s cipher %s key %s (length %d) gap %+d" % (n1, n2, key, p, g),
                           (p, "beau" if beaufort else "vig", 0, 1) in hits, 24 - len({i % p for i in pos}), 5,
                           sum(h[2] >= 2 or h[3] >= 2 for h in hits), [m1, m2])

    # -- attack 84: two layers on two different tableaux
    def plant_84(self, kind):
        from . import wordkeys
        rng = self.rng
        mod = attack("84")
        base = [("(A-Z)", A2Z), ("KRYPTOS", KR)]
        theme = [(w, T.keyword_alphabet(w)) for w in T.WORDS if w in set(wordkeys.theme_words())]
        theme = [x for x in theme if x[1] not in (A2Z, KR)]
        other = [(w, T.keyword_alphabet(w)) for w in T.WORDS if w not in set(wordkeys.theme_words())]
        if kind == "dictionary alphabet with A-Z or KRYPTOS":
            pair = [rng.choice(other), rng.choice(base)]
            rng.shuffle(pair)
        else:
            pair = rng.sample(base + theme, 2)
        (an, a), (bn, b) = pair
        e1, e2 = rng.choice([1, -1]), rng.choice([1, -1])
        if kind == "one long key (19-22) with a short one":
            p, q = rng.randrange(19, 23), rng.randrange(1, 4)
            if rng.random() < 0.5:
                p, q = q, p
        else:
            p = rng.randrange(1, 17)
            q = rng.randrange(1, 18 - p)
        ka, kb = T.random_word(rng, p), T.random_word(rng, q)
        mid = T.tableau_encrypt(self.message(), a, a, T.repeating_key(ka, 97), rng.choice(a), e1 < 0)
        ct = T.tableau_encrypt(mid, b, b, T.repeating_key(kb, 97), rng.choice(b), e2 < 0)
        # checks: per connected piece of the graph (key letter of layer one) - (key letter of layer two)
        parent = {}

        def find(x):
            while parent.setdefault(x, x) != x:
                x = parent[x]
            return x
        for i in CLUE_POS:
            parent[find(("a", i % p))] = find(("b", i % q))
        edges, nodes = {}, {}
        for i in CLUE_POS:
            edges[find(("a", i % p))] = edges.get(find(("a", i % p)), 0) + 1
        for x in list(parent):
            nodes[find(x)] = nodes.get(find(x), 0) + 1
        checks = sum(max(0, edges[r] - nodes[r]) for r in edges)
        decoys = [(xn, x, yn, y) for xn, x in base + theme[:3] for yn, y in base + theme[:3] if x != y and (x, y) != (a, b)]
        mod.init(ct, CRIBS)
        hits = mod.work([(an, a, bn, b)] + rng.sample(decoys, 6))[1]
        want = (e1, e2, p, q)
        return self.record("84", "two layers on two tableaux, %s" % kind,
                           "%s then %s, %s/%s, key lengths %d and %d" % (an, bn, "V" if e1 > 0 else "B", "V" if e2 > 0 else "B", p, q),
                           any(h[1] == an and h[3] == bn and h[5:9] == want and h[0] >= 7 for h in hits), checks, 7,
                           sum((h[1], h[3]) != (an, bn) and h[0] >= 7 for h in hits))

    # -- attack 86: any keyword alphabet, solved from its tail
    def plant_86(self, rule):
        from . import idea86_tail as E
        rng = self.rng
        word = rng.choice(T.WORDS)
        alpha = T.keyword_alphabet(word)
        m = minimal_keyword_length(alpha)
        layout, beaufort = rng.choice(LAYOUTS), rng.random() < 0.5
        plain, cipher = strips(layout, alpha)
        n = self.cycle(list(range(1, 27)))
        if rule == "rep":
            ct = T.tableau_encrypt(self.message(), plain, cipher, T.repeating_key(T.random_word(rng, n), 97), rng.choice(plain), beaufort)
        else:
            ct = T.sliding_encrypt(self.message(), plain, cipher, T.random_numbers(rng, n), beaufort)
        eqs, impossible = E.equations(ct, CRIBS, layout, "beau" if beaufort else "vig", rule, n)
        found, judged, note = False, True, ""
        if impossible:
            note = "the attack calls the system impossible"
        else:
            try:
                res = E.solve(eqs, m, 2 * 10 ** 6, 50000)
                found = alpha in res["alphas"]
                judged = found or res["count"] <= 50000
                note = "%d alphabets fit at keyword length %d" % (res["count"], m)
            except E.Budget:
                judged, note = False, "search budget ran out"
        return self.record("86", "keyword alphabet solved from its tail, %s key 1-26" % ("repeating" if rule == "rep" else "sliding"),
                           "%s (keyword of %d) %s %s length %d: %d equations, %s" % (word, m, layout, "beau" if beaufort else "vig",
                                                                                   n, len(eqs), note),
                           found, 1 if judged else 0, 1, None, [alpha])

    # -- attack 89: alphabets that are not keyword alphabets (the battery part)
    def phrase_alphabet(self):
        """A keyphrase alphabet: a stretch of the sculpture's plaintext, each letter the first time it comes,
        stopped after k different letters, the rest in A-Z order."""
        text = T.only_letters(self.english or T.FILLER)
        o, k = self.rng.randrange(len(text) - 200), self.rng.randrange(5, 27)
        head = ""
        for ch in text[o:]:
            if ch not in head:
                head += ch
                if len(head) == k:
                    break
        return head + "".join(c for c in A2Z if c not in head)

    def plant_89(self, rule):
        from . import idea89_orders as O
        rng = self.rng
        m = self.phrase_alphabet()
        layout = "M/M" if rule.startswith("autokey") else rng.choice(LAYOUTS)
        beaufort = rng.random() < 0.5
        plain, cipher = strips(layout, m)
        ct, want_rule, par, spec = self.key_rule(rule, self.message(), plain, cipher, beaufort)
        pl, cl = [CRIBS[i] for i in CLUE_POS], [ct[i] for i in CLUE_POS]
        hits = O.battery_hits("true", m, pl, cl, 7)
        for d in range(10):
            hits += O.battery_hits("decoy%d" % d, self.phrase_alphabet(), pl, cl, 7)
        want = ("true", layout, "beau" if beaufort else "vig", want_rule)
        return self.record("89", "keyphrase alphabet, battery, %s key" % rule, "%s %s %s: %s; %s" % (m, layout, want[2], want_rule, par),
                           any(h[1:] == want for h in hits), rule_checks(spec, CLUE_POS), 7, sum(h[1] != "true" for h in hits), [m])

    # -- attacks 57 and 80 score English; only their conventions are checked
    def plant_57(self, index, layout):
        """A running key of English on a keyword tableau. No scoring: are the planted key letters among the
        28 readings attack 57 (and 80, which uses the same views) would score for the true alphabet?"""
        rng = self.rng
        name, m = self.alphabet(mixed=False)
        beaufort = rng.random() < 0.5
        plain, cipher = strips(layout, m)
        text = T.only_letters(T.FILLER + self.english)
        o = rng.randrange(len(text) - 97)
        key = text[o:o + 97]
        ct = T.tableau_encrypt(self.message(), plain, cipher, key, "A" if index == "A" else plain[0], beaufort)
        label = {"M/AZ": "Q1", "AZ/M": "Q2", "M/M": "Q3", "M/KR": "Q4a", "KR/M": "Q4b"}[layout] + ("/beau" if beaufort else "/vig")
        truth = ([A2Z.index(key[i]) for i in B1], [A2Z.index(key[i]) for i in B2])
        found = False
        for lab, s1, s2 in attack("57").views_for(m, ct, CRIBS):
            if lab == label:
                reads = [([(x + c) % 26 for x in s1], [(x + c) % 26 for x in s2]) for c in range(26)]
                reads += [([A2Z.index(al[x]) for x in s1], [A2Z.index(al[x]) for x in s2]) for al in (m, KR)]
                found = truth in reads
        return self.record("57", "English running key [%s], key letter set under %s" % (
            layout, "the plain A (ACA)" if index == "A" else "the first letter of the plain strip (as K1, K2)"),
            "%s %s key %s|%s" % (name, label, key[21:34], key[63:74]), found, 24, 0, None, [m])

    # -- maps of two stacked keys through the copies of the battery
    def stacked_map(self, which, setting):
        """Every pair of lengths p < q <= 13 (q not a multiple of p), one message each, through one attack.
        Returns [(p, q, exact checks, found)]."""
        out = []
        for p in range(2, 13):
            for q in range(p + 1, 14):
                if q % p == 0:
                    continue
                self.records = []
                if which == "68":
                    self.plant_68("gap", "stacked", pair=(p, q), gap=setting, layout="M/M", decoys=False)
                elif which == "70":
                    self.plant_70("stacked", pair=(p, q), cells=setting, decoys=False)
                elif which == "81":
                    self.plant_81("stacked", "plain", pair=(p, q), decoys=False)
                else:
                    self.plant_88("stacked", pair=(p, q), decoys=False)
                r = self.records[0]
                out.append((p, q, r["checks"], r["status"] == "found"))
        self.records = []
        return out


# ---------------------------------------------------------------- the cells

def cells():
    """Every (attack, call) the audit plants: one model in one layout or range."""
    out = []

    def add(att, call):
        out.append((att, call))
    for feed, lo, hi in (("cipher", 1, 21), ("cipher", 22, 33), ("cipher", 34, 60), ("plain", 1, 6), ("plain", 7, 9)):
        add("59", lambda a, f=feed, x=lo, y=hi: a.plant_59(f, x, y))
    for rule in ("repeating", "sliding", "progressive", "autokey plain", "autokey cipher", "stacked", "chain"):
        add("68", lambda a, r=rule: a.plant_68("clue 1 alone", r))
    for rule in ("repeating", "sliding", "autokey cipher"):
        add("68", lambda a, r=rule: a.plant_68("clue 2 alone", r))
    for rule in ("repeating", "sliding", "progressive", "stacked"):
        add("68", lambda a, r=rule: a.plant_68("gap", r))
    for rule in ("repeating", "sliding", "progressive", "autokey plain", "autokey cipher", "stacked", "chain", "multiply"):
        add("70", lambda a, r=rule: a.plant_70(r))
    for feed, kind in (("cipher", "period 13"), ("cipher", "distances 17-20"), ("plain", "periods 7-13"), ("plain", "distances 7-8")):
        add("74", lambda a, f=feed, k=kind: a.plant_74e(f, k))
    for rule in ("sliding", "stacked"):
        add("78", lambda a, r=rule: a.plant_68("gap", r, via78=True))
    add("78", lambda a: a.plant_68("clue 2 alone", "repeating", via78=True))
    for rule in ("repeating", "sliding", "progressive", "autokey plain", "multiply"):
        add("78", lambda a, r=rule: a.plant_70(r, via78=True))
    for rule in ("repeating", "sliding", "progressive", "autokey plain", "stacked", "chain"):
        add("81", lambda a, r=rule: a.plant_81(r, "plain"))
    for rule in ("repeating", "sliding"):
        add("81", lambda a, r=rule: a.plant_81(r, "cipher"))
    for wrong in ("plain", "cipher"):
        add("81", lambda a, w=wrong: a.plant_81_pairs(w))
        add("81", lambda a, w=wrong: a.plant_81_rotor(w))
    for rule in ("repeating", "sliding", "stacked", "chain"):
        add("88", lambda a, r=rule: a.plant_88(r))
    add("88", lambda a: a.plant_88("progressive", p2=0, pmin=1, pmax=12))
    add("88", lambda a: a.plant_88("progressive", p1=2, p2=1, pmin=1, pmax=5))
    add("88", lambda a: a.plant_88("progressive", p1=2, p2=1, pmin=6, pmax=12))
    for feed, lo, hi, sh in (("plain", 7, 7, False), ("plain", 8, 8, False), ("plain", 34, 48, False), ("plain", 34, 48, True),
                             ("cipher", 1, 21, False), ("cipher", 22, 29, False), ("cipher", 30, 33, False), ("cipher", 34, 63, False),
                             ("cipher", 64, 66, False), ("cipher", 34, 48, True)):
        add("90", lambda a, f=feed, x=lo, y=hi, s=sh: a.plant_90(f, x, y, s))
    for kind in ("position", "grid row + column", "earlier plain letter", "earlier cipher letter", "later plain letter",
                 "digits of pi", "prime numbers", "grid row + column + previous plain letter"):
        add("54", lambda a, k=kind: a.plant_54(k))
    for when in ("after plain", "at plain", "after cipher", "word starts"):
        add("56", lambda a, w=when: a.plant_56(w))
    for k in (2, 3, 4):
        add("60", lambda a, k=k: a.plant_60_switch(k))
        add("60", lambda a, k=k: a.plant_60_interleaved(k))
    for kind in ("Vigenere", "Beaufort", "same-column rule inside a clue"):
        add("60", lambda a, k=kind: a.plant_60_slidefair(k))
    for kind in ("columnar", "quarter turn", "quarter turn the other way", "two quarter turns", "skip", "snake rows"):
        add("61", lambda a, k=kind: a.plant_61(k))
    for lo, hi in ((2, 9), (10, 40)):
        add("62", lambda a, x=lo, y=hi: a.plant_62(x, y))
    for kind in ("taps up to 8 back", "taps 9-10 back", "any multipliers"):
        add("65", lambda a, k=kind: a.plant_65_chain(k))
    for q in (False, True):
        add("65", lambda a, q=q: a.plant_65_grid(q))
    for kind in ("one tableau", "two tableaux, same cipher strip", "two tableaux, key given as numbers",
                 "two tableaux, key letters found on each row's own strip"):
        add("69", lambda a, k=kind: a.plant_69(k))
    for side in ("cipher", "plain", "self", "Chaocipher"):
        add("73", lambda a, s=side: a.plant_73(s))
    for kind in ("position", "grid row + column", "earlier plain letter"):
        add("79", lambda a, k=kind: a.plant_54(k, gap=True))
    add("79", lambda a: a.plant_79_join())
    for kind in ("A-Z, KRYPTOS and theme alphabets", "dictionary alphabet with A-Z or KRYPTOS", "one long key (19-22) with a short one"):
        add("84", lambda a, k=kind: a.plant_84(k))
    for rule in ("rep", "slide"):
        add("86", lambda a, r=rule: a.plant_86(r))
    for rule in ("repeating", "sliding", "progressive", "autokey plain"):
        add("89", lambda a, r=rule: a.plant_89(r))
    for index in ("first", "A"):
        for layout in LAYOUTS:
            add("57", lambda a, x=index, la=layout: a.plant_57(x, la))
    return out


def run_cell(args):
    """One cell, `n` messages, its own random stream (so the run can be split over processes)."""
    index, n, seed, english = args
    a = Audit(random.Random(seed * 1000 + index), english)
    call = cells()[index][1]
    for _ in range(n):
        call(a)
    return a.records


MISTAKES = (lambda a: a.plant_59("cipher", 1, 21), lambda a: a.plant_68("clue 1 alone", "repeating"),
            lambda a: a.plant_68("gap", "sliding"), lambda a: a.plant_70("sliding"), lambda a: a.plant_81("sliding", "plain"),
            lambda a: a.plant_90("cipher", 1, 21), lambda a: a.plant_54("grid row + column"), lambda a: a.plant_56("after plain"),
            lambda a: a.plant_61("columnar"), lambda a: a.plant_62(2, 9), lambda a: a.plant_65_grid(False),
            lambda a: a.plant_69("one tableau"), lambda a: a.plant_73("cipher"), lambda a: a.plant_84("A-Z, KRYPTOS and theme alphabets"),
            lambda a: a.plant_86("slide"), lambda a: a.plant_89("repeating"))


def planted_mistake(args):
    """The audit must be able to see a mistake: messages whose clue words sit ONE letter late are given
    to the attacks as if they were in place. Returns the records; none may be 'found'."""
    index, n, seed = args
    a = Audit(random.Random(seed * 77 + index), offset=1, n_decoys=5)
    for _ in range(n):
        MISTAKES[index](a)
    return a.records


def stacked_job(args):
    which, setting, seed = args
    return which, setting, Audit(random.Random(seed)).stacked_map(which, setting)


table = A91.table
