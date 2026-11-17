"""Idea 91: feed messages made by the textbook encryptors (kryptos/idea91_textbook.py, which shares
no code with the attacks) to the test functions of attacks 63, 66, 71, 72, 74 and 78, and see
whether each attack finds the setting that was planted.

Every message is K4-shaped: 97 letters of English with EASTNORTHEAST at 22-34 and BERLINCLOCK at
64-74, so the attacks are called exactly as they are on K4, with the repository's own CRIBS.

A planted message ends in one of three ways:
  found   the attack lists the planted setting (alphabet, layout, form and rule all right)
  limit   not listed, but the attack never claimed to judge it: the planted setting leaves fewer
          independent checks than the attack's stated threshold (counted here, independently)
  HOLE    not listed although it has enough checks: the attack's scope is smaller than stated

"decoy hits" counts settings the attack lists on the 40 other alphabets it was handed with the
true one (a rough false-alarm rate).
"""
import importlib.util
from pathlib import Path

from . import idea91_textbook as T
from .data import CRIBS

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = {"63": "63_three_keywords.py", "66": "66_keyword_tableau_battery.py",
           "71": "71_multiplier_and_adder_words.py", "72": "72_paper_rotor.py", "74": "74_keyed_lag_autokey.py"}
A2Z = T.A2Z
KR = T.keyword_alphabet("KRYPTOS")
FACES = {"AZ": A2Z, "KR": KR}
CLUE_POS = sorted(T.clue_map())                      # independent of kryptos.round11.POS
MULTS = [a for a in range(3, 24, 2) if a != 13]      # usable multipliers other than 1 and 25
LAYOUTS = ("M/M", "M/AZ", "AZ/M", "M/KR", "KR/M")
_MODS = {}


def attack(key):
    """An attack script loaded by path, once per process. Attack 71 shrinks its key lengths in
    smoke mode; the audit always wants the full-run value."""
    if key not in _MODS:
        spec = importlib.util.spec_from_file_location("idea91_attack_" + key, ROOT / "attacks" / SCRIPTS[key])
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if key == "71":
            mod.PMAX = 17
        _MODS[key] = mod
    return _MODS[key]


def all_forms(mixed=None):
    """[(name, alphabet)] from the audit's own word list. mixed: None = every form, False = plain
    keyword alphabets only, True = only column-mixed forms that are not also a plain keyword alphabet."""
    plain = {T.keyword_alphabet(w) for w in T.WORDS}
    out, seen = [], set()
    for w in T.WORDS:
        for tag, m in T.alphabet_forms(w):
            if mixed is False and tag or mixed is True and (not tag or m in plain) or m in seen:
                continue
            seen.add(m)
            out.append((w + tag, m))
    return out


def strips(layout, m):
    plain, cipher = layout.split("/")
    pick = {"M": m, "AZ": A2Z, "KR": KR}
    return pick[plain], pick[cipher]


class Audit:
    """Plants messages and collects one record per message."""

    def __init__(self, rng, english="", n_decoys=40, offset=0):
        self.rng, self.english = rng, english
        self.n_decoys = n_decoys
        self.offset = offset              # a deliberate mistake: the clue words sit this many letters late
        self.records = []

    # -- helpers
    def message(self):
        pt = T.k4_like(self.rng, self.english)
        return pt[len(pt) - self.offset:] + pt[:len(pt) - self.offset]

    def alphabet(self, mixed=None):
        return self.rng.choice(all_forms(mixed))

    def chunk(self, true, mixed=None):
        """The true alphabet(s) first, then decoy alphabets that are different from them."""
        taken = {m for _, m in true}
        pool = [a for a in all_forms(mixed) if a[1] not in taken]
        return list(true) + self.rng.sample(pool, min(self.n_decoys, len(pool)))

    def record(self, att, model, params, found, checks, needed, others, alphabets=(), exact=None):
        status = "found" if found else ("limit" if checks < needed else "HOLE")
        self.records.append({"attack": att, "model": model, "params": params, "status": status,
                             "checks": checks, "needed": needed, "others": others, "alphabets": list(alphabets), "exact": exact})
        return status

    # -- attack 63: Quagmire with two keyword alphabets and a repeating key (hash join)
    def plant_63(self, kind, beaufort):
        rng = self.rng
        n1, m1 = self.alphabet()
        n2, m2 = self.alphabet()
        while m2 == m1:
            n2, m2 = self.alphabet()
        if kind == "Quagmire I":
            n2, m2 = "(A-Z)", A2Z
        elif kind == "Quagmire II":
            (n1, m1), (n2, m2) = ("(A-Z)", A2Z), (n1, m1)
        elif kind == "Quagmire III":
            n2, m2 = n1, m1
        p = rng.randrange(1, 25)
        key = T.random_word(rng, p)
        index = rng.choice(m1)                      # ACA sets the key under A, Kryptos under K: any letter
        ct = T.tableau_encrypt(self.message(), m1, m2, T.repeating_key(key, 97), index, beaufort)
        true = [(n1, m1)] if m1 == m2 else [(n1, m1), (n2, m2)]
        hits = attack("63").search(ct, CRIBS, self.chunk(true))
        want = (p, "beau" if beaufort else "vig", 0, len(true) - 1)
        checks = 24 - len({i % p for i in CLUE_POS})
        return self.record("63", "%s, %s, repeating key 1-24" % (kind, "Beaufort" if beaufort else "Vigenere"),
                           "plain %s cipher %s key %s (length %d) index %s" % (n1, n2, key, p, index),
                           want in hits, checks, 5, sum(h[2] >= len(true) or h[3] >= len(true) for h in hits),
                           [m for m in (m1, m2) if m != A2Z])

    # -- attack 66: any keyword tableau, battery of key rules
    def plant_66(self, rule, layout, beaufort, key_on="cipher"):
        rng = self.rng
        name, m = self.alphabet()
        plain, cipher = strips(layout, m)
        pt = self.message()
        checks = 24
        if rule == "repeating":
            p = rng.randrange(1, 18)
            key = T.random_word(rng, p)
            ct = T.tableau_encrypt(pt, plain, cipher, T.repeating_key(key, 97), rng.choice(plain), beaufort)
            want, par, checks = "repeating p=%d" % p, "key %s" % key, 24 - len({i % p for i in CLUE_POS})
        elif rule == "sliding":
            p = rng.randrange(1, 16)
            moves = T.random_numbers(rng, p)
            ct = T.sliding_encrypt(pt, plain, cipher, moves, beaufort)
            want, par = "sliding p=%d" % p, "moves %s" % moves
            checks = 22 - len({i % p for i in CLUE_POS if i - 1 in T.clue_map()})
        elif rule == "progressive":
            p, step = rng.randrange(1, 13), rng.randrange(1, 26)
            key = T.random_word(rng, p)
            along = A2Z if key_on == "label" else cipher
            ct = T.tableau_encrypt(pt, plain, cipher, T.progressive_key(key, step, along, 97), rng.choice(plain), beaufort)
            want, par = "progressive p=%d step=%d" % (p, step), "key %s step %d" % (key, step)
            checks = 24 - len({i % p for i in CLUE_POS})
        elif rule in ("autokey plain", "autokey cipher"):
            lag = rng.randrange(1, 7)
            primer = T.random_word(rng, lag)
            ct = T.autokey_encrypt(pt, plain, cipher, primer, rule.split()[1], key_on, beaufort)
            want = "%s lag=%d sign=%+d" % (rule, lag, -1 if key_on == "plain" else 1)
            par, checks = "primer %s, key letter found on the %s strip" % (primer, key_on), 24 - 2 * lag - 1
        else:   # two stacked keys
            p = rng.randrange(2, 8)
            q = rng.choice([q for q in range(p + 1, 14) if q % p])
            a, b = T.random_word(rng, p), T.random_word(rng, q)
            ct = T.tableau_encrypt(pt, plain, cipher, T.stacked_key(a, b, cipher, 97), rng.choice(plain), beaufort)
            want, par = "two stacked keys p=%d q=%d" % (p, q), "keys %s + %s" % (a, b)
            rows = [[int(j == i % p) for j in range(p)] + [int(j == i % q) for j in range(q)] for i in CLUE_POS]
            checks = 24 - T.rank_mod(rows, 13)
        mod = attack("66")
        mod.init(ct, CRIBS)
        hits = mod.work(self.chunk([(name, m)]))[1]
        form = "beau" if beaufort else "vig"
        found = any(h[1:] == (name, layout, form, want) for h in hits)
        model = rule
        if rule.startswith("autokey"):
            model += {"cipher": ", key letter on the cipher strip", "plain": ", key letter on the plain strip",
                      "label": ", key letter picks the row by its A-Z label"}[key_on]
        elif key_on == "label":
            model += ", key moved on in A-Z order"
        return self.record("66", "%s [%s]" % (model, layout), "%s %s %s: %s; %s" % (name, layout, form, want, par),
                           found, checks, 7, sum(h[1] != name for h in hits), [m])

    def stacked_map(self):
        """Two stacked keys, every pair of lengths p < q <= 13 (q not a multiple of p), two messages each
        on a Quagmire III tableau. Returns [(p, q, exact checks, found of 2 by attack 66, what attack 66's
        own exact solver says about the true key values, found of 2 by kryptos.round11.battery)]."""
        from . import round11
        rng, mod, out = self.rng, attack("66"), []
        for p in range(2, 13):
            for q in range(p + 1, 14):
                if q % p == 0:
                    continue
                rows = [[int(j == i % p) for j in range(p)] + [int(j == i % q) for j in range(q)] for i in CLUE_POS]
                checks, found, solver, r11 = 24 - T.rank_mod(rows, 13), 0, None, 0
                rule = "two stacked keys p=%d q=%d" % (p, q)
                for _ in range(2):
                    name, m = self.alphabet()
                    a, b = T.random_word(rng, p), T.random_word(rng, q)
                    pt = self.message()
                    ct = T.tableau_encrypt(pt, m, m, T.stacked_key(a, b, m, 97), m[0], False)
                    mod.init(ct, CRIBS)
                    hits = mod.work([(name, m)])[1]
                    found += any(h[1:] == (name, "M/M", "vig", "two stacked keys p=%d q=%d" % (p, q)) for h in hits)
                    k = [(m.index(ct[i]) - m.index(pt[i])) % 26 for i in CLUE_POS]
                    solver = mod._stacked_exact(k, p, q)
                    r11 += any(r == rule for _, r in round11.battery(k, round11.POS))
                out.append((p, q, checks, found, solver, r11))
        return out

    # -- attack 71 part A: multiplier word + adder word on A-Z / KRYPTOS
    def plant_71a(self, an, bn):
        rng = self.rng
        p, q = rng.randrange(1, 10), rng.randrange(1, 10)
        mults = [rng.choice([1, 25] + MULTS) for _ in range(p)]
        adds = [rng.randrange(26) for _ in range(q)]
        pt = self.message()
        ct = T.multiplier_adder_encrypt(pt, FACES[an], FACES[bn], mults, adds)
        rows = [[FACES[an].index(pt[i]) * (j == i % p) for j in range(p)] + [int(j == i % q) for j in range(q)]
                for i in CLUE_POS]
        checks = 24 - T.rank_mod(rows, 13)
        hits = attack("71").pairs_search(ct, CRIBS)[1]
        want = ("pt%s/ct%s" % (an, bn), "multiplier word %d + adder word %d" % (p, q))
        found = any(h[1:] == want for h in hits)
        return self.record("71A", "multiplier word + adder word [pt%s/ct%s]" % (an, bn),
                           "multipliers %s adders %s" % (mults, adds), found, checks, 7, None)

    def _fixed_multiplier(self, m, layout, rule):
        """A fixed multiplier on the plain letter, then a repeating or sliding key (attack 71 part B)."""
        rng = self.rng
        plain, cipher = strips(layout, m)
        mu = rng.choice(MULTS)
        if rule == "repeating":
            p = rng.randrange(1, 18)
            adds = T.random_numbers(rng, p)
            checks = 24 - len({i % p for i in CLUE_POS})
        else:
            p = rng.randrange(1, 16)
            moves, adds, t = T.random_numbers(rng, p), [], 0
            for i in range(97):
                t += moves[i % p]
                adds.append(t)
            checks = 22 - len({i % p for i in CLUE_POS if i - 1 in T.clue_map()})
        ct = T.multiplier_adder_encrypt(self.message(), plain, cipher, [mu], adds)
        return ct, "x%d" % mu, "%s p=%d" % (rule, p), checks

    def plant_71b(self, layout, rule):
        name, m = self.alphabet(mixed=False)
        ct, mult, want, checks = self._fixed_multiplier(m, layout, rule)
        mod = attack("71")
        mod.init(ct, CRIBS)
        hits = mod.work(self.chunk([(name, m)], mixed=False))
        found = any(h[1:] == (name, layout, mult, want) for h in hits)
        return self.record("71B", "fixed multiplier, %s key [%s]" % (rule, layout), "%s %s %s" % (name, mult, want),
                           found, checks, 7, sum(h[1] != name for h in hits), [m])

    # -- attack 72: paper rotor
    def plant_72(self, kind):
        rng = self.rng
        an, bn, nn = rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"]), rng.choice(["AZ", "KR"])
        sign = rng.choice([1, -1])
        wiring = list(range(26))
        rng.shuffle(wiring)
        pt = self.message()
        num = FACES[nn]
        mod = attack("72")
        needed, seq = 5, None
        if kind in ("word", "sliding word", "word + 1 per letter"):
            w = rng.choice(T.WORDS)
            vals = [num.index(ch) for ch in w]
            if kind == "word":
                seq = [vals[i % len(w)] for i in range(97)]
            elif kind == "word + 1 per letter":
                seq = [vals[i % len(w)] + i for i in range(97)]
            else:
                seq, t = [], 0
                for i in range(97):
                    t += vals[i % len(w)]
                    seq.append(t)
            want = "%s %s (%s numbering), out %+d" % (kind, w, nn, sign)
        elif kind == "key":
            p = rng.randrange(1, 7)
            key = T.random_numbers(rng, p)
            seq = [key[i % p] for i in range(97)]
            norm = [(k - key[0]) % 26 for k in key]
            want, needed = "key %s, out %+d" % ("".join(A2Z[k] for k in norm), sign), 6
            job = (p, tuple(norm[:1 if p == 1 else 2 if p < 5 else 3]))
        elif kind == "constant speeds":
            a, b = rng.randrange(26), rng.randrange(26)
            want = "speeds in %d out %d" % (a, b)
        elif kind == "previous plain letter":
            seq = [0] + [num.index(pt[i - 1]) for i in range(1, 97)]
            want = "previous plain letter (%s), out %+d" % (nn, sign)
        else:
            want = "%s (%s), out %+d" % (kind, nn, sign)
        if kind == "constant speeds":
            t_in, t_out = [a * i for i in range(97)], [b * i for i in range(97)]
            ct = T.rotor_encrypt(pt, wiring, t_in, t_out, FACES[an], FACES[bn])
        elif seq is not None:
            t_in = seq
            ct = T.rotor_encrypt(pt, wiring, seq, [sign * t for t in seq], FACES[an], FACES[bn])
        else:   # the turn depends on the cipher text written so far
            ct, t_in, total = "", [], 0
            for i, ch in enumerate(pt):
                last = num.index(ct[-1]) if ct else 0
                t = last if kind == "previous cipher letter" else total
                t_in.append(t)
                ct += T.rotor_encrypt(ch, wiring, [t], [sign * t], FACES[an], FACES[bn])
                total += num.index(ct[-1])
        used = [i for i in CLUE_POS if kind != "previous plain letter" or i - 1 in T.clue_map()]
        checks = len(used) - len({(FACES[an].index(pt[i]) + t_in[i]) % 26 for i in used})
        if kind in ("word", "sliding word", "word + 1 per letter"):
            mod.init(ct, CRIBS)
            hits = mod.work_words([w])
        elif kind == "key":
            mod.init(ct, CRIBS)
            hits = mod.work_keys([job])
        else:
            hits = mod.fixed_rules(ct, CRIBS)[1]
        found = any(h[1:] == ("pt%s/ct%s" % (an, bn), want) for h in hits)
        return self.record("72", "rotor turned by: " + kind, "faces pt%s/ct%s; %s" % (an, bn, want),
                           found, checks, needed, None)

    # -- attack 74: autokey with a keyed distance
    def _keyed_lag(self, feed, plain, cipher, numbering, pmax):
        rng = self.rng
        p = rng.randrange(1, pmax + 1)
        lags = [rng.randrange(1, 21 if feed == "cipher" else 9) for _ in range(p)]
        const, beaufort, subtract = rng.randrange(26), rng.random() < 0.5, rng.random() < 0.5
        ct = T.keyed_lag_autokey_encrypt(self.message(), plain, lags, const, feed, rng, beaufort, subtract,
                                         cipher, numbering)
        clue = T.clue_map()
        seen = [i for i in CLUE_POS if feed == "cipher" or i - lags[i % p] in clue]
        checks = len(seen) - p - 1 if len(seen) >= 9 else 0
        shown = tuple(lags[r] for r in range(p) if any(i % p == r for i in CLUE_POS))
        want = ("beau" if beaufort else "vig", "%s feed %+d" % (feed, -1 if subtract else 1), "period %d " % p,
                "period %d lags %s const %d" % (p, shown, const))
        return ct, want, checks, "lags %s const %d" % (lags, const)

    def plant_74(self, feed, view):
        mod = attack("74")
        if view == "dictionary M/M":
            name, m = self.alphabet(mixed=False)
            ct, want, checks, par = self._keyed_lag(feed, m, m, m, 13 if feed == "cipher" else 6)
            mod.init(ct, CRIBS)
            hits, alphabets = mod.work(self.chunk([(name, m)], mixed=False)), [m]
        else:
            an, bn, nn = (self.rng.choice(["AZ", "KR"]) for _ in range(3))
            name = "pt%s/ct%s feed on %s" % (an, bn, nn)
            ct, want, checks, par = self._keyed_lag(feed, FACES[an], FACES[bn], FACES[nn], 13 if feed == "cipher" else 6)
            ix = {k: {c: i for i, c in enumerate(v)} for k, v in FACES.items()}
            hits, alphabets = mod.test_view(name, ix[an], ix[bn], ix[nn], ct, CRIBS), []
        mine = [h for h in hits if h[1] == name and h[2] == want[0] and h[3] == want[1]]
        found = any(h[4].startswith(want[2]) for h in mine)
        return self.record("74", "keyed-lag autokey, %s feed [%s]" % (feed, view),
                           "%s %s %s %s%s" % (name, want[0], want[1], want[2], par), found, checks, 7,
                           sum(h[1] != name for h in hits), alphabets, exact=any(h[4] == want[3] for h in mine))

    # -- attack 78: the round 11 tests on column-mixed alphabets
    def plant_78(self, test, rule="sliding", feed="cipher"):
        from . import idea78_mixed as i78
        rng = self.rng
        name, m = self.alphabet(mixed=True)
        exact = None
        if test == "68":        # each clue alone: only the first clue is long enough to carry a key rule
            layout, beaufort = rng.choice(LAYOUTS), rng.random() < 0.5
            plain, cipher = strips(layout, m)
            if rule == "repeating":
                p = rng.randrange(1, 7)
                ct = T.tableau_encrypt(self.message(), plain, cipher, T.repeating_key(T.random_word(rng, p), 97),
                                       rng.choice(plain), beaufort)
                checks = 13 - p
            else:
                p = rng.randrange(1, 6)
                ct = T.sliding_encrypt(self.message(), plain, cipher, T.random_numbers(rng, p), beaufort)
                checks = 12 - p
            want = (name, layout, "beau" if beaufort else "vig", "clue 1 alone", "%s p=%d" % (rule, p))
            model = "clue 1 alone, %s key" % rule
        elif test == "71":
            layout = rng.choice(LAYOUTS)
            ct, mult, rl, checks = self._fixed_multiplier(m, layout, rule)
            want, model = (name, layout, mult, rl), "fixed multiplier, %s key" % rule
        else:
            ct, w, checks, par = self._keyed_lag(feed, m, m, m, 13 if feed == "cipher" else 6)
            want, model = (name,) + w[:3], "keyed-lag autokey, %s feed" % feed
        i78.init(ct, CRIBS, (test,))
        hits = i78.work(self.chunk([(name, m)], mixed=True))[test]
        if test == "74":
            mine = [h for h in hits if h[1:4] == want[:3]]
            found = any(h[4].startswith(want[3]) for h in mine)
            exact = any(h[4] == w[3] for h in mine)
        else:
            found = any(h[1:] == want for h in hits)
        return self.record("78/" + test, model + " [column-mixed alphabet]", " ".join(str(x) for x in want),
                           found, checks, 7, sum(h[1] != name for h in hits), [m], exact=exact)


def cells():
    """Every (label, call) the audit plants: one model in one layout."""
    out = []
    for kind in ("Quagmire IV", "Quagmire III", "Quagmire I", "Quagmire II"):
        for beaufort in (False, True):
            out.append(lambda a, k=kind, b=beaufort: a.plant_63(k, b))
    for layout in LAYOUTS:
        for rule in ("repeating", "sliding", "progressive", "autokey plain", "autokey cipher", "two stacked keys"):
            for beaufort in (False, True):
                out.append(lambda a, r=rule, la=layout, b=beaufort: a.plant_66(r, la, b))
        for rule in ("autokey plain", "autokey cipher"):
            out.append(lambda a, r=rule, la=layout: a.plant_66(r, la, False, key_on="plain"))
    for rule in ("autokey plain", "autokey cipher", "progressive"):
        out.append(lambda a, r=rule: a.plant_66(r, "M/M", False, key_on="label"))
    for an in FACES:
        for bn in FACES:
            out.append(lambda a, x=an, y=bn: a.plant_71a(x, y))
    for layout in LAYOUTS:
        for rule in ("repeating", "sliding"):
            out.append(lambda a, la=layout, r=rule: a.plant_71b(la, r))
    for kind in ("word", "sliding word", "word + 1 per letter", "key", "constant speeds", "previous cipher letter",
                 "running sum of cipher text", "previous plain letter"):
        out.append(lambda a, k=kind: a.plant_72(k))
    for feed in ("cipher", "plain"):
        for view in ("dictionary M/M", "A-Z/KRYPTOS faces"):
            out.append(lambda a, f=feed, v=view: a.plant_74(f, v))
    for rule in ("repeating", "sliding"):
        out.append(lambda a, r=rule: a.plant_78("68", rule=r))
        out.append(lambda a, r=rule: a.plant_78("71", rule=r))
    for feed in ("cipher", "plain"):
        out.append(lambda a, f=feed: a.plant_78("74", feed=f))
    return out


def planted_mistake(seed, n=6):
    """The audit must be able to see a mistake. Messages whose clue words sit ONE letter late (23-35 and
    65-75) are given to attacks 63 and 66 as if they were at 22-34 and 64-74. Returns (messages, found):
    found must be 0."""
    import random
    a = Audit(random.Random(seed), offset=1)
    for _ in range(n):
        a.plant_63("Quagmire III", False)
        a.plant_66("sliding", "M/M", False)
        a.plant_66("autokey plain", "M/M", False)
    return len(a.records), sum(r["status"] == "found" for r in a.records)


def run_cell(args):
    """One cell, `n` messages, its own random stream (so the run can be split over processes)."""
    import random
    index, n, seed, english = args
    a = Audit(random.Random(seed * 1000 + index), english)
    call = cells()[index]
    for _ in range(n):
        call(a)
    return a.records


def table(records):
    """{(attack, model): [planted, found, limit, HOLE]} in first-seen order."""
    out = {}
    for r in records:
        row = out.setdefault((r["attack"], r["model"]), [0, 0, 0, 0])
        row[0] += 1
        row[1 + ("found", "limit", "HOLE").index(r["status"])] += 1
    return out
