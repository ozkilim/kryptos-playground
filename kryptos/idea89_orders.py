"""Idea 89 helpers: alphabets that are not keyword alphabets, and three tests on them.

The alphabets (new_alphabets):
  text orders   read a text of the sculpture from any starting letter, forwards or backwards,
                and write each letter down the first time it appears. Stop after 1, 2, ... 26
                different letters (so every phrase that starts anywhere is in the list) and
                append the unused letters in A-Z or Z-A order. "full" = read to the end.
  fixed orders  typewriter rows and columns, Morse-code orders, letter-frequency orders.
Fixed orders and "full" text orders are also taken reversed. Anything that is A-Z, KRYPTOS or
a dictionary keyword alphabet (plain or transposition-mixed) is dropped: those were tested.

The tests:
  battery   kryptos.round11.battery on the key values each alphabet forces (five layouts,
            Vigenere and Beaufort)
  score     attack 57: are the 13 + 11 forced key letters English?
  join      attack 63's hash join, one side from the new alphabets and the other from the
            dictionary alphabets (or both sides new), repeating key of length 1-20
"""
import heapq
import importlib.util
from pathlib import Path

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import DATA_DIR, load, letters
from .round11 import POS, SMOKE, battery, dictionary_alphabets, pmap, streams
from .score import word_coverage
from .visual import MORSE as MORSE_CODE

ROOT = Path(__file__).resolve().parent.parent
ZA = AZ[::-1]
MORSE_TEXT = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUSHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ"
GAUGE, MIN_CHECKS, MAX_P = 5, 7, 20
_MODS, _S = {}, {}


def attack(key):
    """The module of attack 57 or 63, loaded by path once per process."""
    if key not in _MODS:
        name = {"57": "57_running_key_keyword_alphabets.py", "63": "63_three_keywords.py"}[key]
        spec = importlib.util.spec_from_file_location("idea89_attack_" + key, ROOT / "attacks" / name)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MODS[key] = mod
    return _MODS[key]


# ---------------------------------------------------------------- the alphabets

def first_seen(text):
    seen, out = set(), []
    for ch in text:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
            if len(out) == 26:
                break
    return "".join(out)


def fill(head, order=AZ):
    """A full alphabet: the letters of head in order, then the unused letters in the given order."""
    return head + "".join(c for c in order if c not in head)


def texts():
    """{name: letters}: the sculpture's texts, as carved and with the known slips corrected."""
    k1, k2, k3 = (load(k) for k in ("k1", "k2", "k3"))
    p1, p2, p3 = letters(k1["plaintext"]), letters(k2["plaintext"]), letters(k3["plaintext"])
    c1 = p1.replace("IQLUSION", "ILLUSION")
    c2 = letters(k2["plaintext_corrected"])
    c2g = c2.replace("UNDERGRUUND", "UNDERGROUND")
    c3 = p3.replace("DESPARATLY", "DESPERATELY")
    k4 = load("k4")["ciphertext"]
    ct = letters(k1["ciphertext"]) + letters(k2["ciphertext"]) + letters(k3["ciphertext"]) + k4
    ctc = letters(k1["ciphertext"]) + letters(k2["ciphertext_corrected"]) + letters(k3["ciphertext"]) + k4
    assert c1 != p1 and c2g != c2 and c3 != p3 and c2 != p2
    return {"K1": p1, "K1fix": c1, "K2": p2, "K2layer": c2, "K2fix": c2g, "K3": p3, "K3fix": c3,
            "K123": p1 + p2 + p3, "K123fix": c1 + c2g + c3, "CT": ct, "CTfix": ctc, "MORSE": MORSE_TEXT}


def text_orders():
    """Yield (name, alphabet, tier). tier 'full' = read on to the end of the text (the listed
    alphabets of the plan); 'phrase' = stopped earlier, after k different letters."""
    for tn, t in texts().items():
        for d, s in ((">", t), ("<", t[::-1])):
            for start in range(len(s)):
                seq = first_seen(s[start:])
                for k in range(1, len(seq) + 1):
                    tier = "full" if k == len(seq) else "phrase"
                    for fn, order in (("az", AZ), ("za", ZA)):
                        yield "%s%s%d:%s+%s" % (tn, d, start, seq[:k], fn), fill(seq[:k], order), tier


def fixed_orders():
    """[(name, alphabet)]: typewriter, Morse and frequency orders."""
    rows = ["QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"]
    out = [("qwerty rows", "".join(rows)), ("qwerty rows bottom-up", "".join(rows[::-1])),
           ("qwerty rows boustrophedon", rows[0] + rows[1][::-1] + rows[2]),
           ("qwerty columns", "".join(r[c] for c in range(10) for r in rows if c < len(r))),
           ("qwerty columns bottom-up", "".join(r[c] for c in range(10) for r in rows[::-1] if c < len(r))),
           ("qwertz rows (German)", "QWERTZUIOPASDFGHJKLYXCVBNM"),
           ("azerty rows (French)", "AZERTYUIOPQSDFGHJKLMWXCVBN")]
    code = MORSE_CODE
    dot = lambda c: code[c].replace(".", "a").replace("-", "b")     # noqa: E731  dot sorts first
    dash = lambda c: code[c].replace("-", "a").replace(".", "b")    # noqa: E731  dash sorts first
    out += [("morse by length, dot first", "".join(sorted(AZ, key=lambda c: (len(code[c]), dot(c))))),
            ("morse by length, dash first", "".join(sorted(AZ, key=lambda c: (len(code[c]), dash(c))))),
            ("morse dot/dash sort, dot first", "".join(sorted(AZ, key=dot))),
            ("morse dot/dash sort, dash first", "".join(sorted(AZ, key=dash))),
            ("morse by duration", "".join(sorted(AZ, key=lambda c: (sum(1 if x == "." else 3 for x in code[c])
                                                                      + len(code[c]) - 1, dot(c))))),
            ("morse sort on the code read backwards", "".join(sorted(AZ, key=lambda c: dot(c)[::-1])))]
    # frequency orders: the linotype keyboard, three printed tables, and the repository's own English table
    out += [("ETAOIN SHRDLU (linotype)", "ETAOINSHRDLUCMFWYPVBGKQJXZ"),
            ("ETAOIN table 2", "ETAOINSHRDLCUMWFGYPBVKJXQZ"),
            ("ETAOIN table 3", "ETAONIRSHDLUCMPFYWGBVKJXZQ"),
            ("ETAOIN table 4", "ETOANIRSHDLUCMPFYWGBVKJXZQ")]
    cnt = dict.fromkeys(AZ, 0)
    with open(DATA_DIR / "english" / "quadgrams.txt") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                q, c = line.split()
                cnt[q[0]] += int(c)
    out.append(("frequency order of the English table", "".join(sorted(AZ, key=lambda c: -cnt[c]))))
    tx = texts()
    for tn in ("K123", "K123fix", "CT", "MORSE"):
        t = tx[tn]
        for fn, order in (("az", AZ), ("za", ZA)):
            freq = "".join(sorted(order, key=lambda c: -t.count(c)))   # stable: ties keep az / za order
            out.append(("frequency order of %s (ties %s)" % (tn, fn), freq))
    k4 = load("k4")["ciphertext"]
    out.append(("frequency order of K4", "".join(sorted(AZ, key=lambda c: -k4.count(c)))))
    for _, m in out:
        assert sorted(m) == list(AZ), m
    return out


_NEW = None


def new_alphabets():
    """([(name, alphabet)], stats). Fixed orders first, then full text orders, then phrases.
    Duplicates and everything in the tested set (A-Z, KRYPTOS, dictionary keyword alphabets
    with their two transposition-mixed forms) are dropped."""
    global _NEW
    if _NEW is None:
        old = {m for _, m in dictionary_alphabets(mixed=True)} | {AZ, KRYPTOS_ALPHABET}
        seen, out = set(), []
        stats = {"fixed": 0, "full": 0, "phrase": 0, "reversed": 0, "already tested": 0, "generated": 0}

        def add(name, m, tier):
            stats["generated"] += 1
            if m in old:
                if m not in seen:
                    stats["already tested"] += 1
                seen.add(m)
            elif m not in seen:
                seen.add(m)
                out.append((name, m))
                stats[tier] += 1

        for name, m in fixed_orders():
            add(name, m, "fixed")
            add(name + " reversed", m[::-1], "reversed")
        phrases = []
        for name, m, tier in text_orders():
            if tier == "full":
                add(name, m, "full")
                add(name + " reversed", m[::-1], "reversed")
            else:
                phrases.append((name, m))
        if SMOKE:   # a slice, but keep the openings of K2 and K3 (the planted messages use them)
            phrases = [x for j, x in enumerate(phrases) if j % 40 == 0 or x[0].startswith(("K2>0:", "K3>0:"))]
        for name, m in phrases:
            add(name, m, "phrase")
        _NEW = (out, stats)
    return _NEW


# ---------------------------------------------------------------- test 1: the key-rule battery

def init(ct, cribs, score=True):
    _S["ct"], _S["cribs"], _S["score"] = ct, cribs, score
    _S["pl"], _S["cl"] = [cribs[i] for i in POS], [ct[i] for i in POS]
    attack("57").init(ct, cribs)


def battery_hits(name, m, pl, cl, min_checks=GAUGE):
    out = []
    for lay, form, k, xp, xc in streams(m, pl, cl):
        for checks, rule in battery(k, POS, xp=xp, xc=xc, min_checks=min_checks):
            out.append((checks, name, lay, form, rule))
    return out


def work(chunk):
    """(battery hits with 5+ checks, the 20 best forced-key English scores) for a chunk."""
    m57 = attack("57")
    tab = m57.quad_table()
    ct, cribs, pl, cl = _S["ct"], _S["cribs"], _S["pl"], _S["cl"]
    hits, best = [], []
    for name, m in chunk:
        hits += battery_hits(name, m, pl, cl)
        if _S["score"]:
            best += m57.score_alphabet((name, m), ct, cribs, tab, keep=1)
    return hits, heapq.nlargest(20, best)


def search(ct, cribs, alphas, chunk=400, procs=None, score=True):
    """Battery and (if score) key-text score over all alphabets. Returns (hits, top 20 key readings)."""
    hits, best = [], []
    for h, b in pmap(work, alphas, init, (ct, cribs, score), chunk=chunk, procs=procs):
        hits += h
        best += b
    return hits, heapq.nlargest(20, best)


def split(hits):
    """(settings with 7+ checks, settings with 5-6 checks)."""
    return [h for h in hits if h[0] >= MIN_CHECKS], [h for h in hits if h[0] < MIN_CHECKS]


# ---------------------------------------------------------------- test 3: the two-alphabet join

_NEG = bytes((26 - x) % 26 for x in range(256))


def _classes(alphas, letters_at):
    """Alphabets that put the given letters at the same places act the same: {places: [index]}."""
    g = {}
    for a, (_, m) in enumerate(alphas):
        g.setdefault(bytes(m.index(c) for c in letters_at), []).append(a)
    return g


def pair_plan(pos, pmax=MAX_P):
    """{key length: [(r, k)]}: pairs of clue letters (indexes into pos) sharing a key slot."""
    out = {}
    for p in range(1, pmax + 1):
        g = {}
        for k, i in enumerate(pos):
            g.setdefault(i % p, []).append(k)
        out[p] = [(v[0], k) for v in g.values() for k in v[1:]]
    return out


def join(ct, cribs, new, dic, pmax=MAX_P):
    """Every (p, form, plain alphabet, cipher alphabet) that fits the clue letters with a repeating
    key of length p, where at least one of the two alphabets is new. Alphabets are given as
    ("n", index) or ("d", index). New alphabets that place the clue letters alike are tried once;
    the hit names the first of them and says how many there are."""
    pos = sorted(cribs)
    pl, cl = [cribs[i] for i in pos], [ct[i] for i in pos]
    plans = pair_plan(pos, pmax)
    np_, nc = _classes(new, pl), _classes(new, cl)
    dp = [bytes(m.index(c) for c in pl) for _, m in dic]
    dc = [bytes(m.index(c) for c in cl) for _, m in dic]
    hits = []
    for p in range(1, pmax + 1):
        pairs = plans[p]

        def sig(v):
            return bytes([(v[k] - v[r]) % 26 for r, k in pairs])

        tp, tc = {}, {}
        for v, ids in np_.items():
            tp.setdefault(sig(v), []).append(ids)
        for v, ids in nc.items():
            tc.setdefault(sig(v), []).append(ids)
        # plain = new, cipher = dictionary or new
        for side, vecs in (("d", enumerate(dc)), ("n", ((ids[0], v) for v, ids in nc.items()))):
            for b, v in vecs:
                s = sig(v)
                for form, key in (("vig", s), ("beau", s.translate(_NEG))):
                    for ids in tp.get(key, ()):
                        hits.append((p, form, ("n", ids[0]), (side, b), len(ids)))
        # plain = dictionary, cipher = new
        for a, v in enumerate(dp):
            s = sig(v)
            for form, key in (("vig", s), ("beau", s.translate(_NEG))):
                for ids in tc.get(key, ()):
                    hits.append((p, form, ("d", a), ("n", ids[0]), len(ids)))
    return hits, len(np_), len(nc)


def checks_by_length(pos=POS, pmax=MAX_P):
    return {p: len(v) for p, v in pair_plan(sorted(pos), pmax).items()}


_BIG = None


def big_score(text):
    """Mean big-model quadgram score over the decrypted stretches, and the number of quadgrams."""
    global _BIG
    if _BIG is None:
        _BIG = attack("57").quad_table()
    t, n = 0.0, 0
    for run in text.split("."):
        v = [ord(c) - 65 for c in run]
        for i in range(len(v) - 3):
            t += _BIG[((v[i] * 26 + v[i + 1]) * 26 + v[i + 2]) * 26 + v[i + 3]]
            n += 1
    return (t / n if n else -9.0), n


def analyse(ct, cribs, new, dic, word_limit=1500):
    """Run the join, decrypt every fit where the clues fix the key, score it, and ask whether
    the key letters can be a dictionary word (first word_limit fits per key length)."""
    m63 = attack("63")
    hits, n_plain, n_cipher = join(ct, cribs, new, dic)
    lists = {"n": new, "d": dic}
    by_p, readings, worded = {}, [], []
    for p, form, (sa, a), (sb, b), mult in hits:
        by_p[p] = by_p.get(p, 0) + 1
        (n1, m1), (n2, m2) = lists[sa][a], lists[sb][b]
        pt, shift = m63.decrypt(ct, cribs, p, form, m1, m2)
        sc, nq = big_score(pt)
        rec = (round(sc, 3), nq, p, form, n1, n2, mult, pt)
        readings.append(rec)
        if p >= 5 and by_p[p] <= word_limit:
            w = m63.key_is_word(shift, p, m1, m2)
            if w:
                worded.append(rec + (w,))
    readings.sort(reverse=True)
    best = readings[0] if readings else None
    long_ = [r for r in readings if r[1] >= 40]
    return {"n": len(hits), "by_p": dict(sorted(by_p.items())), "best": best,
            "best40": long_[0] if long_ else None, "top": readings[:12], "worded": worded,
            "classes": (n_plain, n_cipher)}


def join_job(args):
    kind, ct, cribs = args
    new, _ = new_alphabets()
    dic = _S.get("dic")
    if dic is None:
        dic = _S["dic"] = [("KRYPTOS", KRYPTOS_ALPHABET)] + dictionary_alphabets(mixed=True)
    return kind, analyse(ct, cribs, new, dic)


def reading_line(r):
    sc, nq, p, form, n1, n2, mult, pt = r[:8]
    return "%.2f over %d quadgrams, word cover %.2f | p=%d %s | plain %s | cipher %s | x%d | %s" % (
        sc, nq, word_coverage(pt.replace(".", "")), p, form, n1, n2, mult, pt)


# ---------------------------------------------------------------- planted messages

def english(rng, n=97):
    text = letters("".join(load(k)["plaintext"] for k in ("k2", "k3", "k1")))
    o = rng.randrange(len(text) - n)
    return text[o:o + n]


def plant_sliding(rng, m, p=7):
    """Sliding key on M/M: each key letter moves the strip on from where it stands."""
    pt = english(rng)
    word = [rng.randrange(1, 26) for _ in range(p)]
    ct, k = [], 0
    for i, ch in enumerate(pt):
        k = (k + word[i % p]) % 26
        ct.append(m[(m.index(ch) + k) % 26])
    return "".join(ct), pt


def plant_three_words(rng, m1, m2, key):
    """Quagmire IV: plain alphabet m1, cipher alphabet m2, repeating key word named on m2."""
    pt = english(rng)
    ct = "".join(m2[(m1.index(ch) + m2.index(key[i % len(key)])) % 26] for i, ch in enumerate(pt))
    return ct, pt


def plant_running_key(rng, m):
    """K1/K2's kind of tableau on alphabet M with an English sentence as the key."""
    text = letters("".join(load(k)["plaintext"] for k in ("k2", "k3", "k1")))
    a = rng.randrange(len(text) - 97)
    b = (a + 150 + rng.randrange(100)) % (len(text) - 97)
    pt, key = text[a:a + 97], text[b:b + 97]
    ct = "".join(m[(m.index(x) + m.index(k)) % 26] for x, k in zip(pt, key))
    return ct, pt, key
