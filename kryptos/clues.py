"""The clue scorecard: a pre-filter every K4 idea goes through before it is queued.

Every clue we have (docs/CLUES.md) gets a level:

  fact   checked against the sculpture; a hypothesis that breaks one is REJECTED
  firm   Sanborn/Scheidt said it plainly; breaking one gets the idea FLAGGED
         (allowed only with an argument for why the statement means something else)
  hint   suggestive, post hoc, or open to interpretation; never a filter, only
         points for explaining it

Each cipher family is then marked against each clue, two ways:

  * probes (automatic): the family's encryptor is run on English text with random
    keys, and we measure properties directly: does the cipher keep letters in place
    ("BERLINCLOCK matches directly")? does the same word at the same place encrypt
    the same way in two messages (the K5 statement)? can a letter encrypt to itself
    (S->S, K->K)? how often does it make K4's statistical oddities (likelihood vs a
    one-time pad)?
  * marks (by hand): for clues no probe can measure (LAYER TWO, World Clock, Egypt,
    hand process, multi-stage, ...), with a one-line reason.

  python -m kryptos.clues            rebuild docs/CLUE_MATRIX.md (probes + marks + ranking)
  from kryptos.clues import prefilter
  prefilter("my idea", encrypt_fn, marks={...})   scorecard for a NEW idea before you build it

Marks: pass / fail / explains (a hint it accounts for) / against (makes a hint
LESS likely than chance) / cond (only under an extra assumption) / ? (unknown).
"""

import math
import random
from dataclasses import dataclass, field

from .ciphers import AZ, KRYPTOS_ALPHABET, keyed_alphabet
from .data import CRIBS, K4, ROOT
from . import fingerprint as FP

N = 97
LIGHT = set("KRYPTOS")


# ================================================================== clues

@dataclass
class Clue:
    id: str
    level: str  # fact / firm / hint
    short: str
    text: str
    probe: str = None  # name of the automatic probe, if any


CLUES = [
    # ---- facts
    Clue("cribs", "fact", "24 clue letters", "EAST, NORTHEAST, BERLIN, CLOCK at their exact positions (the campaign's exact tests)"),
    Clue("selfenc", "fact", "S->S, K->K", "two clue letters encrypt to themselves, so the cipher must allow fixed points", "selfenc"),
    Clue("not_pure_tr", "fact", "not pure transposition", "the clues need 3 E's, the ciphertext has 2"),
    Clue("hand", "fact", "hand, paper charts, pre-1990", "plaintext strips 1990, 'coding charts' in the auction lot: done by hand from paper"),
    # ---- firm statements
    Clue("in_place", "firm", "matches directly", "Sanborn: BERLINCLOCK 'matches directly', plain letter i -> cipher letter i", "aligned"),
    Clue("k5", "firm", "K5 same words, same places",
         "K5 (same time, same length) shares coded words with K4 in the same positions: the key depends on position, "
         "not on the message", "k5"),
    Clue("multistage", "firm", "masked, >1 stage, new method",
         "Scheidt: English 'masked', 'more than one stage', a 'change in methodology' from K1-K3"),
    Clue("english", "firm", "English sentences", "plaintext is 97 letters of sensible English in several sentences"),
    # ---- hints: measured oddities (probed: likelihood vs a one-time pad)
    Clue("kryptos_close", "hint", "KRYPTOS letters barely move", "9 of 10 KRYPTOS-letter clues within +-2 (shuffled p~0.003)",
         "kryptos_close"),
    Clue("bean_close", "hint", "clues near their cipher letters", "12 of 24 clue letters within 3 places (Bean, ~1 in 5,520)",
         "close"),
    Clue("flat_ioc", "hint", "flat letter counts", "index of coincidence 0.0361, like random text", "ioc"),
    Clue("stehle", "hint", "lag-4 run DIAWINFBN", "a run of 5 equal differences at lag 4 (p=0.003, post hoc)", "stehle"),
    Clue("doublets", "hint", "doublets on mod 7", "5 of 6 doubled letters on one residue mod 7 (p=0.001, post hoc)", "doublets"),
    Clue("vpairs", "hint", "width-21 pairs", "11 repeated pairs at width 21 (Bean; ~1 in 90-210 corrected)", "vpairs"),
    # ---- hints: narrative (marked by hand)
    Clue("nonperiodic", "hint", "key not simply periodic", "no periodic signature; the key jumps 12-13 somewhere (ours)"),
    Clue("layer_two", "hint", "LAYER TWO", "K2's corrected ending"),
    Clue("two_systems", "hint", "two separate systems", "1990; may just mean K3 vs K4 (the 'lower half')"),
    Clue("k123_keys", "hint", "K1-K3 hold clues", "answers to K1-K3 contain clues to K4; KRYPTOS alphabet, PALIMPSEST, ABSCISSA"),
    Clue("berlin_clock", "hint", "World Clock / 1989", "Weltzeituhr at Alexanderplatz; the Wall fell in 1989"),
    Clue("egypt", "hint", "Egypt 1986", "Sanborn's 1986 trip to Egypt is in the solution"),
    Clue("message", "hint", "delivering a message", "the 2025 theme"),
    Clue("math_base", "hint", "different math base", "Scheidt: bases 2-16, Mayan base 60"),
    Clue("shift_matrix", "hint", "shifting matrices", "Scheidt taught shifting matrices"),
    Clue("visual", "hint", "visual systems / not math", "2005 'visual systems'; 2025 'who says it is even a math solution?'"),
    Clue("mistakes", "hint", "mistakes on purpose", "IQLUSION, UNDERGRUUND, DESPARATLY, PALIMPCEST, the K2 S"),
    Clue("sentences_x", "hint", "sentence strips, X breaks", "plaintext cut into sentence strips; K1-K3 use X between sentences"),
    Clue("layout", "hint", "carved layout 4+31+31+31", "row structure; the April 2020 layout release"),
]
CLUE = {c.id: c for c in CLUES}


# ================================================================== families

@dataclass
class Family:
    id: str
    name: str
    ideas: list
    status: str  # dead / dead-in-scope / disfavoured / open / pending / untested
    encrypt: object = None  # name of a fingerprint family, or a function (pt, rng) -> ct
    marks: dict = field(default_factory=dict)  # clue id -> (mark, reason)
    note: str = ""


def _two_long(pt, rng):
    L1 = rng.randint(13, 25)
    L2 = rng.choice([x for x in range(14, 27) if x != L1])
    a = [rng.randrange(26) for _ in range(L1)]
    b = [rng.randrange(26) for _ in range(L2)]
    return "".join(AZ[(AZ.index(p) + a[i % L1] + b[i % L2]) % 26] for i, p in enumerate(pt))


def _hidden_long(pt, rng):
    from .solvers import freealpha as FA
    return FA.plant("quag2", pt, rng, period=rng.randint(23, 26))[0]


def _selective(pt, rng):
    L = rng.randint(4, 9)
    key = [rng.randrange(26) for _ in range(L)]
    light = [rng.randint(-2, 2) for _ in range(N)]
    return "".join(AZ[(AZ.index(p) + (light[i] if p in LIGHT else key[i % L])) % 26] for i, p in enumerate(pt))


def _restart(pt, rng):
    s1, s2, L = rng.randint(3, 21), rng.randint(36, 63), rng.randint(5, 11)
    key = [rng.randrange(26) for _ in range(L)]
    st = lambda i: s2 if i >= s2 else (s1 if i >= s1 else 0)  # noqa: E731
    return "".join(AZ[(AZ.index(p) + key[(i - st(i)) % L]) % 26] for i, p in enumerate(pt))


def _per_part(pt, rng):
    b, L1, L2 = rng.randint(34, 63), rng.randint(3, 9), rng.randint(3, 9)
    k1 = [rng.randrange(26) for _ in range(L1)]
    k2 = [rng.randrange(26) for _ in range(L2)]
    return "".join(AZ[(AZ.index(p) + (k1[i % L1] if i < b else -k2[(i - b) % L2])) % 26] for i, p in enumerate(pt))


def _sel_restart(pt, rng):
    """Hybrid (idea 46): KRYPTOS letters lightly shifted only inside the two sentences holding the
    clues; every other letter keyed by a repeating key that restarts at each sentence."""
    a1, b1 = rng.randint(0, 21), rng.randint(34, 50)
    a2, b2 = rng.randint(b1, 63), rng.randint(74, 97)
    L = rng.randint(5, 11)
    key = [rng.randrange(26) for _ in range(L)]
    starts = sorted({0, a1, b1, a2, b2} - {97})
    light = set(range(a1, b1)) | set(range(a2, b2))
    out = []
    for i, p in enumerate(pt):
        st = max(s for s in starts if s <= i)
        k = rng.randint(-2, 2) if (p in LIGHT and i in light) else key[(i - st) % L]
        out.append(AZ[(AZ.index(p) + k) % 26])
    return "".join(out)


def _gromark_base(pt, rng):
    base = rng.choice([5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16])
    k = [rng.randrange(base) for _ in range(5)]
    while len(k) < N:
        k.append((k[-5] + k[-4]) % base)
    pa, ca = "".join(rng.sample(AZ, 26)), "".join(rng.sample(AZ, 26))
    return "".join(ca[(pa.index(p) + k[i]) % 26] for i, p in enumerate(pt))


def _columnar_only(pt, rng):
    from .solvers import stack as S
    w = rng.randint(5, 10)
    o = list(range(w))
    rng.shuffle(o)
    m = S.columnar_map(tuple(o))
    return S.encrypt_stack(pt, m, AZ, "vigenere", ("shift", "x", None), "after", key=[0] * N)


def _three_layers(pt, rng):
    w = keyed_alphabet(rng.choice(["BERLIN", "CLOCK", "EGYPT", "SHADOW", "PALIMPSEST", "ABSCISSA"]))
    t = [AZ.index(c) for c in w[: rng.randint(5, 10)]]
    L1, L2 = rng.randint(5, 13), rng.randint(5, 13)
    a = [rng.randrange(26) for _ in range(L1)]
    b = [rng.randrange(26) for _ in range(L2)]
    return "".join(AZ[(AZ.index(p) + t[i % len(t)] + a[i % L1] + b[i % L2]) % 26] for i, p in enumerate(pt))


P, F, E, A, C, U, NA = "pass", "fail", "explains", "against", "cond", "?", "n/a"

# Hand marks. Probed clues (in_place, k5, selfenc, and the measured hints) are filled
# automatically for families with an encryptor; a hand mark here overrides a probe.
FAMILIES = [
    Family("periodic", "Repeating key (Vigenere/Beaufort), A-Z or KRYPTOS alphabet", ["01", "06", "15"], "dead",
           "periodic Vigenere 4-14, KRYPTOS (K1/K2 style)",
           {"cribs": (F, "no length 1-29 fits"), "hand": (P, ""), "multistage": (F, "this IS K1/K2's method"),
            "nonperiodic": (A, "periodic by definition"), "k123_keys": (E, "K1/K2 tableau")}),
    Family("keyword_alpha", "Keyword alphabets / Quagmire I-IV with short keys", ["05", "14", "15", "20", "27", "37"], "dead",
           "Quagmire III (random keyword alphabet), period 4-14",
           {"cribs": (F, "I/II/III keyword alphabets dead; hidden alphabets dead up to length 22"), "hand": (P, ""),
            "multistage": (C, "only if the alphabet counts as a stage"), "nonperiodic": (A, "periodic"),
            "k123_keys": (E, "KRYPTOS-style tableau"), "egypt": (C, "idea 37 tried Egypt-era orders"),
            "mistakes": (C, "idea 27 tried misspelling swaps")}),
    Family("hidden_long", "One hidden alphabet with a long key (length 23+)", ["20"], "open", _hidden_long,
           {"cribs": (C, "undecidable from 24 letters; completions only"), "hand": (P, "a long key on a chart"),
            "multistage": (P, "alphabet + key"), "nonperiodic": (C, "period 23+ looks non-periodic in 97 letters"),
            "k123_keys": (C, "")}),
    Family("autokey", "Autokey (plaintext or ciphertext feeds the key)", ["03", "10"], "dead", "plaintext autokey",
           {"cribs": (F, "all primers 1-20 dead"), "hand": (P, ""), "multistage": (C, ""), "nonperiodic": (E, "")}),
    Family("running_key", "Running key from a text", ["04"], "dead-in-scope", "running key (English text), A-Z",
           {"cribs": (F, "every known text tried is dead; unknown texts can't be tested"), "hand": (P, ""),
            "multistage": (C, ""), "nonperiodic": (E, ""), "message": (C, "if the key text is 'the message'"),
            "k5": (C, "only if K5 reused the same key text at the same offset")}),
    Family("transposition", "Transposition + substitution (columnar, double, routes, Myszkowski, strips)",
           ["02", "07", "08", "09", "10", "11", "12", "13", "17", "35"], "dead", "columnar then periodic key",
           {"cribs": (F, "dead for every width/order/key model searched"), "hand": (P, "K3 was one"),
            "multistage": (P, "two stages"), "layer_two": (C, "a second layer"),
            "layout": (C, "idea 35: strips cut at carved rows")}),
    Family("pure_transposition", "Pure transposition (letters only rearranged)", ["02"], "dead", _columnar_only,
           {"cribs": (F, ""), "not_pure_tr": (F, "3 E's needed, 2 in the ciphertext"), "hand": (P, ""),
            "multistage": (F, "")}),
    Family("gromark", "Gromark / chain-addition digits, both alphabets hidden (base 10)", ["19", "45"], "disfavoured",
           "Gromark, both alphabets hidden",
           {"cribs": (C, "454 primers survive; completions no better than shuffles"), "hand": (P, "ACA hand cipher"),
            "multistage": (P, "digits + two alphabets"), "nonperiodic": (E, "")}),
    Family("gromark_bases", "Chain addition in other bases (3-16)", ["41"], "dead", _gromark_base,
           {"cribs": (F, "1,470 survivors, completions no better than shuffles"), "hand": (P, ""), "multistage": (P, ""), "nonperiodic": (E, ""),
            "math_base": (E, "Scheidt's 'different math base'")}),
    Family("two_keys", "Two stacked repeating keys (LAYER TWO), long lengths", ["23", "38", "45"], "open", _two_long,
           {"cribs": (C, "short pairs disfavoured; long pairs information-limited (shuffled K4 completes to English-level scores)"),
            "hand": (P, "two passes on the same tableau"), "multistage": (P, "two stages"),
            "nonperiodic": (E, "period lcm(L1,L2) > 97"), "layer_two": (E, "literally two layers"),
            "k123_keys": (E, "K1/K2 tableau used twice"), "berlin_clock": (C, "if a key is BERLIN/CLOCK/a 1989 word"),
            "egypt": (C, "if a key is an Egypt word"), "two_systems": (C, "")}),
    Family("three_layers", "Three layers: a theme word plus two keys", ["26"], "dead-in-scope", _three_layers,
           {"cribs": (F, "fully clue-determined configs dead"), "hand": (P, ""), "multistage": (P, ""),
            "nonperiodic": (E, ""), "layer_two": (C, ""), "berlin_clock": (E, "theme word"), "egypt": (C, "")}),
    Family("world_clock", "World Clock 1989 keys (cities, initials, UTC offsets)", ["24"], "dead", None,
           {"cribs": (F, "best 7/24"), "hand": (P, ""), "in_place": (P, ""), "k5": (P, ""), "selfenc": (P, ""),
            "multistage": (C, ""), "berlin_clock": (E, "the clock itself"), "nonperiodic": (E, "")}),
    Family("visual_letters", "Visual letter transforms (semaphore, Morse reversal) alone or stacked", ["30"], "dead", None,
           {"cribs": (F, "no schedule fits"), "hand": (P, ""), "in_place": (P, ""), "k5": (P, ""), "selfenc": (P, ""),
            "multistage": (P, ""), "visual": (E, "")}),
    Family("compass", "Compass-bearing keys across the carved layout", ["31"], "dead", None,
           {"cribs": (F, "best 6/24"), "hand": (P, ""), "in_place": (P, ""), "k5": (P, ""), "selfenc": (P, ""),
            "multistage": (C, ""), "layout": (E, "reads the carved rows"), "visual": (E, "")}),
    Family("self_mask", "Self-masking (K4 keyed by its own text in scrambled order)", ["33"], "dead", None,
           {"cribs": (F, ""), "hand": (P, ""), "in_place": (P, ""), "k5": (F, "the key IS the message"),
            "selfenc": (P, ""), "multistage": (P, "")}),
    Family("teleprinter", "Teleprinter: Baudot/Vernam XOR, Lorenz wheels", ["34", "36"], "dead", None,
           {"cribs": (F, "no key model fits"), "hand": (U, "XOR by hand is possible but tape-era"),
            "in_place": (P, ""), "k5": (P, "periodic wheels"), "selfenc": (P, "key code 0"), "multistage": (P, ""),
            "message": (E, "'transmitted underground'"), "berlin_clock": (C, "Berlin Tunnel")}),
    Family("shift_matrix", "Shifting matrices / coordinate wheels on a grid", ["39"], "dead", None,
           {"cribs": (F, "no wheel set fits in any grid"), "hand": (P, ""), "in_place": (P, ""), "k5": (P, ""),
            "selfenc": (P, ""), "multistage": (P, ""), "shift_matrix": (E, "literally"), "math_base": (E, "grid coordinates"),
            "nonperiodic": (C, "")}),
    Family("egypt_alpha", "Egypt-era alphabets (hieroglyph, Coptic, Greek order) x key models", ["37"], "dead", None,
           {"cribs": (F, "0 survivors"), "hand": (P, ""), "in_place": (P, ""), "k5": (P, ""), "selfenc": (P, ""),
            "multistage": (P, ""), "egypt": (E, "")}),
    Family("selective", "Selective masking: KRYPTOS letters lightly shifted, others keyed", ["42"], "pending", _selective,
           {"cribs": (U, "round 7"), "hand": (P, "trivial on a chart"), "multistage": (P, "two treatments"),
            "two_systems": (E, "two rules by letter class"), "k123_keys": (E, "the KRYPTOS keyword decides"),
            "nonperiodic": (E, "")}),
    Family("sel_restart", "Hybrid: KRYPTOS letters light only in the clue sentences + key restarting per sentence", ["46"],
           "pending", _sel_restart,
           {"cribs": (U, "round 7"), "hand": (P, "two simple rules on a chart"), "multistage": (P, "two treatments"),
            "two_systems": (E, "two rules by letter class"), "k123_keys": (E, "the KRYPTOS keyword decides"),
            "nonperiodic": (E, "restarts + masked letters"), "sentences_x": (E, "sentence-level structure"),
            "k5": (C, "only if K5's sentences break at the same places"),
            "flat_ioc": (A, "flat in only ~0.5% with a short key, ~5% with a long/stacked key (chance 27%)")}),
    Family("restart", "Key restarts at each sentence (+X between sentences)", ["43"], "pending", _restart,
           {"cribs": (U, "round 7"), "hand": (P, "Cyrillic Projector did this"), "multistage": (C, ""),
            "k5": (C, "only if K5's sentences break at the same places"), "nonperiodic": (E, "restarts break the period"),
            "sentences_x": (E, ""), "k123_keys": (C, "")}),
    Family("per_part", "A different simple system for each part", ["44"], "pending", _per_part,
           {"cribs": (U, "round 7; smoke run: nothing fits either half"), "hand": (P, ""), "multistage": (P, ""),
            "two_systems": (E, "literally"), "nonperiodic": (E, "")}),
    Family("one_mistake", "Any family above, with one deliberate wrong clue letter", ["45"], "pending", None,
           {"cribs": (C, "drops one clue by design"), "hand": (P, ""), "in_place": (P, ""), "k5": (P, ""),
            "selfenc": (P, ""), "multistage": (C, "inherits"), "mistakes": (E, "")}),
    Family("visual_step", "A genuinely non-arithmetic visual/physical step (untested)", [], "untested", None,
           {"cribs": (U, "nobody has defined one precisely enough to test"), "hand": (P, ""), "in_place": (U, ""),
            "k5": (U, ""), "selfenc": (U, ""), "multistage": (P, ""), "visual": (E, ""), "layout": (C, "")}),
]
FAMILY = {f.id: f for f in FAMILIES}


# ================================================================== probes

def _text():
    return FP.english_windows()


def _shift(c, p):
    d = (AZ.index(c) - AZ.index(p)) % 26
    return min(d, 26 - d)


def _kryptos_close(ct, pt):
    pos = [i for i in CRIBS if pt[i] in LIGHT]
    return sum(_shift(ct[i], pt[i]) <= 2 for i in pos)


K4_STATS = dict(FP.stats(K4), kryptos_close=_kryptos_close(K4, {**{i: "?" for i in range(N)}, **CRIBS}))


def _odd(name, value):
    """Is a statistic at least as odd as K4's?"""
    k = K4_STATS[name]
    if name == "ioc":
        return value <= k + 0.0005
    return value >= k


def _fn(enc, text):
    if callable(enc):
        return enc
    return FP.families(text)[enc]


def probe(enc, n=300, seed=0, text=None):
    """Run every automatic probe on an encryptor fn(pt, rng) -> ct (same seed = same key)."""
    text = text or _text()
    fn = _fn(enc, text)
    rng = random.Random(seed)
    out = {"aligned": 0, "local": 0, "k5": 0, "selfenc": 0}
    odd = {k: 0 for k in ("kryptos_close", "close", "ioc", "stehle", "doublets", "vpairs")}
    for t in range(n):
        s = rng.randrange(1 << 30)
        pt = FP.k4_like_plaintext(text, rng)
        c1 = fn(pt, random.Random(s))
        # in place / local: change one letter, same key
        j = rng.randrange(N)
        pt2 = pt[:j] + AZ[(AZ.index(pt[j]) + rng.randint(1, 25)) % 26] + pt[j + 1:]
        c2 = fn(pt2, random.Random(s))
        out["aligned"] += c1[j] != c2[j]
        out["local"] += all(c1[i] == c2[i] for i in range(N) if i != j)
        # K5: another message with the same key, sharing BERLINCLOCK at 63-73
        pt3 = FP.k4_like_plaintext(text, rng)
        c3 = fn(pt3, random.Random(s))
        out["k5"] += all(c1[i] == c3[i] for i in range(63, 74))
        out["selfenc"] += sum(c1[i] == pt[i] for i in CRIBS) >= 2
        st = FP.stats(c1)
        st["kryptos_close"] = _kryptos_close(c1, pt)
        for k in odd:
            odd[k] += _odd(k, st[k])
    res = {k: v / n for k, v in out.items()}
    res.update({f"odd_{k}": v / n for k, v in odd.items()})
    res["n"] = n
    return res


_BASE = {}


def baseline(n=4000, text=None):
    """How often a one-time pad produces each oddity (the 'chance' reference)."""
    if "otp" not in _BASE:
        text = text or _text()
        rng = random.Random(99)
        odd = {k: 0 for k in ("close", "ioc", "stehle", "doublets", "vpairs")}
        for _ in range(n):
            ct = "".join(rng.choice(AZ) for _ in range(N))
            st = FP.stats(ct)
            for k in odd:
                odd[k] += _odd(k, st[k])
        b = {f"odd_{k}": max(v, 0.5) / n for k, v in odd.items()}
        # KRYPTOS closeness under chance: exact binomial, 10 positions, p = 5/26
        p, m, k = 5 / 26, sum(CRIBS[i] in LIGHT for i in CRIBS), K4_STATS["kryptos_close"]
        b["odd_kryptos_close"] = sum(math.comb(m, r) * p ** r * (1 - p) ** (m - r) for r in range(k, m + 1))
        _BASE["otp"] = b
    return _BASE["otp"]


def _pc(x):
    return f"{x:.2%}" if x >= 0.001 else f"{x * 100:.1g}%"


HINT_PROBES = {"kryptos_close": "odd_kryptos_close", "bean_close": "odd_close", "flat_ioc": "odd_ioc",
               "stehle": "odd_stehle", "doublets": "odd_doublets", "vpairs": "odd_vpairs"}


def marks_from_probe(pr, base):
    m = {}
    m["in_place"] = (P if pr["aligned"] >= 0.9 else F, f"letter i -> letter i in {pr['aligned']:.0%} of probes")
    m["k5"] = (P if pr["k5"] >= 0.9 else F, f"shared word encrypts identically in {pr['k5']:.0%} of message pairs")
    m["selfenc"] = (P if pr["selfenc"] >= 0.02 else F, f">=2 fixed points among clue letters in {pr['selfenc']:.0%}")
    for clue, key in HINT_PROBES.items():
        f, b = pr[key], base[key]
        hits = f * pr["n"]
        lr = (max(hits, 0.5) / pr["n"]) / b
        if hits >= 3 and lr >= 5:
            m[clue] = (E, f"as odd as K4 in {f:.1%} vs chance {_pc(b)} (x{min(lr, 9999):.0f}{'+' if lr > 9999 else ''})")
        elif hits == 0 and b * pr["n"] >= 5:
            m[clue] = (A, f"never as odd as K4 ({pr['n']} probes) vs chance {_pc(b)}")
        else:
            m[clue] = ("neutral", f"{f:.1%} vs chance {_pc(b)}")
    return m


# ================================================================== scorecard

def card(marks):
    """Summarise one family's marks -> (verdict, fact fails, firm fails, hint score, explained list)."""
    fact_f = [c.id for c in CLUES if c.level == "fact" and c.id != "cribs" and marks.get(c.id, (U,))[0] == F]
    firm_f = [c.id for c in CLUES if c.level == "firm" and marks.get(c.id, (U,))[0] == F]
    expl = [c.id for c in CLUES if c.level == "hint" and marks.get(c.id, (U,))[0] == E]
    cond = [c.id for c in CLUES if c.level == "hint" and marks.get(c.id, (U,))[0] == C]
    against = [c.id for c in CLUES if c.level == "hint" and marks.get(c.id, (U,))[0] == A]
    score = len(expl) + 0.4 * len(cond) - 0.5 * len(against)
    if fact_f:
        verdict = "REJECT"
    elif firm_f:
        verdict = "FLAG"
    else:
        verdict = "PASS"
    return {"verdict": verdict, "fact_fails": fact_f, "firm_fails": firm_f, "explains": expl, "cond": cond,
            "against": against, "score": round(score, 1)}


def prefilter(name, encrypt=None, marks=None, n=300, verbose=True):
    """Scorecard for a NEW idea: give an encryptor fn(pt, rng) -> ct (same rng seed must mean
    the same key) and/or hand marks {clue_id: (mark, reason)}. Prints and returns the card."""
    m = {}
    pr = None
    if encrypt is not None:
        pr = probe(encrypt, n=n)
        m.update(marks_from_probe(pr, baseline()))
    m.update(marks or {})
    cd = card(m)
    if verbose:
        print(f"[prefilter] {name}: {cd['verdict']}  (score {cd['score']})")
        for c in CLUES:
            if c.id in m:
                print(f"   {c.level:4} {c.short:32} {m[c.id][0]:9} {m[c.id][1]}")
        missing = [c.short for c in CLUES if c.id not in m and c.level != "hint"]
        if missing:
            print("   unmarked facts/firm clues (mark them!):", ", ".join(missing))
    return cd, m, pr


def evaluate_all(n=300):
    base = baseline()
    text = _text()
    rows = []
    for f in FAMILIES:
        m, pr = {}, None
        if f.encrypt is not None:
            pr = probe(f.encrypt, n=n, text=text)
            m.update(marks_from_probe(pr, base))
        m.update(f.marks)
        rows.append((f, m, pr, card(m)))
    return rows, base


SYM = {P: "✓", F: "✗", E: "★", A: "▼", C: "~", U: "?", "neutral": "·", NA: "-"}
STATUS_ORDER = {"open": 0, "untested": 1, "pending": 2, "disfavoured": 3, "dead-in-scope": 4, "dead": 5}


def combos(rows, top=6):
    """Pairs of still-live families whose union explains the most hints, without breaking facts/firm clues."""
    live = [(f, m, c) for f, m, _, c in rows
            if f.status in ("open", "untested", "pending", "disfavoured") and c["verdict"] != "REJECT"
            and f.id != "one_mistake"]
    out = []
    for i in range(len(live)):
        for j in range(i + 1, len(live)):
            a, b = live[i], live[j]
            ex = set(a[2]["explains"]) | set(b[2]["explains"])
            out.append((len(ex), a[0].name, b[0].name, sorted(ex)))
    out.sort(key=lambda x: -x[0])
    return out[:top]


def write_matrix(path=None, n=300):
    rows, base = evaluate_all(n)
    path = path or ROOT / "docs" / "CLUE_MATRIX.md"
    cols = [c for c in CLUES]
    L = ["# Clue matrix: every idea against every clue", "",
         "Generated by `python -m kryptos.clues` (do not edit by hand; edit the marks in `kryptos/clues.py`).", "",
         "**How to read it.** Each row is a cipher family; each column a clue from `docs/CLUES.md`.",
         "Levels: **fact** (break one → REJECT), **firm** statement (break one → FLAG, needs an argument), **hint** "
         "(only scores points). Marks: ✓ consistent · ✗ breaks it · ★ explains the hint · ▼ makes the hint *less* "
         "likely than chance · ~ only under an extra assumption · ? unknown · · neutral.",
         "Columns marked (p) are measured by probes: the family's encryptor is run on English text with random keys "
         f"({n} probes per family); measured hints compare how often it produces K4's oddity with a one-time pad.", ""]
    head = "| Family | Ideas | Clue test | Verdict | Score | " + " | ".join(
        f"{c.short}{' (p)' if c.probe else ''}" for c in cols) + " |"
    L += ["## The matrix", "", head, "|" + "---|" * (5 + len(cols))]
    rows_sorted = sorted(rows, key=lambda r: (STATUS_ORDER[r[0].status], {"PASS": 0, "FLAG": 1, "REJECT": 2}[r[3]["verdict"]],
                                              -r[3]["score"]))
    for f, m, pr, cd in rows_sorted:
        cells = [SYM.get(m.get(c.id, (U,))[0], "?") for c in cols]
        L.append(f"| {f.name} | {', '.join(f.ideas) or '-'} | {f.status} | {cd['verdict']} | {cd['score']} | "
                 + " | ".join(cells) + " |")
    L += ["", "Column groups, left to right: facts (" + ", ".join(c.short for c in cols if c.level == "fact")
          + "); firm (" + ", ".join(c.short for c in cols if c.level == "firm") + "); hints (the rest).", ""]
    # ranking
    L += ["## Where to search next (re-ranked open gaps)", "",
          "Live families only (open / untested / pending / disfavoured), passing every fact; ordered by firm-statement "
          "conflicts, then hint score (★ = 1, ~ = 0.4, ▼ = -0.5).", ""]
    live = [r for r in rows_sorted if r[0].status in ("open", "untested", "pending", "disfavoured")]
    live.sort(key=lambda r: ({"PASS": 0, "FLAG": 1, "REJECT": 2}[r[3]["verdict"]], -r[3]["score"]))
    for k, (f, m, pr, cd) in enumerate(live, 1):
        ex = "; ".join(CLUE[c].short for c in cd["explains"]) or "nothing yet"
        bad = ", ".join(CLUE[c].short for c in cd["firm_fails"] + cd["fact_fails"])
        L.append(f"{k}. **{f.name}** ({f.status}, {cd['verdict']}, score {cd['score']}): explains {ex}"
                 + (f"; conflicts: {bad}" if bad else "")
                 + (f"; against: {', '.join(CLUE[c].short for c in cd['against'])}" if cd["against"] else ""))
    L += ["", "## Hybrids worth building (two live families, most hints explained together)", ""]
    for nex, a, b, ex in combos(rows):
        L.append(f"* **{a}** + **{b}**: {nex} hints ({'; '.join(CLUE[c].short for c in ex)})")
    L += ["", "## Details per family", ""]
    for f, m, pr, cd in rows_sorted:
        L.append(f"### {f.name}")
        L.append(f"Ideas {', '.join(f.ideas) or '-'} · clue test: **{f.status}** · verdict **{cd['verdict']}** · score {cd['score']}")
        L.append("")
        for c in cols:
            if c.id in m and (m[c.id][1] or m[c.id][0] in (F, E, A)):
                L.append(f"* {c.level} · {c.short}: {SYM.get(m[c.id][0], '?')} {m[c.id][1]}")
        L.append("")
    L += ["## The clues", "", "| id | level | clue | detail |", "|---|---|---|---|"]
    for c in cols:
        L.append(f"| {c.id} | {c.level} | {c.short} | {c.text} |")
    L += ["", "Chance reference (one-time pad), probability of being at least as odd as K4: "
          + ", ".join(f"{k[4:]} {_pc(v)}" for k, v in base.items()), ""]
    path.write_text("\n".join(L) + "\n")
    return path, rows


if __name__ == "__main__":
    import sys
    n = 60 if "--quick" in sys.argv else 300
    p, rows = write_matrix(n=n)
    for f, m, pr, cd in rows:
        print(f"{cd['verdict']:6} {cd['score']:5}  {f.status:13} {f.name}")
    print("wrote", p)
