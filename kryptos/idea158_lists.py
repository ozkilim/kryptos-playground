"""Tools for idea 158: recited lists (counting words, compass points, hours, months, planets, letter names,
the World Clock's city ring) used as exact running keys.

Three parts:
  lists       every list is built here in code (the World Clock ring comes from data/weltzeituhr_1989.json);
              `streams()` returns [(name, text)]: each list written out without spaces, forwards and with its
              letters reversed. A list that comes round again (compass, hours, months) is repeated so that
              every start inside one round has 97 key letters after it.
  gate        on ANY tableau with distinct rows and columns, two clue letters that share plain and cipher
              letter must share the key letter, and two that share exactly one of them must not.
  join        for a keyword alphabet M the clue letters force the 24 key values; the key letters they spell
              are looked up in a hash of all list windows. One rule covers every form:

                  value(key letter) = sign * kreq + shift   (mod 26)
                  kreq = idx_B(C) - idx_A(P)  ("vig")   or   idx_B(C) + idx_A(P)  ("beau")

              sign -1 on "vig" is the variant Beaufort. The key letter is valued on A-Z, on KRYPTOS or on M
              itself; the shift (which row the key letter A points at) is free, all 26.
"""
import json
import unicodedata
from collections import Counter

from .ciphers.substitution import AZ, KRYPTOS_ALPHABET
from .data import DATA_DIR

POS = list(range(21, 34)) + list(range(63, 74))
REL = POS
SPAN = 97
IZ = {c: i for i, c in enumerate(AZ)}
IK = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
NPRE = 6          # letters of the first clue used as the fast pre-check


# ---------------------------------------------------------------- number words

_E1 = ("ZERO ONE TWO THREE FOUR FIVE SIX SEVEN EIGHT NINE TEN ELEVEN TWELVE THIRTEEN FOURTEEN FIFTEEN SIXTEEN "
       "SEVENTEEN EIGHTEEN NINETEEN").split()
_E10 = "- - TWENTY THIRTY FORTY FIFTY SIXTY SEVENTY EIGHTY NINETY".split()
_EO1 = ("ZEROTH FIRST SECOND THIRD FOURTH FIFTH SIXTH SEVENTH EIGHTH NINTH TENTH ELEVENTH TWELFTH THIRTEENTH "
        "FOURTEENTH FIFTEENTH SIXTEENTH SEVENTEENTH EIGHTEENTH NINETEENTH").split()
_EO10 = "- - TWENTIETH THIRTIETH FORTIETH FIFTIETH SIXTIETH SEVENTIETH EIGHTIETH NINETIETH".split()


def english(n, land=False):
    if n < 20:
        return _E1[n]
    if n < 100:
        return _E10[n // 10] + (_E1[n % 10] if n % 10 else "")
    rest = n % 100
    return _E1[n // 100] + "HUNDRED" + (("AND" if land else "") + english(rest) if rest else "")


def english_ordinal(n):
    if n < 20:
        return _EO1[n]
    if n < 100:
        return _EO10[n // 10] if n % 10 == 0 else _E10[n // 10] + _EO1[n % 10]
    rest = n % 100
    return _E1[n // 100] + ("HUNDRED" + english_ordinal(rest) if rest else "HUNDREDTH")


# German with u-umlaut as "}" and o-umlaut as "{", a-umlaut as "|", turned into UE/OE/AE or U/O/A later
_G1 = ("NULL EINS ZWEI DREI VIER F}NF SECHS SIEBEN ACHT NEUN ZEHN ELF ZW{LF DREIZEHN VIERZEHN F}NFZEHN SECHZEHN "
       "SIEBZEHN ACHTZEHN NEUNZEHN").split()
_G10 = "- - ZWANZIG DREISSIG VIERZIG F}NFZIG SECHZIG SIEBZIG ACHTZIG NEUNZIG".split()
_GO1 = "NULLTE ERSTE ZWEITE DRITTE VIERTE F}NFTE SECHSTE SIEBTE ACHTE NEUNTE ZEHNTE ELFTE ZW{LFTE".split()


def german(n):
    if n < 20:
        return _G1[n]
    if n < 100:
        u = n % 10
        return (("EIN" if u == 1 else _G1[u]) + "UND" if u else "") + _G10[n // 10]
    rest = n % 100
    return ("" if n < 200 else _G1[n // 100]) + "HUNDERT" + (german(rest) if rest else "")


def german_ordinal(n):
    if n < 13:
        return _GO1[n]
    return german(n) + ("TE" if n < 20 else "STE")


def umlauts(text):
    """The two ways of writing German without umlauts: FUENF and FUNF."""
    long = text.replace("}", "UE").replace("{", "OE").replace("|", "AE")
    short = text.replace("}", "U").replace("{", "O").replace("|", "A")
    return [long] if long == short else [long, short]


def roman(n, clock=False):
    if clock and n == 4:
        return "IIII"
    out = ""
    for v, s in ((100, "C"), (90, "XC"), (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")):
        while n >= v:
            out += s
            n -= v
    return out


# ---------------------------------------------------------------- compass

P32 = ("N NbE NNE NEbN NE NEbE ENE EbN E EbS ESE SEbE SE SEbS SSE SbE S SbW SSW SWbS SW SWbW WSW WbS W WbN WNW "
       "NWbW NW NWbN NNW NbW").split()
_LONG = {"N": "NORTH", "E": "EAST", "S": "SOUTH", "W": "WEST", "b": "BY"}
_SHORT = {"N": "N", "E": "E", "S": "S", "W": "W", "b": "B"}
_GLONG = {"N": "NORD", "E": "OST", "S": "S}D", "W": "WEST", "b": "ZU"}
_GSHORT = {"N": "N", "E": "O", "S": "S", "W": "W", "b": "Z"}


def compass(points=32, names=_LONG):
    return ["".join(names[ch] for ch in p) for p in P32[::32 // points]]


# ---------------------------------------------------------------- other lists

MONTHS = "JANUARY FEBRUARY MARCH APRIL MAY JUNE JULY AUGUST SEPTEMBER OCTOBER NOVEMBER DECEMBER".split()
MONATE = "JANUAR FEBRUAR M|RZ APRIL MAI JUNI JULI AUGUST SEPTEMBER OKTOBER NOVEMBER DEZEMBER".split()
DAYS = "MONDAY TUESDAY WEDNESDAY THURSDAY FRIDAY SATURDAY SUNDAY".split()
TAGE = "MONTAG DIENSTAG MITTWOCH DONNERSTAG FREITAG SAMSTAG SONNTAG".split()
PLANETS = "MERCURY VENUS EARTH MARS JUPITER SATURN URANUS NEPTUNE PLUTO".split()
PLANETEN = "MERKUR VENUS ERDE MARS JUPITER SATURN URANUS NEPTUN PLUTO".split()
CLASSICAL = "SATURN JUPITER MARS SUN VENUS MERCURY MOON".split()          # the old order, slowest first
ZODIAC = "ARIES TAURUS GEMINI CANCER LEO VIRGO LIBRA SCORPIO SAGITTARIUS CAPRICORN AQUARIUS PISCES".split()
TIERKREIS = ("WIDDER STIER ZWILLINGE KREBS L{WE JUNGFRAU WAAGE SKORPION SCH}TZE STEINBOCK WASSERMANN "
             "FISCHE").split()
NATO = ("ALFA BRAVO CHARLIE DELTA ECHO FOXTROT GOLF HOTEL INDIA JULIETT KILO LIMA MIKE NOVEMBER OSCAR PAPA "
        "QUEBEC ROMEO SIERRA TANGO UNIFORM VICTOR WHISKEY XRAY YANKEE ZULU").split()
ABLE = ("ABLE BAKER CHARLIE DOG EASY FOX GEORGE HOW ITEM JIG KING LOVE MIKE NAN OBOE PETER QUEEN ROGER SUGAR "
        "TARE UNCLE VICTOR WILLIAM XRAY YOKE ZEBRA").split()
GREEK = ("ALPHA BETA GAMMA DELTA EPSILON ZETA ETA THETA IOTA KAPPA LAMBDA MU NU XI OMICRON PI RHO SIGMA TAU "
         "UPSILON PHI CHI PSI OMEGA").split()


def clock_rings():
    """[(name, [words])]: the World Clock's city plates, facet by facet round the drum."""
    d = json.loads((DATA_DIR / "weltzeituhr_1989.json").read_text())
    facets = sorted(d["facets"], key=lambda f: f["order_on_drum"])
    fix = {"Ä": "|", "Ö": "{", "Ü": "}", "ß": "SS", "Á": "A", "É": "E", "Í": "I", "Ó": "O", "Ú": "U"}

    def clean(name):
        s = name.upper()
        for a, b in fix.items():
            s = s.replace(a, b).replace(a.lower(), b)
        s = unicodedata.normalize("NFKD", s)        # any other accent: keep the bare letter
        return "".join(ch for ch in s if ch in IZ or ch in "}{|")

    out = []
    for tag, pick in (
            ("best 1989 state, all plates", lambda f: f.get("cities_1989") or f.get("cities_post_1997")),
            ("best 1989 state, upper plates", lambda f: f.get("cities_1989_top") or f.get("cities_post_1997_top")),
            ("after 1997, all plates", lambda f: f.get("cities_post_1997")),
            ("after 1997, upper plates", lambda f: f.get("cities_post_1997_top")),
            ("best 1989 state, first city of each facet",
             lambda f: (f.get("cities_1989") or f.get("cities_post_1997") or [])[:1])):
        words = [w for w in (clean(c) for f in facets for c in (pick(f) or [])) if w]
        if words:
            out.append(("World Clock ring, " + tag, words))
    return out


def all_lists():
    """[(name, [words], comes round again)]. German words still carry the umlaut marks."""
    L = []

    def add(name, words, ring=True, back=True):
        words = list(words)
        L.append((name, words, ring))
        if back:
            L.append((name + ", said backwards", words[::-1], ring))

    for tag, f in (("English numbers", english), ("English numbers with AND", lambda n: english(n, True)),
                   ("English ordinals", english_ordinal), ("German numbers", german),
                   ("German ordinals", german_ordinal)):
        if "AND" not in tag:
            add("%s 0-120" % tag, [f(n) for n in range(0, 121)], ring=False)
            for a, b in ((0, 9), (1, 9), (1, 10), (1, 12), (1, 24), (0, 23), (1, 7), (1, 26), (1, 31), (1, 60),
                         (0, 59), (1, 97)):
                add("%s %d-%d round and round" % (tag, a, b), [f(n) for n in range(a, b + 1)])
            add("%s, even 2-240" % tag, [f(n) for n in range(2, 241, 2)], ring=False)
            add("%s, odd 1-239" % tag, [f(n) for n in range(1, 240, 2)], ring=False)
            add("%s, fives 5-600" % tag, [f(n) for n in range(5, 601, 5)], ring=False)
            add("%s, fives 5-60 round and round" % tag, [f(n) for n in range(5, 61, 5)])
            add("%s, tens 10-900" % tag, [f(n) for n in range(10, 901, 10)], ring=False)
        else:
            add("%s 90-200" % tag, [f(n) for n in range(90, 201)], ring=False)
    add("German numbers, HUNDERT as EINHUNDERT, 90-200",
        [german(n) if n < 100 else "EIN" + german(n) for n in range(90, 200)], ring=False)

    for n in (32, 16, 8, 4):
        add("compass %d points, English long" % n, compass(n, _LONG))
        add("compass %d points, English short" % n, compass(n, _SHORT))
        add("compass %d points, German long" % n, compass(n, _GLONG))
        add("compass %d points, German short" % n, compass(n, _GSHORT))

    for h in (12, 24):
        add("hours ONEOCLOCK-%s" % english(h), [english(n) + "OCLOCK" for n in range(1, h + 1)])
        add("hours EINUHR-%d" % h, [("EIN" if n == 1 else german(n)) + "UHR" for n in range(1, h + 1)])
        add("Roman numerals I-%s round and round" % roman(h), [roman(n) for n in range(1, h + 1)])
    add("hours NULLUHR-23", [("EIN" if n == 1 else german(n)) + "UHR" for n in range(0, 24)])
    add("clock-face Roman numerals with IIII", [roman(n, True) for n in range(1, 13)])
    add("hours TWELVEAM-ELEVENPM", [english(n or 12) + ap for ap in ("AM", "PM") for n in range(12)])
    add("hours MIDNIGHT ONE ... NOON ONE ...", [w for mid in ("MIDNIGHT", "NOON")
                                                 for w in [mid] + [english(n) for n in range(1, 12)]])
    for tail in ("HUNDRED", "HUNDREDHOURS"):
        add("military hours ZERO%s-TWENTYTHREE%s" % (tail, tail),
            [("ZERO" if n == 0 else ("ZERO" + english(n) if n < 10 else english(n))) + tail for n in range(24)])
        add("military hours OH-ONE-%s" % tail,
            [("ZERO" if n == 0 else ("OH" + english(n) if n < 10 else english(n))) + tail for n in range(24)])
    add("Roman numerals I-C", [roman(n) for n in range(1, 101)], ring=False)

    add("months", MONTHS)
    add("months, three letters", [m[:3] for m in MONTHS])
    add("Monate", MONATE)
    add("days of the week", DAYS)
    add("days, three letters", [m[:3] for m in DAYS])
    add("Wochentage", TAGE)
    add("Wochentage with SONNABEND", TAGE[:5] + ["SONNABEND", "SONNTAG"])
    add("planets Mercury-Pluto", PLANETS)
    add("planets Mercury-Neptune", PLANETS[:8])
    add("planets with SUN first", ["SUN"] + PLANETS)
    add("planets with SUN first, to Neptune", ["SUN"] + PLANETS[:8])
    add("Planeten Merkur-Pluto", PLANETEN)
    add("Planeten Merkur-Neptun", PLANETEN[:8])
    add("Planeten with SONNE first", ["SONNE"] + PLANETEN)
    add("seven classical planets", CLASSICAL)
    add("zodiac", ZODIAC)
    add("Tierkreis", TIERKREIS)
    add("NATO letter names", NATO)
    add("NATO letter names with ALPHA, JULIET", ["ALPHA"] + NATO[1:9] + ["JULIET"] + NATO[10:])
    add("NATO letter names in KRYPTOS alphabet order", [NATO[IZ[c]] for c in KRYPTOS_ALPHABET])
    add("Able Baker letter names", ABLE)
    add("Able Baker letter names in KRYPTOS alphabet order", [ABLE[IZ[c]] for c in KRYPTOS_ALPHABET])
    add("Greek letter names", GREEK)
    add("the alphabet A-Z", list(AZ))
    add("the KRYPTOS alphabet", list(KRYPTOS_ALPHABET))
    for name, words in clock_rings():
        add(name, words)
    return L


def streams(smoke=False):
    """[(name, text)]: every list as a key text, forwards and letter-reversed, no two the same."""
    seen, out = set(), []
    for name, words, ring in all_lists():
        for text in umlauts("".join(words)):
            tag = name + (" (umlauts dropped)" if "}" in "".join(words) + "{|" and text != umlauts("".join(words))[0]
                          else "")
            if ring:
                reps = -(-(len(text) + SPAN) // len(text))
                text = (text * reps)[:len(text) + SPAN - 1]
            if len(text) < SPAN:
                continue
            for t, tg in ((text, ""), (text[::-1], ", letters reversed")):
                if t not in seen:
                    seen.add(t)
                    out.append((tag + tg, t))
    return out[::7] if smoke else out


def n_windows(strs):
    return sum(len(t) - SPAN + 1 for _, t in strs)


# ---------------------------------------------------------------- the any-tableau gate

def gate_pairs(ct, cribs):
    """(eq, ne): pairs of clue indices whose key letters must be equal / must differ on any Latin square."""
    eq, ne = [], []
    for a in range(24):
        for c in range(a + 1, 24):
            sp = cribs[POS[a]] == cribs[POS[c]]
            sc = ct[POS[a]] == ct[POS[c]]
            if sp and sc:
                eq.append((a, c))
            elif sp or sc:
                ne.append((a, c))
    return eq, ne


def gated_windows(strs, ct, cribs):
    """[(stream index, start, 24 key letters)] for every window that passes the gate, and three counts:
    all windows, windows passing the equal-letter rules, windows passing everything."""
    eq, ne = gate_pairs(ct, cribs)
    out, n, neq = [], 0, 0
    for si, (_, t) in enumerate(strs):
        for s in range(len(t) - SPAN + 1):
            n += 1
            if any(t[s + POS[a]] != t[s + POS[c]] for a, c in eq):
                continue
            neq += 1
            if any(t[s + POS[a]] == t[s + POS[c]] for a, c in ne):
                continue
            out.append((si, s, "".join(t[s + i] for i in POS)))
    return out, (n, neq, len(out))


# ---------------------------------------------------------------- the hash join on keyword tableaux

def build_index(wins):
    """Hashes of the gated windows: the 24 letters (key valued on M) and the 23 differences of their values
    on A-Z and KRYPTOS with either sign (shift-free)."""
    full, sig = {}, {}
    for si, s, k in wins:
        full.setdefault(k, []).append((si, s))
        for kn, iv in (("AZ", IZ), ("KR", IK)):
            v = [iv[c] for c in k]
            for sign in (1, -1):
                key = bytes((sign * (x - v[0])) % 26 for x in v[1:])
                sig.setdefault(key, []).append((si, s, kn, sign, v[0]))
    return {"full": full, "pre": {k[:NPRE] for k in full}, "sig": sig, "sigpre": {k[:NPRE - 1] for k in sig}}


def layouts(m):
    im = {c: i for i, c in enumerate(m)}
    return (("M/M", im, im), ("M/AZ", im, IZ), ("AZ/M", IZ, im), ("M/KR", im, IK), ("KR/M", IK, im))


def join(indexes, cts, cribs, alphabets):
    """Every exact hit of every list window on every alphabet. indexes[j] belongs to cts[j].
    Returns [(ct index, alphabet name, M, layout, form, sign, key alphabet, shift, stream index, start)]."""
    pl = [cribs[i] for i in POS]
    cls = [[ct[i] for i in POS] for ct in cts]
    rng26 = range(26)
    hits = []
    for name, m in alphabets:
        m2 = m + m
        for lay, ia, ib in layouts(m):
            a = [ia[c] for c in pl]
            for j, cl in enumerate(cls):
                ix = indexes[j]
                pre, sigpre = ix["pre"], ix["sigpre"]
                b = [ib[c] for c in cl]
                for form in ("vig", "beau"):
                    if form == "vig":
                        k = [(y - x) % 26 for x, y in zip(a, b)]
                    else:
                        k = [(y + x) % 26 for x, y in zip(a, b)]
                    k0 = k[0]
                    if bytes([(k[1] - k0) % 26, (k[2] - k0) % 26, (k[3] - k0) % 26, (k[4] - k0) % 26,
                              (k[5] - k0) % 26]) in sigpre:
                        for si, s, kn, sign, v0 in ix["sig"].get(bytes((x - k0) % 26 for x in k[1:]), ()):
                            hits.append((j, name, m, lay, form, sign, kn, (v0 - sign * k0) % 26, si, s))
                    for sign in (1, -1):
                        q0, q1, q2, q3, q4, q5 = k[:6] if sign == 1 else [(-x) % 26 for x in k[:6]]
                        for c in rng26:
                            if m2[q0 + c] + m2[q1 + c] + m2[q2 + c] + m2[q3 + c] + m2[q4 + c] + m2[q5 + c] in pre:
                                w = "".join(m[(sign * x + c) % 26] for x in k)
                                for si, s in ix["full"].get(w, ()):
                                    hits.append((j, name, m, lay, form, sign, "M", c, si, s))
    return hits


SETTINGS_PER_ALPHABET = 5 * 2 * 2 * 3 * 26      # layouts, vig/beau, sign, key alphabet, shift


def _maps(m, lay, kn):
    im = {c: i for i, c in enumerate(m)}
    alph = {"M": m, "AZ": AZ, "KR": KRYPTOS_ALPHABET}
    pa, cb = lay.split("/")
    return alph[pa], alph[cb], {"M": im, "AZ": IZ, "KR": IK}[kn]


def decrypt(ct, key, m, lay, form, sign, kn, shift):
    """All letters of ct under one setting; key = the list text from the window's start."""
    pa, cb, iv = _maps(m, lay, kn)
    ib = {c: i for i, c in enumerate(cb)}
    out = []
    for c, w in zip(ct, key):
        kreq = sign * (iv[w] - shift)
        out.append(pa[(ib[c] - kreq) % 26 if form == "vig" else (kreq - ib[c]) % 26])
    return "".join(out)


def encrypt(pt, key, m, lay, form, sign, kn, shift):
    pa, cb, iv = _maps(m, lay, kn)
    ia = {c: i for i, c in enumerate(pa)}
    out = []
    for p, w in zip(pt, key):
        kreq = sign * (iv[w] - shift)
        out.append(cb[(ia[p] + kreq) % 26 if form == "vig" else (kreq - ia[p]) % 26])
    return "".join(out)


# ---------------------------------------------------------------- how close does any list come (A-Z / KRYPTOS)

def near_miss(strs, ct, cribs):
    """Over ALL windows (no gate), the four A-Z/KRYPTOS layouts, both forms, both signs, key valued on A-Z or
    KRYPTOS, any shift: the most clue letters right at once. Returns (best, histogram, example)."""
    pl, cl = [cribs[i] for i in POS], [ct[i] for i in POS]
    req = []
    for an, ia in (("AZ", IZ), ("KR", IK)):
        for bn, ib in (("AZ", IZ), ("KR", IK)):
            a, b = [ia[c] for c in pl], [ib[c] for c in cl]
            for sign in (1, -1):
                req.append(("%s/%s" % (an, bn), "vig", sign, [(sign * (y - x)) % 26 for x, y in zip(a, b)]))
                req.append(("%s/%s" % (an, bn), "beau", sign, [(sign * (y + x)) % 26 for x, y in zip(a, b)]))
    best, hist, ex = 0, Counter(), None
    for si, (_, t) in enumerate(strs):
        for kn, iv in (("AZ", IZ), ("KR", IK)):
            tv = [iv[c] for c in t]
            for s in range(len(t) - SPAN + 1):
                v = [tv[s + i] for i in POS]
                for lay, form, sign, r in req:
                    shift, n = Counter([(x - y) % 26 for x, y in zip(v, r)]).most_common(1)[0]
                    hist[n] += 1
                    if n > best:
                        best, ex = n, (lay, form, sign, kn, shift, si, s)
    return best, hist, ex
