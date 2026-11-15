"""K4's statistical fingerprint, and which cipher families can produce it.

No key search. For each cipher family: encrypt thousands of 97-letter English
messages (with EASTNORTHEAST / BERLINCLOCK in K4's positions) under random
keys, measure the same statistics as K4, and ask how often the family's
output looks as odd as K4 does. Families that almost never do get pushed
down the search queue; families that often do go up. (Approximate Bayesian
computation, used as a soft prior, because the oddities were found post hoc.)

Statistics (all chosen to correct for "we looked at every lag / width"):
  ioc        index of coincidence (K4 0.0361: flat)
  stehle     longest run of a constant letter difference at any lag 1-20 (K4: 5 at lag 4)
  doublets   excess concentration of doubled letters on one residue, any modulus 2-12 (K4: 5 of 6 mod 7)
  vpairs     most repeated (c[i], c[i+w]) pairs at any width 2-30 (K4: 11 at width 21, Bean)
  close      clue letters within 3 alphabet places of their cipher letter (K4: 12 of 24, Bean)
"""

import random
from collections import Counter

from .ciphers import AZ, KRYPTOS_ALPHABET, keyed_alphabet, vigenere_encrypt
from .data import CRIBS, K4, letters
from .solvers import stack as S

N = 97
STATS = ("ioc", "stehle", "doublets", "vpairs", "close")
# direction in which K4 is "odd" for each statistic
TAIL = {"ioc": "near", "stehle": "ge", "doublets": "ge", "vpairs": "ge", "close": "ge"}
IOC_TOL = 0.004


def stats(ct, cribs=CRIBS):
    v = [AZ.index(c) for c in ct]
    n = len(v)
    cnt = Counter(ct)
    ioc = sum(c * (c - 1) for c in cnt.values()) / (n * (n - 1))
    stehle = 0
    for lag in range(1, 21):
        d = [(v[i] - v[i + lag]) % 26 for i in range(n - lag)]
        run = 1
        for i in range(1, len(d)):
            run = run + 1 if d[i] == d[i - 1] else 1
            if run > stehle:
                stehle = run
    dbl = [i + 1 for i in range(n - 1) if ct[i] == ct[i + 1]]
    dscore = 0.0
    if len(dbl) >= 2:
        for m in range(2, 13):
            c = Counter(d % m for d in dbl).most_common(1)[0][1]
            dscore = max(dscore, c - len(dbl) / m)
    vpairs = 0
    for w in range(2, 31):
        vb = [(ct[i], ct[i + w]) for i in range(n - w)]
        vpairs = max(vpairs, len(vb) - len(set(vb)))
    close = sum(min((v[i] - AZ.index(p)) % 26, (AZ.index(p) - v[i]) % 26) <= 3 for i, p in cribs.items())
    return {"ioc": ioc, "stehle": stehle, "doublets": dscore, "vpairs": vpairs, "close": close}


K4_STATS = stats(K4)


# ------------------------------------------------------------ plaintexts

def english_windows():
    import pydoc_data.topics as t
    text = letters(" ".join(t.topics.values()))
    return text


def english_window(text, rng):
    s = rng.randrange(0, len(text) - N)
    return text[s:s + N]


def k4_like_plaintext(text, rng):
    """A random 97-letter English window with K4's two clues dropped into place."""
    s = rng.randrange(0, len(text) - N)
    pt = list(text[s:s + N])
    for i, ch in CRIBS.items():
        pt[i] = ch
    return "".join(pt)


# ------------------------------------------------------------ families

def _rand_key(rng, n):
    return [rng.randrange(26) for _ in range(n)]


def _gromark(pt, rng):
    """Gromark: 5-digit primer, chain addition mod 10, KRYPTOS cipher alphabet."""
    k = [rng.randrange(10) for _ in range(5)]
    while len(k) < N:
        k.append((k[-5] + k[-4]) % 10)
    ca = KRYPTOS_ALPHABET
    return "".join(ca[(AZ.index(p) + k[i]) % 26] for i, p in enumerate(pt))


def _with_map(pt, rng, m_fn, model_fn, place, alpha=AZ, variant="vigenere"):
    m = m_fn(rng)
    model, key, primer = model_fn(rng)
    return S.encrypt_stack(pt, m, alpha, variant, model, place, key=key, primer=primer)


IDENT = lambda rng: list(range(N))  # noqa: E731


def _columnar(rng, wmin=5, wmax=10):
    w = rng.randint(wmin, wmax)
    o = list(range(w))
    rng.shuffle(o)
    return S.columnar_map(tuple(o))


def _double(rng):
    return S.compose(_columnar(rng, 4, 9), _columnar(rng, 4, 9))


def _periodic(pmin, pmax):
    def f(rng):
        p = rng.randint(pmin, pmax)
        return ("periodic", p), _rand_key(rng, p), None
    return f


def _progressive(rng):
    p = rng.randint(4, 12)
    return ("progressive", p, rng.randint(1, 25)), _rand_key(rng, p), None


def _auto(kind):
    def f(rng):
        L = rng.randint(3, 12)
        return (kind, L), None, _rand_key(rng, L)
    return f


def _shift_key(values):
    def f(rng):
        return ("shift", "x", None), [rng.choice(values) for _ in range(N)], None
    return f


def _two_key(rng):
    a, b = _rand_key(rng, 7), _rand_key(rng, 11)
    return ("shift", "x", None), [(a[t % 7] + b[t % 11]) % 26 for t in range(N)], None


def families(text):
    """name -> function(pt, rng) -> ciphertext."""
    F = {
        "random letters (one-time pad)": lambda pt, rng: "".join(rng.choice(AZ) for _ in range(N)),
        "running key (English text), A-Z": lambda pt, rng: vigenere_encrypt(pt, english_window(text, rng), AZ),
        "running key (English text), KRYPTOS": lambda pt, rng: vigenere_encrypt(pt, english_window(text, rng),
                                                                                  KRYPTOS_ALPHABET),
        "periodic Vigenere 4-14, KRYPTOS (K1/K2 style)":
            lambda pt, rng: _with_map(pt, rng, IDENT, _periodic(4, 14), "after", KRYPTOS_ALPHABET),
        "periodic Vigenere 20-40, A-Z": lambda pt, rng: _with_map(pt, rng, IDENT, _periodic(20, 40), "after"),
        "periodic Beaufort 4-14, A-Z":
            lambda pt, rng: _with_map(pt, rng, IDENT, _periodic(4, 14), "after", AZ, "beaufort"),
        "Quagmire III (random keyword alphabet), period 4-14":
            lambda pt, rng: vigenere_encrypt(pt, "".join(rng.choice(AZ) for _ in range(rng.randint(4, 14))),
                                             keyed_alphabet("".join(rng.sample(AZ, rng.randint(5, 10))))),
        "progressive key": lambda pt, rng: _with_map(pt, rng, IDENT, _progressive, "after"),
        "ciphertext autokey": lambda pt, rng: _with_map(pt, rng, IDENT, _auto("ctauto"), "after"),
        "plaintext autokey": lambda pt, rng: _with_map(pt, rng, IDENT, _auto("ptauto"), "after"),
        "Gromark (chain-addition digits, KRYPTOS alphabet)": lambda pt, rng: _gromark(pt, rng),
        "random digit key (Gronsfeld, aperiodic)": lambda pt, rng: _with_map(pt, rng, IDENT,
                                                                             _shift_key(list(range(10))), "after"),
        "small shifts +-3 (aperiodic)": lambda pt, rng: _with_map(pt, rng, IDENT,
                                                                  _shift_key([0, 1, 2, 3, 23, 24, 25]), "after"),
        "two periodic keys summed (7 + 11)": lambda pt, rng: _with_map(pt, rng, IDENT, _two_key, "after"),
        "columnar then periodic key": lambda pt, rng: _with_map(pt, rng, _columnar, _periodic(4, 14), "after"),
        "periodic key then columnar": lambda pt, rng: _with_map(pt, rng, _columnar, _periodic(4, 14), "before"),
        "double columnar + periodic key": lambda pt, rng: _with_map(pt, rng, _double, _periodic(4, 14), "after"),
        "columnar then ciphertext autokey": lambda pt, rng: _with_map(pt, rng, _columnar, _auto("ctauto"), "after"),
        "columnar then small shifts +-3":
            lambda pt, rng: _with_map(pt, rng, _columnar, _shift_key([0, 1, 2, 3, 23, 24, 25]), "after"),
        "decimation mod 97 + periodic key":
            lambda pt, rng: _with_map(pt, rng, lambda r: S.decimation_map(r.randint(2, 95), r.randrange(97)),
                                      _periodic(4, 14), "after"),
    }
    for p in (4, 5, 6, 7, 8, 10, 12, 14, 21):  # where in "period space" do K4's oddities come from?
        F[f"periodic Vigenere, period {p} exactly, A-Z"] = (
            lambda pt, rng, p=p: _with_map(pt, rng, IDENT, _periodic(p, p), "after"))
    return F


# ------------------------------------------------------------ ranking

def simulate(name, fn, text, n, seed):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        pt = k4_like_plaintext(text, rng)
        out.append(stats(fn(pt, rng)))
    return name, out


def tail_probs(sims, target):
    """Fraction of a family's simulated ciphertexts at least as odd as target, per statistic."""
    n = len(sims)
    out = {}
    for s in STATS:
        if TAIL[s] == "near":
            hit = sum(abs(x[s] - target[s]) <= IOC_TOL for x in sims)
        else:
            hit = sum(x[s] >= target[s] for x in sims)
        out[s] = (hit + 1) / (n + 1)
    joint = sum(all((abs(x[s] - target[s]) <= IOC_TOL) if TAIL[s] == "near" else (x[s] >= target[s])
                    for s in STATS) for x in sims)
    out["joint"] = (joint + 1) / (n + 1)
    return out


def rank(table, target):
    """table: {family: [stats...]} -> sorted [(log10 score, family, tail probs)]; higher = more K4-like."""
    import math
    rows = []
    for fam, sims in table.items():
        tp = tail_probs(sims, target)
        score = sum(math.log10(tp[s]) for s in STATS)
        rows.append((score, fam, tp))
    rows.sort(key=lambda r: -r[0])
    return rows
