"""Crack Vigenere / Beaufort / variant Beaufort with an unknown key.

For each plausible period: pick each key letter by chi-squared on its
column, then polish the whole key by hill-climbing on quadgram score.
Tried on both the plain A-Z alphabet and the KRYPTOS tableau.

    crack_periodic(load("k2")["ciphertext"])[0]   # finds ABSCISSA
"""

from ..ciphers.substitution import (
    AZ, KRYPTOS_ALPHABET, vigenere_decrypt, beaufort_decrypt, variant_beaufort_decrypt,
)
from ..analysis import periodic_ioc
from ..data import letters
from ..score import chi_squared, quadgram_score
from . import Candidate

VARIANTS = {
    "vigenere": vigenere_decrypt,
    "beaufort": beaufort_decrypt,
    "variant_beaufort": variant_beaufort_decrypt,
}
ALPHABETS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}


def _initial_key(ct, period, fn, alphabet):
    key = []
    for col in range(period):
        stream = ct[col::period]
        best = min(alphabet, key=lambda k: chi_squared(fn(stream, k, alphabet)))
        key.append(best)
    return key


def _polish(ct, key, fn, alphabet, rounds=3):
    """Hill-climb the key on quadgram score, one key letter at a time."""
    best = quadgram_score(fn(ct, "".join(key), alphabet))
    for _ in range(rounds):
        improved = False
        for i in range(len(key)):
            for k in alphabet:
                if k == key[i]:
                    continue
                trial = key[:i] + [k] + key[i + 1:]
                s = quadgram_score(fn(ct, "".join(trial), alphabet))
                if s > best:
                    best, key, improved = s, trial, True
        if not improved:
            break
    return best, "".join(key)


def _minimal(key):
    """ABSCISSAABSCISSA -> ABSCISSA."""
    for p in range(1, len(key) + 1):
        if len(key) % p == 0 and key == key[:p] * (len(key) // p):
            return key[:p]
    return key


def crack_periodic(ct, max_period=16, n_periods=4, variants=VARIANTS, alphabets=ALPHABETS):
    raw = letters(ct)
    # Most promising periods by column IoC (plus a few short ones always).
    # Needs roughly 15+ letters per column; for short texts like K1 (63
    # letters, period 10) use crack_wordlist instead.
    ranked = sorted(periodic_ioc(raw, max_period)[1:], key=lambda x: -x[1])
    periods = sorted({p for p, _ in ranked[:n_periods]} | {1, 2, 3})
    out = []
    for aname, alpha in alphabets.items():
        for vname, fn in variants.items():
            for period in periods:
                key = _initial_key(raw, period, fn, alpha)
                score, key = _polish(raw, key, fn, alpha)
                key = _minimal(key)
                out.append(Candidate(score, fn(raw, key, alpha), vname,
                                     {"key": key, "alphabet": aname, "period": len(key)}))
    out.sort(key=lambda c: -c.score)
    return out


def default_wordlist():
    """Keys to try: data/keys.txt (Kryptos-themed) + the system dictionary."""
    from ..data import DATA_DIR, WORDS
    words = []
    for path in (DATA_DIR / "keys.txt", WORDS):
        try:
            with open(path) as f:
                words += [w.strip().upper() for w in f if w.strip().isalpha() and not w.startswith("#")]
        except OSError:
            pass
    return list(dict.fromkeys(words))  # dedupe, keep order


def crack_wordlist(ct, words=None, min_len=3, max_len=14, variants=VARIANTS, alphabets=ALPHABETS, top=10):
    """Try every dictionary word as the key. This is how K1 falls: too short
    for statistics, but PALIMPSEST is in the dictionary."""
    raw = letters(ct)
    words = default_wordlist() if words is None else words
    words = [w for w in words if min_len <= len(w) <= max_len]
    out = []
    for aname, alpha in alphabets.items():
        for vname, fn in variants.items():
            for w in words:
                pt = fn(raw, w, alpha)
                out.append((quadgram_score(pt), pt, vname, w, aname))
            out.sort(key=lambda r: -r[0])
            del out[top:]
    return [Candidate(s, pt, v, {"key": w, "alphabet": a, "period": len(w)}) for s, pt, v, w, a in out]
