"""First-look statistics: what kind of cipher might this be?

  triage(ct)  -> dict of the classic tells, plus a plain-English guess.

Rules of thumb:
  * IoC ~0.066 and letter frequencies look English  -> transposition
    (letters were only moved, not changed).
  * IoC ~0.045-0.055                                -> periodic polyalphabetic
    (Vigenere family); the period shows up as a spike in periodic IoC.
  * IoC ~0.038 (flat, like random)                  -> long key, running key,
    multiple layers, or something stranger. K4 lives here.
"""

from collections import Counter

from .data import letters
from .score import chi_squared, ioc, ENGLISH_IOC, RANDOM_IOC


def periodic_ioc(ct, max_period=20):
    """Average IoC of the columns when the text is cut into `p` streams.
    A Vigenere with period p gives English-like IoC at p (and multiples)."""
    p = letters(ct)
    out = []
    for period in range(1, max_period + 1):
        cols = [p[i::period] for i in range(period)]
        vals = [ioc(c) for c in cols if len(c) > 1]
        out.append((period, sum(vals) / len(vals) if vals else 0.0))
    return out


def best_periods(ct, max_period=20, top=3):
    """Periods whose column IoC is most English-like, best first.
    Only periods leaving >= 6 letters per column count (shorter columns
    give meaninglessly high IoC)."""
    max_period = max(2, min(max_period, len(letters(ct)) // 6))
    scored = periodic_ioc(ct, max_period)[1:]  # skip period 1
    scored.sort(key=lambda x: (-round(x[1], 3), x[0]))
    return scored[:top]


def triage(ct):
    p = letters(ct)
    i = ioc(p)
    chi = chi_squared(p)
    missing = sorted(set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") - set(p))
    periods = best_periods(p)
    if i > 0.058 and chi < 120:
        guess = "transposition (English letter frequencies, just shuffled)"
    elif i > 0.058:
        guess = "monoalphabetic substitution (English-like IoC, wrong letters)"
    elif periods and periods[0][1] > 0.055:
        guess = f"periodic polyalphabetic, period ~{periods[0][0]} (Vigenere family)"
    elif i > 0.045:
        guess = "polyalphabetic with a long/unclear period"
    else:
        guess = "flat: long key, running key, layered cipher, or something unusual"
    return {
        "length": len(p),
        "ioc": round(i, 4),
        "ioc_vs_english": round((i - RANDOM_IOC) / (ENGLISH_IOC - RANDOM_IOC), 2),
        "chi2": round(chi, 1),
        "missing_letters": "".join(missing),
        "top_letters": "".join(c for c, _ in Counter(p).most_common(6)),
        "best_periods": [(per, round(v, 4)) for per, v in periods],
        "guess": guess,
    }
