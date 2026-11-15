"""The internal check for K4. Free, instant, run it millions of times.

A K4 candidate must put the 24 known letters (the cribs EASTNORTHEAST and
BERLINCLOCK) in the right places. If it does, rank it by how English the
rest looks. Only then is it worth $1 on Paradigm's site.
"""

from .data import CRIBS, K4, letters
from .score import chi_squared, ioc, quadgram_score
from .ciphers.substitution import AZ, KRYPTOS_ALPHABET

normalize = letters  # back-compat name


def crib_hits(plaintext):
    """How many of the 24 known letters this candidate gets right."""
    p = letters(plaintext)
    return sum(1 for i, ch in CRIBS.items() if i < len(p) and p[i] == ch)


def passes_cribs(plaintext):
    """True only if all 24 known letters are in place and length is 97."""
    p = letters(plaintext)
    return len(p) == 97 and crib_hits(p) == len(CRIBS)


def english_score(plaintext):
    """Chi-squared vs English letter frequencies (lower = more English)."""
    return chi_squared(plaintext)


def crib_report(plaintext):
    """Human-readable check. Shows each known position and whether it matched."""
    p = letters(plaintext)
    lines = [
        f"length:          {len(p)} (need 97)",
        f"crib hits:       {crib_hits(p)}/{len(CRIBS)}",
        f"quadgram score:  {quadgram_score(p):.2f} (English ~ -4.7, random ~ -7)",
        f"chi-squared:     {chi_squared(p):.1f} (English 20-60, random 250+)",
        f"IoC:             {ioc(p):.4f} (English ~0.066, random 0.038)",
        f"PASSES:          {passes_cribs(p)}",
    ]
    marks = "".join(
        ("." if i not in CRIBS else ("+" if i < len(p) and p[i] == CRIBS[i] else "x"))
        for i in range(97)
    )
    lines += ["", p, marks, "(+ match, x wrong, . unknown)"]
    return "\n".join(lines)


def crib_keys(alphabet=AZ):
    """The key letter each crib position *would* need under each cipher.

    If K4 were a plain periodic cipher, these keystreams would repeat with
    the period. They don't, which is one of the oldest results about K4.
    Returns {cipher_name: string of 24 key letters, crib order}.
    """
    idx = {c: i for i, c in enumerate(alphabet)}
    out = {"vigenere": [], "beaufort": [], "variant_beaufort": []}
    for pos in sorted(CRIBS):
        c, p = idx[K4[pos]], idx[CRIBS[pos]]
        out["vigenere"].append(alphabet[(c - p) % 26])          # C = P + K
        out["beaufort"].append(alphabet[(c + p) % 26])          # C = K - P
        out["variant_beaufort"].append(alphabet[(p - c) % 26])  # C = P - K
    return {k: "".join(v) for k, v in out.items()}


def crib_key_table():
    rows = []
    positions = sorted(CRIBS)
    rows.append("pos   " + " ".join(f"{p + 1:>2}" for p in positions))
    rows.append("ct    " + " ".join(f"{K4[p]:>2}" for p in positions))
    rows.append("pt    " + " ".join(f"{CRIBS[p]:>2}" for p in positions))
    for aname, alpha in (("AZ", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)):
        for cname, ks in crib_keys(alpha).items():
            rows.append(f"{cname[:5]}/{aname[:2]} " + " ".join(f"{k:>2}" for k in ks))
    return "\n".join(rows)
