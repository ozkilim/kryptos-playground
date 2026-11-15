"""Crib-consistency tools: test a hypothesis using only the 24 known letters,
without decrypting anything. Thousands of times faster than decrypting.

The idea: under a substitution hypothesis, each known (ciphertext,
plaintext) pair forces one key value at one position. If the hypothesis
says some of those key values must be equal (same slot of a repeating key,
or "the key here is the ciphertext 7 letters back"), check whether they are.

    req = required_keys(K4, CRIBS, alphabet, "vigenere")   # {pos: key value}
    periodic_agreement(req, 7)   -> (satisfied, constraints)
"""

from collections import defaultdict

from .ciphers.substitution import KEY_FROM


def required_keys(ct, cribs, alphabet, variant="vigenere", plain_alphabet=None):
    """{position: key shift} each crib forces. With plain_alphabet set, the
    plaintext letter is looked up there instead (Quagmire I/II style)."""
    cidx = {c: i for i, c in enumerate(alphabet)}
    pidx = {c: i for i, c in enumerate(plain_alphabet or alphabet)}
    f = KEY_FROM[variant]
    return {i: f(cidx[ct[i]], pidx[p]) for i, p in cribs.items()}


def periodic_agreement(req, period):
    """For a repeating key of this period: how many of the equalities it
    demands actually hold. Returns (satisfied, constraints). A true
    hypothesis gives satisfied == constraints."""
    groups = defaultdict(list)
    for pos, k in req.items():
        groups[pos % period].append(k)
    sat = con = 0
    for ks in groups.values():
        if len(ks) > 1:
            con += len(ks) - 1
            sat += max(ks.count(v) for v in set(ks)) - 1
    return sat, con
