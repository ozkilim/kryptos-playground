"""Automatic attacks that need no key. Each returns ranked Candidate tuples.

These are the general tools that crack K1-K3 *blind* (without being told
the key), which is how we know the toolkit can be trusted on K4 and the
PK puzzles.
"""

from collections import namedtuple

Candidate = namedtuple("Candidate", "score plaintext method params")

from .periodic import crack_periodic  # noqa: E402,F401
from .transposition import crack_rotation, crack_columnar, crack_railfence  # noqa: E402,F401


def crack_all(ct, top=5):
    """Run every automatic solver and return the best candidates overall."""
    results = []
    results += crack_periodic(ct)
    results += crack_rotation(ct)
    results += crack_columnar(ct)
    results += crack_railfence(ct)
    results.sort(key=lambda c: -c.score)
    return results[:top]
