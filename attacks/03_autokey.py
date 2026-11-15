"""Hypothesis: K4 is an AUTOKEY cipher. After a short secret primer, the key
stops repeating and becomes the message itself. That would explain why the
crib keystream never repeats (a plain periodic key would).

Two flavours, both tested for primer lengths 1-60, Vigenere / Beaufort /
variant, plain and KRYPTOS alphabets:

  ciphertext-autokey: key[i] = ciphertext[i - L]
      Every crib letter is testable on its own, and if it fits we can decrypt
      everything after the primer without knowing the primer at all.
  plaintext-autokey:  key[i] = plaintext[i - L]
      Testable wherever two crib letters sit exactly L apart (e.g. L=42 links
      EASTNORTHEAST to BERLINCLOCK).

  python attacks/03_autokey.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET, autokey_decrypt  # noqa: E402
from kryptos.cribtools import required_keys  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402

ALPHABETS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")


def scan(ct, cribs, max_primer=60, ex=None):
    """Yield (mode, L, variant, alphabet, satisfied, testable) for every hypothesis."""
    for aname, alpha in ALPHABETS.items():
        idx = {c: i for i, c in enumerate(alpha)}
        for variant in VARIANTS:
            req = required_keys(ct, cribs, alpha, variant)
            for L in range(1, max_primer + 1):
                # ciphertext-autokey: the key at i must be the ciphertext letter L back
                tests = [(req[i], idx[ct[i - L]]) for i in cribs if i >= L]
                sat = sum(a == b for a, b in tests)
                if ex is not None:
                    ex.count(1)
                    if tests and sat == len(tests):
                        ex.add(autokey_decrypt(ct, "A" * L, "ciphertext", variant, alpha),
                               mode="ciphertext", primer_len=L, variant=variant, alphabet=aname)
                yield ("ciphertext", L, variant, aname, sat, len(tests))
                # plaintext-autokey: the key at i must be the plaintext letter L back
                tests = [(req[i], idx[cribs[i - L]]) for i in cribs if (i - L) in cribs]
                sat = sum(a == b for a, b in tests)
                if ex is not None:
                    ex.count(1)
                yield ("plaintext", L, variant, aname, sat, len(tests))


def main():
    best = {}
    with Experiment("autokey-crib-consistency", puzzle="k4",
                    notes="ct- and pt-autokey, primer 1-60, vig/beau/varbeau, AZ+KRYPTOS") as ex:
        survivors = []
        for mode, L, v, a, sat, n in scan(K4, CRIBS, ex=ex):
            if n >= 3 and sat == n:
                survivors.append((mode, L, v, a, sat, n))
            key = mode
            if n and (key not in best or sat / n > best[key][4] / max(best[key][5], 1)):
                best[key] = (mode, L, v, a, sat, n)
        ex.notes += f"; survivors with >=3 tests: {len(survivors)}"
    print("\nBest agreement per mode (a real hit needs every test to pass):")
    for mode, (m, L, v, a, sat, n) in best.items():
        print(f"  {mode:10} primer={L:<2} {v:16} {a:8} {sat}/{n}")
    print(f"Hypotheses passing every test (with at least 3 tests): {len(survivors)}")
    for s in survivors[:10]:
        print("  ", s)


if __name__ == "__main__":
    main()
