"""Hypothesis: K4's key is a long piece of TEXT (a running key), read from
some starting point. A running key never repeats, which fits K4's flat,
random-looking statistics.

Sources tried:
  * the K1, K2, K3 plaintexts (separately and joined, K2 both as carved and corrected)
  * the sculpture's own ciphertext (K1-K3 as carved, and the whole left panel)
  * every .txt you drop in data/texts/
Each source is tried forwards and backwards, from every starting offset,
with Vigenere / Beaufort / variant on plain and KRYPTOS alphabets.

  python attacks/04_running_key.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, load, letters  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET, PLAIN_FROM  # noqa: E402
from kryptos.cribtools import required_keys  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402

ALPHABETS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")


def sources():
    k1, k2, k3 = load("k1"), load("k2"), load("k3")
    pts = {
        "K1 plaintext": k1["plaintext"],
        "K2 plaintext (carved)": k2["plaintext"],
        "K2 plaintext (corrected)": k2["plaintext_corrected"],
        "K3 plaintext": k3["plaintext"],
        "K1+K2+K3 plaintext": k1["plaintext"] + k2["plaintext_corrected"] + k3["plaintext"],
        "K1+K2+K3 ciphertext": k1["ciphertext"] + k2["ciphertext"] + k3["ciphertext"],
        "whole left panel": k1["ciphertext"] + k2["ciphertext"] + k3["ciphertext"] + K4,
    }
    for p in sorted((DATA_DIR / "texts").glob("*.txt")):
        pts[p.name] = p.read_text(errors="ignore")
    return {name: letters(t) for name, t in pts.items()}


def scan(ct, cribs, texts, ex=None):
    """Returns best (satisfied, name, offset, direction, variant, alphabet)."""
    n = len(ct)
    best = (0,)
    for aname, alpha in ALPHABETS.items():
        idx = {c: i for i, c in enumerate(alpha)}
        for variant in VARIANTS:
            req = required_keys(ct, cribs, alpha, variant)
            dec = PLAIN_FROM[variant]
            for name, text in texts.items():
                for direction, t in (("forward", text), ("reversed", text[::-1])):
                    tv = [idx[ch] for ch in t]
                    for off in range(0, len(tv) - n + 1):
                        sat = sum(req[i] == tv[off + i] for i in req)
                        if sat > best[0]:
                            best = (sat, name, off, direction, variant, aname)
                        if ex is not None:
                            ex.count(1)
                            if sat >= 6:  # chance level is ~1 of 24
                                pt = "".join(alpha[dec(idx[ct[i]], tv[off + i])] for i in range(n))
                                ex.add(pt, source=name, offset=off, direction=direction,
                                       variant=variant, alphabet=aname)
    return best


def main():
    texts = sources()
    total = sum(len(t) for t in texts.values())
    with Experiment("running-key", puzzle="k4",
                    notes=f"{len(texts)} sources ({total} letters) fwd+rev, every offset, "
                          f"vig/beau/varbeau, AZ+KRYPTOS") as ex:
        best = scan(K4, CRIBS, texts, ex=ex)
        ex.notes += f"; best {best[0]}/24"
    print(f"\nBest running key: {best[0]}/24 clue letters  (chance level ~1-3, a real hit = 24)")
    print(f"  source={best[1]!r} offset={best[2]} {best[3]} {best[4]} {best[5]}")


if __name__ == "__main__":
    main()
