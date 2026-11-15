"""Example attack: try every word in a list as a Vigenere key, on both a
normal and a KRYPTOS-scrambled alphabet, and rank by crib hits.

This exact attack has been tried to death and won't crack K4. It's here to
show the loop you'll reuse: generate candidate -> internal check -> rank.

  python examples/brute_vigenere.py                # built-in word list
  python examples/brute_vigenere.py words.txt      # your own list, one per line
"""

import sys
from pathlib import Path
from string import ascii_uppercase as AZ

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, crib_hits, english_score, passes_cribs  # noqa: E402
from kryptos.ciphers import vigenere_decrypt, beaufort_decrypt, keyed_alphabet  # noqa: E402

DEFAULT_KEYS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "BERLINCLOCK",
    "SANBORN", "SCHEIDT", "LANGLEY", "CIA", "EGYPT", "CARTER", "TUTANKHAMUN",
    "SHADOW", "LUCID", "MEMORY", "NORTHEAST", "WEBSTER", "IQLUSION", "LAYERTWO",
]


def main():
    if len(sys.argv) > 1:
        keys = [w.strip().upper() for w in open(sys.argv[1]) if w.strip().isalpha()]
    else:
        keys = DEFAULT_KEYS

    alphabets = {"plain": AZ, "kryptos": keyed_alphabet("KRYPTOS")}
    results = []
    for key in keys:
        for aname, alpha in alphabets.items():
            for cname, fn in (("vig", vigenere_decrypt), ("beau", beaufort_decrypt)):
                pt = fn(K4, key, alpha)
                results.append((crib_hits(pt), -english_score(pt), key, aname, cname, pt))

    results.sort(reverse=True)
    print(f"Tried {len(results)} combos. Top 10 by crib hits (24 = all):\n")
    for hits, neg_eng, key, aname, cname, pt in results[:10]:
        print(f"{hits:>2}/24  eng={-neg_eng:6.1f}  {cname:4} {aname:7} {key:12} {pt[:40]}...")
    winners = [r for r in results if passes_cribs(r[5])]
    print(f"\nFull passes: {len(winners)}")
    for r in winners:
        print("  ->", r[5])


if __name__ == "__main__":
    main()
