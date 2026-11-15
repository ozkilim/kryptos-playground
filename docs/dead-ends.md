# Dead ends

Things that **can't** be K4, so nobody burns time (or dollars) on them again. Add a line whenever an attack comes back empty, and link its row in `experiments/ledger.csv`.

## Ruled out by statistics (solid)

| Hypothesis | Why it's dead | Check |
|---|---|---|
| Pure transposition of English | K4's IoC is 0.036; moving letters around keeps English's ~0.066 | `kryptos triage k4` |
| Monoalphabetic substitution | Same IoC argument: one-to-one letter swaps keep the IoC | `kryptos triage k4` |
| Vigenère / Beaufort / variant, any short period, plain or KRYPTOS alphabet | The crib keystream isn't periodic | `kryptos cribkeys` |

## Ruled out by our runs

| Date | Hypothesis | Range | Best | Ledger |
|---|---|---|---|---|
| 2026-11-15 | Dictionary word as Vigenère/Beaufort/variant key, AZ + KRYPTOS | data/keys.txt + /usr/share/dict/words: 1.4M candidates | 7/24 cribs, 0 full passes | `vigenere-family-wordlist` |
| 2026-11-15 | Columnar transposition + periodic Vigenère/Beaufort, either order | widths 2–8 (all ~46k column orders), periods 1–12, AZ + KRYPTOS | 17/24 at best (chance level); nothing near 24. Test proves it finds a planted solution | `columnar+vigenere-crib-consistency` |

## Community knowledge to import

The Kryptos community has decades of eliminated ideas. Worth reading before a big run:

* elonka.com/kryptos (Elonka Dunin's Kryptos pages and FAQ)
* the Kryptos groups.io list and its archives
* r/Kryptos
