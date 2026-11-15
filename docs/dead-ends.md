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

| 2026-11-15 | Autokey (key = ciphertext or plaintext L letters back), Vigenère/Beaufort/variant, AZ + KRYPTOS | primer length 1–60 | ciphertext-autokey best 3/11 tests; 0 survivors | `autokey-crib-consistency` |
| 2026-11-15 | Running key from Kryptos's own texts (K1–K3 plaintexts, carved ciphertext, whole left panel), forwards and backwards | every offset, ~36k keys × 6 variants | 6/24 (chance level for this many tries) | `running-key` |
| 2026-11-15 | Quagmire I/II/III: periodic key on an alphabet scrambled by an unknown keyword | 208,648 distinct dictionary-word alphabets, periods 1–13 (8.1M hypotheses) | 6/11 equalities; 0 survivors | `quagmire-keyword-alphabets` |

Every attack in this table has a test that plants a fake answer and confirms the attack finds it (`tests/test_attacks.py`, `tests/test_k4_tools.py`), so these are real negatives, not broken code.

Not yet covered, worth doing next: Quagmire with Beaufort arithmetic; Quagmire IV (two different keywords); running keys from outside texts (drop them in `data/texts/`); transposition stacked on autokey or Quagmire.

## Community knowledge to import

The Kryptos community has decades of eliminated ideas. Worth reading before a big run:

* elonka.com/kryptos (Elonka Dunin's Kryptos pages and FAQ)
* the Kryptos groups.io list and its archives
* r/Kryptos
