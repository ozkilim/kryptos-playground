# Kryptos K4

A workbench for attacking K4, the last unsolved part of the Kryptos sculpture at CIA headquarters.

K4 is a classic hard-to-find, easy-to-check problem. This repo splits it the same way:

- **Data**: the 97-letter ciphertext and the 24 known plaintext letters.
- **Internal check**: free and instant. Does a candidate put every known letter in the right place, and does the rest look like English? Run it millions of times.
- **External check**: Paradigm's official verifier. $1 per try, so only send candidates that pass the internal check.

Pure Python 3, no installs needed.

## Quick start

```bash
python -m kryptos show                       # K4 with the clues lined up
python -m kryptos check "SOME97LETTERGUESS..." # free internal check
python examples/brute_vigenere.py            # example attack loop
python tests/test_basics.py                  # sanity tests
```

## The data

`data/k4.json`

```
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
.....................EASTNORTHEAST.............................BERLINCLOCK.......................
```

| Clue | Letters (1-indexed) | Ciphertext | Released |
|---|---|---|---|
| EAST | 22-25 | FLRV | Aug 2020 |
| NORTHEAST | 26-34 | QQPRNGKSS | Jan 2020 |
| BERLIN | 64-69 | NYPVTT | Nov 2010 |
| CLOCK | 70-74 | MZFPK | Nov 2014 |

`data/k1.json` holds the solved K1, used to prove the Vigenere code works.

## The internal check

`kryptos/check.py`

- `crib_hits(pt)`: how many of the 24 known letters match.
- `passes_cribs(pt)`: all 24 match and length is 97.
- `english_score(pt)`: chi-squared vs English letter frequency. At 97 letters, English scores ~30-60, random letters ~250-1000.
- `index_of_coincidence(pt)`: ~0.066 for English, ~0.038 for random.

Write any attack as: generate candidate plaintext, run `passes_cribs`, keep survivors, rank by `english_score`.

## The external check

Paradigm runs the official verifier at https://www.paradigm.xyz/kryptos/k4. Every check costs **$1** (paid via Stripe). There's no public API for K4, so submission is by hand.

```bash
python -m kryptos submit "YOUR97LETTERS..." --method "double transposition, key X"
# refuses if it fails the internal check
# refuses if you've already paid to check that exact answer
# logs it to submissions.csv, prints the answer, opens the page

python -m kryptos result "YOUR97LETTERS..." wrong
python -m kryptos stats
```

## Ciphers included

`kryptos/ciphers.py`: Caesar, Vigenere and Beaufort (with the KRYPTOS keyed alphabet), keyed columnar transposition. Add your own; any function that returns a candidate plaintext plugs into the checks.

## Background

- K1 and K2: Vigenere with the KRYPTOS alphabet (keys PALIMPSEST, ABSCISSA).
- K3: transposition.
- K4: unknown. Sanborn says it uses a "masking" technique. The plaintext is known to Paradigm (who bought it in Nov 2025) but sealed.

## Ideas for next steps

- Add K2 and K3 to `data/` and solve them with this code.
- Add a quadgram English scorer (much sharper than single-letter frequency).
- Try stacked ciphers: transposition then Vigenere, and the reverse.
- Read the r/Kryptos and groups.io Kryptos archives so you don't redo old dead ends.
