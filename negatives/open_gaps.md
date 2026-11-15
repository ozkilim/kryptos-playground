# K4: open gaps (untested or undecidable, not negatives)

These came out of the community research notes (2026-11-15). None of them has been ruled out. Each one is open because the cribs can't decide it, because nobody has searched it, or because a search was cut off before it finished.

## Periodic / keyed-alphabet
- **Arbitrary-alphabet periodic substitution at undecidable periods (8, 11-13, 16, 18-20, 22-24, 26+).** The 24 crib letters put no constraint on these periods. zeyeteam reports periods 19 and 38 as undecidable. Source: https://github.com/zeyeteam-debug/kryptos-k4-eliminations
- **Repeating keys longer than 26.** The cribs don't constrain lengths of 27 or more, and keithadler lists these as open. Source: https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md
- **Quagmire III, Beaufort form, arbitrary alphabet, at L=13 and L=18.** The exact solver timed out after 30 minutes. Source: https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md
- **Quagmire I/II at lengths 13, 16, 19, 20, 23, 24, 26, and Quagmire IV at 8, 13, 16, 19, 20, 23, 24, 26.** The cribs give at most 1 constraint at these lengths, or random texts pass just as often, so the result tells us nothing. Annealing could not detect two free alphabets at L=8, Quagmire II at L≥20, or Quagmire I at L=26. Source: https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md
- **Two free alphabets at once, and stacked layers with long keys.** keithadler states both are open. 472 two-layer key-length pairs have too many unknowns to solve. Source: https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md
- **Some keyword-mixed-alphabet variants.** kryptosbot says these are "not yet fully closed". Source: https://www.kryptosbot.com/

## Gromark / key generators
- **Gromark with arbitrary plain and cipher alphabets.** 39 base-10 primers with 5 digits survive the cribs, but they were only checked by annealing. Other bases, other primer lengths, and expansion rules that don't use the first primer digit are not closed. keithadler's digit-key result covers only A-Z, KRYPTOS and dictionary alphabets. Source: https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109
- **Chaocipher, run dictionary by dictionary.** This was explicitly left untested. Source: https://github.com/Barneyjm/kryptos-k4
- **Subtractive feedback keys.** Only the short-primer bounded version was excluded. The subtractive feedback itself was not tested. Source: https://github.com/reggiechan74/kryptos-k4
- **Wichmann-Hill PRNG beyond seeds 0-50.** Only a tiny fraction of the roughly 30,000³ seed space was searched. Source: https://www.numberworld.blog/2017/03/kryptos-cipher-part-2.html

## Transposition (with or without substitution)
- **Myszkowski and disrupted columnar at width 10 or more, keyed routes, and irregular hand masks.** zeyeteam lists these as open. Source: https://github.com/zeyeteam-debug/kryptos-k4-eliminations
- **Columnar + periodic beyond the exhaustive range.** The search is exhaustive only to width 11. Widths 12-14 were pruned and bounded, and wider orders were tested only for keyword-derived orders. Source: https://github.com/Barneyjm/kryptos-k4
- **Keyed double columnar combined with substitution, route ciphers other than columns and rotations, and typo-tolerant transposition.** keithadler states these are open. Source: https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md
- **10×10 turning grille beyond the roughly 42% exactly searched (one variant only).** The annealer gave no clear answer. Source: https://github.com/zeyeteam-debug/kryptos-k4-eliminations

## Polygraphic / fractionation
- **Hill 6×6 and larger.** Searches covered only up to 5×5. Source: https://github.com/zeyeteam-debug/kryptos-k4-eliminations
- **Hill 4×4 at the two block alignments the cribs cannot test.** These are eliminated only under guessed cribs. Source: https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md
- **Fractionation on a 6×6 square.** keithadler lists it as open. A 6×6 Bifid alone was judged infeasible. Source: https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md

## Clock / physical / running key
- **The 1990 Weltzeituhr configuration: plate order, city names, and per-letter lookups from before 1997.** The 1990 plate order is unavailable, so the 1990 setup was only partly tested. Source: https://github.com/zeyeteam-debug/kryptos-k4-eliminations
- **Running keys from obscure texts.** Only obvious corpora were searched (K1-K3, Carter, Gutenberg-scale English and German, the KJV, US founding documents). An obscure source can't be ruled out. Source: https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md
- **Hand "masking", null or extra-character models, and "visual" or physical steps.** Scheidt says the masking technique "may not be known". Sanborn describes his own "visual systems", and no search has modelled them. Source: http://www.wired.com/news/culture/0,1284,66359,00.html

## Untested observations
- **The Stehle (2000) offset-letter-difference in DIAWINFBN.** Each of its first five letters minus the letter four places to its right gives 5 mod 26. Bean calls this unusual but did not test it. Source: https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109
- **A K4/K5 depth attack.** Sanborn says K5 shares coded words at the same positions as K4. The K5 ciphertext has not been released yet; Paradigm plans to release it. Source: https://www.paradigm.xyz/writing/kryptos

## Source-coverage gaps (research, not cipher space)
- **Reddit, groups.io and Yahoo archives.** None of them could be fetched (Reddit was blocked, groups.io returned HTTP 402), so posted forum scopes are missing. Source: https://groups.io/g/kryptos
- **The NSA 2007 summary and DOC_7.** Both returned 403, so their eliminations are not captured. Source: https://media.defense.gov/2021/Jul/12/2002760458/-1/-1/0/DOC_7.PDF
