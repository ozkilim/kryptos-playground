# K4: open gaps (untested or undecidable, not negatives)

These came out of the community research notes (2026-11-15). None of them has been ruled out. Each one is open because the cribs can't decide it, because nobody has searched it, or because a search was cut off before it finished.

## Periodic / keyed-alphabet
- **Arbitrary-alphabet periodic substitution at undecidable periods (8, 11-13, 16, 18-20, 22-24, 26+).** The 24 crib letters put no constraint on these periods. zeyeteam reports periods 19 and 38 as undecidable. Source: https://github.com/zeyeteam-debug/kryptos-k4-eliminations
- **Repeating keys longer than 26.** The cribs don't constrain lengths of 27 or more, and keithadler lists these as open. Source: https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md
  - *Partly closed 2026-11-15 by this repo (attack 06):* at key lengths 27, 28 and 29, the only short lengths the clues leave open, Vigenère/Beaufort/variant on A–Z, KRYPTOS and 208,648 dictionary-keyword alphabets show no signal. The 24 clue letters force 24 key letters, the 3–5 free ones were brute-forced or hill-climbed, and K4 scores the same as shuffled K4s. Still open: lengths 53+ and arbitrary (non-keyword) alphabets at 27–29. Source: experiments/ledger.csv (long-period-27-29)
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
  - *Partly closed 2026-11-15 by this repo (attack 07):* double columnar with every column order at widths 2–7 on both layers (34.9M pairs), plus themed keyword orders up to width 15, with a periodic Vigenère or Beaufort key (A–Z or KRYPTOS alphabet, length 1–26) placed before, between or after the two layers. That is 11.1 billion hypotheses with 0 survivors (at least 6 clue equalities required). A planted test recovers a hidden stack exactly. Still open: widths 8+ with arbitrary orders, dictionary-keyword pairs, and scrambled (Quagmire) alphabets in the stack. Source: experiments/ledger.csv (double-columnar+periodic)
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

## Added from TRIED.md compilation (2026-11-15)
- **Hagelin M-209 / C-38 as the full machine.** Only restricted versions were tested; the 24 crib letters can't decide the full machine. Source: https://github.com/jcolinpatrick/kryptos
- **Chaocipher with fully free wheels.** Catalog searches went up to about 10 billion alphabet pairs, but free wheels were not closed. Source: https://github.com/barneyjm/kryptos-k4
- **10×10 turning grille with longer keys.** markmnl, akaalias and Colin Patrick ruled out periods 1-4 plus 415k keywords only. Source: https://github.com/markmnl/kryptos
- **Three-stage stacks.** Every tester lists three stages as open, beyond the two-stage long-key gap above. Source: https://github.com/keithadler/kryptos
- **Keys drawn from Sanborn's 1986 Egypt trip.** Sanborn named the trip in the Nov 2025 clues, but no key source from it has been found or tested. Source: https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/
- **Affine or mixed Vigenère/Beaufort per-position keys longer than 10.** Lengths 1-10 are ruled out; longer ones can't be decided from the cribs. Source: https://github.com/barneyjm/kryptos-k4
- **Clock lamp-sum and table-selection key streams.** mproffitt reports these were not run exhaustively. No direct URL in TRIED.md; cited via the prior-art register. Source: https://github.com/reggiechan74/kryptos-k4
- **Variable-rate encipherment (1 or 2 plaintext letters per cipher letter).** neuroretransmit has no completed result. No direct URL in TRIED.md; cited via the prior-art register. Source: https://github.com/reggiechan74/kryptos-k4
- **Word-level decoders and beam search on K4 itself.** They sometimes recover test messages but have never been run on K4 to a result. Source: https://github.com/markmnl/kryptos
- **SIGABA.** Engineering work only, with no test result. Source: https://github.com/reggiechan74/kryptos-k4
- **Which Weltzeituhr face points east-northeast.** The ray falls near a boundary between two panels, so this is unresolved. Source: https://github.com/markmnl/kryptos

## Closed or narrowed by campaign 1 (2026-11-15, this repo)
See `campaign/SUMMARY.md`. Each item has a planted-answer test.
- **Transposition + non-periodic key models**: progressive, autokey and digit/small-shift keys behind every columnar order to width 10–11, behind double columnar 2–6 × 2–6, behind decimation/routes/rotations, and behind Myszkowski (189,743 words). All dead. Still open: widths 11+ for progressive/autokey, wider double columnar.
- **Double columnar + periodic key**: now covered at width 8 × widths 2–6 (both ways round), 21.9B hypotheses, only 4 minimum-threshold survivors (noise).
- **Keyword alphabets at key lengths 14–26**: forced plaintext scored for English; K4 looks like shuffled controls. Still open: arbitrary (non-keyword) alphabets at these lengths.
- **Sanborn 2025 theme words**: dead as Quagmire I–IV alphabets/keys and as columnar orders with every key model.

## Pointers from campaign 1 statistics (where to look next)
- **Stehle lag-4 run (p=0.003) and mod-7 doublets (p=0.001)** survive a look-elsewhere-corrected shuffle test (post hoc caveat). Any proposed method should explain them.
- **Fingerprint ranking:** direct substitution with a short or structured key and no transposition looks most K4-like; transposition stacks and running keys look least like it. Top open targets: Gromark with arbitrary alphabets, small-shift keys under an unknown mixed alphabet, Quagmire IV with structured keys scored for English. Source: campaign/FINGERPRINTS.md

## Closed or narrowed by campaign 2 (2026-11-15, this repo)
See `campaign/SUMMARY_2.md`. Each result reports what a planted real answer would have scored.
- **Quagmire I/II with one hidden alphabet**: dead where our annealer recovers planted English: Quagmire I (A-Z or KRYPTOS fixed side) at lengths 13, 16, 19, 20; Quagmire II at 16 and 20. **Still open**: lengths 23, 24, 26 and several Quagmire II settings, where the annealer can't recover planted English (detection power too low).
- **Gromark with both alphabets hidden**: 1.6M primers, 454 survive the clues (39 five-digit, matching Bean). Best English completion -5.36 vs shuffled -5.51/-5.63; planted Gromark texts land -5.78..-4.30. Weakly disfavoured (about 50% detection power), not ruled out.
- **Fingerprint**: hidden-alphabet families rank in the bottom half; K4's statistics favour a plain or near-plain alphabet with a structured key.
- **Known blind spots of our tools**: hidden-alphabet keys of length 23+, stacked keys (PK3: right length found, not exact), Hill 3x3 (PK7 not recovered).

## Campaign 3 (2026-11-15, this repo; see campaign/SUMMARY_3.md)
- **Two stacked repeating keys (LAYER TWO), lengths <=26, A-Z/KRYPTOS**: disfavoured where the annealer has power (66/120 pairs; 47/66 planted beat K4's best). **Still open at the 54 long pairs** (e.g. 22+26, 24+25, 25+26), where the clues leave ~20+ free key letters. Best next step: more ciphertext (K5) or a stronger English model.
- **Three layers with a theme word**: dead where fully clue-determined (349 decrypts at noise level).
- **K1-K3 misspellings as alphabet swaps**: dead (single-layer key models exact; two-key determined configs at noise).
- **1989 World Clock keys** (names, initials, UTC offsets, every facet/direction): dead at chance. Data still incomplete for the west side and the lower plates of +7..+12.

## Campaign 4 (2026-11-15, this repo; see campaign/SUMMARY_4.md)
- **Visual letter transforms** (semaphore rotations/mirrors, Morse reverse/invert), alone or stacked with key layers: dead.
- **Compass-bearing keys across the carved panels** (48 directions, d 1-12, cipher/tableau/mirrored): dead at chance.
- **Stacked keys at long length pairs**: re-tested with three detectors (quadgram, word coverage, LLM judge); K4 looks like shuffled controls on all (best detector AUC planted 0.75 vs K4 0.55). Still not fully closed (power is modest).
- **Learned fingerprint (CNN)**: weakly favours a progressive/structured key on a plain alphabet (p=0.11 vs 0.046 shuffled); held-out accuracy too low to rely on.

## Campaign 5 (2026-11-15, this repo; see campaign/SUMMARY_5.md)
- **Self-masking** (key = own plaintext/ciphertext in scrambled order: reversal, decimation, columnar to w8, routes): dead.
- **Baudot/ITA2 Vernam** (periodic <=60, stacked XOR <=30, autokey <=60, dictionary words, K1-K3/World Clock running keys): dead.
- **Lorenz-style per-bit wheels**: every wheel length 2-61 with >=4 checks contradicted, every bit. Lengths too long to check (few repeats in 97 letters) remain open.
- **Paper strips** (carved rows, equal widths 5-48, any order/flip) x every key model: dead.
- **Egypt-era alphabet orders** (hieroglyph, Coptic, Greek, Phoenician/Hebrew, Arabic) x key models, Quagmire I-IV, two stacked keys: dead.
- **Key shape**: no period signature in letter differences (p=0.16, period 7 p=0.21 vs 20k shuffles); slowly turning dial keys ruled out (clues need a 12-13 step jump).

## Status changes from campaign 6 (2026-11-16, this repo)
See `campaign/SUMMARY_6.md`.
- **Two stacked keys at long lengths is now information-limited, not search-limited.** With a far stronger solver, completions of a shuffled K4 already score like real English, so the 24 clue letters plus an English score cannot decide this region. Closing it needs an extra constraint: the keys guessed (words, phrases, dates), more known plaintext, or a K4/K5 depth attack once K5 is released.
- **Gromark in bases 3-16 (both alphabets hidden): closed within power.** Best completion no better than shuffled K4s.
- **Shifting matrices / per-coordinate wheels on letter grids: closed.** No wheel set fits in any grid tried.

## Status changes from campaign 7 (2026-11-16, this repo)
See `campaign/SUMMARY_7.md`.
- **Key restarts at sentence breaks: closed** for repeating keys of length 1-26 on 18 alphabets (sentence starts before and between the clue blocks). Restarts *inside* BERLINCLOCK (e.g. carved row 4 at position 66) go to round 8 (idea 50).
- **Two systems, one per part: closed** for seven simple key families. Nothing fits either half alone.
- **One deliberate wrong clue letter: closed** for periodic, two-key and base-10 Gromark tests (drop-one survivors at chance).
- **New, measured constraint (not a negative):** the KRYPTOS-letter closeness survives a within-block test (p=0.00125, corrected ~0.02), but it is only compatible with K4's flat letter counts if at most ~20 letters are lightly treated *and* the other letters carry a long or stacked key. Any idea that explains the closeness must pass this (see `docs/CLUE_MATRIX.md`).

## Status changes from campaign 8 (2026-11-16, this repo)
See `campaign/SUMMARY_8.md`.
- **Two or three stacked keys made of real words: closed.** 265k-word vocabulary + 14.8M two-word phrases + K1-K3 phrases + clue dates, exact; also with one wrong clue letter. The long stacked-key gap remains only for keys that aren't words.
- **K1-K3 plaintexts as keys with hidden alphabets: closed** (four alphabet models, periods 2-60 and running).
- **Clock arithmetic (dials 12/24/60, two hands), carved-row restarts (including inside BERLINCLOCK): closed.**
- **Still open and needing new information:** non-word long keys (a K4/K5 depth attack once K5 is released), long hidden-alphabet keys, the World Clock's physical facts (face bearings, 1989 plates; on-site check in progress), and any precise "visual" step.

## Status changes from campaign 9 (2026-11-16, this repo)
See `campaign/SUMMARY_9.md`. All exact (linear algebra mod 26 on the clue letters), all with planted answers and shuffled controls.
- **Short formulas for the key: closed.** No combination of up to 3 of 186 ingredients (position powers, number sequences, grids of width 2-40, the carved layout, neighbouring letters, products) fits; 9.15M formulas, 0 fits.
- **Interrupted keys** (restart at a trigger letter or each word), **autokey stacked with a repeating key**, **two systems in turn** (row switching, interleaved streams, Slidefair) and **a drifting key word**: closed.
- **Transposition applied to the key instead of the text** (columnar to width 8, keyword orders 9-14, single/double rotations, routes, skips): closed for key lengths 2-26.
- **The sculpture read by columns, diagonals or skips as the key: closed** (best 10/24 key letters; chance).
- **Autokey / Condi / Ragbaby with a hidden alphabet: closed where decidable** (lag 1 with both sides hidden; lags 1-6 with one side known). **Still open:** both sides hidden at lag 3 or more (too few clue equations).
- **A sentence key on a keyword tableau: no signal**, with a caveat (planted keys rank top-4 of 92.5M, but in two of four runs the margin over the noise ceiling is thin). **Still open:** German or other-language key text; non-keyword alphabets.
- **Checked and found not significant:** EAST encrypting to FLRV then GKSS nine letters apart (p = 0.061 after paying for the choice of lag and view).

## Status changes from campaign 10 (2026-11-16, this repo)
See `campaign/SUMMARY_10.md`. Clues used: Scheidt's "simple, can be remembered... key word/s", "special characters must be accounted for", the 42-wide K3 worksheet, K3's closing question.
- **Three key words (Quagmire IV, dictionary alphabets on both sides): closed for key lengths 1-22** (445 billion alphabet pairs per length, exact hash join). **Still open:** lengths 23-26 (too few checks).
- **Any dictionary keyword tableau with a sliding, stacked (to 13), progressive, autokey, word-restart, growing or chain-addition key: closed** (6.67M key streams, 0 pass).
- **Chain addition in letters (taps to 10) and row word + column word grids (widths 2-48): closed.**
- **The "?" as a cell (98 = 7 x 14): closed** for the scrambled-key, grid-formula and drifting-key families.
- **Reversed (DIANA) table for text keys: closed** for sculpture readings; no signal for English sentence keys.
- **Carter's reply as a third clue: no tested model appears** (long repeating keys, every stacked pair to 26, sliding, hidden-alphabet autokey to lag 8).
- **Not run:** one-wrong-clue-letter versions of rounds 9-10; German sentence keys.
- **Best remaining lead needs new data:** a written-out 97-letter key shared with K5 (Sanborn: same coded words in the same positions). A two-message attack is the tool; it needs K5's ciphertext.


## Status changes from campaign 11 (2026-11-16, this repo)
See `campaign/SUMMARY_11.md`. This round attacked the assumptions inside rounds 9-10 (exact gap, mod 26, adding keys, fixed alphabets).
- **Each clue alone, and the gap between the clues off by 1-3 letters: closed** for the battery of key rules on 220k keyword tableaux (17.6M settings, 0 pass).
- **Rows of 21 (both clues start a row): closed** for a shared column key with a row offset, a column shift, or a different dictionary tableau per row (3.0e12 pairs, 0 hits).
- **Arithmetic mod 27-31: closed** for the same battery (11.5M key streams).
- **Multiplier word + adder word: closed** (exact for lengths up to 17 on A-Z/KRYPTOS; fixed multipliers on every keyword tableau).
- **Paper rotor with hidden wiring: closed in scope** (constant speeds, letter-fed turning, dictionary-word turning keys, every key to length 6). **Still open:** long non-word turning keys; two rotors.
- **Evolving alphabets (move to front, swaps, turns, Chaocipher): closed in scope** for keyword start alphabets. **Still open:** an arbitrary start alphabet.
- **Autokey with a keyed distance: closed** (596M settings).
- **Wheatstone clock-face cipher: closed by proof for every ring** (outer ring 27-38 cells, 26-letter inner ring).
- **Letters as 5 bits with bit keys; Morse as a switch: closed.**
- **Mirrored / flipped / slanted overlay of the tableau behind the cipher panel: closed** (best 9/24, chance).
- **Not run:** the transposition-mixed alphabets for ideas 68, 70, 71, 74; formula mining and the three-keyword join with gap slack.
