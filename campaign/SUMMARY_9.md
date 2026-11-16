# Campaign 9 summary (2026-11-16): exact tests for nine untested key rules

Rounds 1-8 closed named ciphers one at a time. Round 9 went after rules that had slipped between
them, using one new tool: inside the two clue blocks plaintext and ciphertext are both known, so
any rule that is *linear* in its unknowns (key letters, formula coefficients, even the 26 positions
of a hidden alphabet) becomes a small linear system mod 26. `kryptos/round9.py` solves these
exactly (mod 13 and mod 2, joined by the Chinese remainder theorem). No annealing, no English
scoring except idea 57, so results don't depend on search luck.

Every idea recovered planted answers and was run on shuffled K4s. **All nine are dead.**

| # | Idea (clue it came from) | Result |
|---|---|---|
| 54 | **Formula mining**: every combination of up to 3 ingredients (4 on a smaller library) from 186: position powers, primes, Fibonacci, digits of pi and e, column/row/row x column for every grid width 2-40, the carved 4/31/31/31 layout, neighbouring plaintext and ciphertext letters, six products. Plaintext multiplier free, so Vigenère, Beaufort and affine tableaux are all covered | **Dead.** 9,152,328 formulas, **0 fit** with 8 or more checks (2 shuffled K4s: 0). Planted 3-ingredient formulas found 3/3 |
| 55 | **Autokey, Condi and Ragbaby with a hidden alphabet** (Scheidt's "masking": the message keys itself) | **Dead where decidable.** 330 models: 271 contradicted, **0 consistent with 3 or more checks** (20 shuffled K4s: 0 each). Decided: lag 1 with the alphabet hidden on both sides; lags 1-6 with one side on A-Z or KRYPTOS; Ragbaby in all five alphabet modes. **Undecidable** (59 models): both sides hidden at lag 3 or more. Planted lag-1 autokeys found 6/6 |
| 56 | **Interrupted key**: the key word restarts at or after a trigger letter, or at each word (a classical hand cipher that hides the period) | **Dead.** 247,104 rules (key length 1-26, every trigger letter, A-Z/KRYPTOS + 110 theme keyword alphabets): **0 with 5 or more checks** (10 shuffled K4s: 0). Planted found 5/5 with 16-18 checks |
| 57 | **A sentence as the key, on a keyword tableau** (K1/K2's own system with a new keyword and a whole-sentence key). The 13 + 11 key letters the clues force must read as English | **No signal.** 220,318 keyword alphabets x Quagmire I-IV x 3 ciphers x 28 key letterings = 92.5M key fragments. K4's best **-4.90**, shuffled K4s **-4.88, -4.93, -4.98**. Top fragments are not words (`SWOULTISDTERV`, `OCOLLAPPINDNO`). Planted sentence keys: the true alphabet ranked 1st to 4th of 92.5M every time (best score in those runs -4.30 to -4.83). **Caveat:** the margin over the noise ceiling (about -4.88) is thin in two of the four, so a dull stretch of key text could hide. English keys only |
| 58 | **The sculpture read another way as the key** ("visual"; K3 reads its grid in a new direction): columns, back-and-forth, diagonals, every d-th letter | **Dead.** 269,710 streams (12.4M letters) from both panels, K1-K3 plaintext grids and the Morse text, x 624 cipher views. Best **10 of 24** key letters in place (5 shuffled K4s: 10-11; 24 needed). Planted column-and-skip keys found 24/24 |
| 59 | **Autokey stacked with a repeating key word** ("two separate systems", LAYER TWO, text left in place) | **Dead.** 405,600 settings (ciphertext lags 1-60, plaintext lags 1-9, any multiplier, period 1-26): **0 with 6 or more checks** (10 shuffled K4s: 0). Planted 4/4 with 14-19 checks |
| 60 | **Two systems in turn**: (A) 2-4 fixed tableau rows switched by anything at all; (B) letters 1,3,5... through one system and 2,4,6... through another (also 3 and 4 streams); (C) Slidefair pairs | **Dead.** (A) the best 2/3/4 rows cover only **9/12/14** of 24 clue letters (shuffled max 9/12/15; planted 24). (B) no setting is consistent (shuffled: none; planted 13-20 checks). (C) no pair identity holds |
| 61 | **Scramble the key, not the text**: K2's key word written out 97 long and put through K3's kind of transposition; the message never moves, so BERLINCLOCK stays in place as Sanborn says | **Dead.** 73,010,208 settings: every columnar order to width 8, dictionary keyword orders at widths 9-14, single and double rotations at widths 2-48, routes, skips, grid-linear slots; key length 2-26. **0 with 6 or more checks** (5 shuffled K4s: 0). Planted double-rotation and columnar scrambles found 4/4 with 17-19 checks |
| 62 | **A drifting key word** (each key letter steps on by its own amount every cycle), suggested by a new observation: EAST encrypts to `FLRV` and, 9 letters later, to `GKSS` | **Dead.** No fit at any width 2-40 (200 shuffled K4s: 0; planted 5/5; decidable to width 9). **The observation is not significant** once the choice of lag and cipher view is paid for: p = 0.061 against 5,000 shuffled K4s |

## Pre-filter notes

Ideas 57, 58, 60, 61 and 62 PASS the clue pre-filter. Ideas 55, 56 and 59 (and the neighbour-letter
terms in 54) are FLAGGED: their key follows the message, so a word shared with K5 would not encrypt
the same way (1-15% in probes). They were built anyway because Sanborn's K5 remark may be about the
plaintext only, and each is an exact test that runs in seconds. That clue now counts against every
"the message keys itself" idea.

Rejected at the pre-filter, not built:

* **Per-letter counters** (each plaintext letter cycles through its own little list of cipher letters, a textbook way
  to flatten English). N and O both encrypt to Q, and S and T both to S and to R, so the receiver could not decode.
* **Strip ciphers (M-94, M-138)** and **Porta**: a letter can never encrypt to itself; K4 has S to S and K to K.

## What the clue letters look like through this round's tools

* **Under Beaufort on A-Z the key sits on K.** `C + P` equals 10 (K) at five clue positions, four of them within six
  letters (`T H E A S T` gives K U K K K L), and lies within one of K at nine of 24. This is the same fact as Bean's
  "clue letters sit near their cipher letters" seen from the other side (E, S and T lie next to the two letters a
  K-reflection leaves fixed), but it adds A to L and A to K, which the "barely moves" picture does not explain.
  No model was built on it: two, three or four fixed rows cover no more clue letters than chance (idea 60).
* **Same plaintext letter, nearby cipher letter:** A gives K and L; S gives R and S; E gives F and G; R gives P twice;
  T gives R, S and V; C gives M and P; L gives V and Z; N gives Q and T. The exceptions are E to Y (position 65) and O
  to F (position 72), seven letters apart. Read as "hidden alphabet plus a small number", O needs numbers up to 11 and
  E up to 8, so base 10 does not fit without one exception. Gromark with hidden alphabets was already tested in rounds
  2, 6 and 7.

## What nine rounds now say

* **No method for K4 has been found**: 61 of our own ideas, 327 logged negatives.
* The clue letters now rule out, exactly, every *short rule* we can write for a key that depends on position,
  on a grid, on neighbouring letters, on a scrambled key word, or on a restart rule. What remains is not a rule we
  failed to guess but a key with about as many free letters as the clues can pin down.
* **Still open, and why:**
  * long keys that are not words, and hidden-alphabet keys of 23 letters or more: the clues plus "reads like English"
    cannot decide them (round 6). They need K5 or more plaintext.
  * autokey with the alphabet hidden on both sides at lag 3 or more: too few clue equations.
  * a sentence key in German or another language, or a sentence key on an alphabet that is not a keyword alphabet.
  * the World Clock's physical facts, and any precise "visual" step that changes letters rather than their order.
