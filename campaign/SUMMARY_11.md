# Campaign 11 summary (2026-11-16): systems the earlier tests could not see

Rounds 9 and 10 closed a large family: fixed alphabets slid against each other by some key rule, with
arithmetic mod 26 and both clues tied together across the 42 letters between them. Round 11 went after the
assumptions inside that family rather than more key rules:

* **the gap between the clues is exact** (Sanborn dropped a letter carving K2);
* **the arithmetic is mod 26** (Scheidt: special characters must be accounted for; the tableau rows are 30-31 wide);
* **the key only adds** (decimated alphabets multiply);
* **the alphabets are fixed** (a rotor's wiring turns; a strip can be rearranged after each letter);
* **an autokey looks a fixed distance back**;

plus four clue-led devices: rows of 21, Wheatstone's clock-face cipher, "DIGETAL INTERPRETATU" as bits, and the
tableau seen through the pierced copper.

Every idea recovered planted answers and was run on shuffled K4s. **All ten are dead. K4 is not solved.**

| # | Idea (clue it came from) | Result |
|---|---|---|
| 68 | **Each clue alone, and the gap off by 1-3 letters.** The battery of key rules (repeating, sliding, progressive, autokey, two stacked keys, chain addition) on block 1 only, block 2 only, and both blocks with the second moved -3..+3 places. 220,318 keyword alphabets x 5 layouts x Vigenere/Beaufort | **Dead.** 17.6M settings, 0 pass with 7+ checks (3 shuffled K4s: 0). Planted 3/3 (a sliding-key message with one cipher letter deleted between the clues; a key that changes word half way) |
| 69 | **Rows of 21 ("ID BY ROWS").** Both clues start a row at width 21, so they share 11 columns. If the column gives the key and the row gives an offset, a column shift, or a different tableau or cipher form, the 10 column differences must match. One tableau with the row key moved -5..5 columns; every pair of (alphabet, layout, form) by hash join | **Dead.** 24M one-tableau tests and 3.0e12 pairs: 0 hits (5 shuffled K4s: 0). Planted 3/3 |
| 70 | **Wrong modulus.** Key values mod 27, 28, 29, 30, 31 on every keyword alphabet, same battery; multiplying key mod 29 and 31 | **Dead.** 11.5M key streams, 0 pass (3 shuffled: 0). Planted mod-27 and mod-31 sliding keys 3/3 |
| 71 | **Multiplier word + adder word**, C = A[i mod p] x P + B[i mod q]. Linear in A and B, so exact for every p, q = 1..17 on A-Z/KRYPTOS; on every keyword alphabet, each fixed multiplier other than +-1 against the battery | **Dead.** 1,156 exact systems and 11.0M key streams, 0 fit (3 shuffled: 0). Planted 5/5 |
| 72 | **Paper rotor.** C = R[P + s] - s with the wiring R hidden. No wiring is guessed: each clue letter gives one wire, and a real wiring never crosses. Constant speeds (676 pairs), turning fed by the previous letter or the running cipher sum, 264k words as the turning key (plain, sliding, +1 per letter; two numberings), every key of length 1-6 | **Dead in scope.** 110.8M settings, 0 give a real wiring (3 shuffled: 0). Planted 3/3. About 1 true setting in 20 has too few wire collisions to judge |
| 73 | **Evolving alphabet.** After each letter the alphabet is changed (move to front or end, swap with a neighbour or an end, turn the strip, reverse up to the letter, Chaocipher's left step; real two-wheel Chaocipher). With a known start the message decrypts from letter 0, so we just count clue letters. 220,320 start alphabets | **Dead in scope.** 20.4M settings, best 9/24 (3 shuffled: 8, 8, 9). Planted 3/3 at 24/24. Start alphabets outside the dictionary are not covered |
| 74 | **Autokey with a keyed distance.** A repeating pattern says how far back to look (cipher feed 1-20 back, plain feed 1-8 back, periods 1-13), on every keyword tableau | **Dead.** 596M settings, 0 fits (3 shuffled: 0). Planted 4/4 |
| 75 | **Wheatstone's clock-face cipher, any rings.** See the proof below; cross-checked over 220,319 dictionary outer rings, reversed, 27-31 cells, every blank position, with or without spaces | **Dead, by proof.** 114.6M dictionary settings, 0 consistent (3 shuffled: 0). Planted 3/3 |
| 76 | **"DIGETAL INTERPRETATU".** (A) letters as 5 bits in binary or Gray code (A-Z or KRYPTOS order, from 0 or 1; Bacon is one case), a repeating XOR key per bit, any bit wiring. (B) the entrance text's Morse dots and dashes switching between two systems | **Dead.** A: K4 scores 21; 20 shuffled K4s 0-35; planted 83-88. B: 417k settings, 0 fits (shuffled 0; planted 3/3) |
| 77 | **Tableau seen through the pierced copper** ("SHADOW FORCES"). Every overlay of the cipher panel on the tableau panel: row offset, flipped, mirrored, column offset -33..33, slant -4..4 per row, rows packed left or right, wrapping or not; 16 cipher forms, key read on A-Z or KRYPTOS | **Dead.** 8.2M settings, best 9/24 (5 shuffled: 8 each). Planted 3/3 at 24/24 |

## A proof instead of a search: Wheatstone

Wheatstone's device has a long hand over an outer ring of n cells (alphabet plus blanks) and a short hand over 26
letters, geared one cell for one cell, always turning the same way. So the same cipher letter twice means the long hand
moved a multiple of 26 cells in between.

* Letters 32-33: plain S, T give cipher S, S. So going from S to T is a multiple of 26 cells.
* Letters 23 and 28: plain S and T give cipher R and R. The hand went S, T, N, O, R, T. The first leg is a multiple of
  26; the rest starts and ends on T, so it is m whole turns, n x m cells, with m between 1 and 5.
* n x m is never a multiple of 26 for n = 27..38 and m = 1..5.

That rules the device out for **every** outer and inner ring, not only the ones anyone can enumerate. The same two
repeats (S,S adjacent and R,R five apart, both on plain S then T) are a compact constraint worth carrying into any
future device idea: whatever the mechanism is, its state after S,T,N,O,R,T must treat T as it treated S.

## Noted along the way

* **Move-to-front forgets its start.** In idea 73 a planted message was recovered from a *different* start alphabet:
  after enough letters the alphabet no longer depends on where it began. So for the "move to front/end" rules the
  result does not depend on the dictionary at all.
* **Bit-level XOR does not fit 26 letters.** A 5-bit key gives 32 symbols; a random key would produce one of the six
  non-letters somewhere in 97 symbols all but 2 x 10^-9 of the time. This argues against every five-bit XOR scheme
  on plain numbering, independently of the test.
* **Quick check, not a full idea:** the first clue as the key for the second (autokey 30-52 letters back): K4's best is
  3 of 6 in agreement, the same as 20 shuffled K4s.

## Scope limits (what "dead" does not cover)

* 68, 70, 71B, 74 use plain keyword alphabets (220,318), not the two transposition-mixed forms round 10 used.
* 68 does not re-run formula mining (idea 54) or the three-keyword hash join (63) with gap slack.
* 70's stacked-key test mod 27-31 is a necessary test, not a full solve (it found nothing to confirm).
* 72 cannot judge long non-word turning keys; 73 cannot judge start alphabets that are not keyword alphabets.
* Rows of 21 (69) with a hidden alphabet per row is undecidable from 24 letters.

## Still open

Long non-word keys, key lengths 23+ for three key words, long hidden-alphabet keys, German sentence keys, and any
device not yet described precisely enough to test. No lead in this round beat its controls.
