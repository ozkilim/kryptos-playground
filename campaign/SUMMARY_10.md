# Campaign 10 summary (2026-11-16): the clues we had not used

Round 10 started from a re-read of `research_notes/sanborn_scheidt_methods.md` for statements no
earlier round had turned into a test. Four stood out:

* **Scheidt, 2011 (via Bean):** K4's cipher is like those "provided agents or pilots in case of capture", "simple, can be
  remembered", run years later "with the correct key word/s". So: everything is rebuilt from a few remembered words.
* **Scheidt, 2015 workshop:** "special characters don't work" and must be accounted for. K4 is carved straight after a
  "?". Count it and K4 has 98 symbols = 7 x 14, an exact grid; without it 97 is prime.
* **The K3 worksheet is 42 wide**, and the two clue blocks start exactly 42 letters apart, at positions 22 and 64, both
  one past a multiple of 21.
* **The K3 question.** K3 ends "CAN YOU SEE ANYTHING Q", and K4 begins where the answer would.

One gap of our own also turned up: the "key reads as text" tests in round 9 named the key letter three ways
(C-P, C+P, P-C) and missed the fourth, -(C+P), which is the reversed table of the DIANA one-time-pad chart that agents
actually carried.

Every idea recovered planted answers and was run on shuffled K4s. **All are dead.**

| # | Idea (clue it came from) | Result |
|---|---|---|
| 63 | **Three remembered key words** (Quagmire IV: one word mixes the plain alphabet, one the cipher alphabet, one is the repeating key). All pairs of dictionary alphabets is hundreds of billions per key length, but the clue test splits into a plain-side half and a cipher-side half, so a hash join does it exactly in minutes | **Dead for key lengths 1-22.** 666,993 alphabets per side (every dictionary word as a keyword alphabet and as the two transposition-mixed alphabets): **445 billion pairs per key length**, Vigenère and Beaufort forms. K4: no setting at any length 1-15, 17, 18, 20-22; 10 at length 16 and 2 at 19 (shuffled K4s: 5-6 at 16, 121-145 at 18), all decrypting to noise (best -6.00, shuffled -5.96 to -6.15). **Lengths 23-24** leave only 5-7 checks, so ~100 and ~90,000 chance settings appear for K4 and shuffled K4s alike; none reads as English and none has a dictionary word for its key. Lengths 25-26 not listable. Planted three-word messages found 3/3 |
| 66 | **Any dictionary keyword tableau x a battery of hand key rules.** The same 666,993 alphabets in five layouts (both sides, or one side with A-Z or KRYPTOS on the other), Vigenère and Beaufort: 6.67M key streams. Rules: repeating (to 17), **sliding** (each key letter says how far to *move* the strip, so the key is the running sum of a repeating word; new), **two stacked key words** (lengths to 13; LAYER TWO on any keyword tableau), progressive, autokey (lags 1-6, plaintext or ciphertext), key restarting at each word, growing key, chain addition | **Dead.** K4: **0 settings** pass with 7 or more checks (4 shuffled K4s: 0 each). Planted sliding, autokey and stacked keys on random dictionary tableaux found every time with 12-21 checks |
| 65 | **Keys rebuilt from a short word**: (A) chain addition in letters, any two taps up to 10, any multipliers; (B) row word + column word on a worksheet grid of any width 2-48, with and without the "?" as a cell | **Dead.** 1,112 settings, 0 fit (100 shuffled K4s: 0). Planted 6/6 with 7-14 checks |
| 64 | **The "?" counts: 98 = 7 x 14.** Round 9's grid-based tests re-run with the "?" as cell 0 (`KRYPTOS_QMARK=1`): scrambled key (idea 61), formula mining with every grid shifted (54), drifting key (62) | **Dead.** Scrambled key: 71.3M settings, 0 (shuffled 0; planted 4/4). Formulas: 9.15M, 0 fits (shuffled 0; planted 3/3). Drifting key: 0 |
| 57b, 58b | **The reversed (DIANA) table for text keys**: K = -(C + P) added to the sentence-key and sculpture-reading tests | **Dead.** Sculpture readings: 224M stream-views, best 10/24 (shuffled 10-11). Sentence keys on 220,318 keyword tableaux: K4's best -4.87 (`PTSALINEDOURD`), shuffled -4.84, -4.93, -4.95: no signal, same thin-margin caveat as round 9 |
| 67 | **Carter's reply as a third clue.** "YES WONDERFUL THINGS" (and four variants) placed at the start of K4, then every model the 24 clues could not decide re-run with 37-43 known letters: repeating keys of 27-60, two stacked keys for every pair up to 26, sliding keys to 40, autokey with a hidden alphabet at lags 1-8 | **Dead.** No guess makes anything fit (10 shuffled K4s per guess: 0). Planted messages that do start with the guess are found 3/3. This says nothing about whether K4 opens with those words, only that no tested method appears if it does |

## Measured, not significant

* **Both clue blocks start on a multiple of 7** (0-indexed 21 and 63, and 42 apart). Chance of that for two placements
  is about 1 in 49, post hoc. Nothing built on widths 7, 14, 21 or 42 fits: row word + column word (65), scrambled key
  grids (61/64), grid terms in the formula search (54/64).
* **Bean's "multiples of 5" footnote** (plain letter on A-Z plus cipher letter on KRYPTOS is a multiple of 5 at 13 of 24
  clue letters) is the same thing as round 9's finding that two fixed Beaufort rows cover 9 clue letters: the value 20
  occurs five times and 0 three times. Two rows covering 9 is what shuffled K4s give too (idea 60).

## A correction to round 9

Idea 55's "checks" count for autokey with the alphabet hidden on both sides was looser than it read. Those equations
always have the trivial solution "every letter in the same place", so being consistent proves nothing; what kills a
model is that no solution puts the letters in different places. The K4 result (lag 1: every solution listed, none a real
alphabet) stands. Idea 67 does this properly and extends it: with a guessed third clue, lags 1-8 are decided.

## What ten rounds now say

* **No method for K4 has been found**: 66 of our own ideas, 333 logged negatives.
* The "simple, remembered key words" reading is now closed about as far as the clue letters allow: one, two or three
  dictionary words in any of the usual roles (tableau keyword on either side, repeating key, two stacked keys, sliding
  key, autokey primer) do not produce K4, for key lengths the clues can decide.
* **Still open, and why:**
  * key lengths the clues cannot decide: 23 and up for three-keyword Quagmire IV, 14 and up for stacked keys on a
    non-KRYPTOS tableau, and anything with about 20 or more free key letters. More plaintext (K5, or a correct guess
    of more K4 text) is the only thing that shrinks this.
  * a key that is simply a written-out list of 97 letters on the "coding chart". Sanborn's remark that K5 shares coded
    words with K4 "in the same positions" is exactly what a shared 97-letter key would give, and exactly the handle a
    two-message attack needs once K5's ciphertext is released.
  * sentence keys in German; one-wrong-letter versions of rounds 9-10 (not run).
