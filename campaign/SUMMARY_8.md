# Campaign 8 summary (2026-11-16): extra constraints for the open gaps

Round 6 showed the long stacked-key region can't be decided by "24 clue letters + reads like English":
with free key slots, any ciphertext completes to English-quality text. Round 8 added the missing
constraint (keys that are real words), and tested the remaining clue-led ideas. Every idea went
through the clue pre-filter first and recovered planted answers.

| # | Idea | Result |
|---|---|---|
| 47 | **Two stacked keys that are both real words/phrases/dates** (LAYER TWO with hand keys) | **Dead.** First key: 264,847 words (dictionary + common words + theme words + every 4-26 letter window of K1-K3 + clue dates) **plus 14.8M two-word phrases**; second key: any of the 264,847, by exact lookup. Vigenère/Beaufort/variant x A-Z/KRYPTOS (key letters valued in either alphabet). **0 combinations fit the 24 clue letters** (shuffled K4s: 0). A second pass dropping each clue letter in turn (one deliberate mistake): **0**. Planted word-key messages are found as the single match every time, including one with a wrong clue letter |
| 48 | **Three layers: theme word + two word keys** | **Dead.** 85 theme words x 21,479 first keys x 264,847 second keys: 0 fit (shuffled 0). Planted three-word messages found every time |
| 49 | **K1-K3's plaintexts as keys, with hidden alphabets** (4 models: hidden plain, true Quagmire II, shared hidden, two hidden) | **Dead.** 169,698 key streams (K1/K2/K3/all, forwards/backwards, period 2-60 or running). One-alphabet models: 0 survivors (shuffled 0). Two hidden alphabets: 189 survivors vs 25,930 and 2,830 for shuffled K4s; best completion -5.62 vs shuffled -5.55. Planted streams survive; completions recover 43-65 letters (this completer is the weakest link) |
| 50 | **Clock arithmetic**: dials of 12/24/60 steps, hour + minute hands, keys restarting at each carved row (including the row break inside BERLINCLOCK), affine row/column keys | **Dead.** 2,955,924 schedules x cipher types: 0 fit (shuffled 0). Planted dial keys found exactly |
| 51 | **The letter picks the table** (KRYPTOS letters on the KRYPTOS tableau, others on A-Z, one key; repeating, progressive, row or sentence restarts) | **Dead.** No key fits (shuffled K4s: 0 survivors on average). Planted messages recovered 88-95/97 |
| 52 | **Second look at all 407 saved candidates** (big English model, dictionary word coverage, local LLM judge) | **Nothing missed.** No candidate passes both automatic checks at real-English level (5th percentile of real English with the clues forced in: big-model score -4.82, word coverage 0.68; best candidate -5.04 / 0.66). The 7B LLM judge separates English from noise only weakly (real English median 3/10, noise 1-2), so the automatic checks carried this one |

## What eight rounds now say

* **No method for K4 has been found** across 52 of our own experiments plus ~318 sourced community negatives.
* **LAYER TWO with word keys is closed.** If K4 is two (or three) stacked repeating keys, those keys are *not* dictionary
  words, K1-K3 phrases, two-word phrases from the 4,000 most common words, or clue dates, under the K1/K2 tableaux,
  even allowing one wrong clue letter. The long stacked-key region is now open only for keys that aren't words
  (random-looking key strings, or words in an alphabet/value system we haven't tried).
* **A pattern worth noting:** for "two hidden alphabets" models, K4 consistently gets *fewer* survivors than shuffled K4s
  (Gromark in idea 45: 39 vs 69-2,198; text keys here: 189 vs 2,830-25,930). That says K4's clue letters are unusually
  constraining for this kind of model; it is not a signal for any method.
* **What's left,** ranked in `docs/CLUE_MATRIX.md`: long keys that aren't words (needs K5 or more plaintext), long
  hidden-alphabet keys, and the genuinely "visual" step nobody has written down, plus the on-site World Clock facts
  (face bearings, plates) now being gathered in Berlin.
