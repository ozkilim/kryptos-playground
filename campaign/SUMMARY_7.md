# Campaign 7 summary (2026-11-16): ideas from re-reading the clues

Round 7 came from going back over every clue (`docs/CLUES.md`), and idea 46 was the first idea designed
through the clue pre-filter (`kryptos/clues.py`, `docs/CLUE_MATRIX.md`).

| # | Idea (clue it came from) | Result |
|---|---|---|
| 42 | **Selective masking**: KRYPTOS letters lightly shifted, the rest keyed (9 of 10 KRYPTOS-letter clues shift by 2 or less) | **The pattern is real; this model of it is dead.** None of 20,000 shuffled K4s match the closeness (p < 0.0001), and KRYPTOS beats 6,187 of 6,190 sets of clue letters. But no repeating key (1-26, 6 cipher/alphabet types) on the other letters fits the clues. The pre-filter also shows the model can't be as flat as K4 |
| 43 | **Key restarts at each sentence**, optional X before each break (sentence strips; K1-K3's X separators; the Cyrillic Projector restarts its key per block) | **Dead.** 18 alphabets x 3 cipher types x L 1-26 x every pair of sentence starts: only 10 survivors, all at the weakest level (2 checks); shuffled K4s get 2-148. Best decode -6.46 vs shuffled -6.32. Planted messages come back 94-95/97 |
| 44 | **A different simple system for each part** ("two separate systems" read literally; split at 34-63) | **Dead.** Seven simple systems (repeating, progressive, Gromark bases 5-16, ciphertext/plaintext autokey, plain substitution) x 6 cipher/alphabet types: **nothing fits even one half on its own**. Planted two-system messages come back 97/97 |
| 45 | **One deliberate mistake** ("rife with mistakes on purpose"): every exact test re-run with each clue letter dropped | **Dead.** Dropping a clue adds nothing K4-specific: repeating keys 0 (shuffled 0); two stacked keys 158 drop-only survivors (shuffled 146-149); Gromark base 10: 39 exact (Bean's 39) and 1,358 drop-only, against 69-2,198 exact and 2,058-13,482 drop-only for shuffled K4s. K4 resists Gromark more than shuffled text does. Best completion -5.78 (two-key completions on a shuffled K4: -6.76; earlier Gromark completions of shuffled K4s reached -5.46) |
| 46 | **KRYPTOS-letter masking inside the clue sentences + restarting key** (the pre-filter's top hybrid) | **Part A (measurement): the closeness survives conditioning on the two clue blocks** (within-block p = 0.00125, rank 1 of 17 natural letter sets, corrected p ~ 0.02). **But it is only compatible with K4's flat letter counts if no more than ~20 letters are masked and the other letters carry a long or stacked key** (likelihood vs chance 10-34x at 10-24 masked letters, below 1 above 30). **Part B (the decidable slice): dead.** 660 survivors, all at 2 checks and nearly all in one theme alphabet (one coincidence repeated); best decode -6.07 = noise. Planted: the true settings decode 66-86/97 letters |

Fix after the run: idea 46's decoder could let a lightly-shifted letter replace a known clue letter. Forcing the
known letters can only lower decode scores, so the verdict stands.

## What seven rounds now say

* **No method for K4 has been found** across 46 of our own experiments plus ~307 sourced community negatives.
* **Sentence structure, a system per part, and one deliberate mistake add nothing** when combined with the simple key
  models: each was strong enough to recover planted answers, and K4 looked like chance.
* **The KRYPTOS-letter closeness is the most solid unexplained oddity we have.** It survives the within-block test and
  the look-elsewhere correction. Yet any scheme that lightly shifts KRYPTOS letters everywhere makes the text less flat
  than K4. If the effect is real, it is local (confined to a couple of sentences) and the other letters carry a strong
  key. That points at the same open region as LAYER TWO: long or stacked keys, which need an extra constraint to decide.
* Round 8 attacks exactly that: stacked keys that are real words or phrases (no free slots left), K1-K3 texts as keys
  with hidden alphabets, clock arithmetic, and a second look at every saved candidate.
