# Campaign 6 summary (2026-11-16): pushing both angles

Round 6 pushed on the two directions the evidence left: the long stacked-key gap (with a much stronger
solver) and Scheidt's "different math base" / "shifting matrices".

| # | Idea (evidence it came from) | Result |
|---|---|---|
| 39 | **Shifting matrices / number-base change** (Scheidt taught shifting matrices; "I could have moved to a different math base") | **Dead.** 1,560 grid hypotheses (grid shapes x A-Z/KRYPTOS fills x per-coordinate repeating wheels): in every grid at least one coordinate has no wheel the clue letters allow. Shuffled controls also 0. A planted wheel set is recovered by the same test |
| 41 | **Gromark in other number bases** (bases 3-16, primers of every length, both alphabets hidden) | **Dead.** 3.5M base/primer hypotheses, 12,833 consistent with the clues, 1,470 survivors completed on English. Best -5.36, versus -5.46 and -5.58 for shuffled K4s through the same pipeline. Planted Gromark messages come back at -5.78 to -4.30 (38-88 letters right). Five-digit base-10 primers: 0 survivors with this filter |
| 38 | **Long stacked keys v2** (LAYER TWO at the 54 long length pairs idea 23 couldn't decide; heat-bath solver + English-key prior, 22.6M-letter English model) | **No signal, and now we know why.** K4's best completion -4.89, shuffled K4 -4.97. The solver is much better (median 58 planted letters right, was ~35; 17% of pairs fully recovered), but completions of a *shuffled* ciphertext already score like real English (true English windows: median -5.06). **At these lengths the 24 clue letters plus "reads like English" can't pick out the answer**: the gap is information-limited, not just search-limited |

Side finding (round 6 research, `research_notes/sanborn_scheidt_methods.md`): read literally as a coding chart,
the carved Vigenère tableau on the sculpture is a **Quagmire II on the KRYPTOS alphabet** (its extra L is never
reached). Quagmire II with the KRYPTOS alphabet is already dead at every testable key length, so "use the
tableau on the sculpture as the chart" adds nothing new.

## What six rounds now say

* **No method for K4 has been found** across 41 of our own experiments plus ~305 sourced community negatives.
* **Scheidt's "different math base" is now covered** in both obvious readings (chain addition in bases 3-16, and
  grid coordinates with shifting wheels). Both dead.
* **The long stacked-key gap changes status.** Better search no longer helps: a random ciphertext gets English-quality
  completions too. It can only be closed by an *extra constraint*: guessing the keys (words, phrases, dates),
  more known plaintext, or the K5 ciphertext (same method, same positions: a depth attack).
* The live list (re-ranked in `docs/CLUE_MATRIX.md`) is now: masking/sentence ideas (round 7), long keys that need
  an extra constraint, and the genuinely "visual" step nobody has written down.
