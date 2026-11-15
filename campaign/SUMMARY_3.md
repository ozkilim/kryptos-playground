# Campaign 3 summary (2026-11-15): using every clue

| # | Clue it came from | Idea | Result |
|---|---|---|---|
| 23 | K2 "X LAYER TWO"; Sanborn's "two separate systems"; Paradigm's PK3/PK8 | Two stacked repeating keys K = A[i mod L1] + B[i mod L2], every length pair <=26, 3 cipher types, A-Z/KRYPTOS: exact clue equations, then the 710 clue-consistent configs completed for English | **Disfavoured, not dead.** At the 66 pairs where planted two-key messages come back (>=80/97 letters), 47/66 score above K4's best (-5.00), and K4 never beats shuffled controls (-5.04). **Open** at the 54 long pairs (e.g. 25+26) where ~26 free key letters let any text look English-ish |
| 26 | PK8 (four stacked keys) | Three layers: +-theme word + two unknown keys, configs fully fixed by the clues | Dead: 349 determined decrypts, best -6.56 vs shuffled -6.30 |
| 27 | Sanborn: K1-K3 answers hold clues; the misspellings are deliberate | IQLUSION L/Q, UNDERGRUUND O/U, DESPARATLY E/A, PALIMPCEST S/C as swaps in A-Z/KRYPTOS (30 near-plain alphabets) x every key model, + two stacked keys | Dead: 0 survivors for single-layer keys; 98 determined two-key decrypts, best -6.53 vs shuffled -6.48 |
| 24 | Sanborn 2025: BERLINCLOCK = the World Clock, 1989 matters | Pre-1997 World Clock plates reconstructed from dated photos (`data/weltzeituhr_1989.json`): 576 city-name/initial running keys + 144 UTC-offset keys, every facet, both directions | Dead at chance: best 7/24 clue letters (shuffled 6/24); 24/24 needed |

## Takeaways

* **Stacked keys are the most interesting survivor of the night.** They aren't ruled out at long length pairs, which are also the pairs where a hand cipherer's two keywords would be long words. A stronger completion (more ciphertext, K5, or a better English model) is what would decide them.
* **The 1989 World Clock data is new and reusable.** 7/24 facets are verified from photos; the west side and the lower plates of +7..+12 are still missing (see `research_notes/weltzeituhr_1989.md` for archive leads).
* **K1-K3 as direct key material is now exhausted,** including the misspellings as alphabet edits.
