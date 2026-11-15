# Campaign 4 summary (2026-11-15): models, visuals and the sculpture itself

| # | Idea | Result |
|---|---|---|
| 30 | **Visual letter transforms**: semaphore arm rotations/mirrors (two hands on a dial), Morse reversed/inverted; alone, on fixed/repeating/"ticking clock" schedules, and stacked with every key layer in both orders | **Dead.** Alone it fails at once: at 22/24 clue positions no transform maps plaintext to ciphertext. Stacked: 0 fits (controls 0) |
| 31 | **Compass bearings across the carved sculpture**: key letter read d steps along a bearing (48 directions incl. ENE, d 1-12) on the cipher panel, tableau or mirrored tableau, using the exact carved layout | **Dead at chance.** Best 6/24 clue letters; shuffled K4s also 6/24 |
| 28 | **SLM cipher detective**: 1-D CNN trained on ~100k synthetic K4-like ciphertexts (37 families) to name the family | Weak but suggestive. The net learned something (held-out accuracy 44% across 37 families, chance 3%) but many families are indistinguishable. It calls K4 a **progressive key** (p=0.11, against 0.046 for shuffled K4s on average), the "structured key on a plain alphabet" story again. That family's own held-out accuracy is only 20%, and 16 of 200 shuffled K4s also get that label, so this is a nudge, not a finding. Plain progressive keys are already ruled out by the clues, with and without transposition |
| 29 | **Local LLM (Qwen2.5-7B) as English judge and generator** | **As a judge it is worse than quadgrams** at spotting real English without spaces (AUC 0.55 against 0.75 for quadgrams, planted vs chance). On the best detector, K4's completions in the blind stacked-key region look like chance (AUC 0.55). **As a generator** it wrote 55 "K4 plaintexts"; **none** put both clues in K4's exact positions, and several just echo the prompt. Example: *GHOSTS OF THE PAST ENSNARE US IN TIME EAST NORTHEAST WE FIND THE PATH TO BERLIN CLOCK…* |

## Takeaways

* **The sculpture-as-key ideas (bearings, visual transforms) are dead.** The verified carved layout (`data/sculpture_layout.json`) and the visual-transform library (`kryptos/visual.py`) are reusable for future physical ideas.
* **Small language models don't help here.** A 7B model can't segment unspaced text well enough to judge it, and it can't place words at exact letter positions. Training on K4 itself was never possible (97 letters).
* **Learned and hand-made fingerprints point the same way**: a structured key on a plain or near-plain alphabet, the family most of our searches have now covered. That is consistent with K4 using something outside every standard family (Sanborn: "Who says it is even a math solution?"), or with K4 needing more ciphertext (K5) to break.
