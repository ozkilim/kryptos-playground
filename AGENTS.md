# Notes for AI agents working on this repo

Read this before you change anything. The README is for people; this file holds the house rules and the
working standard that every experiment here has followed.

## Where things stand (Nov 2026)

* Eleven campaign rounds, 76 of our own ideas, 343 logged negatives. **No method for K4 has been found.**
* Start with `campaign/SUMMARY_11.md` (latest round), `negatives/open_gaps.md` (what is still open and why),
  `docs/CLUES.md` (everything known *for* K4) and `docs/CLUE_MATRIX.md` (every cipher family scored against
  every clue).
* What is still open needs new information more than more computing: long keys that aren't words (K5 would
  settle it), long keys with hidden alphabets, the World Clock's physical facts (someone in Berlin is
  collecting face bearings and plates; they go into `data/weltzeituhr_1989.json`), and a precise version of
  Sanborn's "visual" step.
* Before proposing an idea, check it isn't already dead: `python -m kryptos negatives search <word>` and
  `python -m kryptos ledger`.

## Hard rules

1. **Git identity.** The only GitHub account is **ozkilim**. Never use or push to `ozkilim-lab` or
   `OzGreenFox`, and never commit with the email belonging to OzGreenFox. Commit as:

   ```bash
   git -c user.name="Oz Kilim" -c user.email=ozkilim@hotmail.co.uk commit -m "..."
   ```

   Check `gh api user -q .login` prints `ozkilim` before pushing.
2. **No AI attribution.** No `Co-Authored-By`, `Generated with`, session links or similar trailers in commits
   or PRs. Claude must not appear as a collaborator on GitHub.
3. **Never use the paid check without asking.** `python -m kryptos submit k4 ...` leads to the official
   check, which costs $1 per guess. Use the free internal check (`python -m kryptos check ...`) as much as
   you like; ask the owner before any submission.
4. **Don't fake a result.** A candidate only counts if it beats the shuffled-K4 controls *and* reads as
   English on the big model, word coverage and a human read. Never write "solved" or "signal" without both.

## Environment

* System `python3` (3.9, x86) with the **standard library only**. No numpy, no new dependencies.
* Long runs use `multiprocessing`; spawned workers need their functions in a module run as a script (not
  piped through stdin).
* Tests: `make test` (94 tests, two to three minutes). Keep them green.
* English scoring: `kryptos.score.Quadgrams` (small, `data/english/quadgrams.txt`) and the big 22.6M-letter
  model (`quadgrams_big.txt`), plus `word_coverage`. The local LLM judge (ollama qwen2.5:7b, used by attack
  52) is weak: it rates real English about 3/10, so never let it decide on its own.

## The standard for a new idea

Every idea in rounds 1–10 followed this, which is what makes the results comparable. Do the same.

1. **Pre-filter it against the clues.** Write an encryptor `encrypt(pt, rng) -> ct` that draws its key only
   from `rng`, then run `kryptos.clues.prefilter(...)` (see `attacks/00_template.py`). REJECT means it breaks a
   fact: don't build it. FLAG means it breaks a firm statement: build only with a written reason.
2. **Write the attack** as `attacks/NN_name.py`, copied from `attacks/00_template.py`, logging through
   `kryptos.harness.Experiment` (results go to `results/`, one line to `experiments/ledger.csv`). Test the
   exact clue letters first (weighted union-find in `kryptos/solvers/freealpha.py`, `twokeys.py`; exact linear
   systems mod 26 in `kryptos/round9.py`, which also handle a hidden alphabet when the rule is linear; a hash join
   as in `attacks/63_three_keywords.py` when a test splits into a plain-side and a cipher-side half), then
   complete survivors on English.
   With a hidden alphabet, "consistent" is not enough: all-letters-in-one-place always solves the equations,
   so require a solution with distinct positions (see `attacks/67_carter_reply_crib.py`).
3. **Planted-answer test.** Encrypt a known English 97-letter text with the same model and show the attack
   recovers it. A search that can't find a planted answer proves nothing.
4. **Shuffled controls.** Run the same attack on shuffled K4s (`kryptos.campaign.shuffled(ct, seed)`) and
   compare. K4's best score must beat the controls before anyone calls it a signal.
5. **Add a test** in `tests/test_roundN.py` covering the planted recovery.
6. **Log the outcome.** Dead ideas go into the negatives database:
   `python -m kryptos negatives add --family ... --hypothesis ... --outcome ... --confidence ... --source ...`.
   Confidence must be one of `solid`, `partial`, `disputed`, `statement`, `rejected-claim`.

## Running a round

* Add ideas to `campaign/ideas.json` (`id`, `title`, `script`, `est_min`, `why`, optional `args`).
* `python campaign/run.py --smoke` first: a tiny slice of every idea in throwaway mode (`KRYPTOS_SMOKE`), so the
  real ledger stays clean.
* Then `caffeinate -i python campaign/run.py` for the real run. It's resumable (`campaign/state.json`), gives
  each idea a time limit, and rebuilds `campaign/STATUS.md` after every idea. It reads `ideas.json` once at
  start, so ideas added mid-run wait for the next run.
* When a round ends, write `campaign/SUMMARY_N.md`, add the negatives, add a status section to
  `negatives/open_gaps.md`, update the README's campaign paragraph, update family statuses in
  `kryptos/clues.py` and rebuild `docs/CLUE_MATRIX.md` with `python -m kryptos.clues`.

## Writing style

Plain English, short sentences, numbers with their comparison (K4 vs shuffled, planted recovered or not).
Say what was ruled out *and* its exact scope (keys, lengths, alphabets), so the negative can't be overread.
