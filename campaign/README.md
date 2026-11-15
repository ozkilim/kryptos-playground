# campaign/

Ten ideas, queued and run unattended. Every idea has a planted-answer test (`tests/test_stack.py`,
`tests/test_attacks.py`), so "dead" means dead within the stated scope, not "the code was broken".

| File | What |
|---|---|
| `ideas.json` | The queue: id, title, why it's open, script, time estimate |
| `STATUS.md` | **Live table**: what ran, how many hypotheses, survivors, verdict. Rebuilt after every idea |
| `results/<id>.json` | Full result per idea (survivors, shuffled-K4 controls, best decrypts) |
| `logs/<id>.log` | Raw output |
| `state.json` | Which ideas are done (the runner skips them on restart) |

```bash
python campaign/run.py            # run everything not yet done (resumable)
python campaign/run.py --smoke    # tiny slice of every idea, results to a temp dir (doesn't touch the ledger)
python campaign/run.py --status   # rebuild STATUS.md
```

Every K4 run also lands in `experiments/ledger.csv` and so in `negatives/NEGATIVES.md` automatically.
To add an idea: write `attacks/NN_name.py` (use `kryptos.campaign.run_stack_idea` for transposition x key
model searches, or `kryptos.campaign.report` for anything custom), add a planted-answer test, append it
to `ideas.json`.

## The engine

`kryptos/solvers/stack.py` tests (transposition) x (key model) using only the 24 clue letters:

* transpositions: columnar (every order), double columnar, decimation mod 97, grid routes, K3 rotations, Myszkowski
* key models: periodic, progressive, ciphertext/plaintext autokey, aperiodic digit/small-shift keys
* placements: key before or after the transposition; Vigenère / Beaufort / variant; A–Z, KRYPTOS or any alphabet

Every K4 run is paired with the same search on shuffled K4s, so survivors can be compared against chance.
