# experiments/

`ledger.csv` gets one line every time an attack runs through `kryptos.harness.Experiment`:
when, which puzzle, what was tried, how many candidates, best crib hits, best English score, best plaintext.

It's committed on purpose: it's the shared memory of what's been tried, so nobody re-runs a dead end.
Full candidate lists go to `results/` (gitignored).

    python -m kryptos ledger
