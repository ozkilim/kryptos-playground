# negatives/

The growing list of what K4 is NOT.

| File | What | Edit? |
|---|---|---|
| `community.jsonl` | Ideas other people tried and ruled out, one JSON object per line, each with a source | Yes: append with `python -m kryptos negatives add` or by hand |
| `NEGATIVES.md` | One big readable file: community entries + every null K4 run from `experiments/ledger.csv` | No: generated |

```bash
python -m kryptos negatives                       # rebuild NEGATIVES.md
python -m kryptos negatives search "hill cipher"   # already dead?
python -m kryptos negatives add --family transposition \
    --hypothesis "Myszkowski transposition alone" --scope "widths 2-20" \
    --outcome "impossible: IoC 0.036 rules out any pure transposition" \
    --confidence solid --source https://example.com/thread --who someone --when 2024-05
```

Our own runs need no typing: every K4 experiment rebuilds `NEGATIVES.md` when it finishes.

## Entry fields

| Field | Meaning |
|---|---|
| `family` | statistics, sanborn-statement, periodic-substitution, keyed-alphabet, autokey, running-key, transposition, stacked, polygraphic, machine, one-time-pad, berlin-clock, physical-sculpture, other, rejected-claim |
| `hypothesis` | The idea, in one line |
| `scope` | Exactly what was covered (widths, periods, alphabets, word lists). Vague scope = weak negative |
| `who`, `when` | Who tested it, when |
| `outcome` | What happened |
| `confidence` | `solid`, `partial`, `disputed`, `statement` (Sanborn/Scheidt said so), `rejected-claim` |
| `source` | URL (or file path for our own) |
