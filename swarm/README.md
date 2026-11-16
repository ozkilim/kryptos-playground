# The swarm: many sessions, one idea queue

This runs the repository's usual loop (have an idea, test it properly, record it, have another) with several headless
Claude Code sessions at once, for days, without two of them doing the same thing or overwriting each other.

```
python3 swarm/swarm.py up --workers 8 --slots 2     # start everything, detached
python3 swarm/swarm.py status                       # queue, who has what, results, alerts
python3 swarm/swarm.py down                         # finish current ideas, then stop   (--now: kill)
python3 swarm/swarm.py merge                        # merge anything finished but not yet merged
```

## The four roles

| Role | How many | What it does |
|---|---|---|
| **worker** `w1..wN` | N | Takes the next open idea, starts ONE fresh headless session for it (`swarm/WORKER_PROMPT.md`), and when the session ends checks the result card and commits the idea's files to its own branch. Then takes the next idea. |
| **ideator** | 1 | When fewer than 6 ideas are open, starts a session (`swarm/IDEATOR_PROMPT.md`) that reads the clues, the negatives and everything the swarm has finished, and adds up to 10 new ideas. It runs no experiments. |
| **merger** | 1 | Every 5 minutes merges each finished idea into `main`, runs its test, logs its negative, and rebuilds `campaign/SWARM.md`. No LLM involved. |
| **slots** | K | A lock. Full-size searches go through `swarm.py slot -- <command>`, so only K run at once however many workers there are. |

## Where things live

* `.swarm/` in the main checkout (not committed): `ideas/NNNN.json` (the queue), `wt/<name>/` (one git worktree per
  role, on branch `swarm/<name>`), `logs/`, `suggestions.jsonl`, `ALERT`, `STOP`.
* In git, per idea: `attacks/N_*.py`, `tests/test_idea_N.py`, `campaign/swarm/N.json` + `N.md`, and a line in
  `experiments/ledger.csv`. The merger adds the entry in `negatives/` and `campaign/ideas.json`.

## The life of one idea

1. **open**: proposed by the ideator, by `seed_ideas.json`, or by you (`swarm.py propose --title --why --plan`). It
   gets the next free number (never one an attack script already uses).
2. **claimed**: a worker takes it under a file lock, so no two workers can take the same one.
3. The worker's worktree is reset and brought up to date with `main`, then a fresh session works on it for up to
   4 hours. It must leave a result card, `campaign/swarm/N.json`, with a verdict (`dead`, `dead-in-scope`, `no-signal`,
   `signal`, `duplicate`, `untestable`), the numbers for K4, controls and planted answers, and a negatives entry.
4. **done**: the card is valid, so the coordinator commits ONLY the idea's own files to the worker's branch. Anything
   else the session changed is discarded. No card: the idea is re-queued once, then marked **failed**.
5. **merged**: the merger merges that commit into `main`, runs `tests/test_idea_N.py` (and the whole suite every
   10th merge), files the negative, commits. If it does not merge cleanly or the test fails, `main` is left untouched,
   the idea is marked **conflict** or **test-failed**, and a line goes to `.swarm/ALERT`.
6. Any follow-up ideas on the card go to the ideator's inbox.

A verdict of `signal` writes an alert at once. Nothing is ever pushed, and the paid K4 check is never run.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `SWARM_AGENT` | `claude -p --permission-mode acceptEdits --allowedTools Bash Read Edit Write Grep Glob` | The headless command; the prompt arrives on stdin. Add `--model ...` here. |
| `SWARM_SLOTS` | 1 (`up --slots K`) | Full-size searches allowed at once. About one per 14-16 cores. |
| `SWARM_IDEA_HOURS` | 4 | Wall-clock limit for one idea's session. |
| `SWARM_MAX_ATTEMPTS` | 2 | Tries before an idea is marked failed. |
| `SWARM_LOW_WATER` / `SWARM_BATCH` | 6 / 10 | Ideator tops the queue up by BATCH when fewer than LOW_WATER are open. |
| `SWARM_BACKOFF` | 300 | Seconds a worker waits (doubling to an hour) when a session dies at once: login or rate limit. |
| `KRYPTOS_SWARM_HOME` | `<main checkout>/.swarm` | Where the state lives. |

## Running it on a server

1. Clone the repository; install Claude Code; log in (`claude` once) or set an API key.
2. Keep the main checkout on `main`, clean, and do not work in it while the swarm runs (the merger commits there).
3. `python3 swarm/swarm.py up --workers N --slots K`, and look at `status` and `.swarm/ALERT` now and then.
4. To take results home: `python3 swarm/swarm.py down`, `python3 swarm/swarm.py merge`, then push `main` yourself.

Sessions run shell commands unattended inside their worktree. Use a machine or container where that is acceptable.
