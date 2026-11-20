You are worker **{{WORKER}}** in a swarm of independent sessions attacking Kryptos K4 in this repository.
You have ONE job this session: test idea {{ID}} to the repository's standard, record the result, and stop.
Nobody is watching; do not ask questions. You have about {{HOURS}} hours of wall-clock time.

## The idea

* **Number:** {{ID}}
* **Title:** {{TITLE}}
* **Why it might be right (the clue behind it):** {{WHY}} {{CLUE}}
* **Plan:** {{PLAN}}

## Before you write code

1. Read `AGENTS.md` (the rules and the standard), then skim the latest `campaign/SUMMARY_*.md` and `negatives/open_gaps.md`.
2. Check the idea is not already dead: `python3 -m kryptos negatives search <term>` for two or three key terms, and
   look at `campaign/SWARM.md`. If it is fully covered, do not run it: write the result card with verdict `duplicate`
   and say which entry covers it.
3. If the idea cannot be turned into a precise test, write the card with verdict `untestable` and say exactly what is missing.

## Doing the work

* Write `attacks/{{ID}}_<short_name>.py` in the style of `attacks/68_*.py` to `attacks/77_*.py`: a docstring that explains
  the idea in plain words, `kryptos.harness.Experiment`, the clue letters forced, shuffled-K4 controls
  (`kryptos.round9.shuffled_control`), and a planted-answer test that the script must pass. Reuse `kryptos/round9.py`
  and `kryptos/round11.py` (dictionary alphabets, key streams, the key-rule battery, `pmap`).
* Smoke-test first: `KRYPTOS_SMOKE=/tmp/swarm_smoke_{{ID}} python3 attacks/{{ID}}_<name>.py`. Fix it until the planted
  answers are found.
* Run the full version through the CPU queue so the swarm does not overload the machine:
  `python3 swarm/swarm.py slot -- python3 attacks/{{ID}}_<name>.py > /tmp/idea_{{ID}}.log 2>&1`
  Design the full run to finish within about 30 minutes; cut the scope and say so rather than run for hours.
* Write `tests/test_idea_{{ID}}.py`: a fast planted test (under 10 seconds) in the style of `tests/test_round11.py`,
  ending with `if __name__ == "__main__": _runner.run(globals())`.

## Ideas the clue letters cannot decide

Many ideas, especially physical, visual or human ones (reading orders, overlays, mirror text, the clock, K1-K3 as
instructions), do not fix enough to be killed by the 24 clue letters, or give the clue letters no special role.
Do not force such an idea into a big keyword-alphabet battery, and do not stretch it into something a person
could not do by hand: test the idea as stated, faithfully, with its natural variants.

* Judge it by **readability**: produce the full 97-letter decryption for each setting and score it with
  `kryptos.score.english_score` (quadgrams) and `kryptos.score.word_coverage`. Also report whether the clue words
  EASTNORTHEAST and BERLINCLOCK appear where they should, when the idea predicts that.
* **Controls:** run the identical procedure on shuffled K4s (at least 20) and report where K4's best score falls in
  that distribution. Only a K4 score far outside the controls AND a decryption that reads as English is a signal.
* **Planted test:** build a message the idea's way from English text and show the procedure finds it.
* If the idea needs information that is not in the repository (a photograph, a measurement you do not have), write
  the card as `untestable` and say exactly what data would make it testable.

## Files you may change

Only these. Anything else you change is thrown away:

* `attacks/{{ID}}_*.py`, `tests/test_idea_{{ID}}.py`, `kryptos/idea{{ID}}_*.py` (helpers, if you need them)
* `campaign/swarm/{{ID}}.json` and `campaign/swarm/{{ID}}.md`
* `experiments/ledger.csv` (the harness appends to it by itself)

Do NOT edit README, AGENTS.md, `kryptos/clues.py`, `campaign/ideas.json`, anything under `negatives/` or `docs/`.
Do NOT run `git commit`, `git push` or any other git command that changes history: the coordinator commits for you.

## Recording the result (required: without the card the idea counts as not done)

Write `campaign/swarm/{{ID}}.json`:

```json
{
  "id": {{ID}},
  "title": "short title of what was actually tested",
  "verdict": "dead | dead-in-scope | no-signal | signal | duplicate | untestable",
  "k4_result": "what K4 gave, with numbers",
  "controls": "what the shuffled K4s gave, with numbers",
  "planted": "planted answers recovered, e.g. 3/3",
  "tested": 123456,
  "scope_limits": "what this run does NOT cover",
  "negative": {
    "family": "short family name",
    "hypothesis": "one sentence: what was supposed to be true",
    "scope": "exactly what was searched",
    "outcome": "Dead: ... (controls ...; planted ...)",
    "confidence": "solid | partial"
  },
  "follow_ups": ["optional: a concrete new idea this work suggested", "..."]
}
```

and `campaign/swarm/{{ID}}.md`: half a page in plain words: the idea, what was run, the numbers for K4, controls and
planted answers, the scope limits, and anything surprising.

## Hard rules

* Never write "solved" or "signal" unless K4 clearly beats every shuffled control AND the decrypted text reads as
  English. If that really happens, use verdict `signal`, put the full decryption and the exact settings in the `.md`,
  and stop. Do not try to confirm it any other way.
* Never run `python -m kryptos submit` (the official check costs money). Never use any network service.
* A result of nothing is a good result. Report it plainly, with its scope limits. Do not stretch a negative.
* Do not depend on K5 or on any data that is not in this repository.
* For the big English word list use `kryptos.data.WORDS` (data/web2.txt), never `/usr/share/dict/words`: the
  system list differs between machines, and the swarm may run on Linux.
