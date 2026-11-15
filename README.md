# Kryptos Playground

A workbench for cracking **K4**, the last unsolved section of the Kryptos sculpture at CIA headquarters. It also includes the three solved sections and Paradigm's ten CTF practice puzzles to practise on.

```
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
.....................EASTNORTHEAST.............................BERLINCLOCK.......................
```

Pure Python 3.9+, no installs.

## The idea

K4 is hard to solve but easy to check. The answer exists: Paradigm bought it in Nov 2025 and keeps it sealed. They run an official checker that costs **$1 per guess**. So the repo works in three loops:

```
 1. PRACTISE                 2. ATTACK K4 (free)                 3. VERIFY (cheap)
 ───────────                 ───────────────────                 ────────────────
 K1-K3 + PK1-PK10            generate millions of candidates     only crib-passing,
 prove each method           → must match all 24 known letters    English-looking
 cracks real puzzles         → rank by English score             candidates go to
 blind before trusting it    → log every run to the ledger       paradigm.xyz ($1)
```

1. **Practise.** A method only counts once it cracks something real without being told the key. The tests check that every solver does this on K1–K3. Paradigm's PK1–PK10 puzzles are **free** to check on their site, so they're where we confirm a new method works end to end.
2. **Attack K4 for free.** Each attack is a small script that generates candidate plaintexts. The harness checks each one against the 24 known letters (EASTNORTHEAST, BERLINCLOCK), scores how English it reads, keeps the best ones, and writes one line to `experiments/ledger.csv`. That ledger is the shared memory of what's been tried, so nobody re-runs a dead end.
3. **Pay to verify only when it's worth it.** `python -m kryptos submit k4 …` refuses anything that fails the free check or has already been checked. It logs the guess and opens the page so you can paste it in.

## What the toolkit can crack blind (no key given)

| Puzzle | Method | Found by | |
|---|---|---|---|
| K1 | Vigenère, KRYPTOS alphabet, key PALIMPSEST | dictionary attack | ✅ |
| K2 | Vigenère, KRYPTOS alphabet, key ABSCISSA | period detection + hill-climb | ✅ |
| K3 | double grid rotation (24 then 8 wide) | tries every grid shape | ✅ |
| PK1 | Vigenère, KRYPTOS alphabet, key PROVENANCE | period detection + hill-climb | ✅ not yet confirmed on site |
| PK2 | 7-column columnar transposition | tries every column order | ✅ not yet confirmed on site |
| PK3–PK10 | ? | | open |
| **K4** | **?** | | **open** |

## Quick start

```bash
python -m kryptos list                 # every puzzle and its status
python -m kryptos show k4              # K4 with the clues lined up
python -m kryptos triage all           # IoC / period / likely cipher type for each puzzle
python -m kryptos crack pk1            # run the automatic solvers on any puzzle
python -m kryptos cribkeys             # key letters K4's clues imply under Vigenère/Beaufort
python -m kryptos check "YOUR97LETTERS..."   # free internal check for a K4 guess
python -m kryptos ledger               # what's been tried so far
python -m kryptos negatives search hill   # is this idea already dead? (169 sourced negatives + ours)
make test                              # everything still works
```

## Layout

```
data/
  sculpture/k1..k4.json   the four sections: ciphertext, plaintext, key, method, notes
  ctf/pk1..pk10.json      Paradigm's CTF puzzles (+ our cracks)
  english/quadgrams.txt   English model for scoring (tools/build_ngrams.py)
  keys.txt                Kryptos-themed keywords for wordlist attacks
kryptos/                  the library
  ciphers/                Vigenère, Beaufort, keyed alphabets, columnar, K3 rotation, rail fence
  score.py                quadgram score, chi-squared, index of coincidence
  analysis.py             triage: what kind of cipher is this?
  check.py                K4 crib check + crib keystream table
  solvers/                blind solvers: periodic, wordlist, rotation, columnar, rail fence
  harness.py              Experiment(): scores, keeps the best, writes results + ledger
  external.py             official-check helper (K4 $1, PK free)
solved/k1.py k2.py k3.py  reproduce each solved section, with the key and blind
attacks/                  K4 attacks, one file per hypothesis (copy 00_template.py)
experiments/ledger.csv    one line per attack run (committed)
results/                  full candidate dumps (gitignored)
negatives/                the growing what-K4-is-NOT database (community.jsonl -> NEGATIVES.md)
docs/                     k4-facts, k1-k3 walkthrough, ctf status
tests/                    pytest or plain `python tests/test_x.py`
```

## The negatives file (read before trying an idea)

[`negatives/NEGATIVES.md`](negatives/NEGATIVES.md) is one big, growing context file of what K4 is **not**:

* **300 community negatives** gathered from public GitHub elimination ledgers (keithadler, gereon, Barneyjm, scott-dunphy, markmnl, reggiechan74 and others), Richard Bean's 2021 paper, blogs, Elonka's FAQ, news, and a contributed TRIED.md compilation. Each one has its scope, who and when, the outcome, a source, and a confidence level.
* **Sanborn and Scheidt's own constraints**, for example "Who says it is even a math solution?" and that K5 shares coded words with K4 at the same positions.
* **Rejected claimed solutions**, including the AI wave and the back-solved keys.
* **Every one of our null K4 runs**, added automatically whenever an experiment finishes.
* **Open gaps**: what's still untested or can't be decided from the 24 clue letters. Aim new ideas here.

To add a negative: `python -m kryptos negatives add --family ... --hypothesis ... --outcome ... --confidence ... --source ...` (see [`negatives/README.md`](negatives/README.md)). The research behind the seed list is in [`reports/`](reports/) and [`research_notes/`](research_notes/).

## Writing an attack

Copy `attacks/00_template.py`, then yield candidates:

```python
from kryptos import K4
from kryptos.harness import Experiment

with Experiment("my-idea", puzzle="k4", notes="what I'm testing") as ex:
    for key in keys:
        ex.add(my_decrypt(K4, key), key=key)
```

You get the top 50 ranked by (crib hits, English score), a JSON dump in `results/`, a ledger line, and a loud `*** FULL CRIB PASS ***` if anything matches all 24 letters. Ctrl-C still saves.

Examples in the repo:
* `01_vigenere_wordlist.py`: every dictionary word as a key, 6 cipher variants (baseline; known dead).
* `02_transposition_plus_vigenere.py`: columnar transposition plus periodic Vigenère in either order. It tests about 46k transpositions × 12 periods in minutes **without decrypting**: it only checks whether the 24 clue letters imply a consistent key. A test plants a solution to confirm it gets found.
* `03_autokey.py`: the key is the message itself, a few letters back (ciphertext or plaintext autokey).
* `04_running_key.py`: the key is a long text (K1–K3, the sculpture itself, or anything in `data/texts/`) from every starting point.
* `05_keyword_alphabets.py`: Quagmire I/II/III, a repeating key on an alphabet scrambled by any dictionary word. 8 million hypotheses in about 20 seconds.
* `06_long_period_27_29.py`: an open gap. At key lengths 27–29 the clues force 85–90% of the plaintext, so the 3–5 free key letters are solved and the result is scored against shuffled-K4 noise.

All six come back empty on K4 so far; see `negatives/NEGATIVES.md`. `kryptos/cribtools.py` holds the shared "test it with only the 24 clue letters" helpers.

## Checking on the website

| | URL | Cost | How |
|---|---|---|---|
| K4 | https://www.paradigm.xyz/kryptos/k4 | $1 per check (Stripe), no prize | type letters into the boxes, "Decrypt K4" |
| PK1–10 | https://paradigm.xyz/kryptos-ctf | free, unlimited (prizes already won) | sign in with X, type, "Decrypt" |

```bash
python -m kryptos submit k4 "YOUR97LETTERS..." --method "how you got it"
python -m kryptos result k4 "YOUR97LETTERS..." wrong      # after the site answers
python -m kryptos stats                                    # what you've spent
```

Your guesses are logged to `submissions.csv`, which is gitignored and stays private.

## Next ideas

* Crack PK3–PK10. They're free to check and probably use K4-style tricks: keyed alphabets with unknown keywords (Quagmire I–IV), running keys, autokey, layered ciphers.
* Add those cipher families to `kryptos/ciphers/` and their blind solvers to `kryptos/solvers/`, then test on the PKs before pointing them at K4.
* Extend attack 02 to wider transpositions (hill-climb the column order) and to K3-style rotations. 97 is prime, so K4 doesn't fit a clean rectangle; try padding or irregular grids.
* Build a sharper English model: run `python tools/build_ngrams.py books/*.txt` on a few public-domain novels.
* Pick targets from the open gaps at the bottom of `negatives/NEGATIVES.md`.

Background: [docs/k4-facts.md](docs/k4-facts.md), [docs/k1-k3.md](docs/k1-k3.md), [docs/ctf.md](docs/ctf.md).
