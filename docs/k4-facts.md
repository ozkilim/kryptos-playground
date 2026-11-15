# K4: what's known

```
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
.....................EASTNORTHEAST.............................BERLINCLOCK.......................
```

97 letters. `python -m kryptos show`

## The four clues (cribs)

All released by Jim Sanborn. Positions are 1-indexed, as everyone counts them.

| Plaintext | Positions | Ciphertext | Released |
|---|---|---|---|
| EAST | 22–25 | FLRV | Aug 2020 |
| NORTHEAST | 26–34 | QQPRNGKSS | Jan 2020 |
| BERLIN | 64–69 | NYPVTT | Nov 2010 |
| CLOCK | 70–74 | MZFPK | Nov 2014 |

24 known letters out of 97. Every candidate must match all of them (`passes_cribs`).

## Statistics

* **IoC 0.036**: flat, like random letters (English ~0.066). So K4 is *not* a pure transposition (that keeps English frequencies) and *not* a simple substitution.
* All 26 letters appear.
* No obvious period: periodic IoC peaks are weak (`python -m kryptos triage k4`).
* The keystream the cribs imply under Vigenère/Beaufort, plain or KRYPTOS alphabet, doesn't repeat at any short period (`python -m kryptos cribkeys`). Under plain Vigenère, BERLINCLOCK needs key MUYKLGKORNA and EASTNORTHEAST needs BLZCDCYYGCKAZ.

## What Sanborn has said (paraphrased)

* K4 uses a "masking" technique; it's not simply the K1–K3 methods again.
* BERLIN CLOCK points at Berlin: the Weltzeituhr (World Clock, Alexanderplatz) and the Mengenlehreuhr (set-theory clock) are the usual suspects.
* The decrypted K4 is itself a riddle; solving it isn't the end.

Treat anything not in `data/sculpture/k4.json` as a hint, not a fact.

## 2025–2026

* **2025:** Sanborn put the K4 solution archive up for auction. Before the sale, writers Jarett Kobek and Richard Byrne reported finding the plaintext in Smithsonian archive material; Sanborn confirmed it but it wasn't published.
* **Nov 2025:** Paradigm (the crypto investment firm) bought the archive. Their words: they "became the new stewards of the Kryptos secret … preserving the answer even from ourselves."
* **2026:** Paradigm runs the official checker at https://www.paradigm.xyz/kryptos/k4 . **$1 per check via Stripe; no prize for K4** unless they say otherwise (per their CTF rules page).
* **12 Jun 2026:** Paradigm launched the Kryptos CTF: 10 Kryptos-style puzzles (PK1–PK10), $1,000 each to the first solver, free unlimited checks. All ten had winners by Oct 2026. See `docs/ctf.md`.

So the answer exists and is sealed. Checking is cheap but not free, which is why this repo does all its filtering locally first.
