# Campaign 2 summary (2026-11-15, ~1.5 hours of compute)

Round 2 followed campaign 1's fingerprint: direct substitution with structured keys and **hidden alphabets**.
New engine: [`kryptos/solvers/freealpha.py`](../kryptos/solvers/freealpha.py) turns the 24 clue letters into exact
equations between hidden-alphabet positions (weighted union-find), then fills in everything the clues leave free
by simulated annealing on English. It is validated against published results: it finds exactly **Bean's 39**
five-digit Gromark survivors and reproduces keithadler's list of Quagmire key lengths the clues kill.

**Still no method for K4.** The new part is *measured power*: every result below gives what a real answer
would have scored through the same pipeline, so "dead" and "can't tell" are kept separate.

## Results

| # | Idea | Result |
|---|---|---|
| 21 | Practice puzzles from the public write-up's keys | **8 of 9 decrypted and recorded** in `data/ctf/` (PK1–6, 8, 9). PK7 (Hill 3×3 + Quagmire) beat our simple Hill attack; PK10 not attempted. Blind calibration: our period solver finds PK1 exactly and gets close on PK3 (right length 40, −5.36 against −5.26 for the true text) |
| 20 | Quagmire I/II (one hidden alphabet), every key length 1–26 | The clues kill most lengths exactly. Where the engine can recover planted English (I at 13, 16, 19, 20; II at 16, 20: 58–97 letters back), K4 scores like shuffled noise: **dead**. At 23, 24, 26 and several II settings, planted English isn't recovered either, so these stay **open** |
| 19 | Gromark, both alphabets hidden, 1.6M primers (base 10 len 2–6, base 26 len 2–4) | 454 primers survive the clues (39 five-digit, as Bean found). Best English completion on K4: −5.36, against −5.51 and −5.63 on shuffled K4s. The best decrypt isn't readable. Planted Gromark texts land between −5.78 and −4.30 (median about −5.26), so about **half of real Gromark messages would beat K4's best**. **Weakly disfavoured, not ruled out** |
| 22 | Fingerprint ranking with the hidden-alphabet families | Hidden alphabets look **less** K4-like: Quagmire IV ranks 15th, Quagmire I 19th, Quagmire II 21st and Gromark with hidden alphabets 25th of 33. Short plain-alphabet periodic keys still top the list. See [FINGERPRINTS_22.md](FINGERPRINTS_22.md) |

## What we learned

1. **K4's statistics look like a plain or near-plain alphabet, not a scrambled one.** Bean's "close letters" and the Stehle run survive a plain or near-plain alphabet; scrambled alphabets wash them out. Two independent lines now agree: the fingerprint ranking and Bean's diagnosis.
2. **Our tools have measured blind spots:**
   * repeating keys of length 23 or more with a hidden alphabet;
   * stacked keys (PK3-style), where the solver gets close but not exact;
   * Hill 3×3 (PK7).

   An answer in these regions would have been missed, so they are written down as open, not dead.
3. **Paradigm's "Kryptos-like" puzzles are stacks of known parts** (Quagmire III, columnar, spiral, Hill). Our pipeline now reproduces 8 of the 10.

## Next targets

* **A plain or near-plain alphabet with a structured but non-periodic key.** That's where the fingerprint points, and simple periodic keys are already dead.
  * keys that change at word or line boundaries;
  * keys read off a physical object (the World Clock face sequence, Egypt or Berlin dates) with a plain alphabet;
  * near-periodic keys with deliberate "mistakes", tested with error-tolerant matching.
* **A stronger annealer** for the measured blind spots (long hidden-alphabet keys, stacked keys, Hill 3×3), checked on PK3 and PK7 before being pointed at K4.
* **K5**, the moment it's released.
