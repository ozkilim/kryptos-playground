# Campaign 1 summary (2026-11-15, ~3 hours of compute)

Eleven ideas, about 43 billion hypotheses. **No method for K4 found.** Every search came back dead within its stated
scope, and each search engine first recovered a planted answer in tests, so these are real negatives. Two
statistical results are worth carrying forward.

## Dead (new negatives)

| # | Idea | Hypotheses | Survivors | Notes |
|---|---|---|---|---|
| 15 | Sanborn's 2025 hint words as alphabets, keys and column orders | 16.3M | 0 | Quagmire I–IV over 86 theme alphabets; theme columnar × every key model |
| 11 | Decimation mod 97, grid routes, K3 rotations × every key model | 41.8M | 0 | |
| 12 | Myszkowski (189,743 dictionary words) × every key model | 809M | 0 | |
| 08 | Columnar, every order to width 11, + digit / ±3 / ±5 aperiodic keys | 791M | 0 | |
| 17 | Double columnar, every order 2–6 × 2–6, + progressive / autokey / digit keys | 3.09B | 0 | |
| 10 | Columnar, every order to width 10, + ciphertext/plaintext autokey (lag ≤60) | 5.81B | 0 | |
| 09 | Columnar, every order to width 10, + progressive key | 10.5B | 0 | |
| 14 | Keyword alphabets (208k) at key lengths 14–26, forced plaintext scored | 10.8M | — | K4's best (−6.13) is worse than every shuffled K4 (−6.05 to −6.11) |
| 13 | Double columnar width 8 × widths 2–6 + periodic key | 21.9B | 4 | All 4 sit at the minimum 6 equalities, key length 25; decrypts are noise |

"Every key model" = periodic (≤26), progressive, ciphertext and plaintext autokey (≤60), and digit/small-shift keys,
before or after the transposition, Vigenère/Beaufort/variant, A–Z and KRYPTOS alphabets.

## What the statistics say

**Idea 16.** Two well-known K4 oddities hold up against 200,000 shuffled K4s, even after allowing for having looked at every lag and modulus:
* Stehle's DIAWINFBN run (five equal differences at lag 4): p = 0.003
* 5 of 6 doubled letters on one residue mod 7: p = 0.001

Both were noticed after the fact, so treat them as hints, not proof.

**Idea 18: which cipher families can make K4-like ciphertext?** See [FINGERPRINTS.md](FINGERPRINTS.md).
* **Most K4-like:** substitution with **no transposition** and a **short or tightly structured key**. That means short periodic keys (period 4–10), small-shift keys and Gromark. These keep the plaintext's local structure, which is what produces Bean's "close letters" and Stehle-type runs.
* **Least K4-like:** running keys, random one-time-pad keys and sums of two keys. Every transposition stack lands in the bottom half (columnar + key −7.65, double columnar −7.80), because transposition destroys the letter-closeness signal.
* **No family matched all five statistics at once** in 4,000 tries. K4's combination of quirks is rare under every standard family.
* **The ranking is weak evidence.** Fake K4s from known families come back at median ranks 7–23 out of 29.

## So what next

The fingerprint and Bean's analysis point the same way: a **direct substitution (no transposition) with a structured
key and probably a non-standard alphabet**. Plain periodic keys are already ruled out by the clue letters, and the
transposition stacks we just spent ~40B hypotheses on look like the *least* likely region. Best next targets:

1. **Gromark / chain-addition keys with arbitrary alphabets.** Bean's 39 surviving primers were only annealed; this family ranks 11th of 29 here.
2. **Small-shift or near-periodic keys under an unknown mixed alphabet.** Find alphabets where all 24 implied shifts are small, then score for English.
3. **Two-alphabet (Quagmire IV-like) systems with structured keys,** scored for English against shuffled controls rather than by clue consistency alone.
4. **K5**, the moment Paradigm releases it.
