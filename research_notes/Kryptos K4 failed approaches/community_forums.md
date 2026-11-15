# Kryptos K4: negative results from community discussion (forums, blogs, public repos)

Scope note on access: as of 2026-11-15, WebFetch is refused for **old.reddit.com and www.reddit.com**, and search engines returned no r/Kryptos or r/codes threads for these queries. **groups.io/g/kryptos returned HTTP 402.** None of the searches found a Yahoo Kryptos group mirror. So there is **no first-hand Reddit, groups.io or Yahoo material** below. What could be reached: Hacker News (Aug 2025 thread), Elonka Dunin's Kryptos FAQ, the Kryptosfan WordPress "speculations" catalogue, the Spray on Security blog, and several public GitHub "elimination ledgers" that the community points to (2026). The GitHub ledgers have the most explicit scopes, so they appear below as community sources. All of them are self-reported and none is peer-reviewed.

Own computation (not a source, reproducible; ciphertext and 1-indexed cribs exactly as given in the task):
- **Self-encryptions:** crib letters equal ciphertext letters at **position 33 (S→S)** and **position 74 (K→K)**. The claim that K4 ciphertext letters differ from crib letters at every position is **false** with this indexing. Two fixed points are mild evidence *against* Enigma-style or other no-fixed-point (reciprocal, involutory) systems as the final layer.
- **Implied direct keystreams** (standard A–Z alphabet, positions 22–34 then 64–74):
  - Vigenère (C−P): `BLZCDCYYGCKA ZMUYKLGKORNA`, read as two runs, 22–34 (13 letters) then 64–74 (11)
  - Beaufort (C+P): `JLJODEGKUKKKLOCGGBGOKTRU`
- **No period 1–26 is consistent** with these 24 values for either Vigenère or Beaufort on the plain alphabet (direct substitution, no transposition).

---

## 1. Which cipher families do forum and community regulars consider eliminated, and on what evidence and scope?

### Takeaway
The consensus is that every *single* textbook cipher applied in the ordinary way is dead: periodic Vigenère, Beaufort and Quagmire, autokey, running keys on obvious texts, Hill, pure transposition, and simple columnar plus periodic. The live space is multi-layer or "bespoke" systems, some keyword-mixed-alphabet variants, long periods (above about 24), large Hill ciphers, irregular masks and grilles, and Sanborn-specific physical or clock schemes. Most eliminations rest on the 24 crib letters. Pure transposition is ruled out by IoC.

### Cited Findings

**General consensus statements (Hacker News, Aug 2025 thread on the auction)**
- rgovostes (2025-08-15) says "everything reasonable has been tried and eliminated," so the solution is probably "unreasonable." This is a consensus claim with no scope (weak, opinion) — [HN thread](https://news.ycombinator.com/item?id=44907366)
- elahieh (2025-08-15) says that after the 2020 clues "it wasn't any single ACA cipher type," and cites K4's low IoC (about 0.036) as evidence for a combination of two or more types. The same commenter says the cribs "haven't helped at all" (opinion with partial evidence) — [HN thread](https://news.ycombinator.com/item?id=44907366)
- derekp7 (2025-08-15) calls a true one-time pad unreasonable for a public sculpture unless the "pad" is a well-known text (an argument, not a test) — [HN thread](https://news.ycombinator.com/item?id=44907366)
- sivm (2025-08-15 to 18) tried poetry-derived cribs and a proposed Vigenère layer plus Berlin-clock transposition, then reported "Stonewalled" (failed attempt, unverified, weak) — [HN thread](https://news.ycombinator.com/item?id=44907366)

**Elimination ledger: gereon/kryptos (README status dated Sept 2026)**
Each entry below is ruled out against the EASTNORTHEAST (22–34) and BERLINCLOCK (64–74) cribs. The README says planted-solution tests confirm the search would detect a real solution of each form. All entries are solid at the stated scope unless marked otherwise. Source for all: [gereon/kryptos](https://github.com/gereon/kryptos)
- **Periodic Vigenère, Beaufort and Variant Beaufort:** A–Z and KRYPTOS alphabets, periods 1–48. Ruled out. Periods 27–29 "fit" only because the cribs place no constraint at those periods.
- **Plaintext and ciphertext autokey:** A–Z and KRYPTOS alphabets, primer lengths 1–96. Ruled out.
- **Keyed columnar transposition plus periodic substitution, either order:** widths 2–10, periods 1–26, A–Z and KRYPTOS alphabets, at least 6 crib checks. Ruled out.
- **Periodic substitution with arbitrary alphabets:** covers every Quagmire and every keyword. Ruled out for periods 1–7, 9, 10, 14, 15, 17, 21, 25, 34, 42, 43 and 45. All other periods up to 48 are **unconstrained** by the cribs (partial).
- **Arbitrary-alphabet periodic substitution plus keyed columnar, either order:** widths 2–8, periods 1–26. No significant fit. The best fits check only 4 crib letters, and a shuffled K4 does as well (weak or partial).
- **Running key from the K1–K3 plaintext:** every offset, forwards and reversed. Best match 8 of 24 crib letters, which is chance. Ruled out.
- **Running key from Carter's *Tomb of Tut-ankh-Amen*, volumes 1–2:** A–Z and KRYPTOS alphabets, every offset, forwards and reversed. Best match 8 of 24. Ruled out.
- **Hill cipher:** A–Z and KRYPTOS alphabets, 2×2 and 3×3 at every block phase, 4×4 at phases 1–2. Ruled out.
- **Pure transposition, or monoalphabetic substitution then transposition:** ruled out by IoC (K4 0.036 against about 0.066 for English).

**Elimination ledger: Barneyjm/kryptos-k4 (Oct 2026; second session 2026-10-17)**
Source for all entries: [Barneyjm/kryptos-k4](https://github.com/Barneyjm/kryptos-k4)

Substitution only:
- **Periodic Vigenère and Beaufort:** key lengths 1–26, standard and KRYPTOS alphabets, exact matches and matches with up to 2 crib errors. Plus about 13k keyword-alphabet (Quagmire) pairs, and 1,850 hand-modified alphabets (one letter moved or two letters swapped). All dead.
- **Autokey, progressive keys, polynomial keys** (mod 26, 24, 12 and 60). All dead.
- **Digit streams:** π, e, √2, φ, the K2 coordinates, 1986 and 1989. All dead.
- **Hill:** 2×2, 3×3 and 4×4 at every alignment, with and without the "?". All 4×4 keys forced by the cribs are **non-invertible** (solid).
- **Linear key rules mod 26:** 1,544 rules with up to 5 terms. Dead.
- **Two summed periodic keys:** lengths 2–26. Dead.
- **Grid keys (column key plus row key):** widths 2–30, every offset. Dead.
- **Running keys:** K1–K3 plaintext and ciphertext, the tableau read 7 ways, and the Morse text. Dead.
- **Gromark:** bases 3–26, primers of 2–8 digits, every two-lag recurrence (2.78B primers). This reproduces Bean (2021). None of the 804,684 survivors explains the width-21 repeat pattern.
- **Running keys with keyword alphabets:** English and German text, 842,006 dictionary alphabets. Scores sit within the shuffled-text range.
- **Gronsfeld, Gromark and clock digits with dictionary alphabets:** no alphabet keeps all 24 implied key values below 16.
- **VIC-style chain addition:** 221,577 primers. About 6,000 chance survivors, none explaining more than 2 of the 11 width-21 repeats.
- **Phrase keys from Sanborn's words:** 613,440 alphabets drawn from his oral history, K1–K3, Morse and clue quotes. Dead.
- **Arbitrary monoalphabetic mask plus periodic key:** inconsistent for lengths 1–12, 14, 15, 17, 21 and 22. Lengths 13, 16, 19, 20, 23, 24 and 26 are underdetermined (partial).
- **"Divided Berlin"** (separate periodic keys per half, 13,456 pairs): no fit.

With transposition:
- **Columnar plus periodic substitution, both orders and both directions:** exhaustive for widths 2–11. Widths 12–13 used a pruned search with period ≤14.
- **Simple hand transpositions (1,282 variants):** reversal, boustrophedon, row and column reads at widths 2–48, the carved 31-wide layout, decimations and rail fence.
- **K3-style double grid rotation** applied to K4, ?K4 and padded K4. Dead.
- **Double keyword columnar** with about 56 English and 56 German clue words. Dead.
- **Running keys behind columnar** up to width 11. Scores equal the null.

Session 2:
- **M-94 wheel:** all 25 published disks, all orders and offsets. Dead.
- **Chaocipher:** 1.02e10 rows. Best 11/24, which shuffled text matches. A full dictionary-by-dictionary run is untested (partial).
- **Clock-derived additive streams:** 1.35M streams from Berlin-clock lamp counts, rows, bits, HHMM, time zones and K2 date cycles. Best 10/24, the same as shuffled text.
- **Wheatstone cryptograph:** 21.9M outer rings. Dead.
- **Base-27 additive:** 22.7M alphabet orders. Dead.
- **Running key from an 8.9M-letter corpus:** 81M configurations. Dead.
- **Independent substitution per position class:** impossible for lengths 1–7, 9, 10, 14, 15, 17, 21 and 25.

**Elimination ledger: zeyeteam-debug/kryptos-k4-eliminations (Thanos Zekios with Claude; living README, ©2026)**
Source for all entries: [zeyeteam-debug ledger](https://github.com/zeyeteam-debug/kryptos-k4-eliminations)
- **Arbitrary independent alphabets per key class:** inconsistent for periods 1–7, 9, 10, 14, 15, 17, 21 and 25. EASTNORTHEAST alone excludes periods 1–5 and 9; BERLINCLOCK alone excludes 1–4 and 7. Periods 19 and 38 are undecidable. Periods 27–60 with standard, KA and Greek alphabets are inconsistent.
- **Transposition families, all with periodic keys ≤12:**
  - Columnar widths 2–9, all orders, both directions, any-alphabet periodic key: 0 hits.
  - Double columnar, width pairs 2–6 (1.5M permutations): 0.
  - Myszkowski widths 3–9, VIC-disrupted columnar widths 5–9, irregular columnar widths 2–8 (18.6M permutations): 0.
  - K3-style double rotation, widths 2–96 (72,200 permutations): 0.
  - Width 21 (6,312 permutations): 0.
- **Hill:** periodic key then Hill 2×2 or 3×3 is inconsistent. Hill and affine Hill 2×2 to 5×5: 0. Hill 3×3 then columnar 2–8: 0. Hill ≥6×6 remains **open**.
- **Turning grille, 10×10:** the annealer was inconclusive (K4 20/24, null 19/24). An exact search covered about 42% of one variant with 0 survivors; the rest is open (partial).
- **Hebern rotor (N = 1–48), Alberti stepping, Hagelin M-209/C-38, LFSR:** all 0. LFSR uses Berlekamp–Massey linear complexity, 26–35 for K4 against 25–33 for the null, so no LFSR of degree about 25 or less. A 6×6 Bifid at periods 2–97 is infeasible.
- **Error tolerance** (one wrong, extra or missing letter, with periodic keys 1–24 and columnar widths 2–8): 0.
- **Split into two segments** (split point 34–63, each part with its own transposition and key): no split works for both halves.
- **Running keys:** Carter vol. I (287,513 letters), an 11.16M-letter Gutenberg, inaugural and State of the Union corpus with columnar 2–8, and 11.66M letters over 270 alphabets. All 0. The README also cites keithadler covering Carter vols. 1–3 at 149M offsets.

**Elimination ledger: kryptosbot.com (Colin Patrick with Claude; rebuilt 2026-10-12)**
- The site claims 597 experiments and 721.7B+ configurations, all negative. By category: bespoke 133, key models 128, substitution 80, multi-layer 73, transposition 68, fractionation 19, uncategorized 96. Named families include Bifid, Playfair, Four-Square, ADFGVX, Hill, Quagmire, rail fence, route, grille, running key, autokey and DRYAD.
- The front page gives no per-family scope, and it says "a few variants built on keyword-mixed alphabets are not yet fully closed" (weak for scope) — [kryptosbot.com](https://www.kryptosbot.com/)
- **W-delimiter hypothesis** (the Ws in K4 as word or segment separators): every simple divider version failed. A 2026 audit found the statistical oddity behind it also appears when non-W letters are deleted, so it "says nothing about the Ws" — [kryptosbot.com](https://www.kryptosbot.com/). The zeyeteam ledger independently excludes key restarts at W, Ws as nulls (periodic keys 1–24, columnar 2–8) and every-other-letter nulls — [zeyeteam ledger](https://github.com/zeyeteam-debug/kryptos-k4-eliminations)

**Older blog-level negatives**
- **Mireya Jurado, Spray on Security, 2021-08-01: "Kryptos K4 is not a Vigenere Cipher."**
  - Tested a KRYPTOS-keyed double-key Vigenère with KRYPTOS as the alphabet key. Every NLTK English word of 4–17 letters (233,383 words) was tried as the secondary key, with a "BERLINCLOCK"-contained oracle.
  - Also tested Karl Wang's 21- and 49-column transposition outputs against the same word list.
  - Outcome: no hit.
  - The author says this rules out only "Vigenère alone" in that configuration (solid within that scope) — [Spray on Security](https://sprayonsecurity.com/kryptos-k4-is-not-a-vigenere-cipher/)
- **Kryptosfan, "Is K4 a Vigenere Cipher?"** argues it is very unlikely because K1 and K2 already use Vigenère. The author admits "I have no well-founded logical arguments" (opinion, not a test) — [Kryptosfan](https://kryptosfan.wordpress.com/speculations/substitutions/is-k4-a-vigenere-cipher/)
- **The Kryptosfan blog has per-family "Is K4 a ___?" pages:**
  - Substitution and fractionation: Caesar, keyed Caesar, Atbash, affine, Gronsfeld, Playfair, Bifid, attempted forced Foursquare, digraphic substitution, Morbit, Pollux, fractionated Morse, straddling checkerboard, Werftschlüssel, nomenclator, runic, Castor, SMS, Pig Latin, Roman numerals.
  - Transposition: columnar, double transposition, permutation, rail fence, Rasterschlüssel, rotational, scytale, Ubchi, merged columnar.
  - These pages were not individually fetched. Treat them as a catalogue of ideas the community has considered, not as verified eliminations — [Kryptosfan index](https://kryptosfan.wordpress.com/speculations/substitutions/is-k4-a-vigenere-cipher/)

### Inferences
- The strongest *structural* eliminations are period-based. Periodic polyalphabetic encryption, even with arbitrary alphabets, is impossible at periods 1–7, 9, 10, 14, 15, 17, 21 and 25; three ledgers agree independently (gereon, Barneyjm, zeyeteam). For the standard and KRYPTOS alphabets, Vigenère and Beaufort fail at every period up to 26, and in gereon's run up to 48 except 27–29. Our repo should treat "single periodic polyalphabetic without transposition" as closed and focus any periodic work on undecidable periods (8, 11–13, 16, 18–20, 22–24, 26+) *combined* with another layer.
- "Columnar plus periodic" is closed only for small widths (about ≤11 exhaustive, 12–13 pruned). Wide or irregular transpositions, Myszkowski ≥10, disrupted columnar ≥10, keyed routes, and turning grilles beyond 42% coverage are still open by the ledgers' own accounts.
- Every running-key search on obvious texts (K1–K3, Carter, large English corpora) reaches only chance scores of about 8/24. A running key on an *obvious* text is therefore weak territory, but an obscure text cannot be eliminated.

### Gaps
- No first-hand r/Kryptos, r/codes, groups.io or Yahoo-archive posts could be fetched (the fetch tool blocks Reddit; groups.io returned 402). Specific Reddit usernames, dates and posted scopes are missing.
- None of the 2026 GitHub ledgers is independently replicated. Their eliminations depend on correct crib indexing and correct code.

---

## 2. Which computational searches were posted with explicit scope?

### Takeaway
Explicit-scope searches come almost entirely from 2021–2026 blog and GitHub ledgers rather than forum posts. The best-specified are columnar widths 2–11 plus periodic substitution, periodic arbitrary alphabets up to 48, Hill up to 5×5, autokey primers up to 96, and multi-million-letter running-key corpora.

### Cited Findings

| Hypothesis | Exact scope | Outcome | Who / when | Confidence |
|---|---|---|---|---|
| Periodic Vig/Beau/Variant | periods 1–48; A–Z and KRYPTOS | none except unconstrained 27–29 | gereon, Sept 2026 — [link](https://github.com/gereon/kryptos) | solid |
| Periodic, arbitrary alphabets (all Quagmires) | periods 1–48 | impossible at 1–7, 9, 10, 14, 15, 17, 21, 25, 34, 42, 43, 45; others unconstrained | gereon — [link](https://github.com/gereon/kryptos) | solid / partial |
| Autokey (plaintext and ciphertext) | primers 1–96; A–Z and KRYPTOS | none | gereon — [link](https://github.com/gereon/kryptos); Barneyjm also lags 1–96 with dictionary alphabets, best 10/24 = null — [link](https://github.com/Barneyjm/kryptos-k4) | solid |
| Columnar + periodic, either order | widths 2–10, periods 1–26 | none | gereon — [link](https://github.com/gereon/kryptos) | solid |
| Columnar + periodic, both directions | widths 2–11 exhaustive; 12–13 pruned (period ≤14) | none | Barneyjm, Oct 2026 — [link](https://github.com/Barneyjm/kryptos-k4) | solid (2–11) |
| Columnar + any-alphabet periodic | widths 2–9 all orders; period ≤12 | 0 | zeyeteam — [link](https://github.com/zeyeteam-debug/kryptos-k4-eliminations) | solid |
| Width-7 columnar + KRYPTOS-keyed Vigenère | width 7 (motivated by an NSA "interval 7" note), 333M attempts | none | kryptos.today — [link](https://kryptos.today/phases/2a1-width7-columnar-vigenere) (via search snippet, not fetched) | weak (unverified) |
| Geographic or keyword column orders | widths 15–26, 353,100 orders | rejected | nitsuah/kryptos PR #247 — [link](https://github.com/nitsuah/kryptos/pull/247) (via search snippet, not fetched) | weak (unverified) |
| Hill | 2×2, 3×3 all phases; 4×4 phases 1–2; A–Z and KRYPTOS | none | gereon — [link](https://github.com/gereon/kryptos) | solid |
| Hill 4×4 | all alignments, with and without "?" | crib-forced keys non-invertible | Barneyjm — [link](https://github.com/Barneyjm/kryptos-k4) | solid |
| Hill and affine Hill | 2×2 to 5×5 | 0; ≥6×6 open | zeyeteam — [link](https://github.com/zeyeteam-debug/kryptos-k4-eliminations) | solid / partial |
| Running key: K1–K3 plaintext | all offsets, forwards and reversed | best 8/24 (chance) | gereon — [link](https://github.com/gereon/kryptos) | solid |
| Running key: Carter *Tut-ankh-Amen* | vols 1–2 (gereon); vol I + transposition families (zeyeteam); vols 1–3, 149M offsets (keithadler, cited by zeyeteam) | chance | [gereon](https://github.com/gereon/kryptos), [zeyeteam](https://github.com/zeyeteam-debug/kryptos-k4-eliminations) | solid (obvious texts only) |
| Running key: large corpus | 8.9M letters / 81M configs (Barneyjm); 11.16M letters + columnar 2–8 (zeyeteam) | 0 | [Barneyjm](https://github.com/Barneyjm/kryptos-k4), [zeyeteam](https://github.com/zeyeteam-debug/kryptos-k4-eliminations) | solid for the corpus used |
| Gromark | bases 3–26, primers 2–8, 2.78B primers | 804,684 chance survivors, none fit the width-21 pattern | Barneyjm (reproduces Bean 2021) — [link](https://github.com/Barneyjm/kryptos-k4) | solid |
| Double columnar | width pairs 2–6, 1.5M permutations | 0 | zeyeteam — [link](https://github.com/zeyeteam-debug/kryptos-k4-eliminations) | solid |
| Myszkowski / disrupted / irregular columnar | widths 3–9 / 5–9 / 2–8 (18.6M permutations) | 0 | zeyeteam — [link](https://github.com/zeyeteam-debug/kryptos-k4-eliminations) | solid |
| Turning grille 10×10 | about 42% of one variant, exact search | 0 survivors; rest open | zeyeteam — [link](https://github.com/zeyeteam-debug/kryptos-k4-eliminations) | partial |
| Rotor and mechanical (Hebern, M-209/C-38, Alberti, M-94, Wheatstone, Chaocipher) | see Q1 | 0 / chance | [zeyeteam](https://github.com/zeyeteam-debug/kryptos-k4-eliminations), [Barneyjm](https://github.com/Barneyjm/kryptos-k4) | solid at stated scope |
| KRYPTOS-alphabet double-key Vigenère with dictionary secondary keys | 233,383 English words, 4–17 letters | no BERLINCLOCK | Mireya Jurado, 2021-08-01 — [link](https://sprayonsecurity.com/kryptos-k4-is-not-a-vigenere-cipher/) | solid (narrow) |

### Inferences
- The most reusable "do not repeat" boundaries for our repo:
  - Columnar widths ≤11 with any periodic key ≤26 on the standard or KRYPTOS alphabet.
  - Hill ≤5×5.
  - Autokey with primer ≤96.
  - Periodic with arbitrary alphabets at the provably impossible periods listed above.
  - Running keys on K1–K3, Carter, or Gutenberg-scale English corpora.

### Gaps
- The kryptos.today width-7 and nitsuah widths 15–26 claims come from search snippets only; the pages were not fetched.
- I found no forum (Reddit or groups.io) post with an explicit scope.

---

## 3. What beginner ideas most often get shot down, and what is the standard rebuttal?

### Takeaway
The recurring dead ends:
- "It's just Vigenère with KRYPTOS / PALIMPSEST / ABSCISSA" (rebuttal: no period fits the cribs)
- "It's a transposition" (rebuttal: IoC 0.036 is far below English, so substitution is present)
- "Use K3's method" (double rotation tested at widths 2–96: dead)
- "Running key from K1–K3 or Carter" (chance scores)
- "Berlin Clock lamp states as key" (0 hits across 11k+ states and 1.35M streams)
- "YAR / misspellings as key or mask" (no hits)
- "W = word separator" (artefact)
- "Enigma" (K4 has fixed points; see the own-computation note above)
- Claimed solutions without a verifiable method

### Cited Findings
- **Elonka Dunin's FAQ** lists long-floated ideas: Morse, palindromes, shadows and sundials, Egyptian references, magnetism, folding the sculpture, Jefferson cylinder, ciphertext as book code, Enigma, candlelight, combining the K1–K3 methods. It warns that "that doesn't necessarily mean we've thought of the exact same technique." Its standard rebuttal to claimed solutions: "Most hoaxsters try to claim a solution, or a method without a solution," so share a verifiable partial plaintext with a moderator first. It also says "We'd rather hear the same idea five times, than to not hear a good idea." — [Elonka FAQ](https://elonka.com/kryptos/faq.html)
- **FAQ community history:** a 1999 ABC message board (deleted); sci.crypt as "one of the primary locations for Kryptos discussions through 2003"; the groups.io list at about 2,300 members as of 2020 (subscribe via kryptos+subscribe@groups.io); a Facebook group of about 200 — [Elonka FAQ](https://elonka.com/kryptos/faq.html)
- **Misspellings and extra letters (FAQ):**
  - Sanborn says IQLUSION and UNDERGRUUND are deliberate, with emphasis on their orientation and positioning.
  - The "?" between K3 and K4 may belong to either part, hence 97 or 98 characters.
  - The CIA transcript has errors, and Gwyn's old transcript omitted an L on the tableau side.
  - The Morse "DIGETAL INTERPRETATU" is misspelled or truncated.
  - Source: [Elonka FAQ](https://elonka.com/kryptos/faq.html)
- **YAR / RAY theories (Kryptosfan "K3's YAR," comments 2009–2013):**
  - The raised letters spell RAY or YAR.
  - Commenters tried reading them as YRA (IRA), the K2 keys used in Vigenère *encrypt* mode (producing "CIA"), overlaying the K3 rows (31 wide) on the tableau ("COR," "NER," "corner": a stretch), and selecting the 101 Y/A/R positions on the tableau as a Beaufort one-time-pad mask (Zac S, 2013-11-11, claimed BERLIN).
  - Outcome: nothing confirmed, no breakthrough (weak) — [Kryptosfan YAR](https://kryptosfan.wordpress.com/speculations/typos/k3s-yar/)
  - Systematic follow-up: YAR-shaped masks at period 4–32, and gear trains built from YAR and misspelling letters, both gave 0 or null-level scores — [zeyeteam ledger](https://github.com/zeyeteam-debug/kryptos-k4-eliminations)
- **K3 method on K4:**
  - K3-style double grid rotation applied to K4, ?K4 and padded K4: dead — [Barneyjm](https://github.com/Barneyjm/kryptos-k4)
  - Double rotation at widths 2–96 (72,200 permutations): 0. Chained K1/K2/K3 methods (72,200 transpositions × 96 chains): best 8/24, which is the null — [zeyeteam](https://github.com/zeyeteam-debug/kryptos-k4-eliminations)
- **Berlin Clock (Mengenlehreuhr) and Weltzeituhr:**
  - Mengenlehreuhr and fill-bar lamp masks used as keys, grilles and null masks (11,613 states): 0.
  - DCF77 frames for four dates: 0.
  - Weltzeituhr city-drum running key (128 streams; standard and KA alphabets; Vigenère, Beaufort and Variant): best 8/24 against a null of 6. With columnar 2–7: best 10/24 against a null of 10.
  - Two coupled clocks (3.3e9 window tests): 8/24, chance. Clock vocabulary as keywords (207 words): 0.
  - Caveat: the 1990 plate order of the Weltzeituhr is unavailable, so the 1990 configuration is only partly tested — [zeyeteam](https://github.com/zeyeteam-debug/kryptos-k4-eliminations)
  - 1.35M clock-derived additive streams (lamp counts, rows, bits, HHMM, time zones): best 10/24, the same as shuffled text — [Barneyjm](https://github.com/Barneyjm/kryptos-k4)
  - One solver site lists the Mengenlehreuhr lamp-count projection as ruled out, and one site says Sanborn identified the clock as the Weltzeituhr in November 2025. That claim is single-sourced in my results — [search summary of solvekryptos.com / ciphermuseum.com](https://ciphermuseum.com/ciphers/kryptos.html) (not fetched directly; weak)
- **One-time pad:** the standard rebuttal is that a true OTP is unrecoverable and unreasonable for a public sculpture, so the only viable variant is a running key on a well-known text, and the obvious ones fail at chance level — [HN derekp7](https://news.ycombinator.com/item?id=44907366); [gereon](https://github.com/gereon/kryptos)
- **Claimed solutions:**
  - A GitHub gist debunks a claim that ChatGPT solved K4 — [atoponce gist](https://gist.github.com/atoponce/1cd01f40786ab21af011f0d6257fba0c) (search snippet)
  - Self-published "solutions" on figshare and Medium are not accepted — [figshare](https://figshare.com/articles/dataset/K4_Paper/29969008), [Medium](https://medium.com/@firalim/the-kryptos-k4-scandal-how-ai-exposed-a-35-year-intelligence-community-hoax-26d0e4f4ad0f) (search snippets; listed as hoax-class, not negatives)
- **Context:** in 2025 the K4 plaintext was found in Sanborn's Smithsonian papers by Kobek and Byrne, but the *method* is not public. Scanning K4 statistics without the method stays an open cryptanalytic problem — [RR Auction](https://content.rrauction.com/kryptos-k4-discovered-not-solved-heres-what-actually-happened/); [Scientific American](https://www.scientificamerican.com/article/a-solution-to-the-cias-kryptos-code-is-found-after-35-years/) (search snippets)

### Inferences
- **Standard rebuttal arguments**, compressed:
  1. **Crib keystream:** the 24 implied key values contradict every short period. The own computation shows Vigenère and Beaufort on A–Z have no consistent period ≤26, and the ledgers extend this to arbitrary alphabets at specific periods.
  2. **IoC:** 0.036 is near random (0.038), which excludes pure transposition and mono-substitution plus transposition.
  3. **Running key on obvious texts:** scores sit at chance against shuffled controls.
  4. **Hill 4×4:** the crib-forced key matrices are singular.
  5. **Enigma:** the "no self-encryption" premise is *false*, since positions 33 and 74 are fixed points (own computation). This counts against Enigma-like reflector systems, not for them.

### Gaps
- No Reddit FAQ or sticky could be retrieved. The canonical r/Kryptos rebuttals ("read the FAQ," "post your method with the cribs") cannot be quoted directly.
- I found no community source specifically eliminating Playfair *with scope*. kryptosbot lists Playfair among its families without scope, and Kryptosfan has a Playfair page that I did not fetch. A standard argument is available: K4 has 97 letters (odd) and contains doubled letters (BB at 19–20, QQ at 26–27, SS, ZZ, TT), and a standard Playfair ciphertext has even length and no doubled letter within a digraph. That argument is inferred here, not cited from a community post.

---

## 4. Any FAQ, wiki or sticky posts that summarise dead ends?

### Takeaway
The long-standing community FAQ is Elonka Dunin's Kryptos FAQ. It catalogues ideas floated, community history, transcript errors and misspellings, but **it does not list formal eliminations**. The Kryptosfan "speculations" catalogue is the closest per-family dead-end index. The modern dead-end databases are 2026 GitHub and web ledgers.

### Cited Findings
- **Elonka Dunin's Kryptos FAQ:** ideas, history, hoax policy and transcript errors. It does not eliminate cipher types — [Elonka FAQ](https://elonka.com/kryptos/faq.html)
- **Kryptosfan, "Kryptos – Beyond K4":** per-family "Is K4 a ___?" pages (about 31) plus typo pages ("K3's YAR," "K3's PRNG," "Typos as locators of keywords") — [Kryptosfan](https://kryptosfan.wordpress.com/speculations/substitutions/is-k4-a-vigenere-cipher/)
- **Machine-readable elimination databases:**
  - [gereon/kryptos](https://github.com/gereon/kryptos)
  - [Barneyjm/kryptos-k4](https://github.com/Barneyjm/kryptos-k4)
  - [zeyeteam-debug/kryptos-k4-eliminations](https://github.com/zeyeteam-debug/kryptos-k4-eliminations), which explicitly lists what is still **open**: Hill ≥6×6, Myszkowski and disrupted columnar ≥10, keyed routes, turning grilles beyond 42%, periods 19 and 38 with arbitrary alphabets, pre-1997 Weltzeituhr per-letter lookups, irregular hand masks
  - [kryptosbot.com](https://www.kryptosbot.com/) (597 experiments, with per-experiment records under its Eliminations pages)
  - [keithadler/kryptos](https://github.com/keithadler/kryptos), seen in search only, not fetched
- **groups.io/g/kryptos:** fetch returned HTTP 402, so the archives could not be accessed — [groups.io](https://groups.io/g/kryptos)

### Inferences
- For our negatives database, the most efficient ingest is to mirror the zeyeteam, gereon and Barneyjm ledgers, since they publish explicit scope plus shuffled-null baselines. Elonka's FAQ and Kryptosfan add ideas but not scopes.

### Gaps
- No r/Kryptos wiki or sticky could be fetched (Reddit blocked).
- No Yahoo Kryptos group mirror was found.
- groups.io is paywalled or blocked for the fetcher.
- The Cryptogram/ACA forums turned up nothing in searches. The cryptography mailing list (metzdowd, Aug 2025) has a K4 thread that was not fetched: [metzdowd thread](https://www.metzdowd.com/pipermail/cryptography/2025-August/038977.html).
- Not fetched or verified: Richard Bean's 2021 Cryptologia "cryptodiagnosis" paper (Gromark and width-21 findings, referenced by Barneyjm), and Sanborn's November 2025 open letter (referenced by zeyeteam).
