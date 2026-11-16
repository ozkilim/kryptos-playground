# Sanborn / Scheidt encipherment techniques: documented methods for K4 hypotheses

Compiled 2026-11-15. Scope: methods that are documented as used, taught, or described by Jim Sanborn
or Ed Scheidt, written so each one can be implemented. No K4 plaintext speculation is included.
Quotes are kept under 15 words. "Unverified" means only a secondary source was found.

K4 facts used below: 97 letters. Known plaintext EASTNORTHEAST at positions 22-34 and BERLINCLOCK at
64-74 (1-indexed), ciphertext FLRVQQPRNGKSS and NYPVTTMZFPK.

---

## 0. Status note: 2025-2026 events (affects what the "method" question means)

- Sept 2025: Jarett Kobek and Richard Byrne found K4 *plaintext* scraps in Sanborn's papers at the
  Smithsonian. Sanborn confirmed the text. Per RR Auction (23 Oct 2025), the five pages were 1990 copies
  of sentence strips cut up and taped out of order for CIA reviewers. They were **not** coding charts.
  Sanborn: "They did not solve K4 and they certainly did not find the key."
  Kobek: "There's no way on earth that this is a cryptographic solve."
  Source: https://content.rrauction.com/kryptos-k4-discovered-not-solved-heres-what-actually-happened/ ;
  https://www.scientificamerican.com/article/a-solution-to-the-cias-kryptos-code-is-found-after-35-years/
  (22 Oct 2025, print Jan 2026).
- The strips match Sanborn's own account of the Department of Historical Intelligence: he cut the
  plaintext into sentences and handed them over "mixed up, they weren't in order" (A.J. Jacobs interview,
  2020, https://scienceblogs.de/klausis-krypto-kolumne/files/2020/10/KRYPTOS-Interview-Jacobs.pdf).
  This was a handling step for security review, not part of the cipher.
- RR Auction Lot 2001 (sold 20 Nov 2025 for $962,500) lists "original coding system for K4" and a
  1988 "alternate K4 plaintext and coding chart, now known as K5". RR Auction did not examine the
  materials and gives no technical detail. https://www.rrauction.com/jim-sanborn-kryptos-k4-solution-auction/
- The Smithsonian sealed the archive for 50 years. **The encryption method is still publicly unknown.**
  The work below targets the method.

---

## 1. Sanborn's other cipher works

### 1a. Cyrillic Projector (early 1990s; UNC Charlotte, bought 1997). Solved 2003.

- **Solvers / dates:** Frank Corr found the method in early July 2003 but did not announce it (the output
  was an unbroken "wall of Russian"). Mike Bales found the same method independently in early
  Sept 2003. Elonka Dunin and others produced the first English translation on 20 Sept 2003, announced
  22 Sept 2003.
  Sources: https://elonka.com/kryptos/CyrillicProjectorAnnouncement.html ;
  https://en.wikipedia.org/wiki/Cyrillic_Projector ; sci.crypt / cryptography list,
  https://diswww.mit.edu/bloom-picayune/crypto/14241 (22 Sep 2003).
- **Method (reconstructed by Habr author, 2019; matches the plaque "Vigenere's Tableaux"):**
  The same family as K1/K2: a Vigenère with a keyword-mixed alphabet, which the ACA calls Quagmire III.
  - Alphabet: 32-letter Russian without Ё (Dunin's page confirms 32 characters). Mixed with the keyword
    ТЕНЬ ("shadow"), giving the first tableau row `ТЕНЬАБВГДЖЗИЙКЛМОПРСУФХШЦЧЩЪЫЭЮЯ` + wrap `ТЕН`.
    The tableau is extended past 32 columns, as on Kryptos (ABCD).
    Unverified detail: the transcribed row has `ХШЦЧЩ`, while standard order is `ХЦЧШЩ`. This could be a
    transcription error or a deliberate Sanborn change.
  - Each tableau row is the mixed alphabet shifted cyclically by one.
  - Repeating key: МЕДУЗА (MEDUSA). "MEDUSA" also appears in Latin letters on the ciphertext panel.
  - **The key restarts at "М" at each new block of ciphertext**, even when the block continues the
    previous plaintext.
  - No transposition, nulls, or masking found. The plaintext has misspellings and dropped letters (e.g.
    "ПОВЕДНИЯ"). The Habr author wondered about a second level and found none.
  - Content: KGB agent-handling text, then a KGB memo on Sakharov.
  Source: https://habr.com/en/articles/469717 (and RU original https://habr.com/ru/post/469717/);
  https://elonka.com/kryptos/cyrillic.html (ТЕНЬ named as "at least one of the keywords").
- **Sanborn on how it relates to Kryptos** (Wired, Jan 2005): the code is one of his "common
  denominators" across works but altered. K4 is "a very different animal".
  https://wirednews.pages.dev/2005/01/questions-for-kryptos-creator
- **Relevance to K4: medium.** It shows Sanborn reusing the K1/K2 machine (keyword-mixed tableau +
  repeating key) after 1990, adding **key restart per block** and tolerating misspellings. K4 should
  differ, but key restart and block segmentation are cheap to test.

### 1b. Antipodes (1997, Hirshhorn; smaller 1992 version)

- English side: Kryptos ciphertext reordered K3, K4, space, K1, K2, K3, K4, K1, K2 (truncated). Two dots
  appear that are not on Kryptos (they mark "WW" in K2). The extra-L tableau line and the misaligned
  letters at the start of K3 are Kryptos-only. K4 appears twice; no Antipodes-specific K4 variant letters
  are reported.
- Cyrillic side: most of the Cyrillic Projector ciphertext plus about 20-25% more text, decrypted with the
  same key and continuing the Sakharov document.
  Sources: https://elonka.com/kryptos/sanborn/antipodes.html ; https://en.wikipedia.org/wiki/Antipodes_(sculpture) ;
  Habr article above.
- **Relevance: low-medium.** The repeated K4 confirms the 97-letter ciphertext is stable. Antipodes places
  K4 directly after K3 and before K1. That suggests K4 is treated as a self-contained block, with no
  leading "?" in the ciphertext. The Cyrillic side again uses key continuation and restart.

### 1c. Other works

- *Indian Run* (1995, Greenbelt MD courthouse): projected-text piece. *Binary Systems* (1999, IRS
  Martinsburg): an enlarged computer chip with "stored binary code". *Ex Nexum* (1997/98, Little Rock).
  No cipher method is documented for these. https://art.gsa.gov/artworks/20294/binary-systems ;
  https://en.wikipedia.org/wiki/Jim_Sanborn
- "Code Breaker": no Sanborn work by this name was found. "Lux": not found.
- Kryptos models / maquettes (sold c. 2015 onward): Sanborn left out the tableau's extra "L" on the
  models he sold (Wikipedia, Kryptos). No other documented ciphertext differences.
- **Relevance: low.** *Binary Systems* only supports Sanborn's interest in binary and "changing base"
  (see section 2).

---

## 2. Ed Scheidt's own statements

### 2a. Wired interview, 21 Jan 2005 ("Inside Info on Kryptos Codes")
Mirror: https://wirednews.pages.dev/2005/01/inside-info-on-kryptos-codes (quotes cross-checked on
https://www.kryptools.com.about.ag/hints.htm and https://kryptosfan.wordpress.com/k4/artichoke/masking-vs-english/)
- "There are four different processes." Two are similar and two are different, in increasing difficulty.
- All four sections are in English: "the English language is still visible through the code" in K1-K3.
- K4: "I masked the English language so it's more of a challenge now."
- "you need to solve the technique first and then go for the puzzle."
- "The masking technique may not be known." He keeps the details secret.
- He never checked that Sanborn followed the agreed method. Asked whether Sanborn changed it:
  "possible I guess."
- Even after decryption there may be more encoding on top of the decoded message.

### 2b. NPR, 9 Jun 2005 ("CIA Experts Still Spooked by Kryptos Puzzle")
https://www.npr.org/transcripts/4684720 (WebFetch timed out; read via curl)
- Scheidt explains frequency analysis (E vs Z). The reporter: "in part four he deliberately masked that
  advantage." He helped with the "basic structure" and never tried to break the final message.
- Sanborn nods that all four passages link, and that solving K4 puts you at "the beginning of the puzzle".

### 2c. Kryptos workshop, CIA Langley, 24 Oct 2015 (transcript by Richard Bean on Klaus Schmeh's blog)
https://scienceblogs.de/klausis-krypto-kolumne/kryptos-workshop-transcript/
Some speaker attributions in the transcript are uncertain.
- The math is substitution plus transposition while still "carrying the weight of the language".
- "it lends itself to building layers": methods can be layered and mixed, including transposition.
- "I could have moved to a different math base" (e.g. base 2 to 16). Some felt that would be unfair.
- Mayan example: a simple substitution in base 60, made much harder by adding transposition.
- An extinct or obscure language was considered and judged unfair.
- On whether K4 is one-stage like K1-K3: he "would consider it more than one stage".
- A masking technique was applied so the English would not show. Whether masking came before or after
  encryption was not answered.
- "special characters don't work" and must be accounted for.
- Sanborn wrote the K4 plaintext. Scheidt verified the math of K1-K3 but not K4. Scheidt showed the
  methods and Sanborn chose which to apply.
- Second-meaning words ("coca-cola" example): a code layer inside the plaintext.

### 2d. Statements quoted in Bean (2021), HistoCrypt "Cryptodiagnosis of Kryptos K4"
https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109 (PDF read in full; code at
https://github.com/RichardBean/k4testing). Original sources are private notes or emails, cited by Bean:
- Scheidt (Kryptos dinner, Zola, 2011, per Ed Hannon): K4 crypto is like what was "provided agents or
  pilots in case of capture". It is "not mathematical" (though it can be modelled mathematically),
  "simple, can be remembered", and run years later "with the correct key word/s".
- Scheidt (Jacobs, 2020, quoted by Bean): "if you can change the language base" it is in the encipherer's
  favour. **Not in the published Jacobs PDF, which is Sanborn-only; source unverified.**
- Sanborn (Bogart, 2019): BERLINCLOCK "matches directly" with NYPVTTMZFPK, "a one-to-one match".
  Mailing-list notes from the Oct 2011 and Oct 2013 dinners also record "one-to-one mapping" and that
  "N decoded to B" (kryptools hints page).
- Scheidt also told The Conversation (Bean, 2021) of an intentional "change in the methodology" across
  sections, a difficulty of about 9/10, and an intended solve time of 5-10 years.
  https://theconversation.com/declassified-cold-war-code-breaking-manual-has-lessons-for-solving-impossible-puzzles-161595

### 2e. Wired feature, Apr 2009 ("Mission Impossible")
https://wirednews.pages.dev/2009/04/ff-kryptos
- Scheidt taught techniques from the late 1800s to WWII. They tried **polyalphabetic substitution,
  "shifting matrices", and transposition**, and chose "old-school, artisanal cryptography".
- Scheidt was told to make "something that will last a while", not something unbreakable.

### 2f. Northern Virginia Magazine, 14 Oct 2022
https://northernvirginiamag.com/culture/culture-features/2022/10/14/cia-kryptos-sculpture-cipher/
- **Could not fetch** (HTTP 403 / Cloudflare; web.archive.org blocked for this tool). Search snippets
  only: for K4 they wanted to "make it a real challenge". Scheidt asked the CIA about using an extinct
  language. "Never tempted" to solve it.

### Interpretation of Scheidt's vocabulary (my synthesis, not his words)
- **"Masking"** = a step that removes English letter frequencies before or around the main substitution.
  K4's IC is 0.036, about flat, which fits. Combined with the one-to-one crib statements, the mask must be
  **positional and letter-for-letter**: a non-repeating or long-period additive key, or a per-letter
  re-encoding. A transposition would break the "N decoded to B" alignment.
- **"Changing the language base"** = re-expressing letters as digits in another number base (2, 3, 5, 12,
  16, 20, 60) and operating on the digits. Support: the workshop (base 2 to 16, Mayan base 60), Binary
  Systems, and the Berlin Clock's base-5/base-12 display ("You'd better delve into that particular
  clock," NYT 2014).
- **"Matrix codes" / "shifting matrices"** = Polybius-type grids, letter to (row, col), with coordinates
  shifted or re-indexed per letter. Sanborn: "I did use some matrix codes Ed gave me" (Wired 2005).
- **"More than one stage" / "four processes, two similar"** = K1 and K2 are the two similar ones. K3
  (transposition) and K4 are the two different ones. K4 = primary cipher + mask.

---

## 3. Scheidt / TecSec patents (only hand-executable ideas)

- Edward M. Scheidt holds about 36 TecSec patents, 1993-2015 (Wikipedia). Main family: **Cryptographic
  Key Split Combiner**, e.g. US 6,549,623 B1 (Scheidt & Wack; priority 13 Feb 1997), US 6,608,901 and
  US 6,075,865 (filed 1998). Also "Constructive Key Management" (ANSI X9.69) and "key split binding"
  (US 7,079,653).
  https://patents.google.com/patent/US6549623 ; https://patents.google.com/patent/US6608901 ;
  https://patents.justia.com/inventor/edward-scheidt (403, not read)
- What it describes: the working key is never stored. It is **built by combining several partial keys
  ("splits")**: random, token/label, organization, maintenance and biometric data. Each split is
  randomized, then the splits are combined, using XOR among other steps, into a key "symbol stream,
  symbol blocks, or a key matrix". "Labels" carry access rules and select which splits apply.
- Hand analogue (inference): **compound / additive key.** Running key k[i] = (k1[i mod L1] + k2[i mod L2]
  + ...) mod 26, from two or three remembered keywords. This matches "remembered and executed years later
  with the correct key word/s" and gives a long effective period (lcm) that hides periodicity.
- Dates: the patents are 1993 onward, after Kryptos (1989-90), so they reflect his thinking at most.
  **Relevance: low-medium.**

---

## 4. Physical coding charts and worksheets

- **K1 worksheet** (NYT, 20-21 Nov 2010): three-line clusters of plaintext, repeated key, ciphertext. Sanborn
  says the tableau was "slightly different" from the carved one and was used "like a mileage chart":
  key letter on the left, plaintext across the top, cipher letter at the intersection. The key header
  reads "PALIMPCEST" (C for S), which explains IQLUSION as a key error. Several overwritten corrections.
  https://inteltoday.org/2019/11/25/kryptos-analysis-of-jim-sanborn-k1-worksheet
- **K3 worksheet** (photographed, published by 2020): step 1 is plaintext in a **42-wide by 8-high grid**
  (336). Step 2 copies it into a **14 by 24 grid** along a rotated path starting at the bottom-left of
  step 1. This is the double grid rotation, done by hand.
  https://inteltoday.org/2020/04/24/kryptos-analysis-of-sanborn-k3-worksheet-a-clue-to-decode-k4
- **"31-column worksheet layout":** no source found for a 31-column *worksheet*. The **carved K4 rows**
  are 31 wide: cipher panel row 24 ends `...?OBKR`, and rows 25-27 are exactly 31 letters each, while
  other rows range from 29 to 33 (data/sculpture_layout.json from the elonka.com transcript). Klaus
  Schmeh's CNN-documentary post (2019) also splits K4 as 4 + 31 + 31 + 31.
  https://scienceblogs.de/klausis-krypto-kolumne/2019/03/15/cnn-documentary-about-kryptos-a-making-of-report-with-many-photographs/
  Whether Sanborn enciphered K4 in 31-wide rows is unknown. Any row-restart hypothesis would use
  boundaries at 4 / 35 / 66 (1-indexed starts 1, 5, 36, 67).
- **RR Auction** lists coding charts for K1-K3, the "original coding system for K4", and a 1988 alternate
  K1 chart and alternate K4 (K5) chart, with no technical description.
- **Mistakes:** "most of my things are rife with mistakes on purpose" (Wired 2005). Some errors were also
  unintentional: "There was nobody I could ask to proofread" (Jacobs 2020). **Solvers should allow
  1-2 symbol errors.**

---

## 5. Known K1-K3 algorithms (reference baselines)

- **K1/K2 (Quagmire III):** alphabet A* = KRYPTOSABCDEFGHIJLMNQUVWXZ. Encrypt
  c = A*[(idx(p) + idx(k)) mod 26] with idx in A*. Keys PALIMPSEST (K1) and ABSCISSA (K2).
- **K3:** double rotation. Decrypt = write the 336-letter ciphertext in rows of width 24, rotate 90°
  clockwise, rewrite at width 8, rotate again, read rows. Implemented in `kryptos/ciphers/transposition.py`
  as `rotation_decrypt(ct, 24, 8)`. NSA described it as keyed columnar on a partly filled 4×86 grid;
  Gillogly as KRYPTOS key order 0362514 with a reversal.

---

## 6. Research findings that constrain method choice

- Bean (2021): Monte Carlo on the cribs gives strong evidence of **one-to-one, letter-for-letter
  substitution with no transposition**.
  - Minor differences: where a plaintext letter is in {K,R,Y,P,T,O,S}, the ciphertext letter is within
    about 2 places in the standard alphabet. p ≈ 1/5,520.
  - Repeated plaintext letters map to nearby ciphertext letters. p ≈ 1/240.
  - At width 21 there are 11 repeated vertical bigrams. p ≈ 1/6,750.
  - Base ≥ 3 is needed for Gromark (some plaintext letters map to 3 different cipher letters).
  - If a periodic key is used: T→V at 0-based position 24 and L→V at 66 imply the key period is not
    21 or 42. Periods 63 or 84 remain possible.
  - Footnote: with plaintext indexed in the standard alphabet and ciphertext in the reversed KRYPTOS
    alphabet, 13 of 24 values of (p − c) mod 26 are multiples of 5 (p ≈ 1/1,470). Bean suggests 5×5
    Polybius or conjugated-matrix bifid; he searched and found nothing.
- Bauer, Link & Molle, "James Sanborn's Kryptos and the Matrix Encryption Conjecture", Cryptologia 40(6),
  2016, pp. 541-552: they read the tableau's extra L (and HILL) as pointing to a **Hill cipher**. Bean
  argues against it: 97 is prime, and the cribs are one-to-one.

---

## Testable techniques

| technique | algorithm | parameters | relevance | source |
|---|---|---|---|---|
| **Gromark / Vimark (lagged-Fibonacci additive key)** | Expand primer d0..d(n-1) by d(i) = (d(i-n) + d(i-n+1)) mod b up to 97 digits. c = C[(P⁻¹(p) + d(i)) mod 26], where P and C are plain and cipher alphabets (standard, KRYPTOS-keyed, or reversed). Variants: other tap rules (Beker-Piper shift registers); base 26 = Vimark. | base b ∈ {3..26}, especially 5, 8, 10, 12. Primer length 4-6. Bean's crib-consistent base-10 5-digit primers: 39, including 26717, 84393, 98800. Base-10 4-digit: 3301, 6740, 9903. Base-8 5-digit: 00351, 00537 (period 84). | **High** ("more than one stage", "simple, can be remembered", agent field cipher, flat IC, width-21 phenomenon, base arithmetic) | Bean 2021 HistoCrypt; Scheidt workshop 2015; Hannon 2011 via Bean |
| **Change of language base: digit-wise masking** | Map each letter to its index in alphabet A (KRYPTOS-keyed or standard), write it as m digits in base b, add key digits mod b with no carry (keyword digits, clock-derived, or Gromark stream), convert back to a letter. This is letter-for-letter, so it keeps the cribs aligned. Variant: Polybius 5×5 / 6×5 coordinates with per-coordinate shifts. | b ∈ {2, 3 (27 cells = 26 + "?"), 5 (5×5 + 1), 12, 16}. Digit key from keyword(s) or Berlin-Clock (Mengenlehreuhr) base-5 lamp counts. | **High** (Scheidt "change the language base", "mask", base 2/16/60; Berlin Clock base 5/12; Bean's multiple-of-5 footnote) | Workshop 2015; Jacobs 2020 via Bean; NYT 2014 clock quote; Bean footnote 2 |
| **Keyed-tableau Vigenère (Quagmire III) with non-periodic or compound key** | K1/K2 machine. Key = sum mod 26 of 2-3 periodic keywords (key-split combiner analogue), or a running key from a text. Check crib keystream positions for an lcm-period structure. | KRYPTOS alphabet. Component keywords from the Kryptos corpus (KRYPTOS, PALIMPSEST, ABSCISSA, BERLIN, CLOCK, SHADOW, MEDUSA...). Lengths coprime to give period 63/84-type. | **Medium-high** (Sanborn's "common denominator", Scheidt "key word/s", K4 = 2 similar + 2 different processes) | Wired 2005; Bean 2021; TecSec US 6,549,623 |
| **Key restart per block / row (Cyrillic Projector rule)** | Same keyed Vigenère, but restart the key at each segment: carved rows (starts 1, 5, 36, 67), sentence or phrase boundaries, or 7- and 21-wide blocks. Combine with an alphabet-per-block change ("change in methodology"). | Segment boundaries; key word; alphabet keyword (KRYPTOS / other). | **Medium** | Habr 2019 Cyrillic Projector solution; carved row widths |
| **Shifting matrix (Polybius with moving coordinates)** | Keyed square (5×5 merging two letters, 6×5, or 3×3×3). Encrypt each letter's (r, c) to ((r + a_i) mod R, (c + b_i) mod C), where (a_i, b_i) follow a schedule (keyword coordinates, counters, clock). Letter-for-letter. Also test conjugated-matrix bifid restricted to 1-letter periods. | Square keyword (KRYPTOS); dimensions; shift schedule. | **Medium** ("shifting matrices", "matrix codes Ed gave me"; 26 letters in the ciphertext rule out a pure 5×5 unless merged) | Wired 2009 feature; Wired 2005 Sanborn |
| **Substitution + mask, error-tolerant** | Any of the above with an extra step (mask before or after) and 1-2 deliberate or accidental symbol errors. Score allowing up to 2 crib mismatches. | Error budget 1-2; insertion or deletion possible (K2 dropped S/X; K1 key misspelled). | **Medium** (method-agnostic; protects against false negatives) | Wired 2005 "rife with mistakes"; NYT 2010 K1 worksheet; Jacobs 2020 |
| **Hill / matrix multiplication** | c-vector = M · p-vector mod 26 over blocks of size n (pad to a multiple of n). | n = 2 or 3; M from a keyword (HILL / extra-L hint). | **Low** (97 is prime; one-to-one crib alignment conflicts) | Bauer-Link-Molle 2016; Bean 2021 rebuttal |
| **Double rotation / columnar transposition layer (K3 machine)** | rotation_decrypt with widths (w1, w2) or keyed columnar, combined with substitution. Must leave the crib positions consistent with the "N decoded to B" statements. | Widths dividing or fitting 97 or 98, e.g. 7×14 with "?". | **Low** (Bean MC and Sanborn's one-to-one statements argue against; Scheidt's workshop says layering with transposition is possible) | K3 worksheet; workshop 2015 |
| **Codeword / second-meaning layer** | Words in the decrypted text stand for other meanings (coca-cola example); "riddle within a riddle". Not testable at the cipher level. | none | **Low** for cipher search | Workshop 2015; Jacobs 2020 |
