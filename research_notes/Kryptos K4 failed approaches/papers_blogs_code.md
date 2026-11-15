# Kryptos K4: systematic computational attacks in papers, blogs and open-source code, and what each ruled out

Research date: 2026-11-15. Positions are 1-indexed unless a source says otherwise (Bean 2021 numbers positions 0–96).
Confidence labels: **solid** = exact or exhaustive elimination against the 24 crib letters, reproducible code, validated on planted ciphers. **weak/partial** = bounded, heuristic or informal. **disputed** = conflicting sources or unverified claims.

Context that changes how to read every result (2025–2026):
- Journalists Jarett Kobek and Richard Byrne found K4's *plaintext* on scraps in Sanborn's papers at the Smithsonian Archives of American Art and emailed Sanborn on 3 Sep 2025. They did **not** recover the encryption method. RR Auction said they "do not possess the method by which K4 was encoded" — [Scientific American](https://www.scientificamerican.com/article/a-solution-to-the-cias-kryptos-code-is-found-after-35-years/); [Citizen Digital / wire](https://citizen.digital/article/auction-of-famed-cia-cipher-shaken-after-archive-reveals-code-n373254)
- Sanborn auctioned the K4 solution (handwritten plaintext plus a copper proof-of-concept piece) through RR Auction on 20 Nov 2025, estimated at $300k–500k — [Schneier on Security, 21 Aug 2025](https://www.schneier.com/blog/archives/2025/08/jim-sanborn-is-auctioning-off-the-solution-to-part-four-of-the-kryptos-sculpture.html)
- Paradigm, the new steward, post dated 12 Jun 2026: answers are checked against Sanborn's solution through a SHA256 + Google Cloud KMS HMAC tag. Each submission costs $1. There has been an "explosion" in AI-assisted attempts but "none have succeeded yet." Paradigm holds the K5 ciphertext (97 characters, made at the same time as K4) and plans to release it, with no date given — [Paradigm, "Project Kryptos"](https://www.paradigm.xyz/writing/kryptos). (Caveat: my fetch summarized the custody chain inconsistently, so check the exact provenance wording on the page.)
- Implication: the method is still publicly unknown, so every negative result below still matters for a method search. The 2025 plaintext find also means **no** published method is known to reproduce K4.

---

## 1. Academic papers that analyse K4, and what they ruled out

### Takeaway
The only substantial peer-reviewed cryptanalysis of K4 is Richard Bean's "Cryptodiagnosis of Kryptos K4" (HistoCrypt 2021). It argues statistically against transposition, shows that crib constraints kill seriated Playfair and digraphic ciphers, and exhaustively narrows base-10 five-digit Gromark to 39 primers, with no convincing plaintext found. The other journal item is Bauer, Link and Molle (Cryptologia 2016), which *proposed* a Hill cipher. Later blog and code work refuted it. I found **no** arXiv, IACR ePrint or Lasry paper on K4.

### Cited Findings

**Bean, R. (2021) "Cryptodiagnosis of 'Kryptos K4'", HistoCrypt 2021, Linköping Univ. Electronic Press.** Code: github.com/RichardBean/k4testing — [paper page](https://ecp.ep.liu.se/index.php/histocrypt/article/view/153); [PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
- *Statistics (all from the PDF):*
  - K4 IoC = 336/97/96 = **0.03608**, which is "flat" (1/26 = 0.03846). Seriated Playfair would typically give 0.048 ± 0.003 (Mason's ACA stats) — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Width-21 repeated vertical bigrams:** 11 repeats among 76 vertical bigrams (AZ BS IT LS LW PK QZ SN WA ZT KK). Monte Carlo permutation of the ciphertext gives this or more in about **1 in 6,750** shuffles. Typical English written at width 21 averages 9.7 (KJV 97-letter windows). Earlier observers: Hannon 2010, LaTurner 2016, Kirchner 2003 — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Width-7 doublets:** BB, QQ, SS, ZZ, TT fall in the same columns at width 7. An NSA analyst (2007) and Gillogly (1999) suggested polyalphabetic substitution plus transposition — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **"Adjacent / offset letter difference" claim (Stehle 2000, sci.crypt):** in segment DIAWINFBN, each of the first five letters minus the letter four positions to its right is 5 (mod 26). Bean calls this unusual but harder to measure or exploit and does not test it — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Materna (2020) "minor differences":** for crib plaintext letters in {K,R,Y,P,T,O,S}, the 10 plain-to-cipher distances in the standard alphabet sum to 21 (mean 2.1). Permutation test: about **1 in 5,520** — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Ciphertext letters for repeated plaintext letters** (A,C,E,L,N,O,R,S,T, 13 distances): mean 3.6, and 10 of 13 are below 5. Permutation p ≈ **1/240** (mean) and **1/310** (count). In the Kryptos alphabet, 7 of 13 distances are multiples of 5. With plain numbered by the standard alphabet and cipher by the reversed Kryptos alphabet, 13 of 24 (plain − cipher) values are multiples of 5, p ≈ **1/1,470**. Bean says this might suggest 5×5 Polybius methods (conjugated matrix bifid), "but nothing was found" — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - Bean's conclusion: these properties "strongly suggest that 'one-to-one' encryption of single letters to single letters is occurring; that is, there is no transposition" — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
- *Eliminations:*
  - **Seriated digraphic cipher (seriated Playfair, Doppelkasten) at width 21:** ruled out. Two different plaintext bigrams ending in I and N would both map to "ZT". CLOCK's K→K kills standard Playfair on vertical bigrams. **solid** — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Seriated digraphic at width 7:** ruled out. Plaintext bigrams ending in N and O would both map to "BQ". **solid** — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Standard Playfair:** ruled out by the 26-letter ciphertext, the KK doublet, the odd length 97, and K→K. **solid** — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Hill cipher (Bauer et al. 2016):** argued against because 97 is prime. **weak** (argument only) — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Gromark with a standard A–Z plaintext alphabet:** ruled out. Plain C and R both map to cipher P but are more than 10 places apart. **solid** — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Periodic Gromark keys:** plain T→V at pos 24 and L→V at pos 66 (0-indexed) mean the key does not repeat at period 21 or 42 (63 or 84 remain possible). The base must be ≥3, because some plaintext letters encipher to at least 3 cipher letters — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Gromark base 10, primer length 5 (exhaustive):** 99,999 non-zero primers. Constraints were 21 key-digit inequalities plus 1 equality from the cribs, leaving 1,040. A SageMath Gröbner basis added 14 inequalities and 1 equality, leaving **39 primers**. 26717 and 84393 are equivalent (inverse keys). The best Blackman per-digit IoC was primer 98800 (0.0625). Plain and cipher alphabets were allowed to vary, fitted by simulated annealing with hexagram scoring. "Many plaintexts close to ordinary English were discovered, none were entirely convincing." **solid for the primer reduction; partial for the alphabet search** (heuristic) — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - **Other bases and lengths:** the only possible base-10 four-digit primers are 3301, 6740 and 9903. Four base-8 five-digit primers remain, including 00351 and 00537 (period 84, with odd/even columns at widths 7 and 21). Other key-expansion rules were also tried, limited to rules that use the first primer digit (Beker & Piper). None was convincing. **partial** — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
  - Bean estimates Gromark unicity distance at about 48 letters, so a solution at length 97 would be unique — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)

**Bauer, Link & Molle (2016) "James Sanborn's Kryptos and the Matrix Encryption Conjecture", Cryptologia 40(6):541–552.** It proposes a Hill cipher for K4, based on the extra "L" in the tableau (a "HILL" reading). This is a hypothesis, not an elimination — cited in [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109) and [Schridde blog](https://www.numberworld.blog/2017/03/kryptos-cipher-part-2.html). Refuted by later work (Schridde, keithadler; see §2–3). **disputed → effectively refuted for 2×2/3×3**

**Redacted NSA analyst (2007) "The CIA Kryptos Sculpture: A summary of previous work and new revelations…"**: cited by Bean for the width-7 doublet observation — [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109). Related declassified NSA document: [media.defense.gov DOC_7.PDF](https://media.defense.gov/2021/Jul/12/2002760458/-1/-1/0/DOC_7.PDF). (I could not read it: HTTP 403.)

**Bean (2020) "The use of Project Gutenberg and hexagram statistics to help solve famous unsolved ciphers"**, HistoCrypt 2020. This is the scoring method behind the 2021 annealing — cited in [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)

**Self-published "solutions" (not peer reviewed, all unverified):** Glanz 2025, "Genie Replication Package: Resolution of Kryptos K4 via Berlin Clock Route and Substitution Funnel"; Salcedo Novoa 2026, "Definitive Plaintext Solution" (Academia.edu). A Zenodo Nov 2025 photometric study explicitly makes no cryptographic claim — [asren aggregator](https://asren-aggregator.asren.net/Record/Manara_ce2fbb5d0997af3dcce98a9fbb71a72e); [Academia.edu](https://independent.academia.edu/MSalcedoNovoa); [Zenodo](https://zenodo.org/records/17620625). **disputed** (none confirmed by the Paradigm verifier as far as I can find)

### Inferences
- Bean's anti-transposition argument rests on permutation tests at about 1/240 to 1/6,750. These were *chosen after looking at the data* (Bean quotes Good on "kinkera"), so the evidence is real but not conclusive. Transposition plus substitution is not proven impossible.
- Bean's Gromark result leaves room open. With **arbitrary** plain and cipher alphabets, 39 base-10 primers survive the cribs and were only checked by annealing. keithadler's "digit keys ruled out" result (§2) covers only A–Z, KRYPTOS and dictionary alphabets. The two do not conflict, but the arbitrary-alphabet Gromark space has not been closed.
- The width-21 repeat property has a natural Gromark explanation (even base, five-digit primer gives a length-21 key structure; Deavours 1977, Blackman 1989), as Bean notes.

### Gaps
- No Cryptologia article on K4 cryptanalysis other than Bauer et al. 2016 turned up in searches. I could not access Cryptologia's index directly.
- No arXiv or IACR ePrint K4 paper was found. No George Lasry or CrypTool (Esslinger) K4-specific publication was found; searches returned nothing.
- The NSA 2007 summary and the declassified DOC_7 could not be fetched (403), so their list of eliminations is not captured here.
- Bean's GitHub repo (RichardBean/k4testing) was not opened, so the full inequality set and the exact list of expansion rules tried are not captured.

---

## 2. GitHub / open-source repos running large K4 searches

### Takeaway
The best-scoped public negative result is **keithadler/kryptos** (status 2026-09-29). It gives exact crib-constraint eliminations, validated on 21 planted ciphers and calibrated against random ciphertexts. It covers repeating, progressive and autokey tableau ciphers, columnar transposition up to width 14 with every column order, general Quagmire I–IV with arbitrary alphabets, Hill, Trifid, 5×5 ciphers, two-layer periodic, and large running-key corpora. **reggiechan74/kryptos-k4** (Oct–Nov 2026) adds bounded study-by-study exclusions. Most other repos are toy brute forcers with no stated scope. Your repo's eliminations are largely a subset of keithadler's, which even uses the same 209k dictionary-alphabet count.

### Cited Findings

**keithadler/kryptos: "A documented search of Kryptos K4: what the 24 released plaintext letters rule out, verified against planted ciphers"** (SEARCH.md status 2026-09-29, release v1.0.0 2026-09-29, MIT) — [repo](https://github.com/keithadler/kryptos); [SEARCH.md](https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md); [release](https://github.com/keithadler/kryptos/releases/tag/v1.0.0)
- *Method:* a family is ruled out only if no key reproduces all 24 crib letters ("a proof"). Survivors are compared with the chance rate (about 26^-c for c constraints). Calibration repeats each test on random ciphertexts with the same cribs. `make verify` runs 21 planted-cipher recovery checks (all pass, about 25 s). Simulated annealing with quadgram scoring is used only where it recovered planted ciphers.
- *Assumptions:* the 97 letters as carved, with no nulls (except a typo pass); crib positions are plaintext and pre-transposition positions; the "?" belongs to K3; alphabets are A–Z, the KRYPTOS-keyed alphabet, or arbitrary where stated; "tableau" = Vigenère or Beaufort × 8 alphabet families; variant Beaufort has the same survivors as Vigenère.
- *Stats reported:* IoC 0.0361. Plain R→cipher P at positions 28 and 66 (38 apart = 2×19). Self-encryption K→K at position 74.
- **Repeating key, lengths 1–26, all 8 families: RULED OUT.** Lengths ≥27 are not constrained by the cribs. **solid**
- **Progressive key K[i mod p] + s·⌊i/p⌋, p ≤ 26: RULED OUT** (only one-constraint survivors at p=26, as chance predicts). **solid**
- **Autokey, ciphertext- or plaintext-keyed, every lag: RULED OUT.** **solid**
- **20 theme-word alphabets** (PALIMPSEST, ABSCISSA, WELTZEITUHR…) × 8 families: ruled out. The best survivors hold 3 constraints, against about 30 expected by chance. **solid**
- **Dictionary-word alphabets, 209k words × 5 arrangements, Vigenère and Beaufort: RULED OUT.** All 68k survivors sit at p=26 on one constraint. **solid**
- **Typo tolerance** (one wrong crib letter, or 1–3 letters inserted or dropped) for repeating, progressive and running keys: 580 survivors vs 516 expected, none above 2 constraints. Ruled out. **solid**
- **Digit keys (Gronsfeld, Gromark, any 0–9 keystream)** over A–Z, KRYPTOS and all dictionary alphabets: ruled out. No alphabet makes all 24 shifts digits (best 21/24). **solid within those alphabets** (it does not cover Bean's arbitrary-alphabet Gromark)
- **World Clock keys repeating every 12 or 24:** 24 faces plus the 24-lamp set-theory clock. Ruled out as special cases of repeating keys. **solid**
- **Running keys:** K1, K2 and K3 plaintexts, the whole carved left side and the tableau, forward and reversed, every offset, 8 families: ruled out. K1–K3 with an **arbitrary (26!) alphabet on one side**, using carved, corrected and pre-2006 spellings (including "IDBYROWS") and the carved K1–K3 ciphertext: 141k tests, **0 survivors**. **solid**
- **Running-key corpora:** Carter's *Tomb of Tut-ankh-Amen* vols 1–3, King James Bible, Declaration of Independence, Constitution, Bill of Rights, Poe vol 1, and a 1923 Tutankhamen account. 8 families, OCR- and typo-tolerant, **149M offsets**. Best 9/24 key letters, which chance reaches about 36 times at this scale. A planted Carter key with 2 typos scores 22/24. **solid within the corpus**
- **Columnar transposition + repeating tableau key:**
  - Every column order at widths 2–11; read down, up or alternating; forward and inverse; key before or after; key length 1–26. **44M column orders, 110 billion combinations: RULED OUT.**
  - Widths 12–14: pruned search, which matches brute force at width 7. 2.9B / 21B / 276B nodes. Width 14 left 3 near-identical orders at 8 constraints, which decrypt to gibberish. **solid**
- **Keyword-ordered columnar, widths 12–30:** 115k dictionary words, names and theme phrases, 287M combinations. Ruled out. **solid within the keyword list**
- **K3-style grid rotation** (one rotation, or two at any pair of widths): 30M combinations, ruled out. **solid**
- **Hill 2×2, 3×3 and 4×4, A–Z and KRYPTOS indexing:** ruled out, except 4×4 at two block alignments the cribs cannot test. Under the guessed cribs OF or IS, all four 4×4 alignments are eliminated. **solid** (the 4×4 part is conditional)
- **Trifid:** any 3×3×3 cube, periods 2–24, every group offset. 299/299 cases unsatisfiable. **solid**
- **Bifid, Playfair, two-square, four-square, ADFGX:** ruled out outright, because K4 uses 26 letters and a 5×5 square outputs 25. **Playfair, Porta, and any cipher that cannot map a letter to itself:** ruled out by K→K at position 74. **solid**
- **General Quagmire I/II (arbitrary alphabet), key lengths 1–26:** ruled out at 1–12, 14, 15, 17, 18, 21, 22, 25 (some variants also 13, 20, 23). The other lengths hold ≤1 constraint, so the cribs cannot test them. **solid for the listed lengths**
- **General Quagmire III, Vigenère form:** ruled out at every length 1–26. **Beaufort form:** ruled out at 1–12, 14–17, 19–22, 24, 25. **13 and 18 unresolved** after a 30-minute timeout. 23 and 26 are satisfiable, but 10–27 of 30 random ciphertexts are too. **solid / partial**
- **General Quagmire IV (two independent alphabets):** ruled out at 1–7, 9, 10, 15, 17, 22, 25. Satisfiable at 8, 13, 16, 19, 20, 23, 24, 26, but random ciphertexts pass at similar rates (uninformative). **partial**
- **Two layers (K1/K2 cipher twice), repeating keys a ≤ b ≤ 26, same alphabet, any Vigenère/Beaufort mix:** solved exactly as linear equations mod 26. Ruled out at all **932 testable length pairs**. 2 consistent pairs (1 constraint each) vs about 4 expected. **472 pairs have too many unknowns.** **solid / partial**
- **English-scored annealing:** recovers planted Quagmire I (L = 13, 16, 20, 24) and Quagmire II (L = 13, 16) at 88–97/97 letters. K4 at those settings scores no better than random ciphertexts (−4.6 to −5.7 vs −4.8 to −5.5 per quadgram). Not informative for two free alphabets at L=8, Quagmire II at L ≥ 20, or Quagmire I at L=26. **partial**
- **Conditional, guessed cribs** (THE at 61–63, OF at 35–36, IS at 75–76): no guess beats the random-text rate. 52 theme words were slid across open positions against repeating keys of length 27–48: 23 survivors vs 109 expected. **weak** (conditional)
- **Explicitly open, per the repo:** two free alphabets at once; keys longer than 26; stacked layers with long keys; hand "masking" methods; other running-key texts; 1990 World Clock city names; typo-tolerant transposition; keyed **double** columnar; route ciphers other than columns and rotations; fractionation on a 6×6 square — [SEARCH.md](https://raw.githubusercontent.com/keithadler/kryptos/main/SEARCH.md)
- *Keystream derived from the repo's crib table (A=0, cipher − plain for Vigenère, cipher + plain for Beaufort):* Vigenère EAST=BLZC, NORTHEAST=DCYYGCKAZ, BERLIN=MUYKLG, CLOCK=KORNA. Beaufort EAST=JLJO, NORTHEAST=DEGKUKKKL, BERLIN=OCGGBG, CLOCK=OKTRU. (The fetch tool derived these from the clue table; recheck them locally.) Vigenère BERLINCLOCK = MUYKLGKORNA matches Schridde's independently reported "MUYKLGKOR" for the standard tableau — [Schridde](https://www.numberworld.blog/2017/03/kryptos-cipher-part-2.html)

**reggiechan74/kryptos-k4: "Reproducible Kryptos K4 research: sources, confirmed clues, hypotheses, and bounded experiments"** (dated docs 2026-10-18 to 2026-11-01). No solution claimed; reports "finite negatives, unresolved computation, and evidence-blocked models" — [repo](https://github.com/reggiechan74/kryptos-k4)
- Candidate-first 051 (32-message pilot) and 052 (1,024-message structural-key bank): all target gates failed. 053: ordinary-language running-key model and corpus failed all 4 criteria. 054: exact source lookup in an **89-document frozen corpus**, zero matches. 055: calibrated English-key fragment screen, 0/12 target pairs survive (heuristic). **weak/partial**
- 056: periodic key plus column route, frozen A–Z Vigenère → ragged columnar: "complete exclusion within frozen family." 057: alphabet-role and Beaufort extensions, bounded exclusion. 058: reverse-stage columnar plus periodic arithmetic, key-cylinder exclusion. **partial** (exact bounds were not visible on the landing page)
- 059: short-primer subtractive feedback, bounded exclusion (the subtractive feedback itself is untested). 064: recurrence-distance key clock, 6 periods excluded plus period 5 newly incompatible. **partial**
- Fold-slide 2D (rows −28…+28, columns −33…+33, two registrations): no excess over whole-search controls. SIGABA synthetic inference failed its resource gate (not a K4 result). Four-family program: no compatible K4 candidate "within its frozen bounds… not broad cipher-family exhaustion." An 810-cell source audit is complete, with 4 cells unresolved — [repo](https://github.com/reggiechan74/kryptos-k4)

**stblake/colossus** (the account name suggests Sam Blake of the Z340 team, but the page does not name him): a shotgun hill climber with backtracking for Vigenère, Gronsfeld, Beaufort, Porta, Quagmire I–IV, autokey, homophonic, Playfair, Bifid, Trifid, Hill, Phillips, two- and four-square, and many transpositions (columnar, double columnar, AMSCO, Myszkowski, Cadenus, route, turning grille…). Its stated purpose is K1–K4. **It reports no K4 result**; the examples cover K2 only — [repo](https://github.com/stblake/colossus). No scope or null result, so it cannot count as an elimination.

**Small or unscoped repos:** rbobillot gist (Vigenère-variant brute force, prints "NO SOLUTION YET"); postrv/kryptos-rs; ElodineOfficial/KryptosK4 (author says later steps "do not shake out in pen and paper"). None states a scope — [rbobillot gist](https://gist.github.com/rbobillot/5a4936702e3f8c58c601958ba3afbcb8); [kryptos-rs](https://github.com/postrv/kryptos-rs); [ElodineOfficial](https://github.com/ElodineOfficial/KryptosK4). **weak**

**"Asynchronous" blog, 3 Apr 2025:** chained ciphers, with Vigenère keyed by **every 8-letter English dictionary word**, Python then Rust (about 3h48m). "No matches." Code written with help from Gemini 2.5 Pro — [blog](https://asynchronous-x-github-io.pages.dev/post/attempting-kryptos-k4). **weak** (the other cipher types are not named)

### Inferences
- For your repo, these overlap with keithadler and add nothing new: dictionary Vigenère/Beaufort keys, columnar 2–8 plus period ≤12, autokey, K1–K3 running keys, and dictionary Quagmire alphabets. keithadler already covers wider scopes, including arbitrary-alphabet Quagmires, widths up to 14 with every order, and key length to 26.
- Real gaps left open by everyone: keyed **double** columnar and general route/irregular transposition combined with substitution; arbitrary-alphabet Quagmire III-Beaufort at L=13 and 18 (timed out); Quagmire I/II at the untestable lengths (13, 16, 19, 20, 23, 24, 26) where cribs give ≤1 constraint; Gromark or other LFSR/lagged-Fibonacci keys with **arbitrary** alphabets, non-standard bases, or other expansion rules (Bean's 39 primers were only annealed); 6×6 fractionation; non-periodic, long or one-time keys from untested texts; "masking" or null and extra-character models.

### Gaps
- I did not inspect the repos' evidence logs, so I could not re-verify any count independently. The numbers above are the authors' own claims.
- I found no repo that reports a SAT/SMT-based K4 search under its own name. keithadler uses exact linear and constraint solving plus C searches, but SAT is not mentioned.
- Exact per-study bounds for reggiechan74 (key spaces, widths) live in linked receipt files that I did not open.

---

## 3. Blogs and forums documenting systematic eliminations and near-misses

### Takeaway
The blog record mostly holds small, explicit eliminations: Hill 3×3 at the BERLINCLOCK block, Wichmann–Hill PRNG seeds ≤50, and tableau-derived running keys. It also has many single-crib "fits" that fail to extend, which are classic near-misses. Nick Pelling's Cipher Mysteries gives only informal reasoning. Schneier's 2025 thread has no systematic work.

### Cited Findings

**Christian Schridde, NumberWorld, "Kryptos – The Cipher (Part 2) – K4 abnormalities and solution attempts"** (URL dated Mar 2017, comments 2018–2024) — [blog](https://www.numberworld.blog/2017/03/kryptos-cipher-part-2.html)
- **Hill 3×3, A=0…Z=25, block at the BERLINCLOCK position 64:** Det(S)·20 ≡ 23 (mod 26) has no solution. **ELIMINATED. solid** (narrow scope)
- **Hill 3×3, A=1…Z=26:** solvable mod 13. Lifting to mod 26 over all 2^9 choices gives no valid solution. **ELIMINATED. solid**
- Hill with keyed alphabets (KOMITE…, SANBOR…, JIMSANBOR…, CIPHER…) and the KRYPTOS alphabet: no further English. **weak**
- **Running key from the tableau:** the standard tabula recta key for BERLINCLOCK is "MUYKLGKOR"; the sculpture tableau key is "SYMLWRHZN". Neither is English, so a book source was not pursued. **partial**
- **Wichmann–Hill PRNG running key:** seeds 0 ≤ s1, s2, s3 ≤ 50 only (the full space is about 30,000³), with Vigenère and various alphabets. No hit. **weak** (tiny fraction of the space)
- CryptoCrack cipher-type identification ranked Running Key first, ahead of Quagmire 2. Gillogly saw likely periodicity only at period 25, possibly chance. **weak**
- Abnormalities noted: KRYPTOS letters clustered at the right of rows 25–28 (also Elonka Dunin, DEF CON 12). In a 7×14 grid, all doubles but one fall in the last two columns, estimated p ≈ 0.01–0.1%. M and Y are the only singletons, and both appear in NYPVTTMZFPK.
- **Near-miss reported second-hand:** "Scott" used the first 11 characters of K1 as a Quagmire III key and reportedly got BERLIN at positions 64–69. It did not extend, and keithadler's exact Quagmire III search now rules out the general case. **disputed/noise**

**Nick Pelling, Cipher Mysteries, "Kryptos sculpture update…" (7 Nov 2011):** monoalphabetic substitution is ruled out because plaintext I and N both map to "TT". He judges transposition unlikely and says simple keyword Vigenère "apparently is not" the method. He counts 6 doubled pairs, slightly above chance but not significant — [Cipher Mysteries](https://ciphermysteries.com/2011/11/07/kryptos-sculpture-update) (via [tag page](https://ciphermysteries.com/tag/kryptos)). **weak** (informal)

**Kryptosfan WordPress, "Krypto Fans, Where are we at?" (7 Dec 2014) and comments to 2016:** many single-crib "fits", all of which fail to extend. A shifted-by-one running key matched the first few letters, then turned to garbage. Keyword IMPLY with +2 fits CLOCK only. Running keys MELIOR, SSOPEN, ESSILK, SPEEDE, GLOOM and GEORGE each fit BERLIN or CLOCK only. A commenter, "Skeptical", showed that an arbitrary passkey can produce any target text. A Dec 2016 "full solution" claim was contested; Sanborn knew of no solution — [kryptosfan](https://kryptosfan.wordpress.com/2014/12/07/krypto-fans-where-are-we-at/). **weak; useful catalogue of near-misses that were noise**. (Only the first 100k of 155k characters were read.)

**Schneier on Security, 21 Aug 2025 (auction post):** no systematic attempt or elimination appears in the comments — [Schneier](https://www.schneier.com/blog/archives/2025/08/jim-sanborn-is-auctioning-off-the-solution-to-part-four-of-the-kryptos-sculpture.html)

**Statements by Sanborn and Scheidt used as constraints** (quoted in Bean):
- Sanborn (Bogart 2019): "BERLINCLOCK in plain matches directly with NYPVTTMZFPK. It is a one-to-one match…".
- Scheidt (2015): "more than one stage".
- Scheidt (2011): "not mathematical… simple, can be remembered".
- Scheidt (2020): "change the language base".
- Source: [Bean PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)

### Inferences
- Sanborn's "one-to-one" statement and Bean's permutation stats both point to position-preserving substitution, at least over the crib region. A transposition, if any, would have to keep crib positions (or the cribs are post-transposition positions). Note that keithadler treats crib positions as *pre*-transposition.
- Single-crib fits from short keywords are expected by chance, as kryptosfan's "Skeptical" showed. Any candidate must satisfy both cribs together and clear a random-ciphertext calibration (keithadler's protocol).

### Gaps
- The sci.crypt posts by Gillogly (1999, 2004) and Stehle (2000), and the kryptos.groups.io archive (Hannon 2010/2011 "Novel K4 Results"), were not fetched. They are referenced only through Bean.
- Elonka Dunin's Kryptos page, and any community-maintained "ruled out" list on kryptos.groups.io, were not retrieved.
- I found no blog with a hill-climbing or simulated-annealing K4 run that reports explicit scope and a null result, other than keithadler and Bean.

---

## 4. AI/LLM-driven attacks, 2023–2026

### Takeaway
LLM "solutions" to K4 are numerous and all unconfirmed. Typical failure modes are wrong length, cribs missing or misplaced, and circular "reverse-engineered" keys. Sanborn has publicly rejected the flood of AI claims. Paradigm (Jun 2026) says no AI-assisted attempt has succeeded. No rigorous published evaluation of LLM cryptanalysis on K4 was found.

### Cited Findings
- Sanborn reported a surge of emails claiming AI tools such as Grok 3 had cracked K4, and said "AI lies, and does not have enough info" — [Boing Boing, 8 Mar 2025](https://boingboing.net/2025/03/08/cia-kryptos-sculptor-disgusted-by-flood-of-wrong-ai-solutions.html); [WION](https://www.wionews.com/trending/ai-cannot-crack-secret-code-on-statue-near-cia-headquarter-says-sculptor-8833427)
- **Aaron Toponce gist, "No, ChatGPT didn't solve Kryptos 4"** (comments Jun 2024 to Mar 2026, last active Oct 2026): it catalogues ChatGPT, Claude and Grok outputs. Most fail the check that EAST (22–25), NORTHEAST (26–34), BERLIN (64–69) and CLOCK (70–74) sit at those positions, and they differ in length. In Thiago Avelar's Dec 2025 Claude-derived "solution", the GROMARK key is labelled "Obtained by reverse engineering", so its round-trip check is circular. That plaintext does place the cribs correctly, so the rejection rests on circularity and on Sanborn not confirming it — [gist](https://gist.github.com/atoponce/1cd01f40786ab21af011f0d6257fba0c). **solid as debunking**
- Paradigm, 12 Jun 2026: "explosion" in AI-assisted attempts, "none have succeeded yet". The lack of a feedback loop is cited as one reason, and a CTF with 10 puzzles at $1,000 each was launched — [Paradigm](https://www.paradigm.xyz/writing/kryptos)
- LLM-assisted *tooling* (not solving): "Asynchronous" used Gemini 2.5 Pro to write the cipher code for an 8-letter-dictionary Vigenère chain search, with null result (Apr 2025) — [blog](https://asynchronous-x-github-io.pages.dev/post/attempting-kryptos-k4)

### Inferences
- In practice, LLM-written "solutions" fall into two failure classes:
  - (a) Free-text generation that ignores the ciphertext.
  - (b) Keys fitted backwards from a chosen plaintext. Any 97-letter plaintext can be "reproduced" by a free running key or a fitted Gromark key.
- The Paradigm $1 verifier is now the only cheap ground-truth check.

### Gaps
- No peer-reviewed or systematic benchmark of LLM agents on K4, with search scope and null results, was found up to Nov 2026.
- I could not find out whether Paradigm publishes submission counts or classes of rejected methods.
