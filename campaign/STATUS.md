# Campaign status

Updated 2026-11-16 04:33 UTC. Rebuilt automatically by `campaign/run.py` after every idea.

| # | Idea | Status | Hypotheses | Survivors | Verdict | Minutes |
|---|---|---|---|---|---|---|
| 16 | Statistics: are Stehle's DIAWINFBN run and the mod-7 doublets real? | done | - | - | Stehle run (length 5 at lag 4): p=0.0032 vs shuffles; doublet mod-7 clustering: p=0.0011 (193/26628 shuffles with >=6 doublets match it) | 1.1 |
| 15 | Sanborn's 2025 hints as keywords everywhere (Quagmire I-IV + theme-keyword columnar x all key models) | done | 15,041,916 | 0 | (a) dead: no theme-word combination places all 24 clue letters; (b) dead: 0 survivors | 1.8 |
| 11 | Decimation (97 is prime), grid routes, K3 rotations x every key model | done | 41,759,874 | 0 | dead: 0 survivors | 0.6 |
| 12 | Myszkowski from ~190k dictionary words x every key model | done | 809,443,638 | 0 | dead: 0 survivors | 3.7 |
| 08 | Columnar (every order, widths 2-11) + digit / small-shift key | done | 791,184,816 | 0 | dead: 0 survivors | 12.6 |
| 17 | Double columnar (widths 2-6 x 2-6) x progressive / autokey / digit keys | done | 3,085,638,272 | 0 | dead: 0 survivors | 13.1 |
| 10 | Columnar (every order, widths 2-10) + autokey (ciphertext or plaintext feeds the key) | done | 5,814,593,280 | 0 | dead: 0 survivors | 26.9 |
| 09 | Columnar (every order, widths 2-10) + progressive key | done | 10,498,571,200 | 0 | dead: 0 survivors | 46.4 |
| 14 | Keyword alphabets at key lengths 14-26, forced plaintext scored for English | done | 10,849,696 | - | dead: K4's best forced plaintext scores like shuffled K4s | 0.4 |
| 13 | Double columnar width 8 x widths 2-6 + periodic key | done | 21,939,240,960 | 4 | dead: 4 survivors, all at the minimum 6 clue equalities (key length 25, one family of near-identical orders); decrypts are noise (q -6.53 to -6.57, English ~ -4.7) | 50.1 |
| 18 | Fingerprint ranking: which cipher families produce K4-like statistics? | done | - | - | most K4-like: periodic Vigenere, period 6 exactly, A-Z (-5.66); periodic Vigenere, period 4 exactly, A-Z (-5.73); small shifts +-3 (aperiodic) (-5.82). Least: two periodic keys summed (7 + 11) (-8.01); running key (English text), A-Z (-8.73); running key (English text), KRYPTOS (-9.47). See campaign/FINGERPRINTS.md | 0.6 |
| 21 | Practice puzzles: decrypt PK1-PK9 from the public keys, test our blind solvers | done | - | - | 8/9 practice puzzles decrypted from the public keys (PK1, PK2, PK3, PK4, PK5, PK6, PK8, PK9); blind period solver recovers PK1: True, PK3 (two keys, period 40): False; PK7 (Hill 3x3 + Quagmire) not recovered by the simple Hill row attack; PK10 (all layers reversed) not attempted | 0.2 |
| 20 | Quagmire I/II (one hidden alphabet) at every key length; undecidable lengths completed by annealing | done | - | - | dead: at every undecidable length K4's best completion scores like shuffled K4s | 5.4 |
| 19 | Gromark / chain-addition keys with both alphabets hidden; survivors completed by annealing | done | 1,586,328 | 454 | dead: 454 primers survive the clues but their best English completion (-5.36) is no better than shuffled K4s (-5.506); planted Gromark texts reach -5.78..-4.30 through the same pipeline | 69.5 |
| 22 | Fingerprint ranking again, with the new hidden-alphabet families | done | - | - | most K4-like: periodic Vigenere, period 6 exactly, A-Z (-5.62); periodic Vigenere, period 4 exactly, A-Z (-5.75); periodic Vigenere, period 10 exactly, A-Z (-5.78). Least: two periodic keys summed (7 + 11) (-8.01); running key (English text), A-Z (-8.73); running key (English text), KRYPTOS (-9.47). See campaign/FINGERPRINTS_22.md | 0.6 |
| 23 | LAYER TWO: two stacked repeating keys, every length pair <=26, completed by annealing | done | - | - | disfavoured where we have power: at the 66/120 length pairs where planted two-key messages come back >=80/97 letters, 47/66 of them score above K4's best completion (-5.00); K4 never beats shuffled controls (-5.04). Open at the 54 long pairs where the annealer can't recover planted text | 52.0 |
| 26 | Three layers: a theme word plus two unknown keys (fully clue-determined configs) | done | 88,400 | - | dead: 349 fully determined decrypts, best -6.56 vs shuffled -6.298 | 0.0 |
| 27 | K1-K3 misspellings (L/Q, O/U, E/A, S/C) as alphabet swaps x key models and two stacked keys | done | 55,530 | - | (a) dead: 0 survivors; (b) dead: 98 determined decrypts, best -6.53 vs shuffled -6.48 | 0.0 |
| 24 | World Clock (Weltzeituhr) as of 1989: city names, initials and UTC offsets as keys | done | - | - | dead: best city-name key 7/24 (shuffled 6), best UTC-offset key 7/24 (shuffled 6); 24/24 needed | 0.3 |
| 30 | Visual letter transforms: semaphore rotations/mirrors and Morse reverse/invert, alone or stacked with key layers | done | 10,866 | 0 | dead: no visual-transform schedule or stack fits all clue letters | 0.0 |
| 31 | Compass-bearing keys read across the exact carved layout (cipher panel, tableau, mirrored tableau) | done | 20,736 | 0 | dead: best bearing matches 6/24 clue letters (shuffled best 6/24); all needed | 0.0 |
| 28 | SLM cipher detective: small neural net trained on ~100k synthetic K4-like ciphertexts names K4's family | done | - | - | K4 classified as 'progressive key' (p=0.1133, that family's held-out accuracy 0.203); overall held-out accuracy 0.437. Shuffled K4s are mostly called 'ciphertext autokey' | 1.3 |
| 29 | Local LLM (Qwen2.5-7B) as English judge for the blind stacked-key region, plus what it generates as K4 | done | - | - | best detector of real two-key English in this blind region: q (planted vs chance AUC 0.75); K4 vs chance on it: AUC 0.55 (K4 looks like chance). LLM generated 55 plaintexts, 0 with both clues in K4's exact positions | 9.2 |
| 32 | Key-shape forensics: period signatures in letter differences; could the key be a slowly turning dial? | done | - | - | difference-stream periodicity: best ('AZ', 4, 28) IoC 0.1012, p=0.156 vs shuffled (look-elsewhere corrected); at period 7 specifically p=0.208. Dial keys: the clues need a max step of 12 even in the smoothest cipher type (shuffled K4s: median 12), so a slowly turning dial key is ruled out | 2.4 |
| 33 | Self-masking: K4 keyed by its own plaintext or ciphertext read in a scrambled order | done | 670,416 | 0 | dead: no scrambled self-key fits all clue letters (shuffled controls also 0) | 0.0 |
| 34 | Baudot/Vernam teleprinter cipher (ITA2 XOR): periodic, stacked, autokey, word and text keys | done | - | 0 | dead: no teleprinter key model fits all clue letters; best running key 5/24 (shuffled 5) | 0.0 |
| 36 | Lorenz-style teleprinter wheels: each of the 5 bits with its own short repeating wheel | done | - | - | dead: no fully pinned 5-wheel combination decrypts to letters (allowed lengths per bit: [0, 0, 0, 0, 0]) | 0.0 |
| 35 | Paper strips: K4's carved rows or equal-width strips, reordered and flipped, x every key model | done | 691,748,964 | 0 | dead: 0 survivors | 5.8 |
| 37 | Egypt-era alphabets (hieroglyph, Coptic, Greek, Phoenician, Arabic orders) x key models, Quagmire, stacked keys | done | 23,044 | - | (a) dead: 0 survivors; (b) dead: Quagmire: 0 consistent (shuffled [0, 0]); two-key: 40 pinned decrypts, best -6.69 vs shuffled -6.51 | 0.0 |
| 39 | Shifting matrices / number-base change: grid coordinates each shifted by its own wheel | done | 1,560 | - | dead: in every grid at least one coordinate has no wheel the clue letters allow | 0.0 |
| 41 | Gromark in other number bases (3-16), both alphabets hidden, completed | done | 3,500,452 | 1470 | dead: 1470 primers survive the clues but their best English completion (-5.36) is no better than shuffled K4s (-5.462); planted Gromark texts reach -5.78..-4.30 through the same pipeline | 125.3 |
| 38 | Long stacked keys revisited: heat-bath solver + English-key prior | done | - | - | no signal: K4 best -4.89 vs shuffled -4.97; planted recovered >=80/97 at 17% of pairs (median 58 letters, was ~35); 6/54 planted score above K4's best | 57.7 |
| 42 | Selective masking: KRYPTOS letters lightly shifted, the rest keyed | done | - | - | closeness: 9/10 KRYPTOS-letter clues within +-2 (shuffled p=0.0000; KRYPTOS beats 6187/6190 letter subsets of at least that size). Model: no repeating key on the other letters fits the clues | 0.0 |
| 43 | Key restarts at each sentence (+X separators), 18 alphabets | done | - | 10 | dead: survivors by clue repeats {2: 10, 3: 0, 4: 0, 5: 0} (>=4 repeats: 0 vs ~0.0 per shuffled K4); best decode -6.46 vs control best -6.317 (chance level) | 1.3 |
| 44 | A different simple system for each part (split 34-63) | done | - | - | dead: part-1 fits 0, part-2 fits 0 (over splits); best two-system decode None vs shuffled None; families above chance: none | 0.2 |
| 45 | One deliberate mistake: drop-one-clue for periodic, two keys, hidden-alphabet Gromark | done | - | - | dead: one-mistake tolerance adds nothing over chance; periodic: exact 0, drop-only 0 (shuffled: 0/0, 0/0, 0/0); two keys: exact 710, drop-only 158 (shuffled: 712/147, 712/149, 715/146); gromark: exact 39, drop-only 1358 (shuffled: 1099/8741, 2198/13482, 69/2058); best completion -5.782 vs control -6.757 | 1.8 |
| 46 | KRYPTOS-letter masking inside the clue sentences + restarting key (pre-filter hybrid) | done | - | 660 | A) closeness: KRYPTOS within-block p=0.00125 (rank 1/17 natural sets; corrected p~0.021); flatness needs <=~20 masked letters and a long/stacked key on the rest (LR vs chance, two stacked keys: {'10-14': 34.22, '15-19': 18.34, '20-24': 9.96, '25-29': 3.82, '30-34': 0.79, '35-39': 0.29}). B) dead: 660 survivors (controls [0, 0, 140, 0]), best decode -6.074293128545049 vs control None | 6.5 |
| 47 | Two stacked keys that are both real words/phrases/dates (+ one-wrong-clue pass) | done | - | - | dead: 0 fully determined word-key decrypts, best None vs shuffled [(0, None), (0, None)]; one-mistake pass 0 decrypts, best None vs shuffled None (English ~ -5) | 29.5 |
| 48 | Three layers: theme word + two word keys | done | - | - | dead: 0 fully determined word-key decrypts, best None vs shuffled [(0, None), (0, None)] (English ~ -5) | 5.3 |
| 49 | K1-K3 plaintexts as keys with hidden alphabets (4 models) | done | - | {'M1': 0, 'M2': 0, 'M3': 0, 'M4': 189} | dead: survivors by model {'M1': 0, 'M2': 0, 'M3': 0, 'M4': 189} (shuffled: [{'M1': 0, 'M2': 0, 'M3': 0, 'M4': 25930}, {'M1': 0, 'M2': 0, 'M3': 0, 'M4': 2830}]); best completion -5.62 vs shuffled -5.547 | 6.5 |
| 50 | Clock arithmetic keys (dials 12/24/60, two hands) + carved-row restarts | done | - | 0 | dead: 0 schedules fit the clues out of 2,955,924 (shuffled: [(0, None), (0, None), (0, None)]); best decode None | 0.3 |
| 51 | Letter class picks the table (KRYPTOS letters on the KRYPTOS tableau) | done | - | 0 | dead: no key fits the clues (shuffled K4s: mean 0.00 survivors) | 0.4 |
| 52 | Second look at every saved candidate (big model, word coverage, LLM judge) | done | - | - | nothing missed: best of 407 candidates big-q -5.04 / coverage 0.66 vs real English >= -4.82 / 0.68 (5th pct); noise max q -6.79; LLM best 3.0 vs real English median 3.0, noise max 2.0; 0 pass both automatic checks (optimised completions), none rated like English | 3.2 |

Verdict key: **dead** = ruled out within the stated scope (each engine has a planted-answer test); **WORTH A LOOK** = beats shuffled-K4 controls, needs a human look.

## Details

### 16. Statistics: are Stehle's DIAWINFBN run and the mod-7 doublets real?

- **Why:** Two famous K4 oddities nobody has put a corrected p-value on. Cheap; tells us whether to chase 4- or 7-spaced structure.
- **Script:** `attacks/16_statistics.py`  ·  log: `campaign/logs/16.log`
- **Status:** done
- **Verdict:** Stehle run (length 5 at lag 4): p=0.0032 vs shuffles; doublet mod-7 clustering: p=0.0011 (193/26628 shuffles with >=6 doublets match it)
- p_stehle: `0.0032399838000809994`
- p_doublets: `0.0010799946000269998`

### 15. Sanborn's 2025 hints as keywords everywhere (Quagmire I-IV + theme-keyword columnar x all key models)

- **Why:** Newest clues (Egypt 1986, Berlin Wall, delivering a message, World Clock) are barely mined.
- **Script:** `attacks/15_sanborn_2025_hints.py`  ·  log: `campaign/logs/15.log`
- **Status:** done
- **Verdict:** (a) dead: no theme-word combination places all 24 clue letters; (b) dead: 0 survivors
- control: `[{"hypotheses": 15041916, "survivors": 0}, {"hypotheses": 15041916, "survivors": 0}]`
- quagmire_part: `{"hypotheses": 1257320, "alphabets": 86, "full_crib_matches": 0, "verdict": "dead: no theme-word combination places all 24 clue letters"}`

### 11. Decimation (97 is prime), grid routes, K3 rotations x every key model

- **Why:** Others tried these scrambles with repeating keys only; progressive, autokey and digit keys behind them are untested.
- **Script:** `attacks/11_routes_decimation_rotation.py`  ·  log: `campaign/logs/11.log`
- **Status:** done
- **Verdict:** dead: 0 survivors
- control: `[{"hypotheses": 41759874, "survivors": 0}, {"hypotheses": 41759874, "survivors": 0}]`

### 12. Myszkowski from ~190k dictionary words x every key model

- **Why:** Myszkowski was only covered at widths 3-9 with a periodic key.
- **Script:** `attacks/12_myszkowski.py`  ·  log: `campaign/logs/12.log`
- **Status:** done
- **Verdict:** dead: 0 survivors
- control: `[{"hypotheses": 80627400, "survivors": 0}]`

### 08. Columnar (every order, widths 2-11) + digit / small-shift key

- **Why:** Digit keys are dead alone but untested behind a transposition; fits Bean's 'letters sit close' finding.
- **Script:** `attacks/08_columnar_digit_keys.py`  ·  log: `campaign/logs/08.log`
- **Status:** done
- **Verdict:** dead: 0 survivors
- control: `[{"hypotheses": 832176, "survivors": 0}, {"hypotheses": 832176, "survivors": 0}]`

### 17. Double columnar (widths 2-6 x 2-6) x progressive / autokey / digit keys

- **Why:** Attack 07 did double columnar with periodic keys only.
- **Script:** `attacks/17_double_columnar_new_keys.py`  ·  log: `campaign/logs/17.log`
- **Status:** done
- **Verdict:** dead: 0 survivors
- control: `[{"hypotheses": 3538576, "survivors": 0}]`

### 10. Columnar (every order, widths 2-10) + autokey (ciphertext or plaintext feeds the key)

- **Why:** Autokey alone is dead; stacked behind a transposition it is untested.
- **Script:** `attacks/10_columnar_autokey.py`  ·  log: `campaign/logs/10.log`
- **Status:** done
- **Verdict:** dead: 0 survivors
- control: `[{"hypotheses": 8513280, "survivors": 0}]`

### 09. Columnar (every order, widths 2-10) + progressive key

- **Why:** Progressive alone is dead; stacked it is untested.
- **Script:** `attacks/09_columnar_progressive.py`  ·  log: `campaign/logs/09.log`
- **Status:** done
- **Verdict:** dead: 0 survivors
- control: `[{"hypotheses": 15371200, "survivors": 0}]`

### 14. Keyword alphabets at key lengths 14-26, forced plaintext scored for English

- **Why:** Clue letters can't decide these lengths (open gap); English scoring against shuffled K4 can.
- **Script:** `attacks/14_keyword_alphabets_long_periods.py`  ·  log: `campaign/logs/14.log`
- **Status:** done
- **Verdict:** dead: K4's best forced plaintext scores like shuffled K4s
- null_best: `[-6.050163760846241, -6.092249720849747, -6.107339411482148]`

### 13. Double columnar width 8 x widths 2-6 + periodic key

- **Why:** Pushes attack 07 one width further.
- **Script:** `attacks/13_double_columnar_width8.py`  ·  log: `campaign/logs/13.log`
- **Status:** done
- **Verdict:** dead: 4 survivors, all at the minimum 6 clue equalities (key length 25, one family of near-identical orders); decrypts are noise (q -6.53 to -6.57, English ~ -4.7)
- control: `{"hypotheses": 548481024, "survivors": 0}`
  - top: `"((4, 3, 0, 5, 2, 1), (1, 2, 7, 5, 0, 6, 3, 4), 'KRYPTOS', 'vigenere', 'after', 25, 6)"`
  - top: `"((4, 3, 0, 5, 2, 1), (1, 4, 7, 5, 0, 6, 3, 2), 'KRYPTOS', 'vigenere', 'after', 25, 6)"`
  - top: `"((4, 3, 0, 5, 2, 1), (2, 1, 7, 5, 0, 6, 3, 4), 'KRYPTOS', 'vigenere', 'after', 25, 6)"`

### 18. Fingerprint ranking: which cipher families produce K4-like statistics?

- **Why:** No key search. Ranks ~30 families by how often their output shows K4's oddities (flat IoC, lag-4 run, mod-7 doublets, width-21 repeats, close letters), as a soft prior for where to search next.
- **Script:** `attacks/18_fingerprint_ranking.py`  ·  log: `campaign/logs/18.log`
- **Status:** done
- **Verdict:** most K4-like: periodic Vigenere, period 6 exactly, A-Z (-5.66); periodic Vigenere, period 4 exactly, A-Z (-5.73); small shifts +-3 (aperiodic) (-5.82). Least: two periodic keys summed (7 + 11) (-8.01); running key (English text), A-Z (-8.73); running key (English text), KRYPTOS (-9.47). See campaign/FINGERPRINTS.md

### 21. Practice puzzles: decrypt PK1-PK9 from the public keys, test our blind solvers

- **Why:** Ground truth for calibration: shows how far our toolkit reaches on Paradigm's idea of 'Kryptos-like' ciphers.
- **Script:** `attacks/21_pk_calibration.py`  ·  log: `campaign/logs/21.log`
- **Status:** done
- **Verdict:** 8/9 practice puzzles decrypted from the public keys (PK1, PK2, PK3, PK4, PK5, PK6, PK8, PK9); blind period solver recovers PK1: True, PK3 (two keys, period 40): False; PK7 (Hill 3x3 + Quagmire) not recovered by the simple Hill row attack; PK10 (all layers reversed) not attempted

### 20. Quagmire I/II (one hidden alphabet) at every key length; undecidable lengths completed by annealing

- **Why:** Lengths 13, 16, 19, 20, 23, 24, 26 can't be decided by the clues (open gap); English completion vs planted and shuffled controls can.
- **Script:** `attacks/20_quagmire_I_II_open_lengths.py`  ·  log: `campaign/logs/20.log`
- **Status:** done
- **Verdict:** dead: at every undecidable length K4's best completion scores like shuffled K4s

### 19. Gromark / chain-addition keys with both alphabets hidden; survivors completed by annealing

- **Why:** A top fingerprint family. Bean's 39 survivors 'can be completed several ways' - this does the completion and compares with controls.
- **Script:** `attacks/19_gromark_free_alphabets.py`  ·  log: `campaign/logs/19.log`
- **Status:** done
- **Verdict:** dead: 454 primers survive the clues but their best English completion (-5.36) is no better than shuffled K4s (-5.506); planted Gromark texts reach -5.78..-4.30 through the same pipeline
- control: `[{"consistent": 1586328, "survivors": 12477, "best_q": -5.506}, {"consistent": 129424, "survivors": 26194, "best_q": -5.634}]`
- best_quadgram: `-5.36396977248201`
  - top: `{"q": -5.364, "base": 10, "primer": "659991", "plaintext": "EASIEYSFMOSUATEDOUTSMEASTNORTHEASTIMENULQZTLYRWVJRIFTHEANAGRONTBERLINCLOCKWITHELEFIHNEHEEVALPCETY"}`
  - top: `{"q": -5.387, "base": 10, "primer": "292930", "plaintext": "TYSIULERUWUMGVARSORTHEASTNORTHEASTLONINTESINEXIVIASBYTHINAFINBABERLINCLOCKWPXYYCSEDITCODEFLEDSPRZ"}`
  - top: `{"q": -5.39, "base": 10, "primer": "015935", "plaintext": "EZIRRAJNYSPOSINVMYSITEASTNORTHEASTEXCIXTESIMISUBJIIQDATTINGWHEDBERLINCLOCKTOTDLDMULTMESTSBITINFOS"}`

### 22. Fingerprint ranking again, with the new hidden-alphabet families

- **Why:** Do Gromark-with-hidden-alphabets and Quagmire I/II/IV look K4-like?
- **Script:** `attacks/18_fingerprint_ranking.py`  ·  log: `campaign/logs/22.log`
- **Status:** done
- **Verdict:** most K4-like: periodic Vigenere, period 6 exactly, A-Z (-5.62); periodic Vigenere, period 4 exactly, A-Z (-5.75); periodic Vigenere, period 10 exactly, A-Z (-5.78). Least: two periodic keys summed (7 + 11) (-8.01); running key (English text), A-Z (-8.73); running key (English text), KRYPTOS (-9.47). See campaign/FINGERPRINTS_22.md

### 23. LAYER TWO: two stacked repeating keys, every length pair <=26, completed by annealing

- **Why:** Stacked keys (PK3/PK8 style, K2's 'LAYER TWO') give a key that never repeats inside 97 letters on a plain alphabet. The undecidable pairs were never completed.
- **Script:** `attacks/23_two_stacked_keys.py`  ·  log: `campaign/logs/23.log`
- **Status:** done
- **Verdict:** disfavoured where we have power: at the 66/120 length pairs where planted two-key messages come back >=80/97 letters, 47/66 of them score above K4's best completion (-5.00); K4 never beats shuffled controls (-5.04). Open at the 54 long pairs where the annealer can't recover planted text
- best_quadgram: `-4.998296407620908`
  - top: `{"alphabet": "KRYPTOS", "variant": "vigenere", "L1": 25, "L2": 26, "q": -4.998, "free": 26, "words": 0.48, "plaintext": "ZEACOUSEITNEGDEFFHQTHEASTNORTHEASTERNFSANARYMAYRESASSEENTSILSAMBERLINCLOCKOATER`
  - top: `{"alphabet": "KRYPTOS", "variant": "variant_beaufort", "L1": 22, "L2": 26, "q": -5.069, "free": 23, "words": 0.58, "plaintext": "USTONCETHANDATASIDTAREASTNORTHEASTATALLUDEMGBNSBBFESEMETHUCANPDBERLINCL`
  - top: `{"alphabet": "AZ", "variant": "variant_beaufort", "L1": 24, "L2": 25, "q": -5.074, "free": 24, "words": 0.52, "plaintext": "EHACTIVENSTHESDESCLXEEASTNORTHEASTRACESTHERSUSCUPFITDISTIUPTETOBERLINCLOCKTH`

### 26. Three layers: a theme word plus two unknown keys (fully clue-determined configs)

- **Why:** PK8 stacked four keys; with one layer a known theme word the rest is exactly solvable.
- **Script:** `attacks/26_three_layers_theme_word.py`  ·  log: `campaign/logs/26.log`
- **Status:** done
- **Verdict:** dead: 349 fully determined decrypts, best -6.56 vs shuffled -6.298
- control: `[{"determined": 355, "best_q": -6.298}, {"determined": 352, "best_q": -6.512}]`
- best_quadgram: `-6.556644186532046`
  - top: `{"q": -6.557, "words": 0.31, "word": "CHECKPOINTCHARLIE", "sign": -1, "alphabet": "AZ", "L1": 9, "L2": 16, "plaintext": "FSKGKCHFTLEZPNQUAOXZUEASTNORTHEASTERPRQKRMAKYENLPJPSFIFXHSDYOTTBERLINCLOCKZHCTC`
  - top: `{"q": -6.557, "words": 0.33, "word": "LUCID", "sign": 1, "alphabet": "AZ", "L1": 9, "L2": 16, "plaintext": "SYWYUXSCUSOLBFVIXHRVQEASTNORTHEASTDSRSBXBXNIYGWJPITERRUITYNWEMDBERLINCLOCKULNCAKEMSOGQGAIMAY`
  - top: `{"q": -6.573, "words": 0.26, "word": "COMPASS", "sign": 1, "alphabet": "AZ", "L1": 9, "L2": 16, "plaintext": "OKFJXOHBZSFOCONBYDZBBEASTNORTHEASTUZWTYOFTMYMUUGNSBLJNQSOQHLNMUBERLINCLOCKNPMFCBOOAUBBKIGH`

### 27. K1-K3 misspellings (L/Q, O/U, E/A, S/C) as alphabet swaps x key models and two stacked keys

- **Why:** Sanborn: K1-K3 answers hold clues and the misspellings are deliberate; as alphabet swaps they give the near-plain alphabets our fingerprint favours. Untested in this form.
- **Script:** `attacks/27_misspelling_alphabets.py`  ·  log: `campaign/logs/27.log`
- **Status:** done
- **Verdict:** (a) dead: 0 survivors; (b) dead: 98 determined decrypts, best -6.53 vs shuffled -6.48
  - top: `{"q": -6.528, "words": 0.29, "alphabet": "KRYPTOS+UNDERGRUUND+DESPARATLY+PALIMPCEST", "variant": "beaufort", "L1": 9, "L2": 16, "plaintext": "PZSQBCANGRTOXKERERNFHEASTNORTHEASTTVCHCNPICNTZQDGOLDREGLYJ`
  - top: `{"q": -6.56, "words": 0.26, "alphabet": "KRYPTOS+IQLUSION+UNDERGRUUND+DESPARATLY+PALIMPCEST", "variant": "vigenere", "L1": 9, "L2": 16, "plaintext": "YVLYWWXDDJGKZMVHVVLOREASTNORTHEASTEGNALDIFXECGUVJW`
  - top: `{"q": -6.56, "words": 0.26, "alphabet": "KRYPTOS+IQLUSION+UNDERGRUUND+DESPARATLY+PALIMPCEST", "variant": "variant_beaufort", "L1": 9, "L2": 16, "plaintext": "YVLYWWXDDJGKZMVHVVLOREASTNORTHEASTEGNALDIF`

### 24. World Clock (Weltzeituhr) as of 1989: city names, initials and UTC offsets as keys

- **Why:** Sanborn (2025): BERLINCLOCK = the World Clock at Alexanderplatz and the 1989 Wall fall matters. Everyone used the post-1997 plates; we reconstructed the 1989 ones from dated photos.
- **Script:** `attacks/24_weltzeituhr_1989.py`  ·  log: `campaign/logs/24.log`
- **Status:** done
- **Verdict:** dead: best city-name key 7/24 (shuffled 6), best UTC-offset key 7/24 (shuffled 6); 24/24 needed
- control: `[{"names": 6, "utc": 5}, {"names": 6, "utc": 6}]`

### 30. Visual letter transforms: semaphore rotations/mirrors and Morse reverse/invert, alone or stacked with key layers

- **Why:** Sanborn's 'visual systems'; semaphore is two hands on a dial (Berlin Clock-shaped). Never tested.
- **Script:** `attacks/30_visual_transforms.py`  ·  log: `campaign/logs/30.log`
- **Status:** done
- **Verdict:** dead: no visual-transform schedule or stack fits all clue letters
- control: `[{"alone": 0, "stacked": 0}, {"alone": 0, "stacked": 0}]`

### 31. Compass-bearing keys read across the exact carved layout (cipher panel, tableau, mirrored tableau)

- **Why:** EAST NORTHEAST is in the clue; physical/visual steps; uses the verified carved line layout.
- **Script:** `attacks/31_compass_bearings.py`  ·  log: `campaign/logs/31.log`
- **Status:** done
- **Verdict:** dead: best bearing matches 6/24 clue letters (shuffled best 6/24); all needed
- control: `[[6, 24], [6, 24]]`

### 28. SLM cipher detective: small neural net trained on ~100k synthetic K4-like ciphertexts names K4's family

- **Why:** A learned, richer version of the fingerprint ranking; training on K4 itself can't work (97 letters).
- **Script:** `attacks/28_slm_cipher_detective.py`  ·  log: `campaign/logs/28.log`
- **Status:** done
- **Verdict:** K4 classified as 'progressive key' (p=0.1133, that family's held-out accuracy 0.203); overall held-out accuracy 0.437. Shuffled K4s are mostly called 'ciphertext autokey'

### 29. Local LLM (Qwen2.5-7B) as English judge for the blind stacked-key region, plus what it generates as K4

- **Why:** Quadgrams can't tell real from fake English where ~20 key letters are free; an LLM judge might, calibrated on planted vs shuffled.
- **Script:** `attacks/29_llm_judge_and_generator.py`  ·  log: `campaign/logs/29.log`
- **Status:** done
- **Verdict:** best detector of real two-key English in this blind region: q (planted vs chance AUC 0.75); K4 vs chance on it: AUC 0.55 (K4 looks like chance). LLM generated 55 plaintexts, 0 with both clues in K4's exact positions

### 32. Key-shape forensics: period signatures in letter differences; could the key be a slowly turning dial?

- **Why:** NSA's 'pattern every 7', the mod-7 doublets, Bean's width 21 and the neural detective's 'progressive' all hint at key shape.
- **Script:** `attacks/32_key_shape.py`  ·  log: `campaign/logs/32.log`
- **Status:** done
- **Verdict:** difference-stream periodicity: best ('AZ', 4, 28) IoC 0.1012, p=0.156 vs shuffled (look-elsewhere corrected); at period 7 specifically p=0.208. Dial keys: the clues need a max step of 12 even in the smoothest cipher type (shuffled K4s: median 12), so a slowly turning dial key is ruled out

### 33. Self-masking: K4 keyed by its own plaintext or ciphertext read in a scrambled order

- **Why:** Scheidt's 'masking' on a plain alphabet; natural-order self-keying (autokey) is dead, scrambled never tried.
- **Script:** `attacks/33_self_masking.py`  ·  log: `campaign/logs/33.log`
- **Status:** done
- **Verdict:** dead: no scrambled self-key fits all clue letters (shuffled controls also 0)
- control: `[0, 0]`

### 34. Baudot/Vernam teleprinter cipher (ITA2 XOR): periodic, stacked, autokey, word and text keys

- **Why:** K2's 'transmitted underground' = the CIA Berlin Tunnel tapping teleprinter lines; never tested on K4.
- **Script:** `attacks/34_baudot_vernam.py`  ·  log: `campaign/logs/34.log`
- **Status:** done
- **Verdict:** dead: no teleprinter key model fits all clue letters; best running key 5/24 (shuffled 5)
- control: `[{"hits": 0, "best_running": 4}, {"hits": 0, "best_running": 5}]`

### 36. Lorenz-style teleprinter wheels: each of the 5 bits with its own short repeating wheel

- **Why:** The Cold War teleprinter machine family; each bit plane is exactly testable on its own.
- **Script:** `attacks/36_lorenz_wheels.py`  ·  log: `campaign/logs/36.log`
- **Status:** done
- **Verdict:** dead: no fully pinned 5-wheel combination decrypts to letters (allowed lengths per bit: [0, 0, 0, 0, 0])
- control: `[{"combos": 1, "decrypts": 0, "best_q": null}, {"combos": 1, "decrypts": 0, "best_q": null}]`

### 35. Paper strips: K4's carved rows or equal-width strips, reordered and flipped, x every key model

- **Why:** Kobek found the plaintext as strips taped out of order; the verified carved layout gives the strips.
- **Script:** `attacks/35_paper_strips.py`  ·  log: `campaign/logs/35.log`
- **Status:** done
- **Verdict:** dead: 0 survivors
- control: `[{"hypotheses": 691748964, "survivors": 0}]`

### 37. Egypt-era alphabets (hieroglyph, Coptic, Greek, Phoenician, Arabic orders) x key models, Quagmire, stacked keys

- **Why:** Sanborn: the 1986 Egypt trip figures in the solution; near-plain alphabets are what the fingerprint favours.
- **Script:** `attacks/37_egypt_alphabets.py`  ·  log: `campaign/logs/37.log`
- **Status:** done
- **Verdict:** (a) dead: 0 survivors; (b) dead: Quagmire: 0 consistent (shuffled [0, 0]); two-key: 40 pinned decrypts, best -6.69 vs shuffled -6.51

### 39. Shifting matrices / number-base change: grid coordinates each shifted by its own wheel

- **Why:** Sanborn: 'matrix codes Ed gave me'; Scheidt: 'a different math base', 'shifting matrices'. Only the base-3 cube with simple keys was tried.
- **Script:** `attacks/39_shifting_matrices.py`  ·  log: `campaign/logs/39.log`
- **Status:** done
- **Verdict:** dead: in every grid at least one coordinate has no wheel the clue letters allow
- control: `[{"grid_survivors": 0, "decrypts": 0, "best_q": null}, {"grid_survivors": 0, "decrypts": 0, "best_q": null}, {"grid_survivors": 0, "decrypts": 0, "best_q": null}]`

### 41. Gromark in other number bases (3-16), both alphabets hidden, completed

- **Why:** Scheidt's 'different math base'; Bean/Barney list survivors in base 8 etc.; completions never done.
- **Script:** `attacks/19_gromark_free_alphabets.py`  ·  log: `campaign/logs/41.log`
- **Status:** done
- **Verdict:** dead: 1470 primers survive the clues but their best English completion (-5.36) is no better than shuffled K4s (-5.462); planted Gromark texts reach -5.78..-4.30 through the same pipeline
- control: `[{"consistent": 3500452, "survivors": 28112, "best_q": -5.462}, {"consistent": 252892, "survivors": 61328, "best_q": -5.581}]`
- best_quadgram: `-5.3643488221872815`
  - top: `{"q": -5.364, "base": 15, "primer": "1341135", "plaintext": "IDEVENTESNOTOAGAODIESEASTNORTHEASTOAODFORFUTTHELCHILEXPREPSXQXMBERLINCLOCKSCRELYARDMMODUCCYXGXWLC"}`
  - top: `{"q": -5.369, "base": 15, "primer": "97424", "plaintext": "GYWYEHINTEDFUNDREFINHEASTNORTHEASTRSETLKLYGDFXOLCDFAXSPSMYACLEOBERLINCLOCKISERVIAGENGEXAMPLIEDLYF"}`
  - top: `{"q": -5.399, "base": 15, "primer": "90375", "plaintext": "LYZBWLGETEMUTFTAGATEVEASTNORTHEASTENTEREONGUPQVEACKISDECSVLQJVDBERLINCLOCKOWWREFERFONLYPRORECASAP"}`

### 38. Long stacked keys revisited: heat-bath solver + English-key prior

- **Why:** Diagnosis showed the open region is search-limited (true answers score higher than what was found), not information-limited.
- **Script:** `attacks/38_long_stacked_keys_v2.py`  ·  log: `campaign/logs/38.log`
- **Status:** done
- **Verdict:** no signal: K4 best -4.89 vs shuffled -4.97; planted recovered >=80/97 at 17% of pairs (median 58 letters, was ~35); 6/54 planted score above K4's best
- best_quadgram: `-4.892918022567974`
  - top: `{"alphabet": "AZ", "variant": "variant_beaufort", "L1": 25, "L2": 26, "q": -4.893, "plaintext": "DLIDNTEXTEDORRETHEEXAEASTNORTHEASTOPEANATESLESEGETAPARECRJOWMANBERLINCLOCKWITITLITEENTITARACVTTCE"}`
  - top: `{"alphabet": "AZ", "variant": "beaufort", "L1": 24, "L2": 26, "q": -5.021, "plaintext": "UZPYVFXOSSTDERESDIFTHEASTNORTHEASTADDEDISTYNSTSAPERAFALISTEANAMBERLINCLOCKLESELFCLONELECPAHESASET"}`
  - top: `{"alphabet": "KRYPTOS", "variant": "variant_beaufort", "L1": 25, "L2": 26, "q": -5.035, "plaintext": "FBHONSSPRINNHFIDESETHEASTNORTHEASTEDLITENOYNMAYREFUNCTIONSWOTHEBERLINCLOCKERORWYXLOCABASUCCESTYCO"`

### 42. Selective masking: KRYPTOS letters lightly shifted, the rest keyed

- **Why:** 9/10 KRYPTOS-letter clues shift <=2 (shuffled p~0.003); maybe the keyword decides which letters get the real key.
- **Script:** `attacks/42_selective_masking.py`  ·  log: `campaign/logs/42.log`
- **Status:** done
- **Verdict:** closeness: 9/10 KRYPTOS-letter clues within +-2 (shuffled p=0.0000; KRYPTOS beats 6187/6190 letter subsets of at least that size). Model: no repeating key on the other letters fits the clues
- control: `[null, null, null]`

### 43. Key restarts at each sentence (+X separators), 18 alphabets

- **Why:** Plaintext = sentence strips; K1-K3 use X between sentences; Cyrillic Projector restarts its key per block.
- **Script:** `attacks/43_sentence_breaks.py`  ·  log: `campaign/logs/43.log`
- **Status:** done
- **Verdict:** dead: survivors by clue repeats {2: 10, 3: 0, 4: 0, 5: 0} (>=4 repeats: 0 vs ~0.0 per shuffled K4); best decode -6.46 vs control best -6.317 (chance level)
- best_quadgram: `-6.459079849336252`
  - top: `{"q": -6.459, "alphabet": "LAYERTWO", "variant": "beaufort", "L": 26, "s1": 15, "s2": 45, "x": true, "tests": 2, "extra_break": 4, "plaintext": "FQKVUSBQEINAMOTNISPOSEASTNORTHEASTXNMIETDXOFXYEOSIUZFZW`
  - top: `{"q": -6.514, "alphabet": "ILLUSION", "variant": "beaufort", "L": 26, "s1": 17, "s2": 44, "x": true, "tests": 2, "extra_break": 74, "plaintext": "WCEFRSZFFDCGFRPNXKCQCEASTNORTHEASTCWMJQRABVXMIINZLULCV`
  - top: `{"q": -6.569, "alphabet": "LAYERTWO", "variant": "beaufort", "L": 25, "s1": 15, "s2": 45, "x": true, "tests": 2, "extra_break": 34, "plaintext": "NDGYTGKQHJKAJIXZRMXPHEASTNORTHEASTNHUAOXZOROCCPELLIZFZ`

### 44. A different simple system for each part (split 34-63)

- **Why:** 'Two separate systems' read literally: one for the EASTNORTHEAST part, another for the BERLINCLOCK part.
- **Script:** `attacks/44_system_per_sentence.py`  ·  log: `campaign/logs/44.log`
- **Status:** done
- **Verdict:** dead: part-1 fits 0, part-2 fits 0 (over splits); best two-system decode None vs shuffled None; families above chance: none
- control: `[null, null, null]`

### 45. One deliberate mistake: drop-one-clue for periodic, two keys, hidden-alphabet Gromark

- **Why:** Sanborn's work is 'rife with mistakes on purpose'; one wrong clue letter makes exact tests reject the true method.
- **Script:** `attacks/45_one_mistake.py`  ·  log: `campaign/logs/45.log`
- **Status:** done
- **Verdict:** dead: one-mistake tolerance adds nothing over chance; periodic: exact 0, drop-only 0 (shuffled: 0/0, 0/0, 0/0); two keys: exact 710, drop-only 158 (shuffled: 712/147, 712/149, 715/146); gromark: exact 39, drop-only 1358 (shuffled: 1099/8741, 2198/13482, 69/2058); best completion -5.782 vs control -6.757

### 46. KRYPTOS-letter masking inside the clue sentences + restarting key (pre-filter hybrid)

- **Why:** Clue matrix: selective masking explains the KRYPTOS closeness but breaks flatness unless <=~20 letters are masked; top hybrid = masking x sentence restarts.
- **Script:** `attacks/46_masking_in_sentences.py`  ·  log: `campaign/logs/46.log`
- **Status:** done
- **Verdict:** A) closeness: KRYPTOS within-block p=0.00125 (rank 1/17 natural sets; corrected p~0.021); flatness needs <=~20 masked letters and a long/stacked key on the rest (LR vs chance, two stacked keys: {'10-14': 34.22, '15-19': 18.34, '20-24': 9.96, '25-29': 3.82, '30-34': 0.79, '35-39': 0.29}). B) dead: 660 survivors (controls [0, 0, 140, 0]), best decode -6.074293128545049 vs control None
- best_quadgram: `-6.074293128545049`
  - top: `{"q": -6.074, "alphabet": "LAYERTWO", "variant": "vigenere", "L": 24, "restart": true, "segments": [0, 40, 40, 80], "plaintext": "OWEREPYOFACLASHKJFFMYEASTOROTHEASTOSYSSTKOTSDFYDYYSJCKSLJACKOECONOTSTO`
  - top: `{"q": -6.074, "alphabet": "LAYERTWO", "variant": "variant_beaufort", "L": 24, "restart": true, "segments": [0, 40, 40, 80], "plaintext": "OWEREPYOFACLASHKJFFMYEASTOROTHEASTOSYSSTKOTSDFYDYYSJCKSLJACKOE`

### 47. Two stacked keys that are both real words/phrases/dates (+ one-wrong-clue pass)

- **Why:** Round 6: long stacked keys are information-limited; hand keys are words (PALIMPSEST, ABSCISSA), which removes every free slot.
- **Script:** `attacks/47_word_stacked_keys.py`  ·  log: `campaign/logs/47.log`
- **Status:** done
- **Verdict:** dead: 0 fully determined word-key decrypts, best None vs shuffled [(0, None), (0, None)]; one-mistake pass 0 decrypts, best None vs shuffled None (English ~ -5)

### 48. Three layers: theme word + two word keys

- **Why:** Same, with a theme word (Berlin/Egypt/clock/K1-K3) as a third layer; three-stage stacks are a listed community gap.
- **Script:** `attacks/47_word_stacked_keys.py`  ·  log: `campaign/logs/48.log`
- **Status:** done
- **Verdict:** dead: 0 fully determined word-key decrypts, best None vs shuffled [(0, None), (0, None)] (English ~ -5)

### 49. K1-K3 plaintexts as keys with hidden alphabets (4 models)

- **Why:** 'Answers to K1-K3 contain clues to K4'; text keys were only tried on A-Z/KRYPTOS alphabets.
- **Script:** `attacks/49_text_keys_hidden_alphabets.py`  ·  log: `campaign/logs/49.log`
- **Status:** done
- **Verdict:** dead: survivors by model {'M1': 0, 'M2': 0, 'M3': 0, 'M4': 189} (shuffled: [{'M1': 0, 'M2': 0, 'M3': 0, 'M4': 25930}, {'M1': 0, 'M2': 0, 'M3': 0, 'M4': 2830}]); best completion -5.62 vs shuffled -5.547
- best_quadgram: `-5.616165035947359`
  - top: `{"q": -5.616, "text": "K1K2K3_rev", "offset": 264, "period": 52, "values": "AZ", "model": "M4", "plaintext": "YNYASSIFTGFOZVXVYTKAMEASTNORTHEASTCHISAXSUBTHATDEPRENAVIORSTHDMBERLINCLOCKINGWVFIIJKFMWGDV`
  - top: `{"q": -5.625, "text": "K1K2K3_rev", "offset": 277, "period": 53, "values": "AZ", "model": "M4", "plaintext": "XJDUPLMEIBIFFVXYYGJDNEASTNORTHEASTERVERYGRPODWHONEBASEDESTTIMAYBERLINCLOCKHSQUESBYRQSUPDAT`
  - top: `{"q": -5.641, "text": "K1K2K3", "offset": 680, "period": 56, "values": "AZ", "model": "M4", "plaintext": "HQFSAKLMHCQMRUEBDUSINEASTNORTHEASTINGBSSINGCKWMANDKNAXORSEEDCANBERLINCLOCKTXFZQTYPEFOOOOCXBUSI`

### 50. Clock arithmetic keys (dials 12/24/60, two hands) + carved-row restarts

- **Why:** 'Delve into that particular clock': a clock is modular arithmetic; carved row 4 restarts inside BERLINCLOCK, which idea 43 couldn't test.
- **Script:** `attacks/50_clock_arithmetic.py`  ·  log: `campaign/logs/50.log`
- **Status:** done
- **Verdict:** dead: 0 schedules fit the clues out of 2,955,924 (shuffled: [(0, None), (0, None), (0, None)]); best decode None

### 51. Letter class picks the table (KRYPTOS letters on the KRYPTOS tableau)

- **Why:** KRYPTOS-letter clues behave differently; two tables by letter class is a fully keyed version that can stay flat.
- **Script:** `attacks/51_letter_class_tableaux.py`  ·  log: `campaign/logs/51.log`
- **Status:** done
- **Verdict:** dead: no key fits the clues (shuffled K4s: mean 0.00 survivors)

### 52. Second look at every saved candidate (big model, word coverage, LLM judge)

- **Why:** Every candidate was judged by one score at the time; re-judge all together, calibrated on real English with forced clues.
- **Script:** `attacks/52_second_look.py`  ·  log: `campaign/logs/52.log`
- **Status:** done
- **Verdict:** nothing missed: best of 407 candidates big-q -5.04 / coverage 0.66 vs real English >= -4.82 / 0.68 (5th pct); noise max q -6.79; LLM best 3.0 vs real English median 3.0, noise max 2.0; 0 pass both automatic checks (optimised completions), none rated like English
  - top: `{"source": "23.json", "big_q": -5.035, "coverage": 0.66, "llm": 2.0, "plaintext": "MUTFORAMEPHARANASMUSSEASTNORTHEASTONERMEDIFXSOEVERRUJOMSCASESTYBERLINCLOCKITARINGDQICTISABOUNEGSP"}`
  - top: `{"source": "23.json", "big_q": -5.134, "coverage": 0.691, "llm": 2.0, "plaintext": "WBDOESTJUCONALLFORTAMEASTNORTHEASTRRESTTRISEVERSLOOGTSSEAREINCABERLINCLOCKDCTHENCTISAGEOFDKCUWOSW"}`
  - top: `{"source": "38.json", "big_q": -5.013, "coverage": 0.629, "llm": 2.0, "plaintext": "FBHONSSPRINNHFIDESETHEASTNORTHEASTEDLITENOYNMAYREFUNCTIONSWOTHEBERLINCLOCKERORWYXLOCABASUCCESTYCO"}`

