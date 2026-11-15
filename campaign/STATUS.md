# Campaign status

Updated 2026-11-15 23:44 UTC. Rebuilt automatically by `campaign/run.py` after every idea.

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

