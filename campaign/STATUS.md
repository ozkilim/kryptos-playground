# Campaign status

Updated 2026-11-15 19:57 UTC. Rebuilt automatically by `campaign/run.py` after every idea.

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

