# Campaign status

Updated 2026-11-15 17:18 UTC. Rebuilt automatically by `campaign/run.py` after every idea.

| # | Idea | Status | Hypotheses | Survivors | Verdict | Minutes |
|---|---|---|---|---|---|---|
| 16 | Statistics: are Stehle's DIAWINFBN run and the mod-7 doublets real? | queued | - | - |  |  |
| 15 | Sanborn's 2025 hints as keywords everywhere (Quagmire I-IV + theme-keyword columnar x all key models) | queued | - | - |  |  |
| 11 | Decimation (97 is prime), grid routes, K3 rotations x every key model | queued | - | - |  |  |
| 12 | Myszkowski from ~190k dictionary words x every key model | queued | - | - |  |  |
| 08 | Columnar (every order, widths 2-11) + digit / small-shift key | queued | - | - |  |  |
| 17 | Double columnar (widths 2-6 x 2-6) x progressive / autokey / digit keys | queued | - | - |  |  |
| 10 | Columnar (every order, widths 2-10) + autokey (ciphertext or plaintext feeds the key) | queued | - | - |  |  |
| 09 | Columnar (every order, widths 2-10) + progressive key | queued | - | - |  |  |
| 14 | Keyword alphabets at key lengths 14-26, forced plaintext scored for English | queued | - | - |  |  |
| 13 | Double columnar width 8 x widths 2-6 + periodic key | queued | - | - |  |  |

Verdict key: **dead** = ruled out within the stated scope (each engine has a planted-answer test); **WORTH A LOOK** = beats shuffled-K4 controls, needs a human look.

## Details

### 16. Statistics: are Stehle's DIAWINFBN run and the mod-7 doublets real?

- **Why:** Two famous K4 oddities nobody has put a corrected p-value on. Cheap; tells us whether to chase 4- or 7-spaced structure.
- **Script:** `attacks/16_statistics.py`  ·  log: `campaign/logs/16.log`
- **Status:** queued

### 15. Sanborn's 2025 hints as keywords everywhere (Quagmire I-IV + theme-keyword columnar x all key models)

- **Why:** Newest clues (Egypt 1986, Berlin Wall, delivering a message, World Clock) are barely mined.
- **Script:** `attacks/15_sanborn_2025_hints.py`  ·  log: `campaign/logs/15.log`
- **Status:** queued

### 11. Decimation (97 is prime), grid routes, K3 rotations x every key model

- **Why:** Others tried these scrambles with repeating keys only; progressive, autokey and digit keys behind them are untested.
- **Script:** `attacks/11_routes_decimation_rotation.py`  ·  log: `campaign/logs/11.log`
- **Status:** queued

### 12. Myszkowski from ~190k dictionary words x every key model

- **Why:** Myszkowski was only covered at widths 3-9 with a periodic key.
- **Script:** `attacks/12_myszkowski.py`  ·  log: `campaign/logs/12.log`
- **Status:** queued

### 08. Columnar (every order, widths 2-11) + digit / small-shift key

- **Why:** Digit keys are dead alone but untested behind a transposition; fits Bean's 'letters sit close' finding.
- **Script:** `attacks/08_columnar_digit_keys.py`  ·  log: `campaign/logs/08.log`
- **Status:** queued

### 17. Double columnar (widths 2-6 x 2-6) x progressive / autokey / digit keys

- **Why:** Attack 07 did double columnar with periodic keys only.
- **Script:** `attacks/17_double_columnar_new_keys.py`  ·  log: `campaign/logs/17.log`
- **Status:** queued

### 10. Columnar (every order, widths 2-10) + autokey (ciphertext or plaintext feeds the key)

- **Why:** Autokey alone is dead; stacked behind a transposition it is untested.
- **Script:** `attacks/10_columnar_autokey.py`  ·  log: `campaign/logs/10.log`
- **Status:** queued

### 09. Columnar (every order, widths 2-10) + progressive key

- **Why:** Progressive alone is dead; stacked it is untested.
- **Script:** `attacks/09_columnar_progressive.py`  ·  log: `campaign/logs/09.log`
- **Status:** queued

### 14. Keyword alphabets at key lengths 14-26, forced plaintext scored for English

- **Why:** Clue letters can't decide these lengths (open gap); English scoring against shuffled K4 can.
- **Script:** `attacks/14_keyword_alphabets_long_periods.py`  ·  log: `campaign/logs/14.log`
- **Status:** queued

### 13. Double columnar width 8 x widths 2-6 + periodic key

- **Why:** Pushes attack 07 one width further.
- **Script:** `attacks/13_double_columnar_width8.py`  ·  log: `campaign/logs/13.log`
- **Status:** queued

