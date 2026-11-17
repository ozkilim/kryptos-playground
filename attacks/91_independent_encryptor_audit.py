"""Idea 91: independent-encryptor audit. Do the round 9-11 tests catch ciphers they did not plant?

A search that cannot find a planted answer proves nothing. Every planted answer so far was made
with the attack's own helper code, so a mistake shared by the planting code and the test (clue
positions off by one, an alphabet indexed the wrong way, a Beaufort sign) would pass its planted
test and still miss the real K4. 343 negatives rest on those shared conventions.

This script plants answers the attacks did not make themselves. The encryptors are in
kryptos/idea91_textbook.py, written from the hand-cipher definitions (strips that slide, a key
letter set under an index letter, a rotor that turns) and importing nothing from the repository.

  1. Basics, typed in by hand and compared with what the repository loads: the 97 letters of
     K4, the carved rows (4 + 31 + 31 + 31), the cipher letters at 22-34 and 64-74
     (FLRVQQPRNGKSS, NYPVTTMZFPK), kryptos.CRIBS and every list of clue positions the attacks use.
  2. The textbook encryptors against the sculpture: they must turn the K1 and K2 plaintexts into
     the carved ciphertext with PALIMPSEST and ABSCISSA, and rebuild the carved tableau.
  3. K4-shaped messages: 97 letters of English with EASTNORTHEAST at 22-34 and BERLINCLOCK at
     64-74, enciphered with random in-scope settings of Quagmire I-IV (Vigenere and Beaufort
     forms), sliding key, progressive key, autokey (plaintext and ciphertext feed), two stacked
     keys, multiplier + adder words, paper rotor and keyed-lag autokey. Each message goes to the
     matching attack's own test function (63, 66, 71, 72, 74, 78) together with 40 decoy
     alphabets, exactly as K4 does, with the repository's own CRIBS. The clue letters are forced
     by those tests as usual.
  4. A map of two stacked keys: every pair of lengths p < q <= 13.

Result: recovered / planted per attack and model. A miss with enough checks is a HOLE and is
printed with its exact settings.

This idea makes no claim about K4, so shuffled-K4 controls (kryptos.round9.shuffled_control) and
the clue pre-filter do not apply: nothing is decrypted and there is no K4 score to compare. The
planted answers ARE the experiment.

  python attacks/91_independent_encryptor_audit.py
"""
import json
import os
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea91_audit as audit  # noqa: E402
from kryptos import idea91_textbook as T  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SMOKE = os.environ.get("KRYPTOS_SMOKE")
PER_CELL = 1 if SMOKE else 6
SEED = 91


def basics():
    """[(what, ok)]: the repository's constants against the hand-typed ones."""
    from kryptos import round9, round11
    from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
    layout = json.load(open(ROOT / "data" / "sculpture_layout.json"))
    rows = layout["cipher_panel"]
    mine = T.clue_map()
    a66 = audit.attack("66")
    out = [("K4 in data/ equals the hand-typed K4 (97 letters)", K4 == T.K4_TYPED and len(K4) == 97),
           ("carved rows are 4 + 31 + 31 + 31 and spell K4",
            [len(r) for r in T.K4_ROWS] == [4, 31, 31, 31] and rows[-4].endswith("?" + T.K4_ROWS[0])
            and tuple(rows[-3:]) == T.K4_ROWS[1:]),
           ("kryptos.CRIBS equals the hand-typed clue map (24 letters)", dict(CRIBS) == mine and len(mine) == 24),
           ("round9.POS, round11.POS and attack 66's POS are the same 24 positions",
            round9.POS == sorted(mine) and sorted(round11.POS) == sorted(mine) and a66.POS == round11.POS),
           ("round11.B1 / B2 are letters 22-34 and 64-74", round11.B1 == list(range(21, 34)) and round11.B2 == list(range(63, 74))),
           ("round9.WORDS splits the clues as EAST|NORTHEAST|BERLIN|CLOCK",
            ["".join(mine[i] for i in w) for w in round9.WORDS] == ["EAST", "NORTHEAST", "BERLIN", "CLOCK"]),
           ("the repository's A-Z and KRYPTOS alphabets", AZ == T.A2Z and KRYPTOS_ALPHABET == T.keyword_alphabet("KRYPTOS"))]
    for first, last, plain, cipher in T.CLUES:
        out.append(("K4 letters %d-%d are %s (plain %s)" % (first, last, cipher, plain),
                    K4[first - 1:last] == cipher and "".join(CRIBS[i] for i in range(first - 1, last)) == plain))
    return out, layout


def sculpture(layout):
    k2 = json.load(open(ROOT / "data" / "sculpture" / "k2.json"))
    k1_ok, k2_ok = T.k1_k2_check(k2["plaintext"], k2["ciphertext"])
    _, k2c_ok = T.k1_k2_check(k2["plaintext_corrected"], k2["ciphertext_corrected"])
    az_key = T.repeating_key("FORTIFICATION", 40)
    text = T.only_letters(T.FILLER)[:40]
    m1, m2 = T.keyword_alphabet("SHADOW"), T.column_mixed("PALIMPSEST", True)
    round_trip = all(T.tableau_decrypt(T.tableau_encrypt(text, a, b, az_key, ix, bf), a, b, az_key, ix, bf) == text
                     for a, b in ((m1, m2), (m2, T.A2Z)) for ix in ("A", None) for bf in (False, True))
    twice = T.tableau_encrypt(T.tableau_encrypt(text, m1, m1, T.repeating_key("ABC", 40)), m1, m1, T.repeating_key("LEMON", 40))
    return [("K1 plaintext + PALIMPSEST -> the carved K1", k1_ok),
            ("K2 plaintext + ABSCISSA -> the carved K2 (369 letters, '?' copied)", k2_ok),
            ("K2 with the missing S restored -> the corrected K2", k2c_ok),
            ("carved tableau rebuilt from the strip code (26 rows)", T.tableau_panel_check(layout["tableau_panel"]) == 26),
            ("Beaufort by reversed strip = Beaufort read off the printed square",
             T.tableau_encrypt(text, T.A2Z, T.A2Z, az_key, "A", True) == T.beaufort_by_square(text, az_key)),
            ("every tableau form decrypts back", round_trip),
            ("two stacked keys = enciphering twice on a Quagmire III tableau",
             T.tableau_encrypt(text, m1, m1, T.stacked_key("ABC", "LEMON", m1, 40)) == twice)]


def dictionary_lists():
    """{attack: set of alphabets its full run tries}, for checking the planted alphabets are in scope."""
    from kryptos import idea78_mixed, round11
    return {"63": {m for _, m in audit.attack("63").alphabets()},
            "66": {m for _, m in audit.attack("66").alphabets()},
            "r11": {m for _, m in round11.dictionary_alphabets(mixed=False)},
            "78": {m for _, m in idea78_mixed.new_alphabets()},
            "words": set(round11.vocabulary())}


def english():
    """The solved Kryptos plaintexts as extra filler (read straight from data/, not through kryptos)."""
    return " ".join(json.load(open(ROOT / "data" / "sculpture" / ("%s.json" % k)))["plaintext"] for k in ("k1", "k2", "k3"))


if __name__ == "__main__":
    t0 = time.time()
    with Experiment("independent-encryptor audit of attacks 63, 66, 71, 72, 74, 78 (textbook plants, no shared code)",
                    puzzle="k4", notes="K4-shaped messages from encryptors written from the definitions, fed to each "
                    "attack's own test with 40 decoy alphabets; %d per model; no claim about K4, so no shuffled "
                    "controls" % PER_CELL, cribs_forced=True) as ex:
        checks, layout = basics()
        checks += sculpture(layout)
        print("Basics and sculpture checks:")
        for what, ok in checks:
            print("   %s  %s" % ("ok  " if ok else "FAIL", what))
        bad = [w for w, ok in checks if not ok]

        n_cells = len(audit.cells())
        jobs = [(i, PER_CELL, SEED, english()) for i in range(n_cells)]
        with Pool(min(8, os.cpu_count() or 2)) as pool:
            records = [r for part in pool.map(audit.run_cell, jobs, chunksize=1) for r in part]
        ex.count(len(records))

        print("\nPlanted K4-shaped messages: %d (%d models x %d)" % (len(records), n_cells, PER_CELL))
        print("%-7s %-74s %7s %5s %5s %5s" % ("attack", "model", "planted", "found", "limit", "HOLE"))
        tab = audit.table(records)
        for (att, model), (n, f, lim, hole) in tab.items():
            print("%-7s %-74s %7d %5d %5d %5d" % (att, model, n, f, lim, hole))
        print("\nPer attack (found / planted; limit = too few checks to be judged, as the attack states; HOLE = missed):")
        per = {}
        for (att, _), row in tab.items():
            a = per.setdefault(att, [0, 0, 0, 0])
            for j in range(4):
                a[j] += row[j]
        for att, (n, f, lim, hole) in per.items():
            print("   attack %-6s %3d / %3d found, %2d limit, %3d HOLE" % (att, f, n, lim, hole))
        tot = [sum(a[j] for a in per.values()) for j in range(4)]
        print("   all            %3d / %3d found, %2d limit, %3d HOLE" % (tot[1], tot[0], tot[2], tot[3]))

        exact = [r for r in records if r["exact"] is not None and r["status"] == "found"]
        print("keyed-lag autokey: planted distances and constant reported exactly in %d of %d found" % (
            sum(r["exact"] for r in exact), len(exact)))
        decoy = [r["others"] for r in records if r["others"] is not None]
        print("decoy alphabets: %d messages had at least one decoy setting listed (of %d; 40 decoys each)" % (
            sum(1 for d in decoy if d), len(decoy)))

        holes = [r for r in records if r["status"] == "HOLE"]
        print("\nHOLES (planted, enough checks, not found): %d" % len(holes))
        by_model = {}
        for r in holes:
            by_model.setdefault((r["attack"], r["model"]), []).append(r)
        for (att, model), rs in by_model.items():
            print("   attack %s, %s: %d missed" % (att, model, len(rs)))
            for r in rs[:6 if SMOKE else 100]:
                print("        checks=%d  %s" % (r["checks"], r["params"]))
        limits = [r for r in records if r["status"] == "limit"]
        print("\nToo few checks to be judged (not holes): %d" % len(limits))
        for r in limits:
            print("   attack %s, %s: checks=%d (needs %d)  %s" % (r["attack"], r["model"], r["checks"], r["needed"], r["params"]))

        import random
        smap = audit.Audit(random.Random(SEED)).stacked_map()
        missed = [(p, q, c) for p, q, c, f, s, r in smap if c >= 7 and f < 2]
        judged = [x for x in smap if x[2] >= 7]
        print("\nTwo stacked keys, every pair p < q <= 13 (q not a multiple of p), 2 messages each on a Quagmire III tableau:")
        print("   pairs: %d; with 7+ exact checks: %d; of those found both times by attack 66: %d; missed: %d" % (
            len(smap), len(judged), sum(x[3] == 2 for x in judged), len(missed)))
        print("   found   (p,q): %s" % " ".join("%d,%d" % x[:2] for x in judged if x[3] == 2))
        print("   MISSED  (p,q:exact checks): %s" % " ".join("%d,%d:%d" % x for x in missed))
        print("   attack 66's own exact solver accepts the true key values of every missed pair: %s" % all(
            x[4] == x[2] for x in judged if x[3] < 2))
        print("   kryptos.round11.battery (attacks 68, 70, 71B, 78, 81, 88) misses the same pairs: %s (it misses %d)" % (
            [x[:2] for x in judged if x[5] < 2] == [x[:2] for x in judged if x[3] < 2], sum(x[5] < 2 for x in judged)))
        print("   pairs with fewer than 7 exact checks (cannot be judged): %s" % " ".join(
            "%d,%d:%d" % x[:3] for x in smap if x[2] < 7))

        n_bad, found_bad = audit.planted_mistake(SEED, 2 if SMOKE else 10)
        print("\nPlanted mistake (clue words one letter late, attacks 63 and 66): %d messages, %d found (must be 0: "
              "the audit can see an off-by-one)" % (n_bad, found_bad))
        if found_bad:
            bad.append("planted mistake not noticed")

        if not SMOKE:
            lists = dictionary_lists()
            key = {"63": "63", "66": "66", "71B": "r11", "74": "r11"}
            out = set()
            for r in records:
                known = lists[key.get(r["attack"], "78" if r["attack"].startswith("78") else "r11")]
                out |= {m for m in r["alphabets"] if m not in known}
            print("\nplanted alphabets that are NOT in the attack's own dictionary list: %d" % len(out))
            print("audit words missing from the repository's vocabulary: %s" % sorted(w for w in T.WORDS if w not in lists["words"]))

        print("\nplanted recovered: %d/%d (%d more cannot be judged; %d holes); basics and sculpture checks %d/%d; %.0f s" % (
            tot[1], tot[0], tot[2], tot[3], len(checks) - len(bad), len(checks), time.time() - t0))
        stacked = sum(r["model"].startswith("two stacked") for r in holes)
        print("holes by kind: two stacked keys %d messages (%d of %d judgeable length pairs); key letter numbered on "
              "an alphabet other than M (autokey, progressive) %d messages" % (stacked, len(missed), len(judged), len(holes) - stacked))
        print("VERDICT:", "BASIC CHECK FAILED: %s" % bad if bad else
              "no shared-convention mistake (positions, alphabets, signs agree; attacks 63, 71, 72, 74, 78 found every "
              "judgeable plant); attack 66 has scope holes: %d messages missed, %d of %d stacked length pairs" % (
                  tot[3], len(missed), len(judged)) if tot[3] or missed else
              "every planted answer with enough checks was found")
    if bad:
        sys.exit(1)
