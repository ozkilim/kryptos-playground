"""Idea 105: audit, part 2. Textbook encryptors against the attacks idea 91 did not reach.

A search that cannot find a planted answer proves nothing, and a planted answer made by the
attack's own code proves less than it seems: idea 91 found two real scope holes in attack 66 that
every planted test had passed. It reached six attacks. This script takes the same audit to twenty
more: 54, 56, 59, 60, 61, 62, 65, 68, 69, 70, 73, 79, 81, 84, 86, 88, 89, 90, the edge settings of
74, tests 68 and 70 inside 78, and the conventions of 57 (and 80, which uses 57's views).

How it works. kryptos/idea91_textbook.py and kryptos/idea105_textbook.py hold encryptors written
from the hand-cipher definitions (strips that slide, a key written over the word spaces, a key
strip read off a grid by columns, an alphabet whose letters move after each use). They share no
code with the attacks. Each planted message is K4-shaped: 97 letters of English with
EASTNORTHEAST at 22-34 and BERLINCLOCK at 64-74 (the clue letters are therefore forced exactly as
they are for K4). It is enciphered with a random setting from the scope the attack claims: every
key rule, every layout, both forms, the shortest and longest lengths, and the edge settings. It
then goes to the attack's own test function with the repository's CRIBS and with decoy alphabets.

A planted message ends in one of three ways:
  found   the attack lists the planted setting
  limit   not listed, but the setting leaves fewer independent checks than the attack's own
          threshold (counted here, independently): the attack never claimed to judge it
  HOLE    not listed although it has enough checks: the scope is smaller than the negative says

There is NO K4 search here and nothing is decrypted, so shuffled-K4 controls
(kryptos.round9.shuffled_control) have nothing to compare and the clue pre-filter does not apply.
The audit has its own controls: messages with the clue words one letter late must not be found,
and decoy alphabets are handed over with each true one. A HOLE is a hole in a negative, not a
signal in K4.

  python attacks/105_textbook_audit_part2.py
"""
import json
import os
import sys
import time
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import idea105_audit as audit  # noqa: E402
from kryptos import idea105_textbook as X  # noqa: E402
from kryptos import idea91_textbook as T  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SMOKE = os.environ.get("KRYPTOS_SMOKE")
PER_CELL = 2 if SMOKE else 24
SEED = 105

# What each attack's docstring / negative says it covers (the claimed scope).
CLAIMS = {
    "54": "any key formula of up to 3 of ~190 ingredients (position, grids 2-40, number sequences, neighbour letters 1-5 away), A-Z/KRYPTOS, 8+ checks",
    "56": "interrupted key of length 1-26, restart at/after a plain or cipher letter or at each word; A-Z/KRYPTOS and theme tableaux; 5+ checks",
    "57": "English running key on every keyword tableau; key letter read as A-Z[s+c], M[s] or KRYPTOS[s] (conventions only)",
    "59": "autokey + repeating key: cipher feed 1-60 back, plain feed 1-9 back, multiplier 1-25, key length 1-26, A-Z/KRYPTOS; 6+ checks",
    "60A": "the clue letters covered by 2, 3 or 4 fixed tableau rows (A-Z/KRYPTOS, Vigenere/Beaufort)",
    "60B": "2-4 interleaved systems, each with its own tableau and repeating key up to 13",
    "60C": "Slidefair pairs (Vigenere, variant, Beaufort) on A-Z or KRYPTOS",
    "61": "repeating key 2-26 scrambled by a columnar (widths 2-8), K3 quarter turns (one or two), routes, skips; 6+ checks",
    "62": "drifting key word, widths 2-40 (widths 10+ said to be undecidable); 4+ checks",
    "65": "chain addition with any two taps n < m <= 10 and any multipliers; row word + column word, widths 2-48, with or without the ?; 4+ checks",
    "68": "battery of key rules on each clue alone and with the gap off by -3..+3, every keyword tableau, 5 layouts; 7+ checks",
    "69A": "rows of 21, one tableau, row key moved -5..5 columns; 7+ checks",
    "69B": "rows of 21, a different tableau (alphabet, layout, form) per row, joined on 10 column differences",
    "70": "battery of key rules mod 27-31 on every keyword tableau, multiplying key mod 29 and 31; 7+ checks",
    "73": "alphabet changed after every letter (10 rules, cipher or plain letter, 4 fixed lookups + self shifted) and the real Chaocipher",
    "74": "keyed-lag autokey: cipher feed distances 1-20, plain feed 1-8, periods 1-13; 7+ checks",
    "78/68": "attack 68's tests on column-mixed alphabets",
    "78/70": "attack 70's tests on column-mixed alphabets",
    "79": "formula mining and the three-keyword join with the gap off by -3..+3",
    "81": "battery, multiplier + adder words and word-turned rotor with any one clue letter left out; 7+ checks (rotor 5+)",
    "84": "two repeating-key layers on two different tableaux, key lengths p + q <= 17 and long keys 19-22 with a short partner; 7+ checks",
    "86": "any keyword alphabet from its tail: repeating key 1-26 and sliding key 1-26, five layouts, every solution listed",
    "88": "key running over word spaces: repeating 1-17, sliding 1-15, progressive 1-12, two stacked keys, chain addition; 3 x 2 clue parsings, offset 0-25; 7+ checks",
    "89": "the battery on alphabets that are not keyword alphabets (keyphrase orders from the sculpture's texts)",
    "90": "row keys the next row: plain feed 7, 8 and 34-48 back (second clue moved -3..3), cipher feed 1-66 back, word of 1-4 on top; 7+ checks",
}
ORDER = ["59", "68", "70", "74", "78/68", "78/70", "81", "88", "90", "54", "56", "57", "60A", "60B", "60C", "61", "62", "65",
         "69A", "69B", "73", "79", "84", "86", "89"]


def english():
    """The solved Kryptos plaintexts as extra filler (read straight from data/, not through kryptos)."""
    return " ".join(json.load(open(ROOT / "data" / "sculpture" / ("%s.json" % k)))["plaintext"] for k in ("k1", "k2", "k3"))


def textbook_checks():
    """[(what, ok)]: the new textbook encryptors against known answers and against idea 91's encryptors."""
    import random
    rng = random.Random(SEED)
    k3 = json.load(open(ROOT / "data" / "sculpture" / "k3.json"))
    p3, c3 = [c for c in k3["plaintext"].upper() if c.isalpha()], [c for c in k3["ciphertext"].upper() if c.isalpha()]
    text = T.only_letters(T.FILLER)[:60]
    m1, m2 = T.keyword_alphabet("SHADOW"), T.column_mixed("PALIMPSEST", True)
    key = T.repeating_key("FORTIFICATION", 60)
    lag_a = X.fed_key_encrypt(text, m1, m2, m1, 3, "plain", 1, [5], random.Random(1))
    lag_b = T.keyed_lag_autokey_encrypt(text, m1, [3], 5, "plain", random.Random(1), cipher=m2, numbering=m1)
    words = X.spaced_k4(rng)
    syms = X.symbols(words)
    flat = "".join(words)
    spaced_key = T.repeating_key("LEMON", len(syms))
    letters_only = [k for k, ch in zip(spaced_key, syms) if ch is not X.SPACE]
    sf, _ = X.slidefair_encrypt("THEQUICKBROWNFOX", T.A2Z, "DIG")
    sf_back = "".join(T.A2Z[(T.A2Z.index(a) + T.A2Z.index(b)) % 26] for a, b in zip(sf[0::2], sf[1::2]))
    sf_want = "".join(T.A2Z[(T.A2Z.index(a) + T.A2Z.index(b)) % 26] for a, b in zip("THEQUICKBROWNFOX"[0::2], "THEQUICKBROWNFOX"[1::2]))
    return [
        ("Chaocipher: Byrne's published example comes out letter for letter", X.chaocipher_encrypt(X.CHAO_PLAIN, X.CHAO_LEFT, X.CHAO_RIGHT) == X.CHAO_CIPHER),
        ("two quarter turns (rows of 42, then rows of 14) turn the K3 plaintext into the carved K3", X.quarter_turn(X.quarter_turn(p3, 42), 14) == c3),
        ("a wheel of 26 cells is the ordinary tableau (Vigenere and Beaufort)",
         all(X.wheel_encrypt(text, m1, m2, key, ix, bf) == T.tableau_encrypt(text, m1, m2, key, ix, bf) for ix in ("A", None) for bf in (False, True))),
        ("a sliding key on a wheel of 26 cells is idea 91's sliding key", X.wheel_sliding(text, m1, m2, [3, 1, 4], True) == T.sliding_encrypt(text, m1, m2, [3, 1, 4], True)),
        ("key + earlier letter with a one-letter key is idea 91's keyed-lag autokey", lag_a == lag_b),
        ("a sheet without spaces: the key over spaces is the ordinary repeating key",
         X.encrypt_over_spaces(list(flat), m1, m1, T.repeating_key("LEMON", 97)) == T.tableau_encrypt(flat, m1, m1, T.repeating_key("LEMON", 97))),
        ("key over spaces = ordinary encryption with the key letters that fell on letters",
         X.encrypt_over_spaces(syms, m1, m2, spaced_key) == T.tableau_encrypt(flat, m1, m2, letters_only)),
        ("the spaced message has the clues at 22-34 and 64-74", flat[21:34] == "EASTNORTHEAST" and flat[63:74] == "BERLINCLOCK" and len(flat) == 97),
        ("Slidefair keeps the sum of each pair (no same-column pair in the example)", sf_back == sf_want),
        ("chain addition 1,1 from 0,1 is Fibonacci", X.chain_key([0, 1], 10, 1, 2, modulus=1000) == [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]),
        ("columnar read-off keeps every letter once", sorted(X.columnar(list(range(97)), [2, 0, 3, 1])) == list(range(97))),
    ]


def list_checks(records):
    """Planted alphabets against the lists the attacks really run (full run only)."""
    from kryptos import idea89_orders as O
    from kryptos import round11
    dic = {m for _, m in round11.dictionary_alphabets(mixed=True)}
    plain = {m for _, m in round11.dictionary_alphabets(mixed=False)}
    new = {m for _, m in O.new_alphabets()[0]}
    out = []
    for r in records:
        for m in r["alphabets"]:
            ok = m in new or m in dic if r["attack"] == "89" else m in dic if r["attack"] in ("90", "79", "78/68", "78/70") else m in plain
            if not ok and r["attack"] != "86":
                out.append((r["attack"], m))
    return out, len(dic), len(new)


if __name__ == "__main__":
    t0 = time.time()
    cells = audit.cells()
    with Experiment("independent-encryptor audit, part 2: attacks 54-62, 65, 68-70, 73, 74, 78, 79, 81, 84, 86, 88-90 "
                    "(textbook plants, no shared code)", puzzle="k4",
                    notes="K4-shaped messages from encryptors written from the definitions, fed to each attack's own "
                          "test with decoy alphabets; %d per model, %d models; no K4 search, so no shuffled controls"
                          % (PER_CELL, len(cells)), cribs_forced=True) as ex:
        checks = textbook_checks()
        print("Textbook encryptor checks:")
        for what, ok in checks:
            print("   %s  %s" % ("ok  " if ok else "FAIL", what))
        bad = [w for w, ok in checks if not ok]

        eng = english()
        jobs = [(i, PER_CELL, SEED, eng) for i in range(len(cells))]
        maps = [("68", g, SEED + g) for g in audit.GAPS] + [("70", n, SEED + n) for n in (27, 28, 29, 30, 31)]
        maps += [("81", None, SEED + s) for s in range(1 if SMOKE else 3)] + [("88", None, SEED + 50 + s) for s in range(1 if SMOKE else 3)]
        if SMOKE:
            maps = maps[:1] + maps[6:7] + maps[-2:]
        mistakes = [(i, 1 if SMOKE else 6, SEED) for i in range(len(audit.MISTAKES))]
        with Pool(min(8, os.cpu_count() or 2)) as pool:
            parts = pool.map_async(audit.run_cell, jobs, chunksize=1)
            smaps = pool.map_async(audit.stacked_job, maps, chunksize=1)
            wrong = pool.map_async(audit.planted_mistake, mistakes, chunksize=1)
            records = [r for part in parts.get() for r in part]
            smaps, wrong = smaps.get(), [r for part in wrong.get() for r in part]
        n_map = sum(len(rows) for _, _, rows in smaps)
        ex.count(len(records) + n_map + len(wrong))

        tab = audit.table(records)
        print("\nPlanted K4-shaped messages: %d (%d models x %d), %.0f s" % (len(records), len(cells), PER_CELL, time.time() - t0))
        per = {}
        for att in ORDER:
            rows = [(model, v) for (a, model), v in tab.items() if a == att]
            if not rows:
                continue
            print("\nattack %s. Claimed: %s" % (att, CLAIMS[att]))
            print("   %-86s %7s %5s %5s %5s" % ("model", "planted", "found", "limit", "HOLE"))
            tot = [0, 0, 0, 0]
            for model, v in rows:
                print("   %-86s %7d %5d %5d %5d" % (model[:86], v[0], v[1], v[2], v[3]))
                tot = [x + y for x, y in zip(tot, v)]
            per[att] = tot
        assert set(a for a, _ in tab) <= set(ORDER)
        print("\nPer attack (found / planted; limit = too few checks to be judged; HOLE = missed with enough checks):")
        for att in ORDER:
            if att in per:
                n, f, lim, hole = per[att]
                print("   attack %-6s %4d / %4d found, %3d limit, %3d HOLE" % (att, f, n, lim, hole))
        tot = [sum(v[j] for v in per.values()) for j in range(4)]
        print("   all           %4d / %4d found, %3d limit, %3d HOLE" % (tot[1], tot[0], tot[2], tot[3]))

        holes = [r for r in records if r["status"] == "HOLE"]
        print("\nHOLES (planted, enough checks, not found): %d messages" % len(holes))
        by_model = {}
        for r in holes:
            by_model.setdefault((r["attack"], r["model"]), []).append(r)
        for (att, model), rs in by_model.items():
            print("   attack %s, %s: %d missed" % (att, model, len(rs)))
            for r in sorted(rs, key=lambda r: len(r["params"]))[:4]:
                print("        checks=%d  %s" % (r["checks"], r["params"][:230]))
        limits = [r for r in records if r["status"] == "limit"]
        print("\nToo few checks to be judged (not holes): %d messages" % len(limits))
        lim_model = {}
        for r in limits:
            lim_model.setdefault((r["attack"], r["model"]), []).append(r)
        for (att, model), rs in lim_model.items():
            print("   attack %s, %s: %d, e.g. checks=%d (needs %d)  %s" % (att, model, len(rs), rs[0]["checks"], rs[0]["needed"], rs[0]["params"][:150]))

        exact = [r for r in records if r["exact"] is not None and r["status"] == "found"]
        print("\nattack 73: of %d found, the attack's best setting was the planted one itself in %d (the others are an "
              "equivalent rule on the same alphabet)" % (len(exact), sum(r["exact"] for r in exact)))
        print("settings listed besides the planted one (decoy alphabets, or another rule on the same message), per attack:")
        for att in ORDER:
            other = [r["others"] for r in records if r["attack"] == att and r["others"] is not None]
            if other:
                print("   attack %-6s %4d of %4d messages had one or more (%d settings in all)" % (
                    att, sum(1 for d in other if d), len(other), sum(other)))

        print("\nTwo stacked keys, every pair p < q <= 13 (q not a multiple of p), one message per pair and setting:")
        missed_all = 0
        for which, setting, rows in smaps:
            judged = [x for x in rows if x[2] >= 7]
            missed = [x for x in judged if not x[3]]
            missed_all += len(missed)
            label = {"68": "attack 68, gap %+d" % (setting or 0), "70": "attack 70, wheel of %s cells" % setting,
                     "81": "attack 81, one wrong plain letter", "88": "attack 88, key over the spaces"}[which]
            print("   %-34s pairs with 7+ exact checks: %2d; found %2d; MISSED %2d: %s" % (
                label, len(judged), len(judged) - len(missed), len(missed), " ".join("%d,%d" % x[:2] for x in missed)))

        n_wrong = sum(r["status"] == "found" for r in wrong)
        print("\nPlanted mistake (clue words one letter late, %d attack tests): %d messages, %d found (must be 0: the "
              "audit can see an off-by-one)" % (len(audit.MISTAKES), len(wrong), n_wrong))
        for r in wrong:
            if r["status"] == "found":
                print("   FOUND ALTHOUGH MISPLACED: attack %s %s %s" % (r["attack"], r["model"], r["params"][:150]))
        if n_wrong:
            bad.append("planted mistake not noticed")

        if not SMOKE:
            out, n_dic, n_new = list_checks(records)
            print("\nplanted alphabets that are NOT in the list the attack runs on: %d (dictionary list %d, non-keyword list %d)" % (
                len(out), n_dic, n_new))
            for att, m in out[:10]:
                print("   attack %s: %s" % (att, m))

        print("\nplanted recovered: %d/%d (%d more cannot be judged; %d holes); stacked-key maps %d messages, %d missed; "
              "textbook checks %d/%d; %.0f s" % (tot[1], tot[0], tot[2], tot[3], n_map, missed_all, len(checks) - len(bad), len(checks),
                                                  time.time() - t0))
        map_bad = sorted({w for w, _, rows in smaps if any(x[2] >= 7 and not x[3] for x in rows)})
        clean = [a for a in ORDER if a in per and not per[a][3] and a not in map_bad]
        print("VERDICT:", "CHECK FAILED: %s" % bad if bad else
              "no convention mistake in any attack (positions, alphabets, signs agree; found every judgeable plant: %s). "
              "Scope smaller than claimed in: %s. Two stacked keys are missed at most length pairs by the battery inside: %s"
              % (", ".join(clean), ", ".join(a for a in ORDER if a in per and per[a][3]) or "none", ", ".join(map_bad) or "none"))
    if bad:
        sys.exit(1)
