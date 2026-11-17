"""Idea 108: the strip is moved by a text. The key is the running sum of a sentence or a sculpture reading.

Round 10 introduced the sliding key: each key letter says how far to MOVE the strip, so the key in
force is the running sum of the key letters. It was only tested with a repeating word of up to 17
letters. Here the moving text is a whole sentence or a reading of the sculpture, so the key never
repeats. Scheidt: simple, can be remembered, "with the correct key word/s". Sanborn: just be able to read.

What the clues force. For any tableau the 24 clue letters give the key values k[21..33] and k[63..73].
The moving text is their differences d[i] = k[i] - k[i-1]: 12 letters under EASTNORTHEAST and 10 under
BERLINCLOCK, 42 places apart. Attacks 57 and 58 compared the key letters themselves with text; no
earlier test looks at the differences.

  tableaux    A-Z, KRYPTOS, every dictionary keyword alphabet and its two transposition-mixed forms
              (666,993), in five layouts (M/M, M/AZ, AZ/M, M/KR, KR/M)
  key views   Vigenere, Beaufort, variant Beaufort, reversed (DIANA) table. The last two are the first
              two with the strip moved the other way, so: 2 forms x 2 directions
  numbering   the moving text's letters numbered on A-Z, on KRYPTOS or on the tableau alphabet,
              from 0 or from 1
  = 120 settings per alphabet (80 for A-Z and KRYPTOS)

Part A, known texts, exact. The 22 letters must stand in one of the readings of attack 58 (both panels
and K1-K3 plaintext by rows, columns, diagonals, back and forth, reversed, every d-th letter for d up to
60; the Morse text), block 2 exactly 42 letters after block 1. Also reported with the gap free (same
reading, any distance). A setting is placed exactly when three six-letter pieces of its fragments occur
anywhere in the texts (bit map of all six-letter pieces); a full match always qualifies. We report the
best count out of 22 for K4 and for 5 shuffled K4s; only 22 is a hit.

Part B, unknown English text. The 22 letters are scored as English on the big model (16 quadgrams), as
attack 57 does for key letters. Best 200 kept; K4 against 3 shuffled K4s; fragments printed to be read.

Part C, second differences (the text moves a strip that moves the strip): 11 + 9 letters, known texts
only, same exact test, 20 needed.

Planted: K2's plaintext as the moving text on a dictionary tableau (must give 22 of 22); a column
reading of the cipher panel as second-order moving text (20 of 20); four messages moved by English
sentences that are in none of the texts (rank of the true fragment among all settings).

  python attacks/108_strip_moved_by_text.py
"""
import os
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, load  # noqa: E402
from kryptos import idea108_moving as H  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import letters  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import dictionary_alphabets, english97, pmap  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
PROCS = int(os.environ.get("IDEA108_PROCS", "4" if SMOKE else "8"))
MAX_SKIP = 6 if SMOKE else 60
MARGIN = 0.35            # per-quadgram lead K4 needs over the best shuffled K4 in part B (as attack 57)
SENTENCES = [
    "THE OLD LIGHTHOUSE KEEPER CLIMBED THE STAIRS EVERY EVENING AND WATCHED THE SHIPS COME HOME THROUGH THE WINTER STORMS BEFORE DARK",
    "WHEN THE TRAIN FINALLY REACHED THE BORDER STATION THE PASSENGERS WERE ASKED TO SHOW THEIR PAPERS AND WAIT IN THE COLD HALL ALL NIGHT",
    "NOBODY IN THE VILLAGE COULD REMEMBER WHO HAD PLANTED THE ORCHARD BUT EVERY AUTUMN THE CHILDREN GATHERED THE APPLES TOGETHER AGAIN",
    "SHE OPENED THE LETTER WITH GREAT CARE BECAUSE THE HANDWRITING ON THE ENVELOPE BELONGED TO SOMEONE SHE THOUGHT WAS LONG GONE FROM HERE",
]


def run(ct, cribs, alphas, parts, paths, thresh=None):
    """Scan every alphabet. Returns merged counts, seeds (best first) and the best distinct fragments."""
    pl, cl = H.clue_letters(ct, cribs)
    out = {"n": 0, "sa": [0] * 4, "sc": [0] * 4, "seeds_a": [], "seeds_c": [], "above": 0}
    frag = {}
    for r in pmap(H.scan, alphas, H.init, (paths[0], paths[1], pl, cl, parts, thresh), chunk=1500, procs=PROCS):
        out["n"] += r["n"]
        out["above"] += r["above"]
        for key in ("sa", "sc"):
            out[key] = [a + b for a, b in zip(out[key], r[key])]
        out["seeds_a"].extend(r["seeds_a"])
        out["seeds_c"].extend(r["seeds_c"])
        for item in r["top"]:
            f = (item[5], item[6])
            if f not in frag or item > frag[f]:
                frag[f] = item
    for key in ("seeds_a", "seeds_c"):
        out[key].sort(key=lambda s: (-s[0][0], -s[0][2], s[1:5]))
    out["top"] = sorted(frag.values(), reverse=True)[:200]
    return out


def best_counts(seeds):
    """(best with the 42-letter gap, best with the gap free) over all placed seeds."""
    return (max((s[0][0] for s in seeds), default=0), max((s[0][2] for s in seeds), default=0))


def where(pos, names, starts):
    from bisect import bisect_right
    st = bisect_right(starts, max(pos, 0)) - 1
    return "%s, letter %d" % (names[st], pos - starts[st])


def show_seed(s, names, starts, need):
    (fx, fpos, fr, p1, p2), name, lay, form, label, t1, t2 = s
    return "%d/%d (gap free %d/%d)  %s %s %s, %s  %s|%s  at %s" % (
        fx, need, fr, need, name, lay, form, label, H.undig(t1), H.undig(t2), where(fpos, names, starts))


def show_frag(item):
    s, name, lay, form, label, t1, t2 = item
    return "%.3f  %s|%s  %s %s %s, %s" % (s / 16, H.undig(t1), H.undig(t2), name, lay, form, label)


def plant(rng, alphas, text, lay, form, numbering, off, sign, order):
    """A 97-letter English message on a random dictionary tableau, the strip moved by `text`."""
    name, m = alphas[rng.randrange(2, len(alphas))]
    pt = english97(rng)
    num = {"AZ": AZ, "KR": KRYPTOS_ALPHABET, "M": m}[numbering]
    ct = H.encrypt(pt, m, lay, form, text, num, off, sign, order, k0=rng.randrange(26))
    return ct, {i: pt[i] for i in CRIBS}, name, m


def true_fragments(text, order):
    if order == 1:
        return H.dig(text[22:34]), H.dig(text[64:74])
    return H.dig(text[23:34]), H.dig(text[65:74])


def prefilter_encrypt(pt, rng):
    """Encryptor for kryptos.clues.prefilter: key drawn from rng only."""
    words = ["PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN", "LODESTONE", "ILLUSION", "COMPASS", "LANGLEY"]
    from kryptos.round9 import keyword_alphabet
    m = keyword_alphabet(rng.choice(words))
    src = letters(load("k2")["plaintext"] + load("k3")["plaintext"] + load("k1")["plaintext"])
    o = rng.randrange(len(src))
    text = (src[o:] + src * (len(pt) // len(src) + 2))[:len(pt)]
    return H.encrypt(pt, m, "M/M", "vig", text, AZ, off=1, k0=rng.randrange(26))


if __name__ == "__main__":
    t0 = time.time()
    alphas = dictionary_alphabets(mixed=True)
    strs = H.text_streams(MAX_SKIP)
    names = [n for n, _ in strs]
    folder = tempfile.mkdtemp(prefix="idea108_")
    paths = H.build_index(strs, folder)
    with open(paths[0], "rb") as f:
        starts = H.stream_starts(f.read())
    n_letters = sum(len(s) for _, s in strs)
    per = sum(len(H.tables(m)) * (8 if m == AZ else 10) for _, m in alphas)
    print("alphabets: %d   settings per text: %d   known-text readings: %d (%d letters)   index built in %.0fs"
          % (len(alphas), per, len(strs), n_letters, time.time() - t0))
    notes = ("%d alphabets x 5 layouts x Vigenere/Beaufort x 2 directions x 2-3 numberings from 0 or 1; "
             "A: 12+10 first differences placed exactly in %d readings (%d letters, skips 1-%d); "
             "B: the same letters scored as English (16 quadgrams); C: 11+9 second differences placed exactly"
             % (len(alphas), len(strs), n_letters, MAX_SKIP))
    try:
        with Experiment("strip moved by a text: differences of the forced key against texts", puzzle="k4",
                        notes=notes, cribs_forced=True) as ex:
            k4 = run(K4, CRIBS, alphas, "ABC", paths)
            ex.count(k4["n"] * 3)
            a4, c4 = best_counts(k4["seeds_a"]), best_counts(k4["seeds_c"])
            print("\nK4 (%d settings, %.0fs)" % (k4["n"], time.time() - t0))
            print("  part A  six-letter pieces found (b1 first half, +second half, +b2 first, +b2 second): %s" % k4["sa"])
            print("  part A  best placement: %d/22 with the 42-letter gap, %d/22 with the gap free" % a4)
            for s in k4["seeds_a"][:5]:
                print("     ", show_seed(s, names, starts, 22))
            print("  part C  six-letter pieces found: %s" % k4["sc"])
            print("  part C  best placement: %d/20 with the 42-letter gap, %d/20 with the gap free" % c4)
            for s in k4["seeds_c"][:5]:
                print("     ", show_seed(s, names, starts, 20))
            print("  part B  best fragments as English (mean log10 per quadgram; English text is about -4.2):")
            for item in k4["top"][:15]:
                print("     ", show_frag(item))

            ctrl_a, ctrl_c, ctrl_b, ctrl_sa, ctrl_sc = [], [], [], [], []
            seeds = (1, 2) if SMOKE else (1, 2, 3, 4, 5)
            nb = 1 if SMOKE else 3
            for j, seed in enumerate(seeds):
                r = run(shuffled_control(seed), CRIBS, alphas, "ABC" if j < nb else "AC", paths)
                a, c = best_counts(r["seeds_a"]), best_counts(r["seeds_c"])
                ctrl_a.append(a)
                ctrl_c.append(c)
                ctrl_sa.append(r["sa"])
                ctrl_sc.append(r["sc"])
                line = "shuffled K4 #%d: A %d/22 (free %d/22) pieces %s; C %d/20 (free %d/20) pieces %s" % (
                    seed, a[0], a[1], r["sa"], c[0], c[1], r["sc"])
                if j < nb:
                    ctrl_b.append(r["top"][0][0] / 16)
                    line += "; B best %s" % show_frag(r["top"][0])
                print(line, "(%.0fs)" % (time.time() - t0))

            # ---- planted answers
            rng = random.Random(108)
            ok, total = 0, 0
            k2 = letters(load("k2")["plaintext"])
            o = rng.randrange(len(k2) - 97)
            text = k2[o:o + 97]
            ct, cribs, name, m = plant(rng, alphas, text, "M/M", "vig", "M", 1, 1, 1)
            r = run(ct, cribs, alphas, "AC", paths)
            hit = [s for s in r["seeds_a"] if s[0][0] == 22 and s[1] == name]
            total += 1
            ok += bool(hit)
            print("\nplanted A: K2 plaintext from letter %d moves the strip, tableau %s, M/M Vigenere, numbered on the "
                  "tableau alphabet from 1 -> best %d/22; true setting %s"
                  % (o, name, best_counts(r["seeds_a"])[0], "FOUND: " + show_seed(hit[0], names, starts, 22) if hit else "MISSED"))
            col = dict(strs).get("cipher panel / columns, left-aligned / every 3 from 1")
            o = rng.randrange(len(col) - 97)
            text = col[o:o + 97]
            ct, cribs, name, m = plant(rng, alphas, text, "M/AZ", "beau", "KR", 0, -1, 2)
            r = run(ct, cribs, alphas, "AC", paths)
            hit = [s for s in r["seeds_c"] if s[0][0] == 20 and s[1] == name]
            total += 1
            ok += bool(hit)
            print("planted C: cipher panel by columns, every 3rd letter, moves a strip that moves the strip (backward, "
                  "KRYPTOS from 0), tableau %s, M/AZ Beaufort -> best %d/20; true setting %s"
                  % (name, best_counts(r["seeds_c"])[0], "FOUND: " + show_seed(hit[0], names, starts, 20) if hit else "MISSED"))

            q = H.quad_dict()
            specs = [("M/M", "vig", "AZ", 1, 1), ("M/AZ", "beau", "M", 0, 1), ("AZ/M", "vig", "KR", 1, -1),
                     ("M/KR", "vig", "AZ", 0, 1)]
            ranks = []
            for sent, (lay, form, numbering, off, sign) in list(zip(SENTENCES, specs))[:2 if SMOKE else 4]:
                text = letters(sent)[:97]
                assert len(text) == 97
                ct, cribs, name, m = plant(rng, alphas, text, lay, form, numbering, off, sign, 1)
                t1, t2 = true_fragments(text, 1)
                truth = sum(q[t[i:i + 4]] for t in (t1, t2) for i in range(len(t) - 3))
                r = run(ct, cribs, alphas, "B", paths, thresh=truth)
                found = any(item[5] == t1 and item[6] == t2 for item in r["top"])
                place = next((i + 1 for i, item in enumerate(r["top"]) if item[5] == t1 and item[6] == t2), None)
                ranks.append(place)
                total += 1
                ok += place == 1
                print("planted B: sentence moves the strip, tableau %s %s %s, numbered on %s from %d %s: true fragment "
                      "%s|%s scores %.3f; %d settings score higher; place among distinct fragments: %s; best other %s"
                      % (name, lay, form, numbering, off, "forward" if sign == 1 else "backward", H.undig(t1),
                         H.undig(t2), truth / 16, r["above"], place if found else "not in the best 200",
                         show_frag(next(item for item in r["top"] if (item[5], item[6]) != (t1, t2)))))
            print("planted recovered: %d/%d (A and C exact; B counts when the true fragment is the best of all settings; "
                  "places %s)" % (ok, total, ranks))

            # ---- verdict
            b4 = k4["top"][0][0] / 16
            print("\nPart A  K4 %d/22 (gap free %d/22); shuffled %s; 22 needed" % (a4[0], a4[1], ctrl_a))
            print("Part C  K4 %d/20 (gap free %d/20); shuffled %s; 20 needed" % (c4[0], c4[1], ctrl_c))
            print("Part B  K4 best %.3f; shuffled best %s; needs %.2f more than the best shuffled"
                  % (b4, ", ".join("%.3f" % c for c in ctrl_b), MARGIN))
            if a4[0] == 22 or c4[0] == 20:
                print("VERDICT: FULL HIT on a known text - look at it")
            elif a4[1] == 22 or c4[1] == 20:
                print("VERDICT: full match with a free gap - look at it")
            elif b4 > max(ctrl_b) + MARGIN:
                print("VERDICT: part B beats the controls - read the fragments")
            else:
                print("VERDICT: no signal (K4 = shuffled in all three parts)")
            print("total time %.0fs" % (time.time() - t0))
    finally:
        shutil.rmtree(folder, ignore_errors=True)
