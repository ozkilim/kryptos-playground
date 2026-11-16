"""Idea 75: Wheatstone's clock-face cipher, with any rings at all.

Wheatstone's cryptograph looks like a clock: a long hand over an outer ring of 27 cells (the
alphabet plus a blank) and a short hand over an inner ring of 26 letters. You turn the long
hand, always the same way round, to each plaintext letter; the short hand is geared to move one
cell for each cell the long hand passes, and it points at the cipher letter. Because the rings
differ by one cell the short hand slips one place every turn. A clock, a 27th symbol (the "?"),
and flat statistics from a simple device.

Others searched millions of outer rings. The clues allow a proof instead, for EVERY ring:

  * The same cipher letter twice means the short hand is on the same inner cell, so the long
    hand moved a multiple of 26 cells in between.
  * S (plain) -> S (cipher) at letter 32 and T -> S at letter 33: the long hand moved a multiple
    of 26 going from S to T.
  * S -> R at letter 23 and T -> R at letter 28: the long hand moved a multiple of 26 going
    S, T, N, O, R, T. The first leg (S to T) is already a multiple of 26. The rest starts and
    ends on T, so it is a whole number m of turns: n * m cells on a ring of n cells, m = 1..4
    (or 5 if the hand also visits the blank between EAST and NORTHEAST).
  * So n * m must be a multiple of 26. For n = 27..38 and m = 1..5 it never is.

So no Wheatstone-type device with a 26-letter inner ring and an outer ring of 27 to 38 cells
can produce K4's clue letters, whatever the two alphabets are. This script checks that
arithmetic, and also runs the device over dictionary rings (hidden inner ring, any blank
position) as an independent check that the code finds a planted Wheatstone message.

  python attacks/75_wheatstone_hidden_ring.py
"""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import B1, B2, SMOKE, dictionary_alphabets, english97, pmap  # noqa: E402

BLANKS = (1, 2, 3, 4, 5)            # outer ring of 27..31 cells
WORD_STARTS = (25, 69)              # NORTHEAST and CLOCK start here (a space before them)
_S = {}


def proof():
    """[(ring size n, turns m)] for which the clue argument does NOT rule the device out."""
    return [(n, m) for n in range(27, 39) for m in range(1, 6) if (n * m) % 26 == 0]


def repeat_argument(ct, cribs):
    """Does this text have the pattern the proof uses (a cipher letter repeated on adjacent clue
    letters, and the same two plain letters giving another repeated cipher letter)?"""
    for blk in (B1, B2):
        for i in blk[:-1]:
            if ct[i] == ct[i + 1]:
                a, b = cribs[i], cribs[i + 1]
                for j in blk:
                    for k in blk:
                        if j < k and (j, k) != (i, i + 1) and ct[j] == ct[k] and cribs[j] == a and cribs[k] == b:
                            return True
    return False


def hand_positions(ring_pos, n, cribs, blank, spaces):
    """Inner-ring cell (mod 26) of each clue letter, per block, up to a constant per block."""
    out = []
    for blk in (B1, B2):
        t, row = 0, [0]
        for i in blk[1:]:
            a, b = ring_pos[cribs[i - 1]], ring_pos[cribs[i]]
            if spaces and i in WORD_STARTS:
                t += ((blank - a) % n or n) + ((b - blank) % n or n)
            else:
                t += (b - a) % n or n
            row.append(t % 26)
        out.append(row)
    return out


def ring_checks(ct, cribs, t1, t2):
    """Forced coincidences if some offset between the blocks gives one consistent inner ring, else -1."""
    f, g = {}, {}
    for t, i in zip(t1, B1):
        if f.setdefault(t, ct[i]) != ct[i] or g.setdefault(ct[i], t) != t:
            return -1
    best = -1
    for d in range(26):
        f2, g2, ok = dict(f), dict(g), True
        for t, i in zip(t2, B2):
            u = (t + d) % 26
            if f2.setdefault(u, ct[i]) != ct[i] or g2.setdefault(ct[i], u) != u:
                ok = False
                break
        if ok:
            best = max(best, 24 - len(f2) - 1, 0)
    return best


def test_ring(name, outer, ct, cribs):
    hits, n_tests = [], 0
    for nb in BLANKS:
        n = 26 + nb
        for gap in range(26):                    # the blank cells sit just before outer[gap]
            pos = {c: (i if i < gap else i + nb) for i, c in enumerate(outer)}
            for spaces in (False, True):
                n_tests += 1
                t1, t2 = hand_positions(pos, n, cribs, gap, spaces)
                ck = ring_checks(ct, cribs, t1, t2)
                if ck >= 0:
                    hits.append((ck, name, n, gap, spaces))
    return n_tests, hits


def init(ct, cribs):
    _S["ct"], _S["cribs"] = ct, cribs


def work(chunk):
    hits, n = [], 0
    for name, m in chunk:
        for tag, ring in (("", m), (" reversed", m[::-1])):
            c, h = test_ring(name + tag, ring, _S["ct"], _S["cribs"])
            n += c
            hits += h
    return n, hits


def search(ct, cribs, alphas):
    hits, n = [], 0
    for c, h in pmap(work, alphas, init, (ct, cribs), chunk=600):
        n += c
        hits += h
    return n, hits


def encrypt(pt, outer, inner, nb, gap, spaces=False):
    n = 26 + nb
    pos = {c: (i if i < gap else i + nb) for i, c in enumerate(outer)}
    t, out = 0, []
    for i, ch in enumerate(pt):
        if i:
            a, b = pos[pt[i - 1]], pos[ch]
            if spaces and i in WORD_STARTS:
                t += ((gap - a) % n or n) + ((b - gap) % n or n)
            else:
                t += (b - a) % n or n
        out.append(inner[t % 26])
    return "".join(out)


if __name__ == "__main__":
    alphas = [("KRYPTOS", KRYPTOS_ALPHABET)] + dictionary_alphabets(mixed=False)
    with Experiment("Wheatstone clock-face cipher: any outer ring of 27-38 cells, hidden inner ring", puzzle="k4",
                    notes="proof from the repeated cipher letters S,S and R,R (any rings); cross-check over %d dictionary "
                          "outer rings x reversed x 27-31 cells x 26 blank positions x spaces or not" % len(alphas),
                    cribs_forced=True) as ex:
        left = proof()
        print("proof: (ring size, turns) pairs not ruled out by the S,S / R,R argument:", left or "none")
        print("K4 has the pattern the proof needs:", repeat_argument(K4, CRIBS))
        n, hits = search(K4, CRIBS, alphas)
        ex.count(n)
        print("dictionary cross-check: %d ring settings; K4 consistent with a real inner ring: %d" % (n, len(hits)))
        for h in sorted(hits, reverse=True)[:10]:
            print("   checks=%d outer %s, %d cells, blank before cell %d, spaces=%s" % h)
        ctrl = []
        for seed in (1, 2) if SMOKE else (1, 2, 3):
            c = shuffled_control(seed)
            ctrl.append((len(search(c, CRIBS, alphas)[1]), repeat_argument(c, CRIBS)))
        print("shuffled K4s (rings consistent, has the proof pattern):", ctrl)
        rng = random.Random(75)
        ok = 0
        for nb, spaces in ((1, False), (1, True), (3, False)):
            name, outer = rng.choice(alphas)
            inner = list(AZ)
            rng.shuffle(inner)
            gap = rng.randrange(26)
            pt = english97(rng)
            ct = encrypt(pt, outer, inner, nb, gap, spaces)
            h = search(ct, {i: pt[i] for i in CRIBS}, alphas)[1]
            found = any(x[1:] == (name, 26 + nb, gap, spaces) for x in h)
            ok += found
            print("planted Wheatstone, outer %s, %d cells, blank %d, spaces=%s -> found=%s (rings consistent %d)" % (
                name, 26 + nb, gap, spaces, found, len(h)))
        print("planted recovered: %d/3" % ok)
        print("VERDICT:", "CONSISTENT RING - inspect" if hits else
              "dead: proof leaves %s; no dictionary ring fits (shuffled %s)" % (left or "nothing", [c[0] for c in ctrl]))
