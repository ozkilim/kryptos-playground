"""Idea 160: find the letter on the copper, write its neighbour.

K3 ends "slowly ... upper left-hand corner ... peered in"; Sanborn says you only need to be able to
read and that the earlier text holds instructions for the later text. A hand code that needs no
arithmetic fits: keep a finger on a carved panel, move on to the next place where a letter occurs,
and take the letter beside it (or one step east-north-east of it: right, up, right). Ideas 85 and 106
used K4 letters as COUNTS through the text. Nobody had searched for the letter itself.

Two roles are tested, because the idea can be read both ways:

  forward   the DECODER searches: go on to the next cell holding the K4 letter; the plain letter is the
            cell at a fixed offset from it. One start cell gives one full 97-letter reading, so every
            setting is read, the clue letters are counted in place, and every reading is scored as
            English on the big model.
  reverse   the ENCODER searches: go on to the next cell holding the plain letter and carve the letter
            at the offset. Easy to do by hand and always possible, but the decoder has to guess. On the
            clue words the walk is fixed by the known plain letters, so each clue word is tested exactly
            from every pointer (13 + 11 = 24 needed). A setting that passed would be decoded in full
            with a beam search over the choices.

  texts     cipher panel as carved (K1-K3 cells only, and all 28 rows), K1-K3 plaintext written into
            the carved cells (alone, and followed by K4), tableau panel (all 28 rows, and the 26-row
            body), Morse text. Rows left- or right-aligned. Read by rows, by columns, and both backwards.
  offsets   1-3 cells left/right, 1-3 rows up/down, the 8 knight steps (east-north-east is -1 row,
            +2 cells), the 4 diagonal neighbours, and 1-3 places on or back along the reading order.
  edges     a cell with no neighbour at that offset is not an occurrence (skipped); also the stricter
            reading where it is one and leaves a hole.
  pointer   same (the found cell may be used again at once), next (search strictly after it), one-on,
            row-reset (back to the start at every carved K4 row: 4 + 31 + 31 + 31), jump (the finger
            moves to the neighbour that was read).
  start     every cell.

A control ciphertext is put into the K4 cells of the panels that hold K4, so K4 and the controls get
the same test. Readings that copy 8 or more letters in a row straight from a reference text are set
aside before the English ranking: with K4 on the panel the finger just walks along K4 itself and reads
off the row above, which is K3's plaintext for K4 and for every shuffle alike.

  python attacks/160_find_letter_write_neighbour.py
"""
import random
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS  # noqa: E402
from kryptos import idea160_neighbour as H  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import shuffled_control  # noqa: E402
from kryptos.round11 import SMOKE, pmap  # noqa: E402
from kryptos.score import Quadgrams, ioc, word_coverage  # noqa: E402

KEEP = 8                    # forward readings with this many clue letters are listed
MAX_HOLES = 5               # a reading with more holes than this is not ranked as English
COPY = 8                    # letters in a row copied from a reference text
B1, B2 = 21, 63
ENE, BC = "EASTNORTHEAST", "BERLINCLOCK"
WORDS = ("BERLIN", "CLOCK", "NORTHEAST", "EASTNORTH")
_S = {}


def big():
    if "big" not in _S:
        _S["big"] = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
    return _S["big"]


def is_copy(reading, grams):
    return any(reading[i:i + COPY] in grams for i in range(len(reading) - COPY + 1))


def scan(ct, cribs, smoke=bool(SMOKE), reverse=True):
    """Every setting for one ciphertext. Returns a summary dict (see the keys below)."""
    texts = H.all_texts(ct, smoke)
    grams = {T.T[i:i + COPY] for T in texts for i in range(T.n - COPY + 1)}
    model = big()
    res = {"settings": 0, "readings": 0, "hist": Counter(), "top": [], "eng": [], "copies": 0, "best_copy": None,
           "words": Counter(), "rev_settings": 0, "rev_hist": Counter(), "rev_top": [], "by_rule": Counter()}
    seen, eng = {}, []
    for ti, T in enumerate(texts):
        for rule, oi, r, s, m in T.readings(ct):
            res["settings"] += m
            c = sum(1 for i, p in cribs.items() if r[i] == p)
            res["hist"][c] += m
            if c > res["by_rule"][rule]:
                res["by_rule"][rule] = c
            if c >= KEEP:
                res["top"].append((c, model.score(r), r, T.name, rule, T.off_label(oi), s, ti, oi))
            if r in seen:
                continue
            seen[r] = 1
            for w in WORDS:
                if w in r:
                    res["words"][w] += 1
            if r.count("?") <= MAX_HOLES:
                q = model.score(r)
                if q > -6.7:
                    eng.append((q, r, T.name, rule, T.off_label(oi), s, c))
        if reverse:
            ce, pe = "".join(ct[B1 + i] for i in range(13)), "".join(cribs[B1 + i] for i in range(13))
            cb, pb = "".join(ct[B2 + i] for i in range(11)), "".join(cribs[B2 + i] for i in range(11))
            for rule in H.RULES:
                for oi in range(len(T.offs)):
                    a = T.segment_fit(pe, ce, rule, oi, B1)
                    b = T.segment_fit(pb, cb, rule, oi, B2)
                    res["rev_settings"] += T.n
                    res["rev_hist"][a + b] += 1
                    if a + b >= 7:
                        res["rev_top"].append((a + b, a, b, T.name, rule, T.off_label(oi), ti, oi))
    res["readings"] = len(seen)
    res["top"].sort(reverse=True)
    res["top"] = res["top"][:40]
    for e in sorted(eng, reverse=True):              # set the copies aside, keep the 8 best of the rest
        if is_copy(e[1], grams):
            if e[0] > -5.6:
                res["copies"] += 1
            if res["best_copy"] is None:
                res["best_copy"] = e[:6]
        elif len(res["eng"]) < 8:
            res["eng"].append(e)
        elif e[0] <= -5.6:
            break
    res["rev_top"].sort(reverse=True)
    res["rev_top"] = res["rev_top"][:20]
    res["best"] = max(res["hist"])
    res["rev_best"] = max(res["rev_hist"]) if res["rev_hist"] else 0
    return res


def init():
    big()


def work(jobs):
    return [(tag, scan(ct, cribs)) for tag, ct, cribs in jobs]


def at_least(hist, k):
    return sum(v for c, v in hist.items() if c >= k)


def line(tag, r):
    e = r["eng"][0] if r["eng"] else (-99, "", "", "", "", 0, 0)
    return ("%s: forward best %d/24 (settings with 7+: %d, 8+: %d, 9+: %d); best English %.2f (copies above -5.6 set aside: %d); "
            "reverse best %d/24 (9+: %d, 10+: %d)"
            % (tag, r["best"], at_least(r["hist"], 7), at_least(r["hist"], 8), at_least(r["hist"], 9), e[0],
               r["copies"], r["rev_best"], at_least(r["rev_hist"], 9), at_least(r["rev_hist"], 10)))


# ------------------------------------------------------------------------------------------- planted answers

PLANTS = [  # role, panel, alignment, order, offset, edge, pointer rule, where the message comes from
    ("forward", "cipher panel, K1-K3 cells only", "left", "rows", (-1, 2), "skip", "next", "words"),
    ("forward", "K1-K3 plaintext in the carved cells", "right", "rows backwards", (1, 0), "skip", "row-reset", "words"),
    ("forward", "K1-K3 plaintext in the carved cells", "left", "columns", (0, -1), "hole", "jump", "words"),
    ("forward", "tableau panel, all 28 rows", "left", "columns", (0, 1), "skip", "same", "english"),
    ("reverse", "cipher panel, K1-K3 cells only", "left", "rows", (-1, 2), "skip", "next", "english"),
    ("reverse", "K1-K3 plaintext in the carved cells", "left", "rows", 1, "skip", "jump", "english"),
    ("reverse", "tableau panel, all 28 rows", "right", "columns backwards", (-2, 1), "skip", "same", "english"),
]


def find_text(texts, spec):
    name = "%s, %s-aligned, %s" % spec[1:4]
    ti = next(i for i, T in enumerate(texts) if T.name == name)
    return ti, texts[ti], texts[ti].off(spec[4], spec[5])


def plant(rng, spec, texts=None):
    """(ciphertext, clue letters, message, start, draws) for one planted case."""
    role, rule, source = spec[0], spec[6], spec[7]
    texts = texts or H.all_texts(K4, bool(SMOKE))
    ti, T, oi = find_text(texts, spec)
    for draw in range(1, 5001):
        s = rng.randrange(T.n)
        if role == "reverse":
            pt = H.english_message(rng)
            ct = T.write(pt, rule, oi, s)
        else:
            pt = H.word_message(T, rule, oi, s, rng) if source == "words" else H.english_message(rng)
            ct = T.encode(pt, rule, oi, s, rng) if pt else None
        if ct:
            return ct, {i: pt[i] for i in CRIBS}, pt, s, draw
    raise RuntimeError("could not plant %r" % (spec,))


def check_plant(spec, ct, cribs, pt, s, res, texts=None):
    """(found?, text of the report line) from the scan result of a planted ciphertext."""
    texts = texts or H.all_texts(ct, bool(SMOKE))
    ti, T, oi = find_text(texts, spec)
    rule = spec[6]
    if spec[0] == "forward":
        hits = [t for t in res["top"] if t[0] == 24]
        ok = any(t[2] == pt and t[7] == ti and t[8] == oi and t[4] == rule for t in hits) and T.read(ct, rule, oi, s) == pt
        return ok, "best %d/24, %d reading%s at 24, planted setting found and read back 97/97: %s" % (
            res["best"], len({t[2] for t in hits}), "" if len({t[2] for t in hits}) == 1 else "s", "yes" if ok else "NO")
    full = [t for t in res["rev_top"] if t[0] == 24]
    here = any(t[6] == ti and t[7] == oi and t[4] == rule for t in full)
    nstart, dec = T.decode_reverse(ct, cribs, rule, oi, big())
    right = sum(a == b for a, b in zip(dec[0][1], pt)) if dec else 0
    ok = here and right >= 88
    return ok, ("best %d/24, %d setting%s at 24, planted setting among them: %s; decoded with the clue letters: "
                "%d/97 letters right (English %.2f, %d readings left in the beam)"
                % (res["rev_best"], len(full), "" if len(full) == 1 else "s", "yes" if here else "NO", right,
                   dec[0][0] if dec else -99, len(dec)))


def study(rng, trials):
    """Can the method be used at all? Forward: how far ordinary English gets. Reverse: how flat it comes out."""
    texts = H.all_texts(K4, True)
    out = []
    for panel in ("cipher panel, K1-K3 cells only", "K1-K3 plaintext in the carved cells", "tableau panel, all 28 rows"):
        for order in ("rows", "columns"):
            T = next(t for t in texts if t.name == "%s, left-aligned, %s" % (panel, order))
            for o in ((-1, 2), (0, 1)):
                oi = T.off(o)
                msgs = [H.english_message(rng) for _ in range(trials)]
                rs = sorted(T.reach(p, "next", oi) for p in msgs)
                ics = []
                for p in msgs:
                    c = T.write(p, "next", oi, rng.randrange(T.n))
                    if c:
                        ics.append(ioc(c))
                out.append((T.name, H.off_name(o), rs[len(rs) // 2], rs[-1], sum(r == H.N for r in rs), trials,
                            sum(ics) / max(1, len(ics)), min(ics) if ics else 0, sum(x <= ioc(K4) + 1e-9 for x in ics),
                            len(ics)))
    return out


if __name__ == "__main__":
    TL = H.all_texts(K4, bool(SMOKE))
    nset = sum(T.n * len(T.offs) * len(H.RULES) for T in TL)
    with Experiment("find the K4 letter on the panel, write its neighbour (search-and-step, both roles)", puzzle="k4",
                    notes="%d texts (7 panels x alignment x 4 reading orders) x 30 offsets x 2 edge rules x 5 pointer "
                          "rules x every start cell; forward role read in full, reverse role exact on the clue words"
                          % len(TL), cribs_forced=True) as ex:
        print("texts: %d, cells %d-%d, offset entries per text %d-%d; forward settings %d, the same again in reverse"
              % (len(TL), min(T.n for T in TL), max(T.n for T in TL), min(len(T.offs) for T in TL),
                 max(len(T.offs) for T in TL), nset))
        rng = random.Random(160)
        planted = [(spec,) + plant(rng, spec, TL) for spec in PLANTS]
        seeds = (1, 2) if SMOKE else range(1, 41)
        jobs = [("K4", K4, CRIBS)] + [("shuffled %d" % sd, shuffled_control(sd), CRIBS) for sd in seeds]
        jobs += [("plant %d" % k, p[1], p[2]) for k, p in enumerate(planted)]
        got = {}
        for part in pmap(work, jobs, init, (), chunk=1):
            for tag, r in part:
                got[tag] = r
        res = got["K4"]
        ex.count(res["settings"] + res["rev_settings"])
        mean = sum(c * v for c, v in res["hist"].items()) / res["settings"]
        print("K4 forward: %d settings give %d different readings; mean clue letters %.2f of 24"
              % (res["settings"], res["readings"], mean))
        print("   " + line("K4", res))
        print("   best per pointer rule: " + ", ".join("%s %d" % (r, res["by_rule"][r]) for r in H.RULES))
        print("   clue words anywhere in a reading: " + ", ".join("%s %d" % (w, res["words"][w]) for w in WORDS))
        print("   readings with the most clue letters (count, big model, word cover):")
        for c, q, r, name, rule, off, s, ti, oi in res["top"][:6]:
            ex.add(r.replace("?", "X"), text=name, rule=rule, offset=off, start=s)
            print("     %d/24  %.2f  %.2f  %s  [%s; %s; %s; start %d]" % (c, q, word_coverage(r.replace("?", "")), r,
                                                                         name, rule, off, s))
        print("   most English-looking readings that are not copies (English needs about -5.1; noise is about -6.5):")
        for q, r, name, rule, off, s, c in res["eng"][:5]:
            print("     %.2f  %.2f  %d/24  %s  [%s; %s; %s; start %d]" % (q, word_coverage(r.replace("?", "")), c, r,
                                                                         name, rule, off, s))
        if res["best_copy"]:
            q, r, name, rule, off, s = res["best_copy"]
            print("   copies above -5.6 set aside: %d; the best one: %.2f %s  [%s; %s; %s; start %d]"
                  % (res["copies"], q, r, name, rule, off, s))
        print("K4 reverse: %d settings; best ENE + BC clue letters:" % res["rev_settings"])
        for t, a, b, name, rule, off, ti, oi in res["rev_top"][:5]:
            print("     %d/24 (%d of 13 + %d of 11)  [%s; %s; %s]" % (t, a, b, name, rule, off))
        for t, a, b, name, rule, off, ti, oi in res["rev_top"]:
            if t == 24 and rule != "row-reset":
                n0, dec = TL[ti].decode_reverse(K4, CRIBS, rule, oi, big())
                print("   REVERSE SURVIVOR decoded [%s; %s; %s]: %s" % (name, rule, off, dec[:3]))

        ctrl = [got["shuffled %d" % sd] for sd in seeds]
        for sd, r in zip(seeds, ctrl):
            print("   " + line("shuffled %d" % sd, r))
        cb, ce = sorted(r["best"] for r in ctrl), sorted((r["eng"][0][0] if r["eng"] else -99) for r in ctrl)
        cr, cc = sorted(r["rev_best"] for r in ctrl), sorted(r["copies"] for r in ctrl)
        k4e = res["eng"][0][0] if res["eng"] else -99
        print("controls (%d shuffled K4s): forward best clue letters %s" % (len(ctrl), dict(sorted(Counter(cb).items()))))
        print("   at or above K4's %d: %d of %d" % (res["best"], sum(x >= res["best"] for x in cb), len(cb)))
        print("   best English (not copies): %.2f to %.2f, median %.2f; at or above K4's %.2f: %d of %d"
              % (ce[0], ce[-1], ce[len(ce) // 2], k4e, sum(x >= k4e for x in ce), len(ce)))
        print("   copies above -5.6 set aside: %d to %d (K4 %d)" % (cc[0], cc[-1], res["copies"]))
        print("   reverse best: %s; at or above K4's %d: %d of %d"
              % (dict(sorted(Counter(cr).items())), res["rev_best"], sum(x >= res["rev_best"] for x in cr), len(cr)))
        for w in WORDS:
            v = sorted(r["words"][w] for r in ctrl)
            print("   %s anywhere: K4 %d, controls %d to %d" % (w, res["words"][w], v[0], v[-1]))

        ok = 0
        for k, (spec, ct, cribs, pt, s, draw) in enumerate(planted):
            good, text = check_plant(spec, ct, cribs, pt, s, got["plant %d" % k])
            ok += good
            print("planted %s on %s, %s-aligned, %s, %s%s, pointer '%s', start %d (%s, draw %d): %s"
                  % (spec[0], spec[1], spec[2], spec[3], H.off_name(spec[4]), "" if spec[5] == "skip" else " with holes",
                     spec[6], s, "common words that can be written" if spec[7] == "words" else "ordinary English",
                     draw, text))
            print("     message: %s\n     cipher:  %s (IC %.4f)" % (pt, ct, ioc(ct)))
        print("planted recovered: %d/%d" % (ok, len(PLANTS)))

        print("can it be used at all? (pointer 'next', %d ordinary English messages; K4's IC is %.4f)"
              % (20 if SMOKE else 200, ioc(K4)))
        for name, off, med, mx, full, n, mic, lic, low, nic in study(rng, 20 if SMOKE else 200):
            print("   %-52s %-20s forward: half die within %d letters, longest %d, whole message %d of %d; "
                  "reverse: IC mean %.4f, lowest %.4f, at or below K4 %d of %d" % (name, off, med, mx, full, n, mic, lic, low, nic))

        sig = (res["best"] == 24 or res["rev_best"] == 24 or res["best"] > cb[-1] + 2 or res["rev_best"] > cr[-1] + 2
               or (k4e > -5.1 and k4e > ce[-1]))
        print("VERDICT:", "K4 stands out - READ THE LINES ABOVE BEFORE CLAIMING ANYTHING" if sig else
              "no signal (forward K4 best %d/24, shuffled %d-%d; reverse K4 best %d/24, shuffled %d-%d; best English "
              "K4 %.2f, shuffled %.2f to %.2f; 24 and about -5.1 needed; planted %d/%d)"
              % (res["best"], cb[0], cb[-1], res["rev_best"], cr[0], cr[-1], k4e, ce[0], ce[-1], ok, len(PLANTS)))
