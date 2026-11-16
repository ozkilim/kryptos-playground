"""Idea 47: two stacked keys that are BOTH real words or phrases (LAYER TWO with hand keys).

Round 6 showed that two stacked repeating keys at long lengths are information-limited: any
ciphertext completes to English-quality text when the key slots are free. Hand keys
aren't free, though; they are words or phrases (PALIMPSEST, ABSCISSA), and the clues
say K2 ends "LAYER TWO". Requiring both keys to be real words leaves nothing free:

  for every word A (length L1) and every length L2:
      the 24 clue letters give the second key's letter at each residue i mod L2;
      look those letters up in an index of all words of length L2 (one dictionary probe).

Every match is a fully determined decrypt, scored for English, so a real answer
would stand far above noise. Vocabulary: /usr/share/dict (236k) + 22k common words +
theme words + every 4-26 letter window of K1-K3's plaintexts + clue dates as digit keys.
Key letters take their value in the tableau's alphabet (K1/K2 style); vig/beau/varbeau x A-Z/KRYPTOS.
"""
import random
import sys
import time
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KEY_FROM, KRYPTOS_ALPHABET, PLAIN_FROM, keyed_alphabet  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402
from kryptos import wordkeys  # noqa: E402

N = 97
ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}
VARIANTS = ("vigenere", "beaufort", "variant_beaufort")
POS = sorted(CRIBS)
G = {}


CONFIGS = [("AZ", "tableau"), ("KRYPTOS", "tableau"), ("KRYPTOS", "az")]  # where a key letter takes its value


def key_values(word, al, mode="tableau"):
    if word.isdigit():
        return tuple(int(d) for d in word)
    ref = al if mode == "tableau" else AZ
    return tuple(ref.index(c) for c in word)


def build_index(vocab, al, mode="tableau", drop=None):
    """Per length L: residue set S_L of the clue positions, and an index tuple(values at S_L) -> words."""
    by_len = defaultdict(list)
    for w in vocab:
        by_len[len(w)].append(w)
    index = {}
    for L, ws in by_len.items():
        S = sorted({i % L for i in POS if i != drop})
        d = defaultdict(list)
        for w in ws:
            v = key_values(w, al, mode)
            d[tuple(v[s] for s in S)].append(w)
        index[L] = (S, d)
    return index


def init(ct, cribs, vocab, theme, drop=None, top=None):
    G["ct"], G["cribs"], G["vocab"], G["theme"], G["top"] = ct, cribs, vocab, theme, top or []
    G["index"] = {(an, mode): build_index(vocab, ALPHAS[an], mode, drop) for an, mode in CONFIGS}
    G["req"] = {}
    for an, al in ALPHAS.items():
        idx = {c: i for i, c in enumerate(al)}
        for v in VARIANTS:
            G["req"][(an, v)] = [(i, KEY_FROM[v](idx[ct[i]], idx[cribs[i]])) for i in POS if i != drop]


def search_chunk(words):
    """For each first-layer key (a word, optionally plus a theme word), find every second word that fits."""
    out = []
    theme = G["theme"] or [None]
    for an, mode in CONFIGS:
        al = ALPHAS[an]
        index = G["index"][(an, mode)]
        for v in VARIANTS:
            req = G["req"][(an, v)]
            for wa in words:
                A = key_values(wa, al, mode)
                L1 = len(A)
                for t in theme:
                    T = key_values(t, al, mode) if t else None
                    base = [(i, (k - A[i % L1] - (T[i % len(T)] if T else 0)) % 26) for i, k in req]
                    for L2, (S, d) in index.items():
                        if L2 == L1:
                            continue
                        need = {}
                        ok = True
                        for i, b in base:
                            s = i % L2
                            if need.setdefault(s, b) != b:
                                ok = False
                                break
                        if not ok:
                            continue
                        for wb in d.get(tuple(need.get(s, -1) for s in S), ()):
                            out.append((an, v, wa, wb, t, mode))
    return out


def search_phrases(heads):
    """First key = head + tail for every tail in the phrase list (built here to keep memory small)."""
    top = G["top"]
    return search_chunk([a + b for a in heads for b in top if len(a) + len(b) <= 26])


def decrypt(ct, an, v, wa, wb, t, mode="tableau"):
    al = ALPHAS[an]
    idx = {c: i for i, c in enumerate(al)}
    A, B = key_values(wa, al, mode), key_values(wb, al, mode)
    T = key_values(t, al, mode) if t else (0,)
    dec = PLAIN_FROM[v]
    return "".join(al[dec(idx[c], (A[i % len(A)] + B[i % len(B)] + T[i % len(T)]) % 26)] for i, c in enumerate(ct))


def run(ct, cribs, vocab, first, theme=None, procs=None, drop=None, top=None):
    """first: list of first-layer keys; top: if given, ALSO every two-word phrase from `top`."""
    procs = procs or cpu_count()
    chunks = [first[k::procs * 4] for k in range(procs * 4)]
    with Pool(procs, initializer=init, initargs=(ct, cribs, vocab, theme, drop, top)) as pool:
        hits = [h for part in pool.map(search_chunk, chunks) for h in part]
        if top:
            heads = [top[k::procs * 16] for k in range(procs * 16)]
            hits += [h for part in pool.map(search_phrases, heads) for h in part]
    qg = Quadgrams()
    seen, scored = set(), []
    for h in hits:
        key = (h[0], h[1], frozenset([h[2], h[3]]), h[4], h[5])  # A+B is symmetric
        if key in seen:
            continue
        seen.add(key)
        pt = decrypt(ct, *h)
        scored.append((qg.score(pt), pt, h))
    scored.sort(key=lambda x: -x[0])
    return scored


def plant(rng, vocab, theme=None):
    from kryptos import load
    text = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4))
    s0 = rng.randrange(0, len(text) - 100)
    pt = text[s0:s0 + 97]
    pool = [w for w in vocab if 6 <= len(w) <= 14 and w.isalpha()]
    while True:
        wa, wb = rng.choice(pool), rng.choice(pool)
        if len(wa) != len(wb):
            break
    an, mode = rng.choice(CONFIGS)
    v = rng.choice(VARIANTS)
    al = ALPHAS[an]
    A, B = key_values(wa, al, mode), key_values(wb, al, mode)
    t = rng.choice(theme) if theme else None
    T = key_values(t, al, mode) if t else (0,)
    enc = {"vigenere": lambda p, k: (p + k) % 26, "beaufort": lambda p, k: (k - p) % 26,
           "variant_beaufort": lambda p, k: (p - k) % 26}[v]
    ct = "".join(al[enc(al.index(p), (A[i % len(A)] + B[i % len(B)] + T[i % len(T)]) % 26)] for i, p in enumerate(pt))
    return ct, pt, (an, v, wa, wb, t)


def phrases(words, maxlen=26):
    return [a + b for a in words for b in words if len(a) + len(b) <= maxlen]


def main(idea, name, three_layers=False):
    t0 = time.time()
    if SMOKE:
        vocab = sorted(set(wordkeys.vocabulary("theme") + wordkeys.common_words(3000))) + wordkeys.date_keys()
        top = wordkeys.theme_words()[:40]
    else:
        vocab = sorted(set(wordkeys.vocabulary("big"))) + wordkeys.date_keys()
        top = sorted(set(wordkeys.theme_words() + wordkeys.common_words(4000)))
    theme = wordkeys.theme_words() if three_layers else None
    if three_layers:
        first = sorted(set(wordkeys.theme_words() + wordkeys.common_words(3000 if SMOKE else 22000)))
    else:
        first = vocab
    nphr = 0 if three_layers else sum(1 for a in top for b in top if len(a) + len(b) <= 26)
    notes = (f"both keys real words/phrases: first key from {len(first)} words + {nphr} two-word phrases, second key from "
             f"{len(vocab)} words/dates" + (f", plus a theme-word third layer ({len(theme)})" if theme else "")
             + "; vig/beau/varbeau x A-Z/KRYPTOS (key letters valued in the tableau or A-Z); exact on 24 clue letters"
             + ("" if three_layers else "; second pass tolerates one wrong clue letter (single-word keys)"))
    with Experiment(name, puzzle="k4", cribs_forced=True, notes=notes) as ex:
        ptop = None if three_layers else top
        res = run(K4, CRIBS, vocab, first, theme, top=ptop)
        ex.count((len(first) + nphr) * len(vocab) * 9 * (len(theme) if theme else 1))
        for q, pt, h in res[:30]:
            ex.add(pt, alphabet=h[0], variant=h[1], key_a=h[2], key_b=h[3], theme=h[4], mode=h[5])
        ctrl = []
        for s in range(1 if SMOKE else 2):
            r = run(shuffled(K4, 4700 + s), CRIBS, vocab, first, theme, top=ptop)
            ctrl.append((len(r), round(r[0][0], 3) if r else None))
        # one deliberate mistake: drop each clue letter in turn (single-word keys only)
        mres, mctrl = [], []
        if not three_layers:
            drops = POS[:2] if SMOKE else POS
            fake = shuffled(K4, 4790)
            for d in drops:
                cr = {i: p for i, p in CRIBS.items() if i != d}
                for q, pt, h in run(K4, cr, vocab, vocab, drop=d):
                    mres.append((q, pt, h, d))
                mctrl += [q for q, _, _ in run(fake, cr, vocab, vocab, drop=d)]
            mres.sort(key=lambda x: -x[0])
            for q, pt, h, d in mres[:15]:
                ex.add(pt, alphabet=h[0], variant=h[1], key_a=h[2], key_b=h[3], mode=h[5], dropped=d)
        rng = random.Random(47 if not three_layers else 48)
        planted = []
        for k in range(1 if SMOKE else 3):
            ct, pt, truth = plant(rng, first if three_layers else vocab, theme)
            r = run(ct, {i: pt[i] for i in CRIBS}, vocab, first, theme)
            found = any({h[2], h[3]} == {truth[2], truth[3]} for _, _, h in r)
            planted.append({"truth": truth, "found": found, "matches": len(r), "top_is_truth": bool(r) and r[0][1] == pt,
                            "top_q": round(r[0][0], 3) if r else None})
        if not three_layers:  # a planted message whose clue letters contain one mistake
            ct, pt, truth = plant(rng, vocab)
            bad = rng.choice(POS)
            cr = {i: pt[i] for i in CRIBS}
            cr[bad] = AZ[(AZ.index(cr[bad]) + 7) % 26]
            exact = run(ct, cr, vocab, vocab)
            dropped = run(ct, {i: p for i, p in cr.items() if i != bad}, vocab, vocab, drop=bad)
            planted.append({"truth": truth, "mistake_at": bad, "exact_finds": any({h[2], h[3]} == {truth[2], truth[3]} for _, _, h in exact),
                            "drop_finds": any({h[2], h[3]} == {truth[2], truth[3]} for _, _, h in dropped)})
        best = res[0][0] if res else None
        mbest = mres[0][0] if mres else None
        cmax = max((c[1] for c in ctrl if c[1] is not None), default=None)
        mcmax = max(mctrl) if mctrl else None
        flag = any(b is not None and b > -5.3 and (c is None or b - c > 0.3) for b, c in ((best, cmax), (mbest, mcmax)))
        verdict = (("WORTH A LOOK: " if flag else "dead: ")
                   + f"{len(res)} fully determined word-key decrypts, best {None if best is None else round(best, 2)} vs "
                   f"shuffled {ctrl}"
                   + ("" if three_layers else f"; one-mistake pass {len(mres)} decrypts, best "
                      f"{None if mbest is None else round(mbest, 2)} vs shuffled {None if mcmax is None else round(mcmax, 2)}")
                   + " (English ~ -5)")
        ex.notes += f"; {verdict}"
    report(idea, name=name, vocabulary=len(vocab), first_keys=len(first), phrases=nphr, theme=len(theme) if theme else 0,
           matches=len(res), best_quadgram=best, controls=ctrl, mistake_matches=len(mres), mistake_best=mbest,
           mistake_control_best=mcmax, planted=planted, verdict=verdict,
           top=[{"q": round(q, 3), "alphabet": h[0], "variant": h[1], "key_a": h[2], "key_b": h[3], "theme": h[4],
                 "mode": h[5], "plaintext": pt} for q, pt, h in res[:10]],
           top_mistake=[{"q": round(q, 3), "dropped": d, "key_a": h[2], "key_b": h[3], "plaintext": pt}
                        for q, pt, h, d in mres[:5]],
           minutes=round((time.time() - t0) / 60, 1))
    print(f"[{idea}]", verdict, "| planted:", planted)


if __name__ == "__main__":
    if "--time" in sys.argv:  # timing probe: K4 only, a slice of first keys
        three = "--three-layers" in sys.argv
        vocab = sorted(set(wordkeys.vocabulary("common" if three else "big"))) + wordkeys.date_keys()
        theme = wordkeys.theme_words() if three else None
        first = vocab if not three else sorted(set(wordkeys.theme_words() + wordkeys.common_words(5000)))
        n = int(sys.argv[sys.argv.index("--time") + 1])
        t = time.time()
        r = run(K4, CRIBS, vocab, first[:n], theme)
        dt = time.time() - t
        print(f"vocab {len(vocab)}, {n} first keys: {dt:.1f}s -> full ~{dt * len(first) / n / 60:.1f} min; matches {len(r)}")
        for q, pt, h in r[:5]:
            print(round(q, 2), h, pt)
        sys.exit(0)
    if "--three-layers" in sys.argv:
        main("48", "three layers: theme word + two word keys", three_layers=True)
    else:
        main("47", "two stacked keys that are both real words")
