"""Idea 57: the key is ordinary English text, on a tableau built from a keyword alphabet.

K1 and K2 use a keyword tableau (KRYPTOS) with a short key word. The natural "change in
methodology" is the same tableau idea with a *different* keyword and a key that is a whole
sentence. A sentence key never repeats, which gives K4's flat statistics, and the cipher
stays "plain letter in, cipher letter out" as Sanborn describes.

Earlier work tested sentence keys from *known* texts, and keyword alphabets with *repeating*
keys. This tests the missing corner: for every keyword alphabet, read off the 13 + 11 key
letters the clues force and ask whether they are English. No key text is needed.

For each of ~236k keyword alphabets M:
  alphabets   plain M / cipher A-Z (Quagmire I), plain A-Z / cipher M (II), M / M (III),
              M / KRYPTOS and KRYPTOS / M (IV with the sculpture's alphabet)
  cipher      Vigenere, Beaufort, variant Beaufort, and the reversed (DIANA one-time-pad) table: K = -(C + P)
  key letter  A-Z[s + c] for every Caesar offset c, or M[s], or KRYPTOS[s]
The 24 forced key letters are scored on the big English quadgram model (18 quadgrams).

  python attacks/57_running_key_keyword_alphabets.py            # K4 + 3 shuffled controls + planted
"""
import heapq
import os
import random
import sys
from multiprocessing import Pool
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, wordkeys  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.data import DATA_DIR  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.round9 import keyword_alphabet, shuffled_control  # noqa: E402
from kryptos.score import Quadgrams  # noqa: E402

SMOKE = os.environ.get("KRYPTOS_SMOKE")
B1, B2 = list(range(21, 34)), list(range(63, 74))
_Q = None
_STATE = {}


def quad_table():
    global _Q
    if _Q is None:
        q = Quadgrams(DATA_DIR / "english" / "quadgrams_big.txt")
        tab = [q.floor] * (26 ** 4)
        for g, lp in q.logp.items():
            if len(g) == 4 and g.isalpha():
                a, b, c, d = (ord(x) - 65 for x in g)
                tab[((a * 26 + b) * 26 + c) * 26 + d] = lp
        _Q = tab
    return _Q


def frag_score(v1, v2, tab):
    """Mean log10 quadgram probability over the two key fragments (letter numbers 0-25)."""
    t = 0.0
    for v in (v1, v2):
        for i in range(len(v) - 3):
            t += tab[((v[i] * 26 + v[i + 1]) * 26 + v[i + 2]) * 26 + v[i + 3]]
    return t / (len(v1) + len(v2) - 6)


def alphabets(limit=None):
    seen, out = set(), []
    vocab = wordkeys.theme_words() + wordkeys.common_words() + wordkeys.big_dictionary()
    for w in vocab:
        if not (3 <= len(w) <= 22):
            continue
        m = keyword_alphabet(w)
        if m not in seen:
            seen.add(m)
            out.append((w, m))
            if limit and len(out) >= limit:
                break
    return out


def init(ct, cribs):
    _STATE["ct"], _STATE["cribs"] = ct, cribs
    quad_table()


def views_for(m, ct, cribs):
    """Yield (label, shifts over block 1, shifts over block 2, key-letter alphabets)."""
    im = {c: i for i, c in enumerate(m)}
    iz = {c: i for i, c in enumerate(AZ)}
    ik = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    combos = (("Q1", im, iz), ("Q2", iz, im), ("Q3", im, im), ("Q4a", im, ik), ("Q4b", ik, im))
    for qn, ia, ib in combos:
        for sn, f in (("vig", lambda c, p: c - p), ("beau", lambda c, p: c + p), ("var", lambda c, p: p - c),
                       ("diana", lambda c, p: -c - p)):
            s1 = [f(ib[ct[i]], ia[cribs[i]]) % 26 for i in B1]
            s2 = [f(ib[ct[i]], ia[cribs[i]]) % 26 for i in B2]
            yield qn + "/" + sn, s1, s2


def score_alphabet(wm, ct, cribs, tab, keep=3):
    w, m = wm
    nm = [ord(c) - 65 for c in m]
    nk = [ord(c) - 65 for c in KRYPTOS_ALPHABET]
    best = []
    for label, s1, s2 in views_for(m, ct, cribs):
        cands = [("az+%d" % c, [(x + c) % 26 for x in s1], [(x + c) % 26 for x in s2]) for c in range(26)]
        cands.append(("M", [nm[x] for x in s1], [nm[x] for x in s2]))
        cands.append(("KR", [nk[x] for x in s1], [nk[x] for x in s2]))
        for kl, v1, v2 in cands:
            sc = frag_score(v1, v2, tab)
            item = (sc, w, label, kl, "".join(AZ[x] for x in v1) + "|" + "".join(AZ[x] for x in v2))
            if len(best) < keep:
                heapq.heappush(best, item)
            elif item > best[0]:
                heapq.heapreplace(best, item)
    return best


def work(chunk):
    tab = quad_table()
    ct, cribs = _STATE["ct"], _STATE["cribs"]
    out = []
    for wm in chunk:
        out.extend(score_alphabet(wm, ct, cribs, tab, keep=1))
    return heapq.nlargest(20, out)


def run(ct, cribs, alphas, procs=None):
    chunks = [alphas[i:i + 500] for i in range(0, len(alphas), 500)]
    with Pool(procs, initializer=init, initargs=(ct, cribs)) as pool:
        res = []
        for r in pool.imap_unordered(work, chunks):
            res.extend(r)
    return heapq.nlargest(20, res)


def english_text():
    from kryptos import load
    from kryptos.data import letters
    return letters("".join(load(k)["plaintext"] for k in ("k2", "k3", "k1")))


def plant(rng, alphas, kind="Q3"):
    """Encrypt real English with a keyword tableau and an English sentence key."""
    text = english_text()
    a = rng.randrange(len(text) - 97)
    pt = text[a:a + 97]
    b = (a + 150 + rng.randrange(100)) % (len(text) - 97)
    key = text[b:b + 97]
    w, m = rng.choice(alphas)
    im = {c: i for i, c in enumerate(m)}
    if kind == "Q3":   # K1/K2 style: key letter picks the row that starts with it
        ct = "".join(m[(im[p] + im[k]) % 26] for p, k in zip(pt, key))
    else:              # Quagmire I: plain alphabet M, cipher A-Z, key letter on A-Z
        ct = "".join(AZ[(im[p] + ord(k) - 65) % 26] for p, k in zip(pt, key))
    return ct, {i: pt[i] for i in CRIBS}, w, key


if __name__ == "__main__":
    alphas = alphabets(limit=3000 if SMOKE else None)
    n_views = 5 * 4 * 28
    with Experiment("running key of unknown English text on keyword tableaux", puzzle="k4",
                    notes=f"{len(alphas)} keyword alphabets x Quagmire I-IV x 4 ciphers (incl. reversed/DIANA table) x 28 key letterings; "
                          "forced 13+11 key letters scored as English", cribs_forced=True) as ex:
        top = run(K4, CRIBS, alphas)
        ex.count(len(alphas) * n_views)
        print("K4 best key fragments:")
        for t in top[:8]:
            print("  %.3f  %-14s %-9s %-6s %s" % t)
        ctrl = []
        for seed in (1, 2, 3):
            c = run(shuffled_control(seed), CRIBS, alphas)
            ctrl.append(c[0][0])
            print("shuffled K4 #%d best: %.3f  %s" % (seed, c[0][0], c[0][4]))
        rng = random.Random(9)
        for kind in ("Q3", "Q1", "Q3", "Q1"):
            ct, cribs, w, key = plant(rng, alphas, kind)
            p = run(ct, cribs, alphas)
            rank = next((i for i, t in enumerate(p) if t[1] == w or keyword_alphabet(t[1]) == keyword_alphabet(w)), None)
            print("planted %s keyword %-12s true key %s|%s -> best %.3f (%s) rank of truth: %s" % (
                kind, w, key[21:34], key[63:74], p[0][0], p[0][4], rank))
        print("\nK4 best %.3f vs shuffled best %s" % (top[0][0], ", ".join("%.3f" % c for c in ctrl)))
        print("VERDICT:", "SIGNAL - look at it" if top[0][0] > max(ctrl) + 0.35 else "no signal (K4 = shuffled)")
