"""Idea 34: K4 as a teleprinter (Baudot/ITA2) Vernam cipher.

K2: "information ... transmitted underground to an unknown location". The
CIA's Berlin Tunnel tapped Soviet teleprinter cables, where messages were
5-bit ITA2 codes enciphered by XOR. Scheidt ran the CIA's cryptographic
centre. Nobody has tested Vernam/Baudot on K4.

Key models (all exact against the 24 clue letters, key = 5-bit codes):
  * repeating key, any 5-bit values, period 1-60
  * two stacked repeating keys XORed (union-find over XOR), periods <= 30
  * ciphertext / plaintext autokey (Vernam's own 1918 autokey), lag 1-60
  * keys spelled by words or texts (code of each key letter): theme words and the
    dictionary as repeating keys, K1-K3 / 1989 World Clock texts as running keys
"""
import importlib.util
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, letters  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.data import DATA_DIR, ROOT  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import quadgram_score  # noqa: E402
from kryptos.solvers.periodic import default_wordlist  # noqa: E402
from kryptos.teleprinter import CODE, LETTER, XorUF, required_keys  # noqa: E402


def periodic(req, maxp=60, min_tests=6):
    hits = []
    for p in range(1, maxp + 1):
        seen, tests, ok = {}, 0, True
        for i, k in req.items():
            if i % p in seen:
                tests += 1
                if seen[i % p] != k:
                    ok = False
                    break
            else:
                seen[i % p] = k
        if ok and tests >= min_tests:
            hits.append(("periodic", p, tests))
    return hits


def stacked(req, maxp=30):
    hits = []
    for a in range(2, maxp + 1):
        for b in range(a + 1, maxp + 1):
            if b % a == 0:
                continue
            uf = XorUF()
            if all(uf.union(("A", i % a), ("B", i % b), k) for i, k in req.items()):
                free = len({("A", r) for r in range(a)} | {("B", s) for s in range(b)}) - len(req)
                if free <= 0:  # the clues over-determine the key: a real constraint was satisfied
                    hits.append(("stacked", a, b))
    return hits


def autokey(ct, req, maxl=60, min_tests=6):
    hits = []
    for L in range(1, maxl + 1):
        tests = [(req[i], CODE[ct[i - L]]) for i in req if i >= L]  # ciphertext autokey
        if len(tests) >= min_tests and all(a == b for a, b in tests):
            hits.append(("ct-autokey", L))
        tests = [(req[i], CODE[CRIBS[i - L]]) for i in req if (i - L) in CRIBS]  # plaintext autokey
        if len(tests) >= min_tests and all(a == b for a, b in tests):
            hits.append(("pt-autokey", L))
    return hits


def word_keys(ct, req, words):
    hits = []
    for w in words:
        kc = [CODE[ch] for ch in w]
        if all(kc[i % len(kc)] == k for i, k in req.items()):
            hits.append(("word", w))
    return hits


def running_texts():
    spec = importlib.util.spec_from_file_location("rk", ROOT / "attacks" / "04_running_key.py")
    rk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rk)
    texts = rk.sources()
    w = importlib.util.spec_from_file_location("wz", ROOT / "attacks" / "24_weltzeituhr_1989.py")
    wz = importlib.util.module_from_spec(w)
    w.loader.exec_module(wz)
    t2, _ = wz.sources()
    texts.update({k: v for k, v in t2.items() if len(v) >= 97})
    return texts


def running(ct, req, texts):
    best = (0,)
    for name, t in texts.items():
        for direction, s in (("fwd", t), ("rev", t[::-1])):
            codes = [CODE[ch] for ch in s]
            for off in range(len(codes) - 96):
                sat = sum(codes[off + i] == k for i, k in req.items())
                if sat > best[0]:
                    best = (sat, name, direction, off)
    return best


def run(ct, words, texts):
    req = required_keys(ct, CRIBS)
    h = periodic(req) + stacked(req) + autokey(ct, req) + word_keys(ct, req, words)
    return h, running(ct, req, texts)


if __name__ == "__main__":
    t0 = time.time()
    words = [w for w in default_wordlist() if 3 <= len(w) <= 30]
    texts = running_texts()
    if SMOKE:
        words, texts = words[:2000], dict(list(texts.items())[:5])
    with Experiment("baudot-vernam (ITA2 XOR) key models", puzzle="k4",
                    notes=f"ITA2 5-bit XOR; periodic 1-60, two stacked XOR keys <=30, ct/pt autokey 1-60, "
                          f"{len(words)} dictionary/theme words, {len(texts)} running texts (K1-K3, 1989 World Clock)") as ex:
        hits, best_run = run(K4, words, texts)
        for h in hits:
            if h[0] == "word":
                kc = [CODE[ch] for ch in h[1]]
                pt = "".join(LETTER.get(CODE[c] ^ kc[i % len(kc)], "?") for i, c in enumerate(K4))
                ex.add(pt.replace("?", "X"), model=str(h))
        ex.count(60 + 400 + 120 + len(words) + sum(len(t) for t in texts.values()) * 2)
        ctrl = []
        for s in range(2):
            ch, cb = run(shuffled(K4, 3400 + s), words, texts)
            ctrl.append({"hits": len(ch), "best_running": cb[0]})
        verdict = ("dead: no teleprinter key model fits all clue letters; best running key "
                   f"{best_run[0]}/24 (shuffled {max(c['best_running'] for c in ctrl)})") if not hits else \
            f"{len(hits)} fits (shuffled controls {[c['hits'] for c in ctrl]}): check"
        ex.notes += f"; {verdict}"
    report("34", name="Baudot/Vernam teleprinter cipher", survivors=len(hits), hits=[str(h) for h in hits[:20]],
           best_running=list(best_run), control=ctrl, verdict=verdict, minutes=round((time.time() - t0) / 60, 1))
    print("[34]", verdict)
