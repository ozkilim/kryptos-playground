"""Idea 80 helpers: attack 57's key-fragment scoring with a language model other than English.

Attack 57 reads off the 13 + 11 key letters that the clues force, for every keyword alphabet, and scores them
on the big English quadgram table. Here the table is a parameter, so the same search can ask "is the key German?".

The repository holds no German text and no German quadgram table. `find_german()` looks for one in the places
listed in `MODEL_PATHS`; while none exists the attack reports `untestable` and stops.

What is needed (both files, letters A-Z only, umlauts written AE OE UE and sharp s written SS):

  data/german/quadgrams.txt   "ABCD count" per line, the format of data/english/quadgrams.txt, built from at
                              least a few million letters of German prose
  data/german/sample.txt      a few thousand letters of German prose that were NOT used to build the table,
                              to cut planted keys from
"""
import heapq
import importlib.util
import math
import os
from multiprocessing import Pool
from pathlib import Path

from .data import DATA_DIR, ROOT

MODEL_PATHS = ("german/quadgrams_big.txt", "german/quadgrams.txt", "german_quadgrams.txt", "quadgrams_de.txt")
TEXT_PATHS = ("german/sample.txt", "texts/german.txt")
_UML = {"Ä": "AE", "Ö": "OE", "Ü": "UE", "ß": "SS", "ä": "AE", "ö": "OE", "ü": "UE", "ẞ": "SS"}
_STATE = {}
_A57 = None


def attack57():
    """Attack 57 as a module (its views, fragment score and alphabet list are reused unchanged)."""
    global _A57
    if _A57 is None:
        spec = importlib.util.spec_from_file_location("attack57", ROOT / "attacks" / "57_running_key_keyword_alphabets.py")
        _A57 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_A57)
    return _A57


def german_letters(text):
    """Upper-case A-Z with the usual hand transliteration of umlauts and sharp s."""
    for a, b in _UML.items():
        text = text.replace(a, b)
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def find_german():
    """Return (quadgram table path, key text path); either is None when the file is not in the repository."""
    env = os.environ.get("KRYPTOS_GERMAN_QUADGRAMS")
    model = next((p for p in ([Path(env)] if env else []) + [DATA_DIR / m for m in MODEL_PATHS] if p.is_file()), None)
    env = os.environ.get("KRYPTOS_GERMAN_TEXT")
    text = next((p for p in ([Path(env)] if env else []) + [DATA_DIR / t for t in TEXT_PATHS] if p.is_file()), None)
    return model, text


def table_from_counts(counts):
    """Flat 26^4 list of log10 probabilities from {quadgram: count}; unseen quadgrams get 0.01 of a count."""
    total = sum(counts.values())
    tab = [math.log10(0.01 / total)] * (26 ** 4)
    for g, c in counts.items():
        if len(g) == 4 and g.isalpha() and g.isupper() and c > 0:
            a, b, cc, d = (ord(x) - 65 for x in g)
            tab[((a * 26 + b) * 26 + cc) * 26 + d] = math.log10(c / total)
    return tab


def table_from_file(path):
    counts = {}
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            q, c = line.split()[:2]
            counts[q.upper()] = int(float(c))
    return table_from_counts(counts)


def table_from_text(text):
    s = german_letters(text)
    counts = {}
    for i in range(len(s) - 3):
        counts[s[i:i + 4]] = counts.get(s[i:i + 4], 0) + 1
    return table_from_counts(counts)


def score_alphabets(alphas, ct, cribs, tab, keep=20):
    """Best forced key fragments over the given (word, alphabet) list, single process."""
    a57, out = attack57(), []
    for wm in alphas:
        out.extend(a57.score_alphabet(wm, ct, cribs, tab, keep=1))
    return heapq.nlargest(keep, out)


def _init(ct, cribs, model_path):
    _STATE["ct"], _STATE["cribs"] = ct, cribs
    _STATE["tab"] = table_from_file(model_path)


def _work(chunk):
    return score_alphabets(chunk, _STATE["ct"], _STATE["cribs"], _STATE["tab"])


def run(ct, cribs, alphas, model_path, procs=None):
    """Attack 57's search with the quadgram table at model_path. Returns the 20 best (score, word, view, lettering, key)."""
    chunks = [alphas[i:i + 500] for i in range(0, len(alphas), 500)]
    res = []
    with Pool(procs, initializer=_init, initargs=(ct, cribs, str(model_path))) as pool:
        for r in pool.imap_unordered(_work, chunks):
            res.extend(r)
    return heapq.nlargest(20, res)


def plant(rng, alphas, key_text, kind="Q3", pt_text=None):
    """English plaintext, keyword tableau, key cut from key_text (German when the file exists)."""
    from . import CRIBS
    a57 = attack57()
    text = pt_text or a57.english_text()
    a = rng.randrange(len(text) - 97)
    pt = text[a:a + 97]
    b = rng.randrange(len(key_text) - 97)
    key = key_text[b:b + 97]
    w, m = rng.choice(alphas)
    im = {c: i for i, c in enumerate(m)}
    if kind == "Q3":   # K1/K2 style: the key letter picks the row that starts with it
        ct = "".join(m[(im[p] + im[k]) % 26] for p, k in zip(pt, key))
    else:              # Quagmire I: plain alphabet M, cipher A-Z, key letter on A-Z
        ct = "".join(chr(65 + (im[p] + ord(k) - 65) % 26) for p, k in zip(pt, key))
    return ct, {i: pt[i] for i in CRIBS}, w, key
