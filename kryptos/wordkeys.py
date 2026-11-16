"""Key vocabularies for 'the keys are real words' searches (ideas 47-48).

Hand keys are words or phrases (PALIMPSEST, ABSCISSA, KRYPTOS). Requiring that turns the
undecidable long-key region into an exact, fully determined test: no free key slots,
so English scoring is decisive again.
"""
from .data import ROOT, letters, load

DICT = "/usr/share/dict/words"


def _read(path):
    try:
        return open(path).read().split("\n")
    except OSError:
        return []


def theme_words():
    out = []
    for f in ("keys.txt", "keys_sanborn2025.txt"):
        for line in _read(ROOT / "data" / f):
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(letters(line))
    return sorted(set(w for w in out if 2 <= len(w) <= 26))


def common_words(n=22000):
    out = []
    for line in _read(ROOT / "data" / "english" / "words_big.txt")[:n]:
        if line.strip():
            out.append(letters(line.split()[0]))
    return [w for w in out if 3 <= len(w) <= 26]


def big_dictionary():
    return [letters(w) for w in _read(DICT) if w.strip()]


def phrase_windows(maxlen=26):
    """Every window of K1-K3's plaintexts (and Sanborn-quote phrases) as a candidate key phrase."""
    texts = [load("k1")["plaintext"], load("k2")["plaintext_corrected"], load("k3")["plaintext"]]
    out = set()
    for t in texts:
        t = letters(t)
        for L in range(4, maxlen + 1):
            for s in range(0, len(t) - L + 1):
                out.add(t[s:s + L])
    return out


def date_keys():
    """Dates from the clues as digit keys (value = digit): 1986 Egypt, 1989 Wall, 1990 dedication."""
    ds = ["1986", "1989", "1990", "11091989", "09111989", "19891109", "3111990", "03111990", "19901103",
          "1922", "26111922", "11261922", "1101", "1109", "38951", "770844", "77084465", "389571", "3857"]
    return sorted(set(ds))


def vocabulary(level="big"):
    """level: 'theme' (~150), 'common' (~22k + theme + phrases), 'big' (+/usr/share/dict, ~260k)."""
    words = set(theme_words())
    if level in ("common", "big"):
        words |= set(common_words()) | phrase_windows()
    if level == "big":
        words |= set(big_dictionary())
    return sorted(w for w in words if 2 <= len(w) <= 26 and w.isalpha())
