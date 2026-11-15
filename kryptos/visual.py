"""Visual / shape-based letter transforms ("visual systems").

Each transform is a (partial) map letter -> letter:
  semaphore rotations: a letter is two flag-arm positions (0-7, 45 degree steps);
      rotating both arms by r steps, optionally mirrored, gives another letter
      (or a non-letter, in which case the map is undefined there)
  Morse operations: reverse the dots/dashes, swap dots and dashes, or both
"""

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Standard flag-semaphore "circles": arm positions numbered 0 (down) round to 7.
SEMAPHORE = {
    "A": (0, 1), "B": (0, 2), "C": (0, 3), "D": (0, 4), "E": (0, 5), "F": (0, 6), "G": (0, 7),
    "H": (1, 2), "I": (1, 3), "K": (1, 4), "L": (1, 5), "M": (1, 6), "N": (1, 7),
    "O": (2, 3), "P": (2, 4), "Q": (2, 5), "R": (2, 6), "S": (2, 7),
    "T": (3, 4), "U": (3, 5), "Y": (3, 6),
    "J": (4, 6), "V": (4, 7),
    "W": (5, 6), "X": (5, 7),
    "Z": (6, 7),
}
_POS2SEM = {frozenset(v): k for k, v in SEMAPHORE.items()}

MORSE = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....",
         "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.",
         "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
         "Y": "-.--", "Z": "--.."}
_MORSE_INV = {v: k for k, v in MORSE.items()}


def semaphore_map(r, mirror=False):
    out = {}
    for letter, (a, b) in SEMAPHORE.items():
        pa, pb = ((-a) % 8, (-b) % 8) if mirror else (a, b)
        t = frozenset(((pa + r) % 8, (pb + r) % 8))
        if t in _POS2SEM:
            out[letter] = _POS2SEM[t]
    return out


def morse_map(reverse=False, invert=False):
    out = {}
    for letter, code in MORSE.items():
        c = code[::-1] if reverse else code
        if invert:
            c = c.translate(str.maketrans(".-", "-."))
        if c in _MORSE_INV:
            out[letter] = _MORSE_INV[c]
    return out


def transforms():
    T = {}
    for r in range(8):
        T[f"semaphore rot{r}"] = semaphore_map(r)
        T[f"semaphore mirror rot{r}"] = semaphore_map(r, mirror=True)
    T["morse reverse"] = morse_map(reverse=True)
    T["morse invert"] = morse_map(invert=True)
    T["morse reverse+invert"] = morse_map(reverse=True, invert=True)
    return T
