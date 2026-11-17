"""Idea 105: more textbook encryptors, for auditing the attacks idea 91 did not reach.

Like kryptos/idea91_textbook.py this file uses NO code of the attacks: it imports only that file
(which itself imports nothing from the repository). Everything is written the way a hand cipher
book describes it: strips that slide, a key written under the text, a grid that is read off by
columns, an alphabet strip whose letters are moved after each use.
"""
import random

from . import idea91_textbook as T

A2Z = T.A2Z
SPACE = None                      # a word space in a list of symbols


# ---------------------------------------------------------------- messages

def k4_like_at(rng, extra_english="", second=64, length=97):
    """English with EASTNORTHEAST at letters 22-34 and BERLINCLOCK starting at letter `second`
    (counted from 1; 64 is where Sanborn put it)."""
    pool = T.only_letters(T.FILLER + extra_english)
    start = rng.randrange(len(pool) - length)
    text = list(pool[start:start + length])
    text[21:34] = "EASTNORTHEAST"
    text[second - 1:second + 10] = "BERLINCLOCK"
    assert len(text) == length
    return "".join(text)


def lose_or_add(ct, g, rng):
    """Damage a cipher text between the clues: g > 0 loses g letters, g < 0 adds -g random letters."""
    ct = list(ct)
    cut = rng.randrange(40, 55)
    if g > 0:
        del ct[cut:cut + g]
    else:
        ct[cut:cut] = [rng.choice(A2Z) for _ in range(-g)]
    return "".join(ct)


def _words_of(rng, words, n):
    """Consecutive English words with exactly n letters in all."""
    while True:
        s = rng.randrange(len(words) - 14)
        out, tot = [], 0
        for w in words[s:s + 14]:
            out.append(w)
            tot += len(w)
            if tot >= n:
                break
        if tot == n:
            return out


def spaced_k4(rng, clue1=("EAST", "NORTH", "EAST"), clue2=("BERLIN", "CLOCK")):
    """A K4-shaped message as a list of words: 21 letters, the first clue, 29 letters, the second
    clue, 23 letters. clue1 / clue2 say how the clue words were written on the sheet."""
    words = [T.only_letters(w) for w in T.FILLER.split()]
    words = [w for w in words if w]
    out = _words_of(rng, words, 21) + list(clue1) + _words_of(rng, words, 29) + list(clue2) + _words_of(rng, words, 23)
    assert sum(len(w) for w in out) == 97
    return out


def symbols(words, double_at=None):
    """The sheet as the encipherer reads it: letters, with SPACE between words. double_at = index of a
    word that is followed by two spaces (a sentence break)."""
    out = []
    for n, w in enumerate(words):
        if n:
            out.append(SPACE)
            if double_at is not None and n == double_at + 1:
                out.append(SPACE)
        out.extend(w)
    return out


# ---------------------------------------------------------------- key written over the spaces

def encrypt_over_spaces(syms, plain, cipher, key_letters, index_letter=None, beaufort=False):
    """One key letter is used up for every symbol of the sheet, spaces included; only letters are
    enciphered and written down."""
    out = []
    for ch, k in zip(syms, key_letters):
        if ch is not SPACE:
            out.append(T.tableau_encrypt(ch, plain, cipher, [k], index_letter, beaufort))
    return "".join(out)


def sliding_over_spaces(syms, plain, cipher, moves, beaufort=False):
    """Sliding key that also moves the strip on at every space."""
    strip = cipher[::-1] if beaufort else cipher
    out = []
    for u, ch in enumerate(syms):
        strip = T.slide(strip, moves[u % len(moves)])
        if ch is not SPACE:
            out.append(strip[plain.index(ch)])
    return "".join(out)


# ---------------------------------------------------------------- keys made from earlier letters

def fed_key_encrypt(pt, plain, cipher, numbering, lag, feed, mult, word, primer_rng, beaufort=False):
    """A repeating list of key numbers with an earlier letter added on top (autokey + key word).

    For letter i the strip is moved word[i mod p] + mult * (number of the letter `lag` places back in
    `numbering`) places. The earlier letter is taken from the plaintext or from the cipher text
    already written; before the start of the message a random number is used."""
    out = []
    for i, ch in enumerate(pt):
        if i < lag:
            number = primer_rng.randrange(26)
        else:
            number = numbering.index((pt if feed == "plain" else out)[i - lag])
        shift = word[i % len(word)] + mult * number
        strip = T.slide(cipher[::-1], -shift - 1) if beaufort else T.slide(cipher, shift)
        out.append(strip[plain.index(ch)])
    return "".join(out)


def chain_key(start, n, t, m, a=1, b=1, c=0, modulus=26):
    """Chain addition: after the starting numbers each key number is a * (the one t back) +
    b * (the one m back) + c."""
    key = list(start)
    assert len(key) == m and t < m
    while len(key) < n:
        key.append((a * key[-t] + b * key[-m] + c) % modulus)
    return key


# ---------------------------------------------------------------- a wheel with more than 26 cells

def wheel_strip(alphabet, cells):
    """An alphabet strip with extra cells after the letters (written as digits)."""
    return alphabet + "0123456789"[:cells - 26]


def wheel_encrypt(pt, plain, cipher, key_symbols, index_symbol=None, beaufort=False):
    """tableau_encrypt for strips of any (equal) length."""
    n = len(plain)
    index_symbol = index_symbol or plain[0]
    if beaufort:
        cipher = cipher[::-1]
    out = []
    for ch, k in zip(pt, key_symbols):
        strip = cipher
        for _ in range(n):
            if strip[plain.index(index_symbol)] == k:
                break
            strip = T.slide(strip, 1)
        else:
            raise ValueError("key symbol not on the strip")
        out.append(strip[plain.index(ch)])
    return "".join(out)


def wheel_sliding(pt, plain, cipher, moves, beaufort=False):
    strip = cipher[::-1] if beaufort else cipher
    out = []
    for i, ch in enumerate(pt):
        strip = T.slide(strip, moves[i % len(moves)])
        out.append(strip[plain.index(ch)])
    return "".join(out)


def wheel_multiply(pt, alphabet, cells, multipliers):
    """Multiplying key on a wheel with a prime number of cells: the letters are numbered 1-26 along
    `alphabet`, the cipher symbol is the one numbered key * plain (mod cells). Cells 27 and up are
    written as digits."""
    strip = "#" + wheel_strip(alphabet, cells - 1)          # cell 0 is never reached
    out = []
    for i, ch in enumerate(pt):
        out.append(strip[(multipliers[i % len(multipliers)] * strip.index(ch)) % cells])
    return "".join(out)


# ---------------------------------------------------------------- interrupted key

def interrupted_key(pt_or_syms, key, when, trigger=None):
    """The key letter used for every letter of an interrupted-key message, when the trigger is known
    before the letter is enciphered.

    when 'after plain': the key goes back to its first letter after each plaintext `trigger`.
    when 'at plain':    the plaintext `trigger` itself takes the first key letter.
    when 'word':        the key goes back to its first letter at each new word (input: symbols)."""
    out, j = [], 0
    for ch in pt_or_syms:
        if ch is SPACE:
            j = 0
            continue
        if when == "at plain" and ch == trigger:
            j = 0
        out.append(key[j % len(key)])
        j += 1
        if when == "after plain" and ch == trigger:
            j = 0
    return out


def interrupted_cipher_encrypt(pt, plain, cipher, key, trigger, index_letter=None, beaufort=False):
    """Interrupted key that goes back to its first letter after each CIPHER letter `trigger`."""
    out, j = [], 0
    for ch in pt:
        c = T.tableau_encrypt(ch, plain, cipher, [key[j % len(key)]], index_letter, beaufort)
        out.append(c)
        j = 0 if c == trigger else j + 1
    return "".join(out)


# ---------------------------------------------------------------- Slidefair

def slidefair_encrypt(pt, alphabet, key, start=0, beaufort=False):
    """Slidefair (ACA): the text is taken two letters at a time. The first letter is found on the top
    strip, the second on the key strip (the strip slid to the pair's key letter; written backwards for
    the Beaufort kind). The cipher pair is the other two corners of the rectangle: the key-strip
    letter under the first, the top-strip letter over the second. If both stand in the same column
    the letters just to their right are taken. Returns (cipher text, pairs that used that last rule).
    Letters before `start` and an odd last letter are copied."""
    out, same = list(pt), []
    for n, i in enumerate(range(start, len(pt) - 1, 2)):
        k = key[n % len(key)]
        row = T.set_strip(alphabet, alphabet[::-1] if beaufort else alphabet, k, alphabet[0])
        c1, c2 = alphabet.index(pt[i]), row.index(pt[i + 1])
        if c1 == c2:
            same.append(i)
            out[i], out[i + 1] = alphabet[(c1 + 1) % 26], row[(c2 + 1) % 26]
        else:
            out[i], out[i + 1] = row[c1], alphabet[c2]
    return "".join(out), same


# ---------------------------------------------------------------- scrambling the key

def grid_rows(seq, width):
    return [seq[r:r + width] for r in range(0, len(seq), width)]


def columnar(seq, order):
    """Write seq in rows under a key of len(order) columns; read off column order[0], then order[1]..."""
    rows = grid_rows(seq, len(order))
    return [row[c] for c in order for row in rows if c < len(row)]


def quarter_turn(seq, width, clockwise=False):
    """K3's step: write seq in rows of `width` and turn the sheet a quarter turn. Anticlockwise the new
    rows are the old columns from the right, each read downwards; clockwise they are the old columns
    from the left, each read upwards."""
    rows = grid_rows(seq, width)
    out = []
    for c in (range(width) if clockwise else range(width - 1, -1, -1)):
        col = [row[c] for row in rows if c < len(row)]
        out += col[::-1] if clockwise else col
    return out


def snake_rows(seq, width):
    """Rows read alternately left to right and right to left (only when every row is full or the
    reversed last row is read as it stands)."""
    out = []
    for r, row in enumerate(grid_rows(seq, width)):
        out += row if r % 2 == 0 else row[::-1]
    return out


def skip_read(seq, a, b):
    """Start at letter b and take every a-th letter, going round."""
    return [seq[(a * i + b) % len(seq)] for i in range(len(seq))]


# ---------------------------------------------------------------- alphabets that change after each letter

def _to_front(s, j):
    return [s[j]] + s[:j] + s[j + 1:]


def _to_end(s, j):
    return s[:j] + s[j + 1:] + [s[j]]


def _swap(s, j, k):
    s = list(s)
    s[j], s[k] = s[k], s[j]
    return s


CHANGES = {
    "move to front": _to_front,
    "move to end": _to_end,
    "swap with previous": lambda s, j: _swap(s, j, (j - 1) % 26),
    "swap with next": lambda s, j: _swap(s, j, (j + 1) % 26),
    "swap with first": lambda s, j: _swap(s, j, 0),
    "swap with last": lambda s, j: _swap(s, j, 25),
    "turn strip to letter": lambda s, j: T.slide(s, j),
    "turn strip one past letter": lambda s, j: T.slide(s, j + 1),
    "reverse up to letter": lambda s, j: s[:j + 1][::-1] + s[j + 1:],
    "Chaocipher left step": lambda s, j: _chao_left(T.slide(s, j)),
}


def _chao_left(s):
    """Chaocipher, left wheel after it has been turned: take out the letter after the top one, close
    the gap up to the 14th place and put the letter in there."""
    return [s[0]] + s[2:14] + [s[1]] + s[14:]


def _chao_right(s):
    """Right wheel after it has been turned one past its letter: the third letter goes to the 14th place."""
    return s[:2] + s[3:14] + [s[2]] + s[14:]


def evolving_encrypt(pt, start, side, fixed, change, driver):
    """An alphabet strip S that is changed after every letter.

    side 'cipher': S is the cipher alphabet under the fixed plain alphabet `fixed`.
    side 'plain':  S is the plain alphabet over the fixed cipher alphabet `fixed`.
    side 'self':   S is used against itself, slid `fixed` places (a number).
    After each letter the cipher letter (driver 'cipher') or the plain letter (driver 'plain') is
    found on S and S is changed there."""
    s, out = list(start), []
    for p in pt:
        if side == "cipher":
            c = s[fixed.index(p)]
        elif side == "plain":
            c = fixed[s.index(p)]
        else:
            c = T.slide(s, fixed)[s.index(p)]
        out.append(c)
        s = CHANGES[change](s, s.index(c if driver == "cipher" else p))
    return "".join(out)


def chaocipher_encrypt(pt, left, right):
    """Byrne's Chaocipher: plain letter on the right wheel, cipher letter opposite it on the left."""
    le, ri, out = list(left), list(right), []
    for p in pt:
        j = ri.index(p)
        out.append(le[j])
        le = _chao_left(T.slide(le, j))
        ri = _chao_right(T.slide(ri, j + 1))
    return "".join(out)


CHAO_LEFT = "HXUCZVAMDSLKPEFJRIGTWOBNYQ"
CHAO_RIGHT = "PTLNBQDEOYSFAVZKGJRIHWXUMC"
CHAO_PLAIN = "WELLDONEISBETTERTHANWELLSAID"
CHAO_CIPHER = "OAHQHCNYNXTSZJRRHJBYHQKSOUJY"       # Byrne's published example


if __name__ == "__main__":
    print(chaocipher_encrypt(CHAO_PLAIN, CHAO_LEFT, CHAO_RIGHT) == CHAO_CIPHER)
    print(" ".join(spaced_k4(random.Random(1))))
