"""Idea 91: textbook encryptors written from the definitions, for auditing the round 9-11 tests.

THIS FILE IMPORTS NOTHING FROM kryptos/. That is the point. Every planted-answer test in rounds
9-11 was built with the attack's own helper code, so a shared mistake (clue positions off by
one, an alphabet indexed the wrong way, a Beaufort sign) would pass its planted test and still
miss the real K4. Here the ciphers are written the way a hand cipher book describes them:
paper strips that slide, a key letter set under an index letter, a rotor that turns. Where a
book would say "slide the strip", the code rotates a string; it does not reuse the attacks'
index arithmetic.

The K4 letters, the clue positions and the carved rows are typed in here by hand as well, so
they can be compared with what the repository loads from data/.
"""
import random

A2Z = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# K4 as carved: the last four letters of one row, then three full rows of 31.
K4_ROWS = ("OBKR",
           "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
           "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
           "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR")
K4_TYPED = "".join(K4_ROWS)

# Sanborn's clues, counted from 1 the way he gave them: (first letter, last letter, plain, cipher).
CLUES = ((22, 34, "EASTNORTHEAST", "FLRVQQPRNGKSS"),
         (64, 74, "BERLINCLOCK", "NYPVTTMZFPK"))

K1_PLAIN = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K1_CARVED = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

# Plain English used as filler around the clue words (written for this audit).
FILLER = """
The old harbour was quiet when the first boats came back with the tide. Nobody on the quay
expected the message to arrive before the weekend, and yet the clerk had already copied it
twice into the green ledger. She folded the paper, put it under the lamp and waited for the
kettle. Outside the rain moved slowly across the square and the lights of the station went
out one after another. A man with a grey coat asked for the time and then walked north along
the wall without looking back. Later that night the radio spoke of weather over the channel,
of ships delayed and trains that would not run. In the morning they found the key under a
stone beside the door, exactly where the letter said it would be, and the long work of
reading the pages could begin. Every line had to be checked against the table, each letter
written down by hand, because one small mistake at the start would spoil everything after it.
"""

# Keywords for the hidden alphabets and key words (ordinary and Kryptos-themed dictionary words).
WORDS = ("SHADOW", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "EGYPT", "COMPASS", "LODESTONE",
         "LANGLEY", "ILLUSION", "MAGNETIC", "MESSAGE", "TABLE", "QUARTZ", "WEBSTER", "SANBORN",
         "LATITUDE", "LONGITUDE", "SECRET", "HISTORY", "CHAMBER", "CANDLE", "PASSAGE", "DOORWAY",
         "NORTHEAST", "UNDERGROUND", "INVISIBLE", "POSITION", "MYSTERY", "FLICKER", "TOMB",
         "WONDERFUL", "DELIVER", "PYRAMID", "ENIGMA", "MORNING", "KITCHEN", "JOURNAL", "WIZARD",
         "BLACKSMITH", "DESPERATLY", "DIGETAL", "EXPLORING", "FORTUNE", "GARDEN", "HARVEST")


def only_letters(text):
    return "".join(ch for ch in text.upper() if ch in A2Z)


def clue_map():
    """{position counted from 0: plaintext letter} for the 24 clue letters."""
    out = {}
    for first, last, plain, _ in CLUES:
        assert last - first + 1 == len(plain)
        for j, ch in enumerate(plain):
            out[first - 1 + j] = ch
    return out


def k4_like(rng, extra_english=""):
    """97 letters of English with EASTNORTHEAST at 22-34 and BERLINCLOCK at 64-74 (counted from 1)."""
    pool = only_letters(FILLER + extra_english)
    start = rng.randrange(len(pool) - 97)
    text = list(pool[start:start + 97])
    for first, _, plain, _ in CLUES:
        text[first - 1:first - 1 + len(plain)] = plain
    assert len(text) == 97
    return "".join(text)


# ---------------------------------------------------------------- alphabets

def keyword_alphabet(word):
    """The keyword with repeated letters dropped, then the rest of the alphabet in order."""
    out = ""
    for ch in word + A2Z:
        if ch not in out:
            out += ch
    return out


def column_mixed(word, by_key_order):
    """Write the keyword alphabet in rows under the keyword and read it off by columns: left to
    right, or (by_key_order) taking the columns in the alphabetical order of the keyword's letters."""
    head = ""
    for ch in word:
        if ch not in head:
            head += ch
    width = len(head)
    alpha = keyword_alphabet(word)
    rows = [alpha[r:r + width] for r in range(0, 26, width)]
    columns = ["".join(row[c] for row in rows if c < len(row)) for c in range(width)]
    order = list(range(width))
    if by_key_order:
        order.sort(key=lambda c: head[c])
    return "".join(columns[c] for c in order)


def alphabet_forms(word):
    """[(tag, alphabet)]: the keyword alphabet and, if the keyword has 3+ different letters, its two
    column-mixed forms. Tags match the names the attacks use (word, word~cols, word~keyed)."""
    out = [("", keyword_alphabet(word))]
    if len(set(word)) >= 3:
        out.append(("~cols", column_mixed(word, False)))
        out.append(("~keyed", column_mixed(word, True)))
    return out


# ---------------------------------------------------------------- sliding strips

def slide(strip, places):
    """Move a strip `places` to the left (letters that fall off come back on the right)."""
    places %= len(strip)
    return strip[places:] + strip[:places]


def set_strip(plain, cipher, key_letter, index_letter):
    """Slide the cipher strip under the plain strip until key_letter sits under index_letter."""
    strip = cipher
    for _ in range(26):
        if strip[plain.index(index_letter)] == key_letter:
            return strip
        strip = slide(strip, 1)
    raise ValueError("key letter not on the strip")


def tableau_encrypt(pt, plain, cipher, key_letters, index_letter=None, beaufort=False):
    """One letter at a time: set the key letter under the index letter, find the plaintext letter
    on the plain strip, read the letter under it.

    plain = cipher = A-Z is Vigenere; plain keyed is Quagmire I; cipher keyed is Quagmire II; both
    keyed alike is Quagmire III (K1 and K2); keyed differently is Quagmire IV. The ACA puts the key
    under the plain A; Kryptos puts it under the first letter of the plain strip (the default).
    Beaufort: the same slide with the cipher strip written backwards."""
    index_letter = index_letter or plain[0]
    if beaufort:
        cipher = cipher[::-1]
    out = []
    for ch, k in zip(pt, key_letters):
        strip = set_strip(plain, cipher, k, index_letter)
        out.append(strip[plain.index(ch)])
    return "".join(out)


def tableau_decrypt(ct, plain, cipher, key_letters, index_letter=None, beaufort=False):
    index_letter = index_letter or plain[0]
    if beaufort:
        cipher = cipher[::-1]
    out = []
    for ch, k in zip(ct, key_letters):
        strip = set_strip(plain, cipher, k, index_letter)
        out.append(plain[strip.index(ch)])
    return "".join(out)


def repeating_key(word, n):
    return [word[i % len(word)] for i in range(n)]


def progressive_key(word, step, alphabet, n):
    """The key word, moved `step` letters along `alphabet` each time it has been used up."""
    out = []
    for i in range(n):
        cycle = i // len(word)
        ch = word[i % len(word)]
        for _ in range(cycle * step % 26):
            ch = alphabet[(alphabet.index(ch) + 1) % 26]
        out.append(ch)
    return out


def stacked_key(word_a, word_b, alphabet, n):
    """Two key words written one under the other and added letter by letter on `alphabet`."""
    out = []
    for i in range(n):
        a, b = word_a[i % len(word_a)], word_b[i % len(word_b)]
        out.append(slide(alphabet, alphabet.index(a))[alphabet.index(b)])
    return out


def sliding_encrypt(pt, plain, cipher, moves, beaufort=False):
    """Sliding key: the strip is never reset. Before each letter it is moved on by the next number
    of a repeating list of moves, from wherever the last letter left it."""
    strip = cipher[::-1] if beaufort else cipher
    out = []
    for i, ch in enumerate(pt):
        strip = slide(strip, moves[i % len(moves)])
        out.append(strip[plain.index(ch)])
    return "".join(out)


def autokey_encrypt(pt, plain, cipher, primer, feed, key_on="cipher", beaufort=False):
    """Autokey: the key is a primer followed by the message itself (feed 'plain') or by the cipher
    text already written (feed 'cipher').

    key_on 'cipher' (the usual way): the key letter is found on the cipher strip and set under the
    first letter of the plain strip. key_on 'plain': the first letter of the cipher strip is set
    under the key letter found on the plain strip. key_on 'label': the key letter picks a row of
    the square by the A-Z label at its left edge (row A = strip not moved, row B = one place...),
    which is how the rows of the carved Kryptos tableau are labelled."""
    out = []
    for i, ch in enumerate(pt):
        if i < len(primer):
            k = primer[i]
        else:
            k = (pt if feed == "plain" else out)[i - len(primer)]
        if key_on == "cipher":
            out.append(tableau_encrypt(ch, plain, cipher, [k], beaufort=beaufort))
        elif key_on == "plain":
            assert not beaufort
            strip = set_strip(plain, cipher, cipher[0], k)
            out.append(strip[plain.index(ch)])
        else:   # "label": rows of the square are picked by their A-Z label, as printed on Kryptos
            assert not beaufort
            out.append(slide(cipher, A2Z.index(k))[plain.index(ch)])
    return "".join(out)


def keyed_lag_autokey_encrypt(pt, alphabet, lags, constant, feed, primer_rng, beaufort=False, subtract=False,
                              cipher=None, numbering=None):
    """Autokey where a repeating list of distances says how far back to look for the key letter.
    The key number is the number of that earlier letter in `numbering` (added, or subtracted),
    plus a constant; the plain letter is found on `alphabet`, the answer read from `cipher`.
    Letters before the start of the message are replaced by random ones."""
    cipher = cipher or alphabet
    numbering = numbering or alphabet
    out = []
    for i, ch in enumerate(pt):
        back = i - lags[i % len(lags)]
        if back < 0:
            number = primer_rng.randrange(26)
        else:
            number = numbering.index((pt if feed == "plain" else out)[back])
        shift = (-number if subtract else number) + constant
        strip = slide(cipher[::-1] if beaufort else cipher, -shift - 1 if beaufort else shift)
        out.append(strip[alphabet.index(ch)])
    return "".join(out)


def multiplier_adder_encrypt(pt, plain, cipher, multipliers, adders):
    """C = A * P + B with a repeating list of multipliers and a repeating list of adders (any
    list of adders as long as the message also works). The multiplier takes every A-th letter of
    the cipher alphabet (a decimated alphabet); the adder then slides it."""
    out = []
    for i, ch in enumerate(pt):
        a, b = multipliers[i % len(multipliers)], adders[i % len(adders)]
        decimated = "".join(cipher[(a * j) % 26] for j in range(26))
        assert len(set(decimated)) == 26, "multiplier must be odd and not 13"
        landed = decimated[plain.index(ch)]
        out.append(slide(cipher, b)[cipher.index(landed)])
    return "".join(out)


def rotor_encrypt(pt, wiring, turns_in, turns_out, face_in=A2Z, face_out=A2Z):
    """A paper rotor between two fixed alphabets. wiring[j] = the contact that contact j is wired to.
    For letter i the input face has turned turns_in[i] contacts and the output face turns_out[i]
    (the same number if both faces turn together, the negative if they turn opposite ways)."""
    out = []
    for ch, t_in, t_out in zip(pt, turns_in, turns_out):
        enters = slide(list(range(26)), t_in)[face_in.index(ch)]     # rotor contact now facing the letter
        leaves = wiring[enters]                                     # the wire
        out.append(face_out[slide(list(range(26)), -t_out)[leaves]])  # fixed contact now facing it
    return "".join(out)


def beaufort_by_square(pt, key_letters):
    """Beaufort from the printed square: find the plain letter in the top row, go down that
    column to the key letter, read the row's label. (A-Z only; a cross-check for the strip form.)"""
    out = []
    for ch, k in zip(pt, key_letters):
        column = A2Z.index(ch)
        for row in range(26):
            if slide(A2Z, row)[column] == k:
                out.append(A2Z[row])
    return "".join(out)


# ---------------------------------------------------------------- checks against the sculpture

def k1_k2_check(k2_plain, k2_carved):
    """Encrypt K1 and K2 with the strip code (KRYPTOS alphabet, PALIMPSEST / ABSCISSA, key under the
    first letter of the strip, '?' copied and not using a key letter). Returns (k1 ok, k2 ok)."""
    kr = keyword_alphabet("KRYPTOS")
    k1 = tableau_encrypt(K1_PLAIN, kr, kr, repeating_key("PALIMPSEST", len(K1_PLAIN)))
    plain = only_letters(k2_plain)
    body = iter(tableau_encrypt(plain, kr, kr, repeating_key("ABSCISSA", len(plain))))
    k2 = "".join(ch if ch == "?" else next(body) for ch in k2_plain)
    return k1 == K1_CARVED, k2 == k2_carved


def tableau_panel_check(panel):
    """The carved tableau: 26 rows, each a row letter followed by the KRYPTOS alphabet slid one
    more place and run on for 30 letters (row N has one extra L). Returns the number of rows that agree."""
    kr = keyword_alphabet("KRYPTOS")
    good = 0
    for r in range(26):
        want = A2Z[r] + (slide(kr, r) * 2)[:30]
        good += panel[r + 1] == want or (A2Z[r] == "N" and panel[r + 1] == want + "L")
    return good


# ---------------------------------------------------------------- small exact tools

def rank_mod(rows, p):
    """Rank of an integer matrix over the integers mod a prime p."""
    m = [[v % p for v in r] for r in rows]
    rank = 0
    for c in range(len(m[0])):
        s = next((i for i in range(rank, len(m)) if m[i][c]), None)
        if s is None:
            continue
        m[rank], m[s] = m[s], m[rank]
        inv = pow(m[rank][c], p - 2, p)
        m[rank] = [v * inv % p for v in m[rank]]
        for i in range(len(m)):
            if i != rank and m[i][c]:
                f = m[i][c]
                m[i] = [(a - f * b) % p for a, b in zip(m[i], m[rank])]
        rank += 1
        if rank == len(m):
            break
    return rank


def random_word(rng, length, alphabet=A2Z):
    """Random letters with no shorter repeat inside them (so 'period 8' really means 8)."""
    while True:
        w = [rng.choice(alphabet) for _ in range(length)]
        if not any(all(w[i] == w[i % d] for i in range(length)) for d in range(1, length)):
            return "".join(w)


def random_numbers(rng, length):
    return [A2Z.index(ch) for ch in random_word(rng, length)]


if __name__ == "__main__":
    print(k4_like(random.Random(1)))
