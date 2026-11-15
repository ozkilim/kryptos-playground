"""Transposition ciphers: the letters stay the same, their order changes.

K3 is a double *rotation*: write the text in a grid, turn the grid 90
degrees, re-cut it to a new width, turn again.
"""


def reverse(text):
    return text[::-1]


# ---------- keyed columnar ----------

def _column_order(key):
    """Column read order. key may be a word ("ZEBRAS") or a list of ints."""
    if isinstance(key, str):
        key = key.upper()
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def columnar_encrypt(pt, key):
    """Write in rows of len(key), read columns in key order."""
    n = len(key)
    return "".join(pt[i::n] for i in _column_order(key))


def columnar_decrypt(ct, key):
    """Undo a keyed columnar transposition (irregular last row is fine).
    Works on strings, or on lists (handy for building position maps:
    columnar_decrypt(list(range(n)), key)[i] = where plaintext letter i sits)."""
    ncols = len(key)
    nrows, extra = divmod(len(ct), ncols)
    col_lens = [nrows + (1 if i < extra else 0) for i in range(ncols)]
    cols, pos = [None] * ncols, 0
    for i in _column_order(key):
        cols[i] = ct[pos:pos + col_lens[i]]
        pos += col_lens[i]
    out = []
    for r in range(nrows + 1):
        for c in range(ncols):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out) if isinstance(ct, str) else out


# ---------- grid rotation (K3) ----------

def _rows(text, width):
    return [text[i:i + width] for i in range(0, len(text), width)]


def rotate_grid(text, width, clockwise=True):
    """Write text in rows `width` wide (must divide evenly), turn 90 degrees,
    read the new rows back out as one string."""
    if len(text) % width:
        raise ValueError(f"width {width} does not divide length {len(text)}")
    rows = _rows(text, width)
    h = len(rows)
    if clockwise:
        new = ["".join(rows[h - 1 - r][c] for r in range(h)) for c in range(width)]
    else:
        new = ["".join(rows[r][width - 1 - c] for r in range(h)) for c in range(width)]
    return "".join(new)


def rotation_decrypt(ct, width1, width2):
    """K3's method. rotation_decrypt(k3_ct, 24, 8) gives the K3 plaintext."""
    return rotate_grid(rotate_grid(ct, width1), width2)


def rotation_encrypt(pt, width1, width2):
    """Exact inverse of rotation_decrypt with the same widths."""
    n = len(pt)
    h1, h2 = n // width1, n // width2
    # undo the second rotation (grid was width2 wide -> h2 wide after turning)
    t = rotate_grid(pt, h2, clockwise=False)
    return rotate_grid(t, h1, clockwise=False)


# ---------- rail fence ----------

def railfence_decrypt(ct, rails):
    if rails < 2:
        return ct
    n = len(ct)
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    rail_of = [pattern[i % len(pattern)] for i in range(n)]
    counts = [rail_of.count(r) for r in range(rails)]
    pieces, pos = [], 0
    for c in counts:
        pieces.append(list(ct[pos:pos + c]))
        pos += c
    return "".join(pieces[r].pop(0) for r in rail_of)
