"""Alphabet orders from Egyptian, Coptic, Greek and Semitic scripts, as Latin letter orders.

Sanborn: his 1986 trip to Egypt figures in the K4 solution. These give
"near-plain" alphabets (our fingerprint's favourite) with an Egyptian or
ancient-Near-East logic. Each order lists the Latin letters in the order the
script's corresponding sounds appear; unused Latin letters follow in A-Z order.
"""

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

ORDERS = {
    # Egyptian uniliteral hieroglyphs (Gardiner order): vulture, reed, double reed, arm, quail chick, foot,
    # stool, viper, owl, water, mouth, shelter, wick, ..., bolt, cloth, pool, hill, basket, jar stand, bread, hand
    "hieroglyph uniliterals": "AIYWBPFMNRHSQKGTD",
    "greek": "ABGDEZHIKLMNXOPRSTYFC",
    "coptic": "ABGDEZHIKLMNXOPRSTUFCJ",
    "phoenician/hebrew": "ABGDHWZYKLMNSOPQRT",
    "arabic abjad": "ABJDHWZYKLMNSOFQRT",
    "arabic hijai": "ABTJDRZSFQKLMNHWY",
}


def full(order):
    seen = []
    for ch in order + AZ:
        if ch not in seen:
            seen.append(ch)
    return "".join(seen)


def alphabets():
    out = {}
    for name, o in ORDERS.items():
        a = full(o)
        out[name] = a
        out[name + " reversed"] = a[::-1]
    return out
