"""Cipher building blocks. Every *_decrypt takes ciphertext and returns a
candidate plaintext, so anything here plugs straight into the checks.

Substitution (letters change):   caesar, vigenere, beaufort, variant_beaufort, autokey
Transposition (letters move):    columnar, rotation (K3), rail fence, reverse
"""

from .substitution import (  # noqa: F401
    AZ, KRYPTOS_ALPHABET, keyed_alphabet,
    caesar_decrypt, vigenere_encrypt, vigenere_decrypt,
    beaufort_decrypt, variant_beaufort_decrypt,
    autokey_decrypt, KEY_FROM, PLAIN_FROM,
)
from .transposition import (  # noqa: F401
    columnar_encrypt, columnar_decrypt, rotate_grid,
    rotation_encrypt, rotation_decrypt, railfence_decrypt, reverse,
)
