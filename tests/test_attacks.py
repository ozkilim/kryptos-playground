"""Positive controls: plant a known answer, check each K4 attack finds it.
A null result on K4 only means something if these pass."""
import importlib.util
import _runner  # noqa: F401
from pathlib import Path

from kryptos.ciphers import AZ, KRYPTOS_ALPHABET, keyed_alphabet, vigenere_encrypt, autokey_decrypt

ROOT = Path(__file__).resolve().parent.parent
PT = ("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENRANAWAYINTOTHEDEEPDARKFORESTWHERE"
      "NOBODYCOULDEVERFINDITAGAIN")[:97]
CRIBS = {i: PT[i] for i in list(range(21, 34)) + list(range(63, 74))}


def _attack(n):
    path = next((ROOT / "attacks").glob(f"{n:02d}_*.py"))
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_autokey_scan_finds_planted_ciphertext_autokey():
    a = _attack(3)
    primer = "SECRET"
    ks, ct = list(primer), ""
    for i, p in enumerate(PT):  # ct-autokey encrypt on the KRYPTOS alphabet
        c = KRYPTOS_ALPHABET[(KRYPTOS_ALPHABET.index(p) + KRYPTOS_ALPHABET.index(ks[i])) % 26]
        ct += c
        ks.append(c)
    assert autokey_decrypt(ct, primer, "ciphertext", "vigenere", KRYPTOS_ALPHABET) == PT
    hits = [h for h in a.scan(ct, CRIBS) if h[0] == "ciphertext" and h[4] == h[5] and h[5] > 0]
    assert ("ciphertext", 6, "vigenere", "KRYPTOS") in [h[:4] for h in hits]


def test_running_key_scan_finds_planted_text():
    a = _attack(4)
    text = "ANYTEXTWILLDO" * 3 + "ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOM" * 3
    ct = vigenere_encrypt(PT, text[17:17 + 97], AZ)
    best = a.scan(ct, CRIBS, {"planted": text})
    assert best[0] == 24 and best[1:5] == ("planted", 17, "forward", "vigenere")


def test_quagmire_scan_finds_planted_keyword_alphabet():
    a = _attack(5)
    alpha = keyed_alphabet("LODESTONE")
    ct = vigenere_encrypt(PT, "BERLINER", alpha)  # Quagmire III, period 8
    survivors, best, _ = a.scan(ct, CRIBS, ["SHADOW", "LODESTONE", "COMPASS"])
    assert ("LODESTONE", "III", 8) in survivors



def test_long_period_attack_recovers_planted_english():
    import random
    from kryptos import load
    a = _attack(6)
    pt = load("k3")["plaintext"][40:137]  # real English, 97 letters
    rng = random.Random(5)
    for L in (27, 29):
        key = "".join(rng.choice(AZ) for _ in range(L))
        ct = vigenere_encrypt(pt, key, KRYPTOS_ALPHABET)
        cribs = {i: pt[i] for i in list(range(21, 34)) + list(range(63, 74))}
        score, got, params = a.run(ct, cribs, {"KRYPTOS": KRYPTOS_ALPHABET}, rng)[0]
        assert params["period"] == L and score > -5.2, (L, score)
        assert sum(x == y for x, y in zip(got, pt)) >= 85, got


if __name__ == "__main__":
    _runner.run(globals())
