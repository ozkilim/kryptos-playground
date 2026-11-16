"""Planted tests for round 8: word-key stacks, text keys with hidden alphabets, clock arithmetic, table switch."""
import importlib.util
import random
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, wordkeys
from kryptos.ciphers import AZ

ROOT = Path(__file__).resolve().parent.parent


def attack(name):
    spec = importlib.util.spec_from_file_location("__main__x", ROOT / "attacks" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_word_keys_exact_lookup_finds_planted_pair():
    m = attack("47_word_stacked_keys.py")
    vocab = sorted(set(wordkeys.theme_words() + wordkeys.common_words(2000)))
    ct, pt, truth = m.plant(random.Random(3), vocab)
    m.init(ct, {i: pt[i] for i in CRIBS}, vocab, None)
    hits = m.search_chunk(vocab)
    assert any({h[2], h[3]} == {truth[2], truth[3]} for h in hits)


def test_word_keys_phrase_head_tail():
    m = attack("47_word_stacked_keys.py")
    top = ["LAYER", "TWO", "BERLIN", "CLOCK", "SHADOW"]
    vocab = sorted(set(wordkeys.theme_words() + wordkeys.common_words(2000)))
    a, b = "LAYERTWO", "PALIMPSEST"  # different lengths (equal lengths collapse to one key)
    A, B = [AZ.index(c) for c in a], [AZ.index(c) for c in b]
    from kryptos import load
    pt = load("k3")["plaintext"][:97]
    ct = "".join(AZ[(AZ.index(p) + A[i % len(A)] + B[i % len(B)]) % 26] for i, p in enumerate(pt))
    m.init(ct, {i: pt[i] for i in CRIBS}, vocab, None, None, top)
    hits = m.search_phrases(["LAYER"])
    assert any(h[2] == "LAYERTWO" and h[3] == "PALIMPSEST" for h in hits)


def test_text_keys_planted_stream_survives():
    m = attack("49_text_keys_hidden_alphabets.py")
    ct, pt, (name, o, L, vname, model) = m.plant(random.Random(4949))
    kl = m.keyletters(m.texts()[name], o, L)
    assert m.consistent(m.equations("M4", ct, {i: pt[i] for i in CRIBS}, kl, "AZ")) is not None


def test_clock_dial_found():
    m = attack("50_clock_arithmetic.py")
    ct, pt, truth = m.plant(random.Random(50))
    res, _ = m.run(ct, {i: pt[i] for i in CRIBS}, smoke=True)
    assert res and res[0][1] == pt


def test_class_tableau_planted():
    m = attack("51_letter_class_tableaux.py")
    ct, pt, truth = m.plant(random.Random(51))
    hits, scored = m.run(ct, {i: pt[i] for i in CRIBS})
    assert scored and sum(a == b for a, b in zip(scored[0][1], pt)) >= 80


def test_second_look_collects_candidates():
    m = attack("52_second_look.py")
    assert len(m.candidates()) > 100


if __name__ == "__main__":
    _runner.run(globals())
