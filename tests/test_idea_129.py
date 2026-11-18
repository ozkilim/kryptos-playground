"""Planted tests for idea 129: repeating key word plus a steady step on one hidden alphabet."""
import random
import _runner  # noqa: F401

from kryptos import CRIBS, K4
from kryptos import idea129_step as h
from kryptos.round11 import english97


def _plant(layout, p, s, form, ph, seed):
    rng = random.Random(seed)
    pt = list(english97(rng))
    for i, c in CRIBS.items():
        pt[i] = c
    pt = "".join(pt)
    x = "".join(rng.sample(h.AZ, 26))
    w = [rng.randrange(26) for _ in range(p)]
    return h.encrypt(layout, pt, h.key_stream(w, s, form, ph), x), pt, x, w


def _recovers(layout, p, s, form, ph, seed):
    ct, pt, x, w = _plant(layout, p, s, form, ph, seed)
    S = h.System(layout, ct, CRIBS, p)
    sol = S.solve(s, form, ph)
    assert sol is not None
    st, arr, capped = h.arrangements(S, sol, cap=50, rng=random.Random(1))
    assert st == "exact" and not capped and arr
    want = {ch: x.index(ch) for ch in S.letters}
    sh = want[S.letters[0]]
    want = {ch: (v - sh) % 26 for ch, v in want.items()}
    assert want in arr                                   # the true placing is among the fits
    # the recovered word and the turned alphabet encrypt the planted text to the same ciphertext
    k = h.key_stream(h.word_values(S, want, s, form, ph), s, form, ph)
    xs = "".join(x[(j + sh) % 26] for j in range(26))
    assert h.encrypt(layout, pt, k, xs) == ct
    return len(arr)


def test_planted_word7_step3_per_pass():
    assert _recovers("V", 7, 3, "pass", 0, 12901) >= 1


def test_planted_half_hidden_kryptos_word5_step2():
    assert _recovers("hcKR", 5, 2, "pass", 0, 12903) >= 1
    assert _recovers("hpKR", 5, 2, "pass", 0, 12904) >= 1


def test_planted_word11_beaufort_survives_exact_test():
    # B with a word of 11 has no loop tests: the true setting must pass and fit (soundness)
    ct, pt, x, w = _plant("B", 11, 1, "letter", 0, 12902)
    S = h.System("B", ct, CRIBS, 11)
    assert S.tests[13] == 0
    sol = S.solve(1, "letter", 0)
    assert sol is not None
    placed = {ch: x.index(ch) for ch in S.letters}
    sh = placed[S.letters[0]]
    placed = {ch: (v - sh) % 26 for ch, v in placed.items()}
    h.word_values(S, placed, 1, "letter", 0)            # raises if the equations fail


def test_k4_decided_cells_are_empty():
    for layout, p in (("V", 1), ("hpAZ", 4), ("hcKR", 6)):
        S = h.System(layout, K4, CRIBS, p)
        assert S.tests[13] >= 3
        assert all(S.solve(s, f, ph) is None for s, f, ph in h.settings(p))
    S = h.System("V", K4, CRIBS, 7)                     # no loop tests, but no placing fits
    for s, f, ph in list(h.settings(7))[:8]:
        sol = S.solve(s, f, ph)
        st, arr, _ = h.arrangements(S, sol, cap=1)
        assert st == "exact" and not arr


def test_attack_reads_planted_back():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parent.parent / "attacks" / "129_stepped_word_hidden_alphabet.py"
    spec = importlib.util.spec_from_file_location("attack129", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    full = m.settings
    for pl in (m.PLANTS[0], m.PLANTS[2], m.PLANTS[5]):    # V word 7, hcKR word 5, hpAZ word 9
        ct, pt, x, w = m.plant(*pl)
        # only the steps 1..4 (the full run tries all 25), to stay fast; s = 1 stands for 3 in layout V
        m.settings = lambda lay, p: [t for t in full(lay, p) if t[0] <= 4]
        try:
            r = m.cell(("plant", ct, CRIBS, pl[0], pl[1], True))
        finally:
            m.settings = full
        assert r["undecided"] == 0 and r["best"] is not None
        assert sum(a == b for a, b in zip(r["best"][1], pt)) >= m.RIGHT and r["best"][0] > m.ENGLISH


if __name__ == "__main__":
    _runner.run(globals())
