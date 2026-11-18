"""Planted tests for idea 122: sentences enciphered one at a time, so the key phase at BERLINCLOCK
(and at NORTHEAST) is free. Planted messages must be found with their phase named and read back;
the fast phase index must give the same answers as testing every phase; the carved phase is left out."""
import importlib.util
import random
from pathlib import Path

import _runner  # noqa: F401

from kryptos import idea122_strips as S
from kryptos.round11 import dictionary_alphabets
from kryptos.idea104_holes import read_score
from kryptos.score import Quadgrams

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("a122", ROOT / "attacks" / "122_strips_enciphered_alone.py")
A = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(A)
ALPHAS = dictionary_alphabets(mixed=True)[:60]


def _slow(k, xp, xc, pl):
    out = []
    for split, fam, spec, rows in pl["single"]:
        v = S.values(spec, k, xp, xc)
        for L, internal, ph, fast in rows:
            for phs, ck, a, b in ph:
                if (internal is None or internal[0](v) == internal[1](v)) and a(v) == b(v):
                    out.append((ck, "%s L=%d" % (S.fam_name(fam), L), split, phs))
    return sorted(out)


def test_fast_index_equals_every_phase():
    pl = S.plan()
    rng = random.Random(122)
    hits = 0
    for t in range(400):
        L, g = rng.randrange(2, 17), rng.randrange(17)
        w = [rng.randrange(26) for _ in range(L)]
        k = [w[i % L] for i in range(21, 34)] + [w[(i + g) % L] for i in range(63, 74)]
        if t % 2:
            k = [rng.randrange(2) for _ in range(24)]
        xp, xc = [rng.randrange(26) for _ in range(24)], [rng.randrange(26) for _ in range(24)]
        fast = sorted(h for h in S.test_stream(k, xp, xc, pl) if h[1].startswith(("rep", "slide", "autokey")))
        assert fast == _slow(k, xp, xc, pl)
        hits += len(fast)
    assert hits > 100


def test_carved_phase_is_left_out_and_chance_is_small():
    n, chance, _, _, _ = S.sizes()
    assert n == 5550 and chance * 6.67e6 < 0.5
    w = [3, 1, 4, 1, 5, 9, 2, 6, 5]
    k = [w[i % 9] for i in range(21, 34)] + [w[i % 9] for i in range(63, 74)]
    assert not [h for h in S.test_stream(k, [0] * 24, [0] * 24) if h[1] == "rep L=9"]


def test_planted_found_with_phase_and_read():
    small = Quadgrams()
    rng = random.Random(1220)
    for kind in ("repeating 9, restart at a sentence start", "sliding 6, sentences enciphered in swapped order",
                 "stacked 4 + 7, both restarted", "repeating 7, restart at NORTHEAST and between the clues"):
        ct, cribs, name, m, want, pt, s = A.plant(kind, rng, ALPHAS)
        sub = [(name, m)] + ALPHAS[:30]
        _, hits = S.search_serial(ct, cribs, sub)
        found = [h for h in hits if S.is_main(h) and h[1:] == want]
        assert found, kind
        text = S.read(found[0], m, ct, cribs, s)
        assert sum(a == b for a, b in zip(text, pt)) >= 90, (kind, text)
        sc, nq, brk, best = S.best_reading(found[0], m, ct, cribs, small, read_score)
        assert sum(a == b for a, b in zip(best, pt)) >= 90, (kind, brk, best)


if __name__ == "__main__":
    _runner.run(globals())
