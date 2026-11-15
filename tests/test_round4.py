"""Planted tests for round 4: visual transforms and compass-bearing keys."""
import importlib.util
import _runner  # noqa: F401
from pathlib import Path

from kryptos import CRIBS, K4
from kryptos.ciphers import AZ
from kryptos.visual import semaphore_map, transforms

ROOT = Path(__file__).resolve().parent.parent


def _attack(n):
    path = next((ROOT / "attacks").glob(f"{n:02d}_*.py"))
    spec = importlib.util.spec_from_file_location(path.stem, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_semaphore_basics():
    assert semaphore_map(0) == {c: c for c in semaphore_map(0)} and len(semaphore_map(0)) == 26
    assert all(len(set(m.values())) == len(m) for m in transforms().values())  # injective


def test_ticking_semaphore_schedule_is_found():
    a = _attack(30)
    T = transforms()
    for r0 in range(8):
        for s in range(1, 8):
            maps = [T[f"semaphore rot{(r0 + s * i) % 8}"] for i in range(97)]
            if all(CRIBS[i] in maps[i] for i in CRIBS):
                ct = list(K4)
                for i, p in CRIBS.items():
                    ct[i] = maps[i][p]
                _, hits, _ = a.schedules_alone("".join(ct), T)
                assert ("ticking", False, r0, s) in hits
                return
    raise AssertionError("no plantable schedule found")


def test_compass_bearing_key_is_found():
    a = _attack(31)
    panels, k4_pos = a.layout()
    cfg, ks = next((c, k) for c, k in a.keystreams(panels, k4_pos) if c == ("tableau", 2, -1, 3, True))
    ct = list(K4)
    for i, p in CRIBS.items():  # Vigenere on A-Z with the bearing key
        ct[i] = AZ[(AZ.index(p) + AZ.index(ks[i])) % 26]
    _, best, hits = a.scan("".join(ct), panels, k4_pos)
    assert ("tableau", 2, -1, 3, True, "AZ", "vigenere") in hits


if __name__ == "__main__":
    _runner.run(globals())
