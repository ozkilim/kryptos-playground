"""Idea 78 helpers: run the round 11 tests of attacks 68, 70, 71 (part B) and 74 on the
transposition-mixed keyword alphabets, using those attacks' own test functions.

The attack scripts have names that cannot be imported the normal way, so they are loaded by
path here. Workers started by multiprocessing import this module and load them again.
"""
import importlib.util
from pathlib import Path

from .round11 import dictionary_alphabets, pmap

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = {"68": "68_blocks_alone_and_gap_slack.py", "70": "70_wrong_modulus.py",
           "71": "71_multiplier_and_adder_words.py", "74": "74_keyed_lag_autokey.py"}
TESTS = ("68", "70", "71", "74")
# key-stream settings each test tries per alphabet (same counting as the original attacks)
PER_ALPHABET = {"68": 10 * 8, "70": 10 * 5 + 2, "71": 5 * 10, "74": 2 * 2 * 2 * 26 * 13}
_MODS = {}


def attack(key):
    """The module of attack 68 / 70 / 71 / 74, loaded once per process."""
    if key not in _MODS:
        spec = importlib.util.spec_from_file_location("idea78_attack_" + key, ROOT / "attacks" / SCRIPTS[key])
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MODS[key] = mod
    return _MODS[key]


def new_alphabets():
    """[(name, alphabet)] for the ~cols and ~keyed forms that are not also a plain keyword alphabet
    (those were covered by ideas 68, 70, 71 and 74). Theme words come first, then common words."""
    plain = {m for _, m in dictionary_alphabets(mixed=False)}
    return [(n, m) for n, m in dictionary_alphabets(mixed=True) if m not in plain]


def init(ct, cribs, tests):
    for t in tests:
        attack(t).init(ct, cribs)
    _MODS["tests"] = tests


def work(chunk):
    """{test: hits} for one chunk of alphabets. 68, 70, 71B and 74 each use their own work()."""
    return {t: attack(t).work(chunk) for t in _MODS["tests"]}


def search(ct, cribs, alphas, tests=TESTS, chunk=1500):
    hits = {t: [] for t in tests}
    for r in pmap(work, alphas, init, (ct, cribs, tuple(tests)), chunk=chunk):
        for t, h in r.items():
            hits[t] += h
    return hits


def plant(test, rng, alphas, variant=0):
    """A planted message for one test, built by that attack's own planting function.
    Returns (ct, cribs, found) where found(hits) says if the planted setting is among the hits."""
    m = attack(test)
    if test == "68":
        ct, cribs, want = (m.plant_dropped_letter, m.plant_two_halves)[variant](rng, alphas)
    elif test == "70":
        ct, cribs, want = m.plant(rng, alphas, (27, 31)[variant])
    elif test == "71":
        ct, cribs, want = m.plant_dict(rng, alphas)
    else:
        src = ("cipher", "plain")[variant]
        ct, cribs, name, s, p = m.plant(rng, alphas, src)
        want = (name, "vig", "%s feed +1" % s, "period %d " % p)
        return ct, cribs, want, lambda hits: any(
            x[1] == name and x[2] == "vig" and x[3] == want[2] and x[4].startswith(want[3]) for x in hits)
    return ct, cribs, want, lambda hits: any(x[1:] == want for x in hits)
