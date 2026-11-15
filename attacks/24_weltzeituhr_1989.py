"""Idea 24: keys from the Berlin World Clock (Weltzeituhr) as it stood in 1989.

Sanborn (Nov 2025): BERLINCLOCK = the World Clock at Alexanderplatz, and the
1989 fall of the Wall figures in the solution. Everyone who tried the clock
used the post-1997 plates; data/weltzeituhr_1989.json reconstructs the
pre-1997 plates from dated photos (7 facets fully verified, the rest
partial, see research_notes/weltzeituhr_1989.md).

Keys built from the clock, read around the drum from every starting facet,
both directions, upper plates / lower plates / both:
  * city names as a running key (with and without umlaut expansion)
  * initial letters of the cities
  * each letter's facet UTC offset as a numeric key (plus any constant shift)
Every key at every offset, Vigenere/Beaufort/variant, A-Z/KRYPTOS. Exact crib
test; best result compared with shuffled K4s.
"""
import importlib.util
import json
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import K4, CRIBS, letters  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.data import DATA_DIR, ROOT  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402

spec = importlib.util.spec_from_file_location("rk", ROOT / "attacks" / "04_running_key.py")
RK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RK)


def facets():
    d = json.loads((DATA_DIR / "weltzeituhr_1989.json").read_text())
    fs = sorted(d["facets"], key=lambda f: int(f["utc_offset"]))  # UTC -11 .. +12
    out = []
    for f in fs:
        top = f.get("cities_1989_top") or []
        bot = f.get("cities_1989_bottom") or []
        if not top and not bot and f.get("cities_1989"):
            top = f["cities_1989"]
        out.append((int(f["utc_offset"]), top, bot))
    return out


def norm(name, umlaut):
    s = name.upper()
    for a, b in (("Ä", "AE"), ("Ö", "OE"), ("Ü", "UE")) if umlaut else (("Ä", "A"), ("Ö", "O"), ("Ü", "U")):
        s = s.replace(a, b)
    return letters(s)


def sources():
    fs = facets()
    texts, numeric = {}, {}
    for direction in (1, -1):
        for start in range(24):
            order = [fs[(start + direction * k) % 24] for k in range(24)]
            for mode in ("top", "bottom", "both"):
                for uml in (False, True):
                    names, offs = [], []
                    for utc, top, bot in order:
                        plate = top if mode == "top" else bot if mode == "bottom" else top + bot
                        for c in plate:
                            w = norm(c, uml)
                            names.append(w)
                            offs += [utc % 26] * len(w)
                    tag = f"dir{direction:+d} start{order[0][0]:+d} {mode}{' umlaut' if uml else ''}"
                    texts[f"names {tag}"] = "".join(names)
                    texts[f"initials {tag}"] = "".join(w[0] for w in names if w)
                    if not uml:
                        numeric[f"utc {tag}"] = offs
    return texts, numeric


def numeric_scan(ct, cribs, keys):
    """Key value = facet UTC offset of the letter + constant c, at every offset."""
    from kryptos.ciphers import AZ, KRYPTOS_ALPHABET
    from kryptos.cribtools import required_keys
    best = (0,)
    for an, al in (("AZ", AZ), ("KRYPTOS", KRYPTOS_ALPHABET)):
        for v in ("vigenere", "beaufort", "variant_beaufort"):
            req = required_keys(ct, cribs, al, v)
            for name, ks in keys.items():
                for off in range(0, max(1, len(ks) - len(ct) + 1)):
                    diffs = [(req[i] - ks[off + i]) % 26 for i in req if off + i < len(ks)]
                    if not diffs:
                        continue
                    sat = max(diffs.count(c) for c in set(diffs))
                    if sat > best[0]:
                        best = (sat, name, off, v, an)
    return best


if __name__ == "__main__":
    t0 = time.time()
    texts, numeric = sources()
    if SMOKE:
        texts = dict(list(texts.items())[:4])
        numeric = dict(list(numeric.items())[:2])
    long_texts = {k: v for k, v in texts.items() if len(v) >= len(K4)}
    with Experiment("weltzeituhr-1989-keys", puzzle="k4",
                    notes=f"pre-1997 World Clock plates (data/weltzeituhr_1989.json): {len(long_texts)} city-name / "
                          f"initial running keys + {len(numeric)} UTC-offset keys, every start facet, both directions, "
                          "every offset, vig/beau/varbeau, A-Z/KRYPTOS") as ex:
        best_text = RK.scan(K4, CRIBS, long_texts, ex=ex)
        best_num = numeric_scan(K4, CRIBS, numeric)
        ctrl = []
        for s in range(2):
            fake = shuffled(K4, 1300 + s)
            ctrl.append({"names": RK.scan(fake, CRIBS, long_texts)[0], "utc": numeric_scan(fake, CRIBS, numeric)[0]})
        cmax_t = max(c["names"] for c in ctrl)
        cmax_n = max(c["utc"] for c in ctrl)
        hit = best_text[0] == 24 or best_num[0] == 24
        verdict = ("HIT: a World Clock key places all 24 clue letters" if hit else
                   f"dead: best city-name key {best_text[0]}/24 (shuffled {cmax_t}), best UTC-offset key "
                   f"{best_num[0]}/24 (shuffled {cmax_n}); 24/24 needed")
        ex.notes += f"; {verdict}"
    report("24", name="Weltzeituhr 1989 keys", running_keys=len(long_texts), numeric_keys=len(numeric),
           best_name_key=list(best_text), best_utc_key=list(best_num), control=ctrl, verdict=verdict,
           data_caveat="7/24 facets verified pre-1997; west side from 1970s readings; orientation undocumented",
           minutes=round((time.time() - t0) / 60, 1))
    print("[24]", verdict, best_text, best_num)
