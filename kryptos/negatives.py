"""The growing negatives database: everything known NOT to be K4.

Two inputs, one output:

  negatives/community.jsonl   ideas other people tried and ruled out (one JSON per line, sourced)
  experiments/ledger.csv      our own K4 runs (added automatically, no typing)
        |
        v
  negatives/NEGATIVES.md      one big generated context file: read it (or paste it into an
                              LLM) before trying a new idea

    python -m kryptos negatives                 rebuild NEGATIVES.md, print a summary
    python -m kryptos negatives search autokey  is this idea already dead?
    python -m kryptos negatives add ...         record a new community/manual negative

The harness rebuilds NEGATIVES.md after every K4 experiment, so our own
nulls land in it without anyone remembering to write them down.
"""

import csv
import json
from collections import Counter, defaultdict
from datetime import date

from .data import ROOT

NEG_DIR = ROOT / "negatives"
COMMUNITY = NEG_DIR / "community.jsonl"
OUTPUT = NEG_DIR / "NEGATIVES.md"
LEDGER = ROOT / "experiments" / "ledger.csv"
GAPS = NEG_DIR / "open_gaps.md"

FIELDS = ["id", "family", "hypothesis", "scope", "who", "when", "outcome",
          "confidence", "source", "added"]
CONFIDENCE = {
    "solid": "Solid elimination",
    "partial": "Partial or weak test",
    "disputed": "Disputed",
    "statement": "Sanborn / Scheidt statement",
    "rejected-claim": "Rejected claimed solution",
}
FAMILY_ORDER = [
    "statistics", "sanborn-statement", "periodic-substitution", "keyed-alphabet",
    "autokey", "running-key", "transposition", "stacked", "polygraphic", "machine",
    "one-time-pad", "berlin-clock", "physical-sculpture", "other", "rejected-claim",
]


def load_community(path=None):
    path = path or COMMUNITY
    if not path.exists():
        return []
    rows = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path.name} line {n}: {e}") from None
    return rows


def load_ours(path=None):
    """Our K4 runs from the ledger that found nothing (0 full crib passes)."""
    path = path or LEDGER
    if not path.exists():
        return []
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if r["puzzle"] != "k4" or r.get("full_passes", "0") not in ("0", ""):
                continue
            if int(r["tried"] or 0) == 0:
                continue
            out.append({
                "id": f"ours-{r['timestamp']}",
                "family": "ours",
                "hypothesis": r["experiment"],
                "scope": f"{int(r['tried']):,} hypotheses/candidates. {r['notes']}",
                "who": "this repo", "when": r["timestamp"][:10],
                "outcome": "0 full crib passes" + (
                    f"; best decrypt matched {r['best_cribs']}/24 clue letters"
                    if r.get("best_cribs") not in ("", "0", None) else ""),
                "confidence": "solid", "source": "experiments/ledger.csv",
            })
    return out


def add(entry, path=None):
    path = path or COMMUNITY
    missing = [k for k in ("family", "hypothesis", "outcome", "confidence", "source") if not entry.get(k)]
    if missing:
        raise ValueError(f"missing fields: {', '.join(missing)}")
    if entry["confidence"] not in CONFIDENCE:
        raise ValueError(f"confidence must be one of {', '.join(CONFIDENCE)}")
    existing = {e.get("id") for e in load_community(path)}
    base = entry.get("id") or "-".join(entry["hypothesis"].lower().split()[:5])
    eid, n = base, 2
    while eid in existing:
        eid, n = f"{base}-{n}", n + 1
    entry = {"id": eid, **{k: entry.get(k, "") for k in FIELDS if k != "id"}}
    entry["added"] = entry["added"] or date.today().isoformat()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return eid


def search(term, community=None, ours=None):
    term = term.lower()
    rows = (community if community is not None else load_community()) + \
           (ours if ours is not None else load_ours())
    return [r for r in rows if term in json.dumps(r).lower()]


def _entry_md(r):
    bits = [f"- **{r['hypothesis']}**"]
    if r.get("scope"):
        bits.append(f"  - Scope: {r['scope']}")
    bits.append(f"  - Outcome: {r['outcome']}")
    who = ", ".join(x for x in (r.get("who"), r.get("when")) if x)
    meta = f"{CONFIDENCE.get(r['confidence'], r['confidence'])}"
    if who:
        meta += f" · {who}"
    src = r.get("source", "")
    if src.startswith("http"):
        src = f"[source]({src})"
    bits.append(f"  - {meta} · {src}")
    return "\n".join(bits)


def build(output=None, community=None, ours=None):
    community = load_community() if community is None else community
    ours = load_ours() if ours is None else ours
    by_family = defaultdict(list)
    for r in community:
        by_family[r.get("family", "other")].append(r)
    conf = Counter(r["confidence"] for r in community)
    lines = [
        "# K4 negatives: what is known NOT to work",
        "",
        "Generated by `python -m kryptos negatives` from `negatives/community.jsonl` (sourced, "
        "hand-curated) and `experiments/ledger.csv` (our own runs). Don't edit this file; "
        "edit those and rebuild.",
        "",
        "Read this before trying a new idea. If your idea is below, either skip it or "
        "say exactly how your version differs (wider scope, different alphabet, stacked with "
        "something else).",
        "",
        f"**{len(community)} community entries** "
        + (f"({', '.join(f'{n} {CONFIDENCE[c].lower()}' for c, n in conf.most_common())}) " if conf else "") +
        f"and **{len(ours)} of our own null runs** "
        f"({sum(int(r['scope'].split()[0].replace(',', '')) for r in ours):,} hypotheses).",
        "",
        "## Contents",
        "",
    ]
    fams = [f for f in FAMILY_ORDER if f in by_family] + sorted(set(by_family) - set(FAMILY_ORDER))
    for fam in fams:
        lines.append(f"- [{fam}](#{fam}) ({len(by_family[fam])})")
    lines.append(f"- [ours](#ours) ({len(ours)})")
    lines.append("- [Open gaps](#open-gaps-not-negatives-untested-or-undecidable)")
    for fam in fams:
        lines += ["", f"## {fam}", ""]
        order = {c: i for i, c in enumerate(CONFIDENCE)}
        for r in sorted(by_family[fam], key=lambda r: (order.get(r["confidence"], 9), r.get("when", ""))):
            lines.append(_entry_md(r))
    lines += ["", "## ours", "",
              "Every K4 experiment run through `kryptos.harness.Experiment` that found no full crib "
              "match. Each attack has a planted-answer test (`tests/`), so these are real nulls.", ""]
    for r in ours:
        lines.append(_entry_md(r))
    if GAPS.exists() and output is None:
        gap_lines = GAPS.read_text().splitlines()
        if gap_lines and gap_lines[0].startswith("# "):
            gap_lines = gap_lines[1:]
        lines += ["", "## Open gaps (NOT negatives: untested or undecidable)", "",
                  "From `negatives/open_gaps.md`. This is where new ideas should aim.", ""]
        lines += [l.replace("## ", "### ", 1) if l.startswith("## ") else l for l in gap_lines]
    out = output or OUTPUT
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n")
    return out, len(community), len(ours)
