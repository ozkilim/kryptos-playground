"""The external check: Paradigm's official verifiers.

  K4        https://www.paradigm.xyz/kryptos/k4      $1 per check (Stripe), no prize
  PK1-PK10  https://paradigm.xyz/kryptos-ctf/pkN     free, unlimited, sign in with X

Both are web forms (type letters into the boxes, click Decrypt), so this
module never submits for you. It:

  1. refuses a K4 answer that fails the free internal check (save your $1),
  2. refuses anything you've already checked (no double paying),
  3. logs it to submissions.csv (gitignored: your private record),
  4. prints the exact letters and opens the right page so you can paste.

Afterwards record what the site said:
  python -m kryptos result k4 <PLAINTEXT> wrong|CORRECT
"""

import csv
import hashlib
import webbrowser
from datetime import datetime, timezone

from .check import passes_cribs, crib_report
from .data import ROOT, load, letters
from .score import quadgram_score

LOG = ROOT / "submissions.csv"
FIELDS = ["timestamp", "puzzle", "sha256", "plaintext", "method", "result", "cost_usd"]


def _fingerprint(puzzle, p):
    return hashlib.sha256(f"{puzzle}:{p}".encode()).hexdigest()


def _read_log():
    if not LOG.exists():
        return []
    with open(LOG, newline="") as f:
        return list(csv.DictReader(f))


def _write_log(rows):
    with open(LOG, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})


def prepare(plaintext, puzzle="k4", method="", open_browser=True, force=False):
    puzzle = puzzle.lower()
    info = load(puzzle)
    check = info.get("check") or {}
    url, cost = check.get("url"), check.get("cost_usd", 0)
    if not url:
        print(f"{puzzle.upper()} is already solved; nothing to submit.")
        return False

    p = letters(plaintext)
    if len(p) != info["length"] and not force:
        print(f"Not submitting: {len(p)} letters, {puzzle.upper()} needs {info['length']}.")
        return False
    if puzzle == "k4":
        print(crib_report(p))
        if not passes_cribs(p) and not force:
            print("\nNot submitting: fails the internal check. Save your dollar.")
            return False
    else:
        q = quadgram_score(p)
        print(f"quadgram score: {q:.2f} (English ~ -4.7, random ~ -7)")
        if q < -5.8 and not force:
            print("Not submitting: doesn't look like English. (--force to send anyway; it's free.)")
            return False

    fp = _fingerprint(puzzle, p)
    rows = _read_log()
    if any(r.get("sha256") == fp for r in rows):
        print("Already checked this exact answer. See submissions.csv.")
        return False

    rows.append({
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "puzzle": puzzle, "sha256": fp, "plaintext": p, "method": method,
        "result": "pending", "cost_usd": cost,
    })
    _write_log(rows)

    price = f"${cost}" if cost else "free"
    print(f"\nLogged. Paste this into the {puzzle.upper()} page ({price}):\n\n{p}\n\n{url}")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    return True


def record_result(plaintext, result, puzzle="k4"):
    fp = _fingerprint(puzzle.lower(), letters(plaintext))
    rows = _read_log()
    for r in rows:
        if r.get("sha256") == fp:
            r["result"] = result
            _write_log(rows)
            print(f"Recorded: {result}")
            return True
    print("That answer isn't in submissions.csv.")
    return False


def stats():
    rows = _read_log()
    spent = sum(float(r.get("cost_usd") or 0) for r in rows)
    print(f"Official checks logged: {len(rows)}  (spent ${spent:.0f})")
    for r in rows[-10:]:
        print(f"  {r['timestamp']}  {r.get('puzzle', 'k4'):4} {r['result']:8}  {r['method'][:30]:30}  {r['plaintext'][:30]}...")
