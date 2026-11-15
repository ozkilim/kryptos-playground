"""The external check: Paradigm's official verifier.

Each official check costs $1 and goes through a web form with a Stripe
payment, so this does NOT submit for you. It:

  1. refuses anything that fails the free internal check,
  2. refuses anything you've already paid to check (no double paying),
  3. logs it to submissions.csv,
  4. prints the exact answer and opens the K4 page so you can paste it.

After Paradigm tells you the result, record it with:
  python -m kryptos result <PLAINTEXT> wrong|CORRECT
"""

import csv
import hashlib
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from .check import normalize, passes_cribs, crib_report

K4_URL = "https://www.paradigm.xyz/kryptos/k4"
LOG = Path(__file__).resolve().parent.parent / "submissions.csv"
FIELDS = ["timestamp", "sha256", "plaintext", "method", "result"]


def _fingerprint(p):
    return hashlib.sha256(p.encode()).hexdigest()


def _read_log():
    if not LOG.exists():
        return []
    with open(LOG, newline="") as f:
        return list(csv.DictReader(f))


def _write_log(rows):
    with open(LOG, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)


def prepare(plaintext, method="", open_browser=True, force=False):
    p = normalize(plaintext)
    if not passes_cribs(p) and not force:
        print(crib_report(p))
        print("\nNot submitting: fails the internal check. Save your dollar.")
        return False

    fp = _fingerprint(p)
    rows = _read_log()
    if any(r["sha256"] == fp for r in rows):
        print("Already checked this exact answer. See submissions.csv.")
        return False

    rows.append({
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": fp, "plaintext": p, "method": method, "result": "pending",
    })
    _write_log(rows)

    print(crib_report(p))
    print("\nLogged. Paste this into the K4 page ($1):\n")
    print(p)
    print(f"\n{K4_URL}")
    if open_browser:
        try:
            webbrowser.open(K4_URL)
        except Exception:
            pass
    return True


def record_result(plaintext, result):
    fp = _fingerprint(normalize(plaintext))
    rows = _read_log()
    for r in rows:
        if r["sha256"] == fp:
            r["result"] = result
            _write_log(rows)
            print(f"Recorded: {result}")
            return True
    print("That answer isn't in submissions.csv.")
    return False


def stats():
    rows = _read_log()
    print(f"Official checks logged: {len(rows)}  (spent ${len(rows)})")
    for r in rows[-10:]:
        print(f"  {r['timestamp']}  {r['result']:8}  {r['method']}  {r['plaintext'][:30]}...")
