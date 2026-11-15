"""Command line. Run from the repo root:

  python -m kryptos list                         every puzzle and its status
  python -m kryptos show [k4|k2|pk3...]          ciphertext (K4: with cribs lined up)
  python -m kryptos triage [id|all]              IoC, periods, best guess at cipher type
  python -m kryptos crack <id> [--wordlist]      run the automatic solvers
  python -m kryptos cribkeys                     key letters K4's cribs imply
  python -m kryptos check <PLAINTEXT>            free K4 internal check
  python -m kryptos ledger                       what's been tried (experiments/ledger.csv)
  python -m kryptos negatives [search TERM]      everything known NOT to work (rebuilds negatives/NEGATIVES.md)

  python -m kryptos submit <id> <PLAINTEXT> [--method "..."]   log + open the official page
  python -m kryptos result <id> <PLAINTEXT> wrong|CORRECT      record what the site said
  python -m kryptos stats                                      what you've checked/paid
"""

import argparse
import csv

from . import external
from .analysis import triage
from .check import crib_report, crib_key_table
from .data import CRIBS, K4, all_ids, load
from .harness import LEDGER


def cmd_list(_):
    print(f"{'id':5} {'len':>4}  {'status':14} {'check':22} notes")
    for pid in all_ids():
        d = load(pid)
        chk = d.get("check") or {}
        cost = "" if not chk else ("free" if not chk.get("cost_usd") else f"${chk['cost_usd']}/try")
        extra = d.get("key") or d.get("method") or ""
        if pid.startswith("pk"):
            extra = f"prize won by {d['prize']['first_solver']} {d['prize']['first_solved_utc']}"
        print(f"{pid:5} {d['length']:>4}  {d['status']:14} {cost:22} {extra}")


def cmd_show(a):
    d = load(a.id)
    ct = d["ciphertext"]
    print(f"{d['name']}  ({d['length']} letters, {d['status']})\n")
    for start in range(0, len(ct), 50):
        print(f"{start + 1:>4}  {ct[start:start + 50]}")
    if a.id.lower() == "k4":
        print("\nKnown plaintext:")
        print(K4)
        print("".join(CRIBS.get(i, ".") for i in range(97)))
    elif d.get("plaintext"):
        print(f"\nPlaintext:\n{d['plaintext']}")
    if d.get("notes"):
        print(f"\n{d['notes']}")


def cmd_triage(a):
    ids = all_ids() if a.id == "all" else [a.id]
    for pid in ids:
        t = triage(load(pid)["ciphertext"])
        per = " ".join(f"{p}:{v:.3f}" for p, v in t["best_periods"])
        print(f"{pid:5} n={t['length']:<4} IoC={t['ioc']:.4f} chi2={t['chi2']:>6.0f} "
              f"periods[{per}]  missing={t['missing_letters'] or '-':8} -> {t['guess']}")


def cmd_crack(a):
    from .solvers import crack_all
    from .solvers.periodic import crack_wordlist
    from .harness import Experiment
    d = load(a.id)
    ct = d["ciphertext"]
    name = "auto-wordlist" if a.wordlist else "auto-solvers"
    with Experiment(name, puzzle=a.id, notes="python -m kryptos crack", quiet=True) as ex:
        cands = crack_wordlist(ct) if a.wordlist else crack_all(ct, top=10)
        for c in cands:
            ex.add(c.plaintext, method=c.method, **c.params)
    print(f"Best guesses for {a.id.upper()} (quadgram: English ~ -4.7, random ~ -7):\n")
    for c in cands[:a.top]:
        print(f"  q={c.score:6.2f}  {c.method:16} {c.params}\n           {c.plaintext[:90]}")
    if d.get("plaintext"):
        ok = cands and cands[0].plaintext == d["plaintext"].replace("?", "")
        print(f"\nMatches the known solution: {bool(ok)}")


def cmd_ledger(a):
    if not LEDGER.exists():
        print("No experiments logged yet.")
        return
    with open(LEDGER, newline="") as f:
        rows = list(csv.DictReader(f))
    print(f"{len(rows)} experiments logged, {sum(int(r['tried']) for r in rows):,} candidates tried\n")
    for r in rows[-a.n:]:
        print(f"  {r['timestamp']}  {r['puzzle']:4} {r['experiment'][:28]:28} tried={int(r['tried']):>9,} "
              f"cribs={r['best_cribs'] or '-':>2} q={r['best_score']:>7}  {r['best_plaintext'][:24]}")


def cmd_negatives(a):
    from . import negatives as neg
    if a.action == "search":
        hits = neg.search(" ".join(a.terms))
        print(f"{len(hits)} matching negatives for {' '.join(a.terms)!r}\n")
        for r in hits:
            print(f"  [{r['confidence']}] {r['hypothesis']}\n      {r['outcome']}\n      {r['source']}")
        return
    if a.action == "add":
        eid = neg.add({k: getattr(a, k) or "" for k in
                       ("family", "hypothesis", "scope", "who", "when", "outcome", "confidence", "source")})
        print(f"added {eid}")
    out, n_comm, n_ours = neg.build()
    print(f"{out.relative_to(neg.ROOT)}: {n_comm} community entries + {n_ours} of our runs")


def main():
    ap = argparse.ArgumentParser(prog="kryptos", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    s = sub.add_parser("show"); s.add_argument("id", nargs="?", default="k4")
    t = sub.add_parser("triage"); t.add_argument("id", nargs="?", default="all")
    c = sub.add_parser("crack"); c.add_argument("id")
    c.add_argument("--wordlist", action="store_true", help="dictionary keys (for short texts like K1)")
    c.add_argument("--top", type=int, default=5)
    sub.add_parser("cribkeys")
    k = sub.add_parser("check"); k.add_argument("plaintext")
    l = sub.add_parser("ledger"); l.add_argument("-n", type=int, default=20)
    ng = sub.add_parser("negatives")
    ng.add_argument("action", nargs="?", default="build", choices=["build", "search", "add"])
    ng.add_argument("terms", nargs="*")
    for f in ("family", "hypothesis", "scope", "who", "when", "outcome", "confidence", "source"):
        ng.add_argument(f"--{f}")
    m = sub.add_parser("submit"); m.add_argument("id"); m.add_argument("plaintext")
    m.add_argument("--method", default=""); m.add_argument("--no-browser", action="store_true")
    m.add_argument("--force", action="store_true")
    r = sub.add_parser("result"); r.add_argument("id"); r.add_argument("plaintext"); r.add_argument("result")
    sub.add_parser("stats")
    a = ap.parse_args()

    {
        "list": cmd_list, "show": cmd_show, "triage": cmd_triage, "crack": cmd_crack,
        "cribkeys": lambda _: print(crib_key_table()),
        "check": lambda a: print(crib_report(a.plaintext)),
        "ledger": cmd_ledger,
        "negatives": cmd_negatives,
        "submit": lambda a: external.prepare(a.plaintext, a.id, a.method,
                                             open_browser=not a.no_browser, force=a.force),
        "result": lambda a: external.record_result(a.plaintext, a.result, a.id),
        "stats": lambda _: external.stats(),
    }[a.cmd](a)


if __name__ == "__main__":
    main()
