"""Command line.

  python -m kryptos show                       print K4 with the clues lined up
  python -m kryptos check  <PLAINTEXT>         free internal check
  python -m kryptos submit <PLAINTEXT> [--method "how you got it"]
  python -m kryptos result <PLAINTEXT> wrong|CORRECT
  python -m kryptos stats                      what you've paid to check
"""

import argparse

from .data import K4, CRIBS
from .check import crib_report
from . import external


def show():
    print("Ciphertext (positions 1-97):\n")
    for start in range(0, 97, 10):
        print(f"{start + 1:>3}  {K4[start:start + 10]}")
    print("\nKnown letters:")
    print(K4)
    print("".join(CRIBS.get(i, ".") for i in range(97)))


def main():
    ap = argparse.ArgumentParser(prog="kryptos")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("show")
    c = sub.add_parser("check"); c.add_argument("plaintext")
    s = sub.add_parser("submit"); s.add_argument("plaintext")
    s.add_argument("--method", default=""); s.add_argument("--no-browser", action="store_true")
    r = sub.add_parser("result"); r.add_argument("plaintext"); r.add_argument("result")
    sub.add_parser("stats")
    a = ap.parse_args()

    if a.cmd == "show":
        show()
    elif a.cmd == "check":
        print(crib_report(a.plaintext))
    elif a.cmd == "submit":
        external.prepare(a.plaintext, a.method, open_browser=not a.no_browser)
    elif a.cmd == "result":
        external.record_result(a.plaintext, a.result)
    elif a.cmd == "stats":
        external.stats()


if __name__ == "__main__":
    main()
