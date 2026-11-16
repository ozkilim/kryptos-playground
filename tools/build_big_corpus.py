"""Build a bigger local English corpus (no downloads) and a quadgram table from it.

Sources already on any Mac with Python: Python's bundled docs (pydoc_data),
docstrings and comments of the Python standard library, and the system manual
pages (/usr/share/man, roff markup stripped). Mostly technical English, but
~10x more text than the default table.

  python tools/build_big_corpus.py   -> data/english/quadgrams_big.txt, data/english/words_big.txt
"""
import ast
import gzip
import re
import sys
import sysconfig
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_Q = ROOT / "data" / "english" / "quadgrams_big.txt"
OUT_W = ROOT / "data" / "english" / "words_big.txt"


def pydoc_text():
    import pydoc_data.topics as t
    yield from t.topics.values()


def stdlib_docstrings():
    lib = Path(sysconfig.get_paths()["stdlib"])
    for p in lib.rglob("*.py"):
        if "test" in p.parts or "site-packages" in p.parts:
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                d = ast.get_docstring(node)
                if d:
                    yield d


ROFF = re.compile(r"^\.[A-Za-z]+.*$|\\f[BIRP]|\\[(*][a-z]{1,2}|\\-|\\&|\\e|\\\(.{2}", re.M)


def man_pages():
    for p in Path("/usr/share/man").rglob("*"):
        if not p.is_file():
            continue
        try:
            raw = gzip.open(p).read() if p.suffix == ".gz" else p.read_bytes()
            yield ROFF.sub(" ", raw.decode("utf-8", errors="ignore"))
        except Exception:
            continue


def main():
    quads, words, total = Counter(), Counter(), 0
    for src in (pydoc_text, stdlib_docstrings, man_pages):
        for text in src():
            for w in re.findall(r"[A-Za-z]+", text):
                if len(w) >= 2 and not (w.isupper() and len(w) > 3):
                    words[w.upper()] += 1
            s = "".join(ch for ch in text.upper() if "A" <= ch <= "Z")
            total += len(s)
            quads.update(s[i:i + 4] for i in range(len(s) - 3))
    with open(OUT_Q, "w") as f:
        f.write(f"# quadgram counts from {total} letters: pydoc + stdlib docstrings + man pages (built locally)\n")
        for q, c in quads.most_common():
            if c >= 2:
                f.write(f"{q} {c}\n")
    with open(OUT_W, "w") as f:
        for w, c in words.most_common(60000):
            if c >= 3:
                f.write(f"{w} {c}\n")
    print(f"{total:,} letters -> {OUT_Q.name} ({len(quads):,} quadgrams), {OUT_W.name}")


if __name__ == "__main__":
    main()
