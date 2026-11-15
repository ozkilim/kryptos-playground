"""Build data/english/quadgrams.txt from English text.

  python tools/build_ngrams.py                    # default: Python's bundled docs (no download)
  python tools/build_ngrams.py books/*.txt        # better: any plain-text books you have

The default corpus is the ~425k characters of English prose that ship
inside every Python install (pydoc_data). It's technical English, which is
good enough to rank candidates. A few Project Gutenberg novels make it
sharper; drop them in and re-run.
"""

import sys
from collections import Counter
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "english" / "quadgrams.txt"


def corpus(paths):
    if paths:
        for p in paths:
            yield Path(p).read_text(errors="ignore")
    else:
        import pydoc_data.topics as t
        yield from t.topics.values()


def main():
    paths = sys.argv[1:]
    counts, chars = Counter(), 0
    for text in corpus(paths):
        s = "".join(ch for ch in text.upper() if "A" <= ch <= "Z")
        chars += len(s)
        counts.update(s[i:i + 4] for i in range(len(s) - 3))
    keep = [(q, c) for q, c in counts.most_common() if c >= 2]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as f:
        src = ", ".join(paths) if paths else "pydoc_data.topics (Python's bundled docs)"
        f.write(f"# quadgram counts from {chars} letters of {src}; quadgrams seen once dropped\n")
        for q, c in keep:
            f.write(f"{q} {c}\n")
    print(f"wrote {len(keep)} quadgrams from {chars} letters -> {OUT}")


if __name__ == "__main__":
    main()
