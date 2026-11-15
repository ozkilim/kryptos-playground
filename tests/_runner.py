"""Tiny runner so tests work with or without pytest: python tests/test_x.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def run(namespace):
    import inspect
    import tempfile
    n = 0
    for name, fn in list(namespace.items()):
        if name.startswith("test_") and callable(fn):
            args = {}
            if "tmp_path" in inspect.signature(fn).parameters:
                args["tmp_path"] = Path(tempfile.mkdtemp())
            fn(**args)
            print("ok ", name)
            n += 1
    print(f"all {n} passed")
