"""The swarm coordinator's queue: ids, claims, duplicate titles, result-card checks."""
import importlib.util
import json
import os
import tempfile
import _runner  # noqa: F401
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def swarm(tmp):
    os.environ["KRYPTOS_SWARM_HOME"] = str(tmp)
    spec = importlib.util.spec_from_file_location("swarm_mod", ROOT / "swarm" / "swarm.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_queue_ids_claims_and_duplicates():
    tmp = Path(tempfile.mkdtemp())
    try:
        s = swarm(tmp)
        a, _ = s.propose("First idea", "why", "plan", root=ROOT)
        b, _ = s.propose("Second idea", "why", "plan", root=ROOT)
        attacks = max(int(p.name.split("_")[0]) for p in (ROOT / "attacks").glob("[0-9]*_*.py"))
        assert a > attacks and b == a + 1                      # never reuses an attack number
        assert s.propose("first  IDEA!", "w", "p", root=ROOT)[0] is None   # same title, refused
        x, y = s.claim("w1"), s.claim("w2")
        assert (x["id"], y["id"]) == (a, b) and s.claim("w3") is None      # each idea goes to one worker
        s.update(a, status="open")
        assert s.claim("w3")["attempts"] == 2
    finally:
        os.environ.pop("KRYPTOS_SWARM_HOME", None)


def test_result_card_checks():
    tmp = Path(tempfile.mkdtemp())
    try:
        s = swarm(tmp)
        wt = tmp / "wt"
        (wt / "campaign" / "swarm").mkdir(parents=True)
        (wt / "attacks").mkdir()
        assert s.read_card(wt, 90)[0] is None                  # no card
        card = {"id": 90, "title": "t", "verdict": "dead", "k4_result": "0", "controls": "0", "planted": "3/3", "tested": 1,
                "scope_limits": "", "negative": {"family": "f", "hypothesis": "h", "scope": "s", "outcome": "o", "confidence": "solid"}}
        p = wt / "campaign" / "swarm" / "90.json"
        p.write_text(json.dumps(card))
        assert "no attack script" in s.read_card(wt, 90)[1]
        (wt / "attacks" / "90_x.py").write_text("")
        assert s.read_card(wt, 90)[0]["verdict"] == "dead"
        p.write_text(json.dumps(dict(card, verdict="solved")))
        assert s.read_card(wt, 90)[0] is None                  # only the allowed verdicts
        p.write_text(json.dumps(dict(card, verdict="untestable", negative={})))
        assert s.read_card(wt, 90)[0]                           # no script or negative needed
    finally:
        os.environ.pop("KRYPTOS_SWARM_HOME", None)


def test_seed_ideas_and_prompts_are_complete():
    seeds = json.load(open(ROOT / "swarm" / "seed_ideas.json"))
    assert seeds and all(x["title"] and x["why"] and x["plan"] for x in seeds)
    w = (ROOT / "swarm" / "WORKER_PROMPT.md").read_text()
    assert all("{{%s}}" % k in w for k in ("ID", "TITLE", "WHY", "PLAN", "WORKER", "HOURS"))
    i = (ROOT / "swarm" / "IDEATOR_PROMPT.md").read_text()
    assert all("{{%s}}" % k in i for k in ("N", "QUEUE", "SUGGESTIONS"))


if __name__ == "__main__":
    _runner.run(globals())
