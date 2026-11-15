"""Run the idea queue unattended. Resumable: finished ideas are skipped.

  python campaign/run.py              run everything not yet done
  python campaign/run.py --smoke      tiny slice of every idea, results to a scratch dir
  python campaign/run.py --status     just rebuild campaign/STATUS.md

Each idea runs as its own process with a time limit; a crash or timeout is
recorded and the queue moves on. STATUS.md is rebuilt after every idea, and
negatives/NEGATIVES.md picks up every K4 run automatically.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAMP = ROOT / "campaign"
sys.path.insert(0, str(ROOT))


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def load_state():
    p = CAMP / "state.json"
    return json.loads(p.read_text()) if p.exists() else {}


def save_state(st):
    (CAMP / "state.json").write_text(json.dumps(st, indent=1))


def write_status(ideas, st, results_dir):
    lines = ["# Campaign status", "",
             f"Updated {now()}. Rebuilt automatically by `campaign/run.py` after every idea.", "",
             "| # | Idea | Status | Hypotheses | Survivors | Verdict | Minutes |", "|---|---|---|---|---|---|---|"]
    details = []
    for idea in ideas:
        i = idea["id"]
        s = st.get(i, {}).get("status", "queued")
        r = {}
        rp = results_dir / f"{i}.json"
        if rp.exists():
            r = json.loads(rp.read_text())
        hyp = f"{r['hypotheses']:,}" if isinstance(r.get("hypotheses"), int) else "-"
        surv = r.get("survivors", "-")
        lines.append(f"| {i} | {idea['title']} | {s} | {hyp} | {surv} | {r.get('verdict', '')} | "
                     f"{r.get('minutes', st.get(i, {}).get('minutes', ''))} |")
        details += [f"### {i}. {idea['title']}", "", f"- **Why:** {idea['why']}",
                    f"- **Script:** `{idea['script']}`  ·  log: `campaign/logs/{i}.log`",
                    f"- **Status:** {s}" + (f" ({st[i].get('note')})" if st.get(i, {}).get("note") else "")]
        if r:
            details.append(f"- **Verdict:** {r.get('verdict')}")
            for k in ("control", "best_quadgram", "null_best", "p_stehle", "p_doublets", "quagmire_part"):
                if k in r and r[k] is not None:
                    details.append(f"- {k}: `{json.dumps(r[k], default=str)[:300]}`")
            for t in (r.get("top") or [])[:3]:
                details.append(f"  - top: `{json.dumps(t)[:200]}`")
        details.append("")
    lines += ["", "Verdict key: **dead** = ruled out within the stated scope (each engine has a planted-answer test); "
              "**WORTH A LOOK** = beats shuffled-K4 controls, needs a human look.", "", "## Details", ""] + details
    (CAMP / ("STATUS.md" if results_dir == CAMP / "results" else "STATUS.smoke.md")).write_text("\n".join(lines) + "\n")


def main():
    ideas = json.loads((CAMP / "ideas.json").read_text())
    smoke = "--smoke" in sys.argv
    env = dict(os.environ)
    if smoke:
        sdir = Path(tempfile.mkdtemp(prefix="kryptos_smoke_"))
        env["KRYPTOS_SMOKE"] = str(sdir)
        results_dir, st = sdir / "results", {}
    else:
        results_dir, st = CAMP / "results", load_state()
    if "--status" in sys.argv:
        write_status(ideas, st, results_dir)
        return
    (CAMP / "logs").mkdir(exist_ok=True)
    for idea in ideas:
        i = idea["id"]
        if not smoke and st.get(i, {}).get("status") == "done":
            continue
        st[i] = {"status": "running", "started": now()}
        if not smoke:
            save_state(st)
        write_status(ideas, st, results_dir)
        t0 = time.time()
        log = (Path(env["KRYPTOS_SMOKE"]) if smoke else CAMP / "logs") / f"{i}.log"
        limit = 60 * max(20, 4 * idea["est_min"]) if not smoke else 600
        with open(log, "w") as lf:
            try:
                rc = subprocess.run([sys.executable, str(ROOT / idea["script"])], cwd=ROOT, env=env,
                                    stdout=lf, stderr=subprocess.STDOUT, timeout=limit).returncode
                status = "done" if rc == 0 and (results_dir / f"{i}.json").exists() else f"failed (exit {rc})"
            except subprocess.TimeoutExpired:
                status = f"timed out after {limit // 60} min"
        st[i] = {"status": status, "started": st[i]["started"], "finished": now(),
                 "minutes": round((time.time() - t0) / 60, 1)}
        if not smoke:
            save_state(st)
        write_status(ideas, st, results_dir)
        print(f"{now()}  idea {i}: {status}", flush=True)
        if not smoke:
            try:
                from kryptos import negatives
                negatives.build()
            except Exception as e:
                print("negatives rebuild failed:", e)
    print("campaign finished", now())


if __name__ == "__main__":
    main()
