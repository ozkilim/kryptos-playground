"""Campaign plumbing: many ideas run unattended, results kept organised.

  campaign/ideas.json        the queue: id, title, why, script, estimate
  campaign/results/<id>.json what each idea found (written by report())
  campaign/STATUS.md         live table, rebuilt after every idea
  campaign/logs/<id>.log     full output of each run

  python campaign/run.py           run everything not yet done (resumable)
"""

import json
import random
import time
from datetime import datetime, timezone

from .data import ROOT

import os

CAMPAIGN = ROOT / "campaign"
RESULTS = CAMPAIGN / "results"
SMOKE = os.environ.get("KRYPTOS_SMOKE")
if SMOKE:  # tiny slices, results to a scratch folder
    from pathlib import Path
    RESULTS = Path(SMOKE) / "results"


def smoke(seq, n=2):
    """In smoke-test mode keep only the first n items of a job list."""
    return list(seq)[:n] if SMOKE else seq


def report(idea, **data):
    RESULTS.mkdir(parents=True, exist_ok=True)
    data["idea"] = idea
    data["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (RESULTS / f"{idea}.json").write_text(json.dumps(data, indent=1, default=str))


def shuffled(ct, seed):
    letters = list(ct)
    random.Random(seed).shuffle(letters)
    return "".join(letters)


def run_stack_idea(idea, name, jobs, kinds, notes, control_jobs=None, places=("before", "after"),
                   n_controls=1, alphabets=None, **model_kw):
    """Run a stack-engine search on K4 plus shuffled-K4 controls, log to the
    ledger (and so to negatives), and write the campaign result."""
    from . import K4, CRIBS
    from .harness import Experiment
    from .score import quadgram_score
    from .solvers import stack as S

    t0 = time.time()
    jobs, control_jobs = smoke(jobs), smoke(control_jobs or jobs, 1)
    with Experiment(name, puzzle="k4", notes=notes) as ex:
        tested, hits = S.scan(K4, CRIBS, jobs, kinds, places=places, alphabets=alphabets, **model_kw)
        ex.count(tested)
        scored = []
        for h in hits:
            pt = S.decrypt_hit(K4, CRIBS, h, alphabets)
            if pt:
                ex.add(pt, label=str(h[0]), alphabet=h[1], variant=h[2], model=str(h[3]),
                       place=h[4], tests=h[5])
                scored.append((quadgram_score(pt), pt, h))
        scored.sort(key=lambda x: -x[0])
        ctrl = []
        for seed in range(n_controls):
            ct_tested, ct_hits = S.scan(shuffled(K4, seed), CRIBS, control_jobs or jobs, kinds,
                                        places=places, alphabets=alphabets, **model_kw)
            ctrl.append((ct_tested, len(ct_hits)))
        k4_rate = len(hits) / max(tested, 1)
        c_rate = sum(h for _, h in ctrl) / max(sum(t for t, _ in ctrl), 1)
        best_q = scored[0][0] if scored else None
        if not hits:
            verdict = "dead: 0 survivors"
        elif best_q is not None and best_q > -5.3:
            verdict = "WORTH A LOOK: a survivor reads like English"
        elif k4_rate > 3 * c_rate + 1e-12 and len(hits) >= 5:
            verdict = "WORTH A LOOK: more survivors than shuffled controls"
        else:
            verdict = "dead: survivors at chance level, none read as English"
        ex.notes += f"; {len(hits)} survivors (control rate {c_rate:.2e}/hyp); {verdict}"
    report(idea, name=name, hypotheses=tested, survivors=len(hits),
           control=[{"hypotheses": t, "survivors": h} for t, h in ctrl],
           k4_rate=k4_rate, control_rate=c_rate, best_quadgram=best_q,
           top=[{"q": round(q, 2), "plaintext": pt, "hit": str(h)} for q, pt, h in scored[:5]],
           verdict=verdict, minutes=round((time.time() - t0) / 60, 1), notes=notes)
    print(f"[{idea}] {name}: {tested:,} hypotheses, {len(hits)} survivors "
          f"(controls {[h for _, h in ctrl]}), best q={best_q} -> {verdict}")
