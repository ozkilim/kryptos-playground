"""Idea 52: a second look at every candidate plaintext the project has saved.

Every experiment keeps its best ~50 decrypts (results/*.json, campaign/results/*.json).
Each was judged by one English score at the time. This re-judges all of them together
with three independent checks, calibrated on known answers:

  big quadgrams   22.6M-letter English model (data/english/quadgrams_big.txt)
  word coverage   fraction of letters covered by dictionary words of 4+ letters
  LLM judge       local Qwen2.5-7B rates 0-10 how much is meaningful English (if ollama is available)

Calibration: real English 97-letter windows with K4's clue letters dropped in (what a correct
answer looks like) vs random letters with the clue letters dropped in (what noise with forced clues
looks like). Anything inside the real-English range is flagged. Runs last in the queue, so it also
re-checks that night's new results.
"""
import glob
import importlib.util
import json
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, load  # noqa: E402
from kryptos.campaign import SMOKE, report  # noqa: E402
from kryptos.ciphers import AZ  # noqa: E402
from kryptos.data import ROOT  # noqa: E402
from kryptos.harness import Experiment  # noqa: E402
from kryptos.score import Quadgrams, word_coverage  # noqa: E402

N = 97


def candidates():
    out = {}
    for f in sorted(glob.glob(str(ROOT / "results" / "*.json")) + glob.glob(str(ROOT / "campaign" / "results" / "*.json"))):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        for x in d.get("top") or []:
            if isinstance(x, dict):
                pt = x.get("plaintext", "")
                if len(pt) == N and pt.isalpha() and pt not in out:
                    out[pt] = Path(f).name
    return out


def with_cribs(text):
    t = list(text)
    for i, p in CRIBS.items():
        t[i] = p
    return "".join(t)


def references(n, rng):
    eng = "".join(load(f"pk{i}")["plaintext"] for i in (1, 2, 3, 4, 5, 6, 8, 9))
    eng += load("k3")["plaintext"] + load("k2")["plaintext_corrected"]
    pos = [with_cribs(eng[s:s + N]) for s in (rng.randrange(0, len(eng) - N) for _ in range(n))]
    neg = [with_cribs("".join(rng.choice(AZ) for _ in range(N))) for _ in range(n)]
    return pos, neg


def llm_tools():
    try:
        spec = importlib.util.spec_from_file_location("a29", ROOT / "attacks" / "29_llm_judge_and_generator.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        proc = m.ensure_server()
        return m.judge, proc
    except Exception as e:
        print("LLM judge unavailable:", e)
        return None, None


if __name__ == "__main__":
    t0 = time.time()
    rng = random.Random(52)
    big = Quadgrams(ROOT / "data" / "english" / "quadgrams_big.txt")
    cands = candidates()
    pos, neg = references(30 if SMOKE else 200, rng)

    def feats(t):
        return big.score(t), word_coverage(t)

    cf = {t: feats(t) for t in cands}
    pf = [feats(t) for t in pos]
    nf = [feats(t) for t in neg]
    q_lo = sorted(x[0] for x in pf)[len(pf) // 20]   # 5th percentile of real English
    w_lo = sorted(x[1] for x in pf)[len(pf) // 20]
    q_hi_noise = sorted(x[0] for x in nf)[-1]
    # completions with free key slots are optimised against quadgrams (round 6), so ALL checks must agree
    flagged_auto = [t for t, (q, w) in cf.items() if q >= q_lo and w >= w_lo]
    ranked = sorted(cf, key=lambda t: -(cf[t][0] - q_lo) - 2 * (cf[t][1] - w_lo))
    judge, proc = llm_tools()
    llm = {}
    if judge:
        top = ranked[:8 if SMOKE else 80]
        for t in top + pos[:5 if SMOKE else 25] + neg[:5 if SMOKE else 25]:
            llm[t] = judge(t)
        if proc:
            proc.terminate()
    pos_llm = [llm[t] for t in pos if t in llm]
    neg_llm = [llm[t] for t in neg if t in llm]
    llm_bar = sorted(pos_llm)[len(pos_llm) // 2] if pos_llm else None  # median real-English rating
    llm_flag = [t for t in flagged_auto if t in llm and llm_bar is not None and llm[t] >= llm_bar]
    with Experiment("second look at every saved candidate", puzzle="k4", cribs_forced=True,
                    notes=f"{len(cands)} saved K4 candidates re-judged: big quadgrams, word coverage, LLM judge; "
                          "calibrated on real English / random letters with the clue letters forced") as ex:
        for t in ranked[:30]:
            ex.add(t, source=cands[t], big_q=round(cf[t][0], 3), coverage=round(cf[t][1], 3), llm=llm.get(t))
        ex.count(len(cands))
        flags = sorted(llm_flag if judge else flagged_auto)
        if flags:
            verdict = f"WORTH A LOOK: {len(flags)} candidates inside the real-English range: " + "; ".join(
                f"{cands[t]}: {t}" for t in flags[:5])
        else:
            verdict = (f"nothing missed: best of {len(cands)} candidates big-q {cf[ranked[0]][0]:.2f} / coverage "
                       f"{cf[ranked[0]][1]:.2f} vs real English >= {q_lo:.2f} / {w_lo:.2f} (5th pct); noise max q "
                       f"{q_hi_noise:.2f}" + (f"; LLM best {max((llm[t] for t in cands if t in llm), default=None)} vs "
                                              f"real English median {llm_bar}, noise max {neg_llm and max(neg_llm)}" if llm else "")
                       + f"; {len(flagged_auto)} pass both automatic checks (optimised completions), none rated like English")
        ex.notes += f"; {verdict}"
    report("52", name="second look at every saved candidate", candidates=len(cands), auto_pass=len(flagged_auto),
           english_q_5pct=q_lo,
           english_cov_5pct=w_lo, noise_q_max=q_hi_noise, llm_english=pos_llm, llm_noise=neg_llm, flagged=len(flags),
           verdict=verdict,
           top=[{"source": cands[t], "big_q": round(cf[t][0], 3), "coverage": round(cf[t][1], 3), "llm": llm.get(t),
                 "plaintext": t} for t in ranked[:10]], minutes=round((time.time() - t0) / 60, 1))
    print("[52]", verdict)
