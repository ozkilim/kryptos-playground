"""Idea 29: a local language model (Qwen2.5-7B via Ollama) as judge and as generator.

Judge: where our quadgram scorer is blind (two stacked keys at long length
pairs, where ~20+ free key letters let any text look English-ish), ask the LLM
how much of each candidate is real English. Compare three groups through the
identical pipeline: K4's completions, shuffled-K4 completions (chance) and
planted real two-key messages (power). If the LLM separates planted from
chance better than quadgrams, its verdict on K4 is the first real test of
that region.

Generator: ask the LLM to write candidate K4 plaintexts in the sculpture's
themes with EAST NORTHEAST and BERLIN CLOCK, keep those landing in the exact
positions, and check whether any implied key looks like two stacked keys.
(An LLM won't guess the true 73 unknown letters exactly, so this is mostly
to see what it imagines.)
"""
import json
import random
import subprocess
import sys
import time
import urllib.request
from multiprocessing import Pool, cpu_count
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kryptos import CRIBS, K4, letters, load  # noqa: E402
from kryptos.campaign import CAMPAIGN, SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.score import quadgram_score, word_coverage  # noqa: E402
from kryptos.solvers import twokeys as T  # noqa: E402

API = "http://127.0.0.1:11434"
MODEL = "qwen2.5:7b"
ALPHAS = {"AZ": AZ, "KRYPTOS": KRYPTOS_ALPHABET}


def api(path, payload=None, timeout=180):
    req = urllib.request.Request(API + path, data=json.dumps(payload).encode() if payload else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def ensure_server():
    try:
        api("/api/tags", timeout=3)
        return None
    except Exception:
        proc = subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            time.sleep(1)
            try:
                api("/api/tags", timeout=3)
                return proc
            except Exception:
                pass
        raise RuntimeError("ollama server did not start")


def judge(text):
    prompt = ("Below is a 97-letter string with spaces and punctuation removed. It may be English or it may be "
              "random letters. First split it into words where you can. Then rate from 0 to 10 how much of it is "
              "genuine, meaningful English prose (0 = random letters, 10 = fully fluent English). Be strict: "
              "isolated short words in noise are not meaningful English.\n\n"
              f"{text}\n\nAnswer only with JSON: {{\"segmented\": \"...\", \"score\": <0-10>}}")
    try:
        r = api("/api/generate", {"model": MODEL, "prompt": prompt, "format": "json", "stream": False,
                                  "options": {"temperature": 0, "num_predict": 300}})
        return float(json.loads(r["response"]).get("score", 0))
    except Exception:
        return None


def _complete(job):
    tag, ct, cribs, an, v, L1, L2, seed, truth = job
    comps = T.solve_exact(T.equations(ct, cribs, ALPHAS[an], v, L1, L2))
    if comps is None:
        return None
    q, pt, _ = T.KeyCompleter(ct, ALPHAS[an], v, L1, L2, comps).anneal(
        random.Random(seed), iters=4000 if SMOKE else 60000, restarts=1 if SMOKE else 4)
    acc = sum(a == b for a, b in zip(pt, truth)) if truth else None
    return tag, an, v, L1, L2, q, pt, acc


def auc(pos, neg):
    if not pos or not neg:
        return None
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


def generate(n):
    prompt = ("The fourth passage (K4) of the CIA's Kryptos sculpture is 97 letters long. Earlier passages talk about "
              "light and shadow, the earth's magnetic field, something buried at a secret location, and Howard "
              "Carter opening Tutankhamun's tomb. The artist says the solution involves his 1986 trip to Egypt, the "
              "1989 fall of the Berlin Wall, delivering a message, and the World Clock in Berlin. Write ONE possible "
              "K4 plaintext: a short message in plain English, all capitals, that contains the exact phrases "
              "'EAST NORTHEAST' and 'BERLIN CLOCK', with about 21 letters before EAST NORTHEAST, about 29 letters "
              "between the two phrases and about 23 letters after BERLIN CLOCK. Answer only with JSON: "
              "{\"plaintext\": \"...\"}")
    out = []
    for k in range(n):
        try:
            r = api("/api/generate", {"model": MODEL, "prompt": prompt, "format": "json", "stream": False,
                                      "options": {"temperature": 1.0, "seed": k, "num_predict": 200}})
            out.append(letters(json.loads(r["response"]).get("plaintext", "")))
        except Exception:
            pass
    return out


if __name__ == "__main__":
    t0 = time.time()
    r23 = json.loads((CAMPAIGN / "results" / "23.json").read_text())
    blind = sorted(tuple(map(int, k.split("x"))) for k, v in r23["planted"].items()
                   if v["letters_right"] is not None and v["letters_right"] < 80)
    if SMOKE:
        blind = blind[:2]
    rng = random.Random(29)
    text = load("k3")["plaintext"] + load("k2")["plaintext_corrected"]
    fake = shuffled(K4, 2900)
    jobs = []
    for k, (L1, L2) in enumerate(blind):
        an, v = "KRYPTOS", "vigenere"
        jobs.append(("k4", K4, CRIBS, an, v, L1, L2, k, None))
        jobs.append(("control", fake, CRIBS, an, v, L1, L2, 1000 + k, None))
        s0 = rng.randrange(0, len(text) - 120)
        pt = "".join(ch for ch in text[s0:] if ch.isalpha())[:97]
        pct, _ = T.plant(pt, rng, ALPHAS[an], v, L1, L2)
        jobs.append(("planted", pct, {i: pt[i] for i in CRIBS}, an, v, L1, L2, 2000 + k, pt))
    with Pool(cpu_count()) as pool:
        res = [r for r in pool.map(_complete, jobs) if r]
    proc = ensure_server()
    try:
        scored = []
        for tag, an, v, L1, L2, q, pt, acc in res:
            scored.append({"group": tag, "L1": L1, "L2": L2, "q": round(q, 3), "words": round(word_coverage(pt), 3),
                           "llm": judge(pt), "acc": acc, "plaintext": pt})
        gens = generate(4 if SMOKE else 60)
    finally:
        if proc:
            proc.terminate()
    G = {g: [s for s in scored if s["group"] == g] for g in ("k4", "control", "planted")}

    def col(g, key):
        return [s[key] for s in G[g] if s[key] is not None]
    summary = {key: {"auc_planted_vs_control": auc(col("planted", key), col("control", key)),
                     "auc_k4_vs_control": auc(col("k4", key), col("control", key)),
                     "mean": {g: (round(sum(col(g, key)) / len(col(g, key)), 3) if col(g, key) else None) for g in G}}
               for key in ("q", "words", "llm")}
    fit = [g for g in gens if len(g) == 97 and g[21:34] == "EASTNORTHEAST" and g[63:74] == "BERLINCLOCK"]
    best_detector = max(summary, key=lambda k: summary[k]["auc_planted_vs_control"] or 0)
    k4auc = summary[best_detector]["auc_k4_vs_control"]
    verdict = (f"best detector of real two-key English in this blind region: {best_detector} "
               f"(planted vs chance AUC {summary[best_detector]['auc_planted_vs_control']:.2f}); "
               f"K4 vs chance on it: AUC {k4auc if k4auc is None else round(k4auc, 2)} "
               f"({'K4 looks like chance' if k4auc is not None and k4auc < 0.65 else 'K4 STANDS OUT: check'}). "
               f"LLM generated {len(gens)} plaintexts, {len(fit)} with both clues in K4's exact positions")
    report("29", name="LLM judge + generator", blind_pairs=[list(p) for p in blind], detectors=summary,
           k4_top=sorted(G["k4"], key=lambda s: -(s["llm"] or 0))[:5], generated_samples=gens[:15],
           generated_exact_fit=fit, verdict=verdict, minutes=round((time.time() - t0) / 60, 1))
    print("[29]", verdict)
    print(json.dumps(summary, indent=1))
