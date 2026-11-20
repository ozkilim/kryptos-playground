#!/usr/bin/env python3
"""Swarm coordinator: many headless agent sessions working the K4 idea queue in parallel.

  python swarm/swarm.py init                  create .swarm/ and load swarm/seed_ideas.json
  python swarm/swarm.py up --workers 8        start workers + idea generator + merger, detached
  python swarm/swarm.py status                queue, workers, results
  python swarm/swarm.py down [--now]          stop after the current idea (or kill now)

  python swarm/swarm.py propose --title ... --why ... --plan ...     add an idea by hand
  python swarm/swarm.py worker w1 | ideator | merge [--loop]         run one role in the foreground
  python swarm/swarm.py slot -- python attacks/NN_x.py               run a heavy job in a CPU slot

How it fits together is described in swarm/README.md. Plain Python 3.9, standard library only.
State lives in .swarm/ of the main checkout (not committed); results are committed to git.
"""
import argparse
import contextlib
import fcntl
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                                   # this checkout (may be a worker's worktree)
GIT_ID = ["-c", "user.name=Oz Kilim", "-c", "user.email=ozkilim@hotmail.co.uk"]
VERDICTS = ("dead", "dead-in-scope", "no-signal", "signal", "duplicate", "untestable")
CARD_KEYS = ("id", "title", "verdict", "k4_result", "controls", "planted", "tested", "scope_limits", "negative")
NEG_KEYS = ("family", "hypothesis", "scope", "outcome", "confidence")


def env_int(name, default):
    return int(os.environ.get(name, default))


def git(*args, cwd=None, check=True):
    r = subprocess.run(["git"] + list(args), cwd=str(cwd or ROOT), capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError("git %s failed: %s" % (" ".join(args), r.stderr.strip() or r.stdout.strip()))
    return r


def main_root():
    """The main checkout (worktrees share its .git)."""
    common = git("rev-parse", "--git-common-dir").stdout.strip()
    p = Path(common)
    if not p.is_absolute():
        p = (ROOT / p).resolve()
    return p.parent


def home():
    h = os.environ.get("KRYPTOS_SWARM_HOME")
    return Path(h) if h else main_root() / ".swarm"


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    print("[%s] %s" % (now(), msg), flush=True)


# ------------------------------------------------------------------ usage limits and login failures

LIMIT_RE = re.compile(r"hit your [\w-]+ limit|reached your [\w-]+ limit|usage limit (?:was |has been )?reached", re.I)
AUTH_RE = re.compile(r"Failed to authenticate|OAuth access token is invalid|Please run /login|Invalid API key", re.I)
RESET_RE = re.compile(r"resets\s+(?:at\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s*(?:\(([\w/+-]+)\))?", re.I)


def limit_wait(text, at=None):
    """Did this session end on a usage limit or a login failure? Returns (kind, seconds to wait) or (None, 0).
    A limit that names its reset time ("resets 7pm (Europe/Budapest)") waits until 3 minutes after it; otherwise 30 min."""
    tail = text[-4000:]
    if AUTH_RE.search(tail):
        return "login", 1800
    if not LIMIT_RE.search(tail):
        return None, 0
    m = RESET_RE.search(tail)
    if not m:
        return "limit", 1800
    hour, minute, ampm, zone = int(m.group(1)), int(m.group(2) or 0), (m.group(3) or "").lower(), m.group(4)
    if ampm == "pm" and hour < 12:
        hour += 12
    if ampm == "am" and hour == 12:
        hour = 0
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(zone) if zone else timezone.utc
    except Exception:
        return "limit", 1800
    cur = (at or datetime.now(timezone.utc)).astimezone(tz)
    reset = cur.replace(hour=hour % 24, minute=minute, second=0, microsecond=0)
    if reset <= cur:
        reset = reset.fromtimestamp(reset.timestamp() + 86400, tz)
    return "limit", int((reset - cur).total_seconds()) + 180


def paused_for():
    """Seconds left before any role may start a new agent session (shared by all roles)."""
    f = home() / "limit_until"
    try:
        return max(0, int(float(f.read_text().split()[0]) - time.time()))
    except (OSError, ValueError, IndexError):
        return 0


def pause(kind, secs):
    """Hold every role until the limit resets (keeps the later time if one is already set)."""
    until = max(time.time() + secs, time.time() + paused_for())
    with locked():
        (home() / "limit_until").write_text("%d %s\n" % (until, kind))
    log("usage %s: no new sessions until %s" % (kind, datetime.fromtimestamp(until, timezone.utc).strftime("%Y-%m-%dT%H:%MZ")))
    if kind == "login":
        alert("agent login failed: log in again (claude auth login), the swarm retries every 30 min")


def wait_if_paused():
    """Sleep in short steps while a usage pause is on. Returns True if it slept."""
    left = paused_for()
    if not left:
        return False
    time.sleep(min(left, 300))
    return True


@contextlib.contextmanager
def locked():
    """One process at a time may change the queue."""
    h = home()
    h.mkdir(parents=True, exist_ok=True)
    with open(h / "lock", "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


# ------------------------------------------------------------------ the queue

def idea_path(i):
    return home() / "ideas" / ("%04d.json" % int(i))


def load_ideas():
    d = home() / "ideas"
    return [json.load(open(p)) for p in sorted(d.glob("*.json"))] if d.exists() else []


def save(idea):
    p = idea_path(idea["id"])
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(idea, indent=1))
    os.replace(tmp, p)


def norm(title):
    return re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()


def next_id(ideas, root=None):
    root = root or main_root()
    used = [int(x["id"]) for x in ideas]
    for p in (root / "attacks").glob("[0-9]*_*.py"):
        used.append(int(p.name.split("_")[0]))
    try:
        for x in json.load(open(root / "campaign" / "ideas.json")):
            m = re.match(r"\d+", str(x["id"]))
            if m:
                used.append(int(m.group()))
    except (OSError, ValueError):
        pass
    return max(used, default=0) + 1


def propose(title, why, plan, clue="", by="human", root=None):
    """Add an idea. Returns (id, None), or (None, reason) if it repeats a queued idea."""
    with locked():
        ideas = load_ideas()
        for x in ideas:
            if norm(x["title"]) == norm(title):
                return None, "same title as idea %s" % x["id"]
        i = next_id(ideas, root)
        save({"id": i, "title": title.strip(), "why": why.strip(), "plan": plan.strip(), "clue": clue.strip(),
              "status": "open", "proposed_by": by, "proposed_at": now(), "attempts": 0})
        return i, None


def claim(worker):
    """Give the lowest-numbered open idea to this worker (atomic)."""
    with locked():
        for x in load_ideas():
            if x["status"] == "open":
                x.update(status="claimed", worker=worker, claimed_at=now(), attempts=x.get("attempts", 0) + 1)
                save(x)
                return x
    return None


def update(i, **fields):
    with locked():
        x = json.load(open(idea_path(i)))
        x.update(fields)
        save(x)
        return x


def alert(msg):
    with open(home() / "ALERT", "a") as f:
        f.write("[%s] %s\n" % (now(), msg))
    log("ALERT: " + msg)


def stopping():
    return (home() / "STOP").exists()


# ------------------------------------------------------------------ CPU slots

def run_in_slot(cmd):
    """Run cmd while holding one of SWARM_SLOTS locks, so heavy searches do not pile up on the cores."""
    d = home() / "slots"
    d.mkdir(parents=True, exist_ok=True)
    n = env_int("SWARM_SLOTS", 1)
    while True:
        for k in range(n):
            f = open(d / ("%d.lock" % k), "w")
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                f.close()
                continue
            try:
                return subprocess.call(cmd)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
                f.close()
        time.sleep(5)


# ------------------------------------------------------------------ agents and worktrees

def agent_cmd():
    return shlex.split(os.environ.get(
        "SWARM_AGENT", "claude -p --permission-mode acceptEdits --allowedTools Bash Read Edit Write Grep Glob"))


def run_agent(prompt, cwd, logfile, extra_env, timeout):
    """Run one headless agent session. Returns (exit code or 'timeout', seconds, the session's output)."""
    env = dict(os.environ, KRYPTOS_SWARM_HOME=str(home()), **extra_env)
    t = time.time()
    with open(logfile, "a") as out:
        out.write("\n===== %s =====\n" % now())
        start = out.tell()
        out.flush()
        p = subprocess.Popen(agent_cmd(), cwd=str(cwd), stdin=subprocess.PIPE, stdout=out, stderr=subprocess.STDOUT,
                             env=env, text=True, start_new_session=True)
        try:
            p.communicate(prompt, timeout=timeout)
            code = p.returncode
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            code = "timeout"
    with open(logfile, errors="replace") as f:
        f.seek(start)
        text = f.read()
    return code, time.time() - t, text


def worktree(name):
    """A private checkout for one role, on branch swarm/<name>, brought up to date with main."""
    root = main_root()
    wt = home() / "wt" / name
    if not wt.exists():
        wt.parent.mkdir(parents=True, exist_ok=True)
        git("worktree", "add", "-B", "swarm/" + name, str(wt), "main", cwd=root)
    git("reset", "--hard", "-q", cwd=wt)
    git("clean", "-fdq", cwd=wt)
    r = git(*GIT_ID, "merge", "--no-edit", "-q", "main", cwd=wt, check=False)
    if r.returncode:
        git("merge", "--abort", cwd=wt, check=False)
        raise RuntimeError("worktree %s cannot merge main: %s" % (name, r.stdout + r.stderr))
    return wt


def fill(template, **fields):
    text = (HERE / template).read_text()
    for k, v in fields.items():
        text = text.replace("{{%s}}" % k, str(v))
    return text


def allowed_paths(i):
    return ["attacks/%d_*.py" % i, "tests/test_idea_%d.py" % i, "campaign/swarm/%d.json" % i,
            "campaign/swarm/%d.md" % i, "kryptos/idea%d_*.py" % i, "experiments/ledger.csv"]


def read_card(wt, i):
    """(card, None) if the worker left a valid result card, else (None, why not)."""
    p = wt / "campaign" / "swarm" / ("%d.json" % i)
    if not p.exists():
        return None, "no result card campaign/swarm/%d.json" % i
    try:
        card = json.load(open(p))
    except ValueError as e:
        return None, "result card is not valid JSON: %s" % e
    missing = [k for k in CARD_KEYS if k not in card]
    if missing:
        return None, "result card lacks %s" % ", ".join(missing)
    if card["verdict"] not in VERDICTS:
        return None, "verdict %r is not one of %s" % (card["verdict"], ", ".join(VERDICTS))
    if int(card["id"]) != i:
        return None, "result card is for idea %s" % card["id"]
    if card["verdict"] not in ("duplicate", "untestable"):
        if not list((wt / "attacks").glob("%d_*.py" % i)):
            return None, "no attack script attacks/%d_*.py" % i
        if [k for k in NEG_KEYS if not (card.get("negative") or {}).get(k)]:
            return None, "result card's negative entry is incomplete"
    return card, None


def commit_idea(wt, i, card):
    """Commit only the files this idea may touch; everything else is thrown away."""
    files = sorted(str(f.relative_to(wt)) for pat in allowed_paths(i) for f in wt.glob(pat))
    git("add", "--", *files, cwd=wt)
    git(*GIT_ID, "commit", "-q", "-m", "Idea %d: %s (%s)" % (i, card["title"], card["verdict"]), cwd=wt)
    sha = git("rev-parse", "HEAD", cwd=wt).stdout.strip()
    git("reset", "--hard", "-q", cwd=wt)
    git("clean", "-fdq", cwd=wt)
    return sha


def worker(name, max_ideas=0):
    h = home()
    (h / "logs").mkdir(parents=True, exist_ok=True)
    base = env_int("SWARM_BACKOFF", 300)
    done, backoff = 0, base
    log("worker %s starting" % name)
    while not stopping() and not (max_ideas and done >= max_ideas):
        try:
            wt = worktree(name)
        except RuntimeError as e:
            alert("worker %s stopped: %s" % (name, e))
            return
        if wait_if_paused():
            continue
        idea = claim(name)
        if not idea:
            time.sleep(env_int("SWARM_IDLE_SLEEP", 120))
            continue
        i = idea["id"]
        log("worker %s takes idea %d: %s" % (name, i, idea["title"]))
        prompt = fill("WORKER_PROMPT.md", ID=i, TITLE=idea["title"], WHY=idea["why"], PLAN=idea["plan"],
                      CLUE=idea.get("clue", ""), WORKER=name, HOURS=env_int("SWARM_IDEA_HOURS", 4))
        code, secs, text = run_agent(prompt, wt, h / "logs" / ("%s.log" % name), {"SWARM_WORKER": name, "SWARM_IDEA": str(i)},
                                     env_int("SWARM_IDEA_HOURS", 4) * 3600)
        card, why = read_card(wt, i)
        if card:
            try:
                sha = commit_idea(wt, i, card)
            except RuntimeError as e:
                card, why = None, "could not commit: %s" % str(e)[:200]
        if card:
            update(i, status="done", done_at=now(), verdict=card["verdict"], commit=sha, minutes=round(secs / 60))
            for s in card.get("follow_ups") or []:
                with open(h / "suggestions.jsonl", "a") as f:
                    f.write(json.dumps({"from_idea": i, "suggestion": s}) + "\n")
            if card["verdict"] == "signal":
                alert("idea %d reports a SIGNAL (%s). Look at campaign/swarm/%d.md on branch swarm/%s" % (i, card["title"], i, name))
            log("worker %s finished idea %d: %s" % (name, i, card["verdict"]))
            done += 1
            backoff = base
            continue
        kind, wait = limit_wait(text)
        if kind:                             # not the idea's fault: put it back as it was and hold every role
            update(i, status="open", attempts=idea["attempts"] - 1, last_error="stopped by usage %s after %d s" % (kind, secs))
            log("worker %s: idea %d stopped by usage %s; re-queued without using an attempt" % (name, i, kind))
            git("reset", "--hard", "-q", cwd=wt, check=False)
            git("clean", "-fdq", cwd=wt, check=False)
            pause(kind, wait)
            continue
        retry = idea["attempts"] < env_int("SWARM_MAX_ATTEMPTS", 2)
        update(i, status="open" if retry else "failed", last_error="%s (agent exit %s after %d s)" % (why, code, secs))
        log("worker %s: idea %d not completed: %s%s" % (name, i, why, "; re-queued" if retry else "; marked failed"))
        if secs < 120:                       # the agent died at once: a login or rate-limit problem, so wait
            log("worker %s: agent exited after %d s, sleeping %d s" % (name, secs, backoff))
            time.sleep(backoff)
            backoff = min(backoff * 2, 3600)
    log("worker %s stopping" % name)


def ideator():
    h = home()
    (h / "logs").mkdir(parents=True, exist_ok=True)
    log("ideator starting")
    while not stopping():
        if wait_if_paused():
            continue
        n_open = sum(1 for x in load_ideas() if x["status"] == "open")
        if n_open >= env_int("SWARM_LOW_WATER", 6):
            time.sleep(env_int("SWARM_IDLE_SLEEP", 120))
            continue
        try:
            wt = worktree("ideator")
        except RuntimeError as e:
            alert("ideator stopped: %s" % e)
            return
        want = env_int("SWARM_BATCH", 10)
        queue = "\n".join("- %s [%s] %s" % (x["id"], x["status"], x["title"]) for x in load_ideas()) or "(empty)"
        sug = h / "suggestions.jsonl"
        prompt = fill("IDEATOR_PROMPT.md", N=want, QUEUE=queue, SUGGESTIONS=sug.read_text() if sug.exists() else "(none)")
        before = len(load_ideas())
        code, secs, text = run_agent(prompt, wt, h / "logs" / "ideator.log", {"SWARM_WORKER": "ideator"}, 2 * 3600)
        added = len(load_ideas()) - before
        log("ideator added %d ideas (agent exit %s, %d s)" % (added, code, secs))
        kind, wait = limit_wait(text)
        if kind:
            pause(kind, wait)
            continue
        if added == 0:
            time.sleep(1800 if secs > 120 else 3600)
    log("ideator stopping")


# ------------------------------------------------------------------ merging results into main

def write_board(root):
    cards = []
    for p in sorted((root / "campaign" / "swarm").glob("*.json"), key=lambda p: int(p.stem)):
        try:
            cards.append(json.load(open(p)))
        except ValueError:
            pass
    lines = ["# Swarm results", "",
             "One line per idea the swarm has finished and merged. Details in `campaign/swarm/<id>.md`.", "",
             "| # | Idea | Verdict | K4 | Controls | Planted |", "|---|---|---|---|---|---|"]
    for c in cards:
        cell = lambda s: str(s).replace("|", "/").replace("\n", " ")  # noqa: E731
        lines.append("| %s | %s | %s | %s | %s | %s |" % (c["id"], cell(c["title"]), c["verdict"], cell(c["k4_result"]),
                                                       cell(c["controls"]), cell(c["planted"])))
    (root / "campaign" / "SWARM.md").write_text("\n".join(lines) + "\n")


def merge_one(root, idea, full_tests=False):
    i = idea["id"]
    head = git("rev-parse", "HEAD", cwd=root).stdout.strip()
    r = git(*GIT_ID, "merge", "--no-ff", "--no-edit", "-q", "-m", "Swarm: merge idea %d" % i, idea["commit"], cwd=root, check=False)
    if r.returncode:
        git("merge", "--abort", cwd=root, check=False)
        update(i, status="conflict", last_error=(r.stdout + r.stderr).strip()[:400])
        alert("idea %d does not merge cleanly into main; left on its branch (commit %s)" % (i, idea["commit"][:8]))
        return False
    card = json.load(open(root / "campaign" / "swarm" / ("%d.json" % i)))
    test = root / "tests" / ("test_idea_%d.py" % i)
    has_pytest = subprocess.run([sys.executable, "-m", "pytest", "--version"], capture_output=True).returncode == 0
    cmds = [[sys.executable, "-m", "pytest", "-q", str(test)] if has_pytest else [sys.executable, str(test)]] if test.exists() else []
    if full_tests:
        cmds.append(["make", "test"])
    for c in cmds:
        t = subprocess.run(c, cwd=str(root), capture_output=True, text=True)
        if t.returncode:
            git("reset", "--hard", "-q", head, cwd=root)
            update(i, status="test-failed", last_error=(t.stdout + t.stderr)[-400:])
            alert("idea %d: tests fail after merging (%s); main left unchanged" % (i, " ".join(c[-2:])))
            return False
    if card["verdict"] not in ("duplicate", "untestable"):
        n = card["negative"]
        subprocess.run([sys.executable, "-m", "kryptos", "negatives", "add", "--family", n["family"], "--hypothesis", n["hypothesis"],
                        "--scope", n["scope"], "--outcome", n["outcome"], "--confidence", n["confidence"],
                        "--who", "this repo (swarm, idea %d)" % i, "--when", now()[:10], "--source", "campaign/swarm/%d.md" % i],
                       cwd=str(root), capture_output=True, text=True, check=True)
    ip = root / "campaign" / "ideas.json"
    ideas = json.load(open(ip))
    if str(i) not in [str(x["id"]) for x in ideas]:
        scripts = sorted((root / "attacks").glob("%d_*.py" % i))
        ideas.append({"id": str(i), "title": card["title"], "script": "attacks/" + scripts[0].name if scripts else "",
                      "est_min": idea.get("minutes", 0), "why": idea.get("why", "")})
        ip.write_text(json.dumps(ideas, indent=1, ensure_ascii=False))
    subprocess.run([sys.executable, "-m", "kryptos", "negatives", "build"], cwd=str(root), capture_output=True)
    write_board(root)
    git("add", "-A", cwd=root)
    git(*GIT_ID, "commit", "-q", "-m", "Swarm idea %d: %s (%s)" % (i, card["title"], card["verdict"]), cwd=root, check=False)
    update(i, status="merged", merged_at=now())
    log("merged idea %d (%s)" % (i, card["verdict"]))
    return True


def merge(loop=False, full_every=10):
    root = main_root()
    count = 0
    while True:
        dirty = git("status", "--porcelain", cwd=root).stdout.strip()
        branch = git("branch", "--show-current", cwd=root).stdout.strip()
        if dirty or branch != "main":
            log("merge: main checkout is %s; not merging" % ("not clean" if dirty else "on branch " + branch))
        else:
            for idea in load_ideas():
                if idea["status"] == "done":
                    count += 1
                    merge_one(root, idea, full_tests=bool(full_every) and count % full_every == 0)
        if not loop or stopping():
            return
        time.sleep(env_int("SWARM_MERGE_SLEEP", 300))


# ------------------------------------------------------------------ commands

def cmd_init(a):
    h = home()
    for d in ("ideas", "logs", "slots", "wt"):
        (h / d).mkdir(parents=True, exist_ok=True)
    if not load_ideas():
        for s in json.load(open(HERE / "seed_ideas.json")):
            i, why = propose(s["title"], s["why"], s["plan"], s.get("clue", ""), by="seed")
            print("seeded idea %s: %s" % (i, s["title"]) if i else "skipped: %s" % why)
    print("swarm home:", h)


def cmd_propose(a):
    i, why = propose(a.title, a.why, a.plan, a.clue or "", by=os.environ.get("SWARM_WORKER", "human"))
    print("added idea %d" % i if i else "not added: %s" % why)
    return 0 if i else 1


def cmd_status(a):
    ideas = load_ideas()
    counts = {}
    for x in ideas:
        counts[x["status"]] = counts.get(x["status"], 0) + 1
    print("swarm home: %s%s" % (home(), "   (STOP requested)" if stopping() else ""))
    print("ideas: " + (", ".join("%d %s" % (v, k) for k, v in sorted(counts.items())) or "none"))
    left = paused_for()
    if left:
        print("PAUSED for a usage limit: about %d min left (.swarm/limit_until)" % (left // 60 + 1))
    for x in ideas:
        extra = x.get("worker", "")
        if x["status"] in ("done", "merged"):
            extra += "  %s  %s min" % (x.get("verdict", ""), x.get("minutes", "?"))
        if x.get("last_error") and x["status"] not in ("done", "merged"):
            extra += "  !! " + x["last_error"][:90]
        print("  %4d  %-11s %-62s %s" % (x["id"], x["status"], x["title"][:62], extra))
    al = home() / "ALERT"
    if al.exists():
        print("\nALERTS:\n" + al.read_text())


def spawn(role_args, logname):
    h = home()
    out = open(h / "logs" / (logname + ".out"), "a")
    p = subprocess.Popen([sys.executable, str(HERE / "swarm.py")] + role_args, cwd=str(main_root()), stdout=out,
                         stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    with open(h / "pids", "a") as f:
        f.write("%d %s\n" % (p.pid, logname))
    print("started %s (pid %d)" % (logname, p.pid))


def cmd_up(a):
    cmd_init(a)
    h = home()
    for f in ("STOP", "pids"):
        if (h / f).exists():
            (h / f).unlink()
    os.environ["SWARM_SLOTS"] = str(a.slots)
    for k in range(1, a.workers + 1):
        spawn(["worker", "w%d" % k], "w%d" % k)
    if not a.no_ideator:
        spawn(["ideator"], "ideator")
    spawn(["merge", "--loop"], "merge")
    print("logs in %s/logs; stop with: python swarm/swarm.py down" % h)


def cmd_down(a):
    h = home()
    (h / "STOP").write_text(now() + "\n")
    print("STOP written: each role finishes what it is doing, then exits.")
    if a.now and (h / "pids").exists():
        for line in (h / "pids").read_text().split("\n"):
            if line.strip():
                try:
                    os.killpg(int(line.split()[0]), signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
        print("all swarm processes signalled; ideas left 'claimed' can be re-opened with: swarm.py reopen")


def cmd_reopen(a):
    for x in load_ideas():
        if x["status"] in (("claimed", "failed", "conflict", "test-failed") if a.all else ("claimed",)):
            update(x["id"], status="open")
            print("re-opened idea %d" % x["id"])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("status")
    p = sub.add_parser("propose")
    for f in ("title", "why", "plan"):
        p.add_argument("--" + f, required=True)
    p.add_argument("--clue")
    w = sub.add_parser("worker")
    w.add_argument("name")
    w.add_argument("--max-ideas", type=int, default=0)
    sub.add_parser("ideator")
    m = sub.add_parser("merge")
    m.add_argument("--loop", action="store_true")
    m.add_argument("--full-tests-every", type=int, default=10)
    u = sub.add_parser("up")
    u.add_argument("--workers", type=int, default=4)
    u.add_argument("--slots", type=int, default=1, help="heavy searches allowed at once")
    u.add_argument("--no-ideator", action="store_true")
    d = sub.add_parser("down")
    d.add_argument("--now", action="store_true")
    r = sub.add_parser("reopen")
    r.add_argument("--all", action="store_true")
    s = sub.add_parser("slot")
    s.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    if a.cmd == "slot":
        cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
        return run_in_slot(cmd)
    if a.cmd == "worker":
        return worker(a.name, a.max_ideas)
    if a.cmd == "ideator":
        return ideator()
    if a.cmd == "merge":
        return merge(a.loop, a.full_tests_every)
    return {"init": cmd_init, "status": cmd_status, "propose": cmd_propose, "up": cmd_up, "down": cmd_down,
            "reopen": cmd_reopen}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main() or 0)
