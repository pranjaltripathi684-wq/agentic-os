"""
Scheduled jobs: goals that run on their own, e.g. a daily disk-space check.

    agentos schedule add "Check free disk space and warn if under 10 GB" --every daily@09:00
    agentos daemon          # keeps running and starts jobs when they're due

Unattended means nobody can approve anything, so scheduled jobs run with
INTERACTIVE off: every call the policy would "ask" about is DENIED. Only
what the policy allows outright (reading, simple read-only commands) can
happen. Each job also gets its own narrow scope (default read-only).

Schedules: "15m", "2h", "daily@09:00".
"""

import json
import re
import time
import uuid
from datetime import datetime, timedelta

from .. import config
from ..notify import notify
from ..security import killswitch
from ..security.audit import log_event


def _load():
    try:
        return json.loads(config.SCHEDULE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return []


def _save(jobs):
    config.SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    config.SCHEDULE_FILE.write_text(json.dumps(jobs, indent=2))


def parse_every(every: str):
    """Validate a schedule string. Returns ('interval', timedelta) or ('daily', (hour, minute))."""
    m = re.fullmatch(r"(\d+)([mh])", every.strip())
    if m:
        n = int(m.group(1))
        if n <= 0:
            raise ValueError("interval must be positive")
        return "interval", timedelta(minutes=n) if m.group(2) == "m" else timedelta(hours=n)
    m = re.fullmatch(r"daily@(\d{1,2}):(\d{2})", every.strip())
    if m and int(m.group(1)) < 24 and int(m.group(2)) < 60:
        return "daily", (int(m.group(1)), int(m.group(2)))
    raise ValueError("use e.g. 30m, 2h or daily@09:00")


def next_run(job, now: datetime) -> datetime:
    kind, value = parse_every(job["every"])
    last = datetime.fromisoformat(job["last_run"]) if job.get("last_run") else None
    if kind == "interval":
        return now if last is None else last + value
    hour, minute = value
    today = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if last is None:
        return today
    candidate = last.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return candidate + timedelta(days=1) if candidate <= last else candidate


def add(goal: str, every: str, scope: str = "read-only") -> dict:
    parse_every(every)
    job = {"id": uuid.uuid4().hex[:6], "goal": goal, "every": every, "scope": scope, "last_run": None}
    jobs = _load()
    jobs.append(job)
    _save(jobs)
    return job


def remove(job_id: str) -> bool:
    jobs = _load()
    kept = [j for j in jobs if j["id"] != job_id]
    _save(kept)
    return len(kept) < len(jobs)


def list_jobs():
    return _load()


def due(now=None):
    now = now or datetime.now()
    return [j for j in _load() if now >= next_run(j, now)]


def run_due(make_agent, now=None) -> list:
    """Run every due job once. make_agent(scope) -> Agent. Returns [(job, RunResult)]."""
    now = now or datetime.now()
    results = []
    previous = config.INTERACTIVE
    config.INTERACTIVE = False                       # nobody is watching: "ask" means "deny"
    try:
        for job in due(now):
            log_event("schedule_run", job=job["id"], goal=job["goal"])
            result = make_agent(job["scope"]).run(job["goal"])
            jobs = _load()
            for j in jobs:
                if j["id"] == job["id"]:
                    j["last_run"] = now.isoformat(timespec="seconds")
                    j["last_answer"] = result.answer[:300]
            _save(jobs)
            notify(f"Agentic OS job {job['id']}", result.answer)
            results.append((job, result))
    finally:
        config.INTERACTIVE = previous
    return results


def daemon(make_agent, poll_seconds=30, say=print):
    """Run due jobs forever (until Ctrl+C or `agentos stop`)."""
    killswitch.register()
    say(f"Scheduler running with {len(_load())} job(s). Stop with Ctrl+C or `agentos stop`.")
    try:
        while not killswitch.stop_requested():
            for job, result in run_due(make_agent):
                say(f"[{datetime.now():%H:%M}] job {job['id']}: {result.answer[:200]}")
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        killswitch.unregister()
