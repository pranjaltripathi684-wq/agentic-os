"""
Shared test setup. Every test gets its own temp workspace and its own
~/.agentos state (audit log, memory, keys, pins), so tests never touch your
real files. The no-isolation sandbox backend is used unless a test picks one.
"""

from types import SimpleNamespace as NS

import pytest

from agentos import config
from agentos.memory import store
from agentos.security import sandbox


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    state = tmp_path / "state"
    for name, value in {
        "WORKSPACE": tmp_path / "workspace", "STATE_DIR": state,
        "LOG_FILE": state / "audit.jsonl", "CHECKPOINT_FILE": state / "checkpoints.jsonl",
        "AUDIT_KEY": state / "keys" / "audit.pem", "STOP_FILE": state / "STOP", "PID_FILE": state / "agent.pid",
        "POLICY_FILE": state / "policy.yaml", "MEMORY_DB": state / "memory.db", "MCP_PINS": state / "pins.json",
        "SCHEDULE_FILE": state / "schedule.json", "MCP_CONFIG": tmp_path / "no-mcp.json",
        "INTERACTIVE": True, "GUARD_HEURISTICS": True, "TAINT_ESCALATION": True, "REDACTION": True,
        "MEMORY_PROVENANCE": True, "MCP_PINNING": True, "MCP_TRUST_ON_FIRST_USE": True, "RATE_LIMIT_PER_MIN": 20,
        "SETTINGS_FILE": state / "settings.json",
        **config.DEFAULTS,                       # your saved settings (agentos config set) never change test results
        "SANDBOX": "none",
    }.items():
        monkeypatch.setattr(config, name, value)
    monkeypatch.setattr("agentos.notify.notify", lambda *a, **k: False)              # no desktop pop-ups from tests
    monkeypatch.setattr("agentos.agents.scheduler.notify", lambda *a, **k: False)
    sandbox._cache.clear()
    store._stores.clear()
    (tmp_path / "workspace").mkdir()
    yield tmp_path
    sandbox._cache.clear()
    store._stores.clear()


@pytest.fixture
def ws(isolated):
    return isolated / "workspace"


# ------------------------------------------------------------------ fake model helpers
def call(name, **args):
    return NS(function=NS(name=name, arguments=args))


def tool_reply(*calls):
    return NS(role="assistant", content="", tool_calls=list(calls))


def text_reply(text):
    return NS(role="assistant", content=text, tool_calls=None)


class FakeLLM:
    """Replays a script of replies and records every conversation it was sent."""

    def __init__(self, script):
        self.script, self.seen, self.tools_seen = list(script), [], []

    def __call__(self, messages, tools=None):
        self.seen.append(list(messages))
        self.tools_seen.append(tools)
        return self.script.pop(0)
