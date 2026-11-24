"""
Settings for the agent, in one place.

Each value comes from, in this order:
  1. an environment variable, for one-off experiments:
         AGENTOS_MODEL=qwen3:1.7b agentos run "how much disk space is free?"
  2. your saved settings in ~/.agentos/settings.json, written by
         agentos model use <name>        agentos config set <key> <value>
  3. the default below.
"""

import json
import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent          # the repo folder when running from a checkout

# Agentic OS keeps its own state OUTSIDE the workspace, so the agent can't edit
# its own audit log, memory, policy or settings. Also outside OneDrive, so nothing syncs.
STATE_DIR = Path(os.getenv("AGENTOS_HOME", Path.home() / ".agentos"))
SETTINGS_FILE = STATE_DIR / "settings.json"

# Settings you can save with `agentos config set` (name -> (attribute here, type, what it does)).
SAVEABLE = {
    "model": ("MODEL", str, "Ollama model that runs the agent"),
    "num_ctx": ("NUM_CTX", int, "context window in tokens"),
    "num_batch": ("NUM_BATCH", int, "tokens processed per batch; smaller uses less VRAM (agentos model tune)"),
    "max_steps": ("MAX_STEPS", int, "tool-call rounds before a task gives up"),
    "sandbox": ("SANDBOX", str, "auto, docker, bwrap or none"),
    "scope": ("DEFAULT_SCOPE", str, "risks a task may use without asking (read-only, standard, full or a list)"),
    "plan_first": ("PLAN_FIRST", bool, "plan the tools (and the task scope) before reading untrusted input"),
    "quarantine": ("GUARD_QUARANTINE", bool, "summarise untrusted text with a tool-less model first"),
    "embed_model": ("MEMORY_EMBED_MODEL", str, "Ollama embedding model for memory search, e.g. nomic-embed-text"),
    "keep_alive": ("KEEP_ALIVE", str, "how long Ollama keeps the model loaded, e.g. 30m"),
}
ENV_VARS = {
    "model": "AGENTOS_MODEL", "num_ctx": "AGENTOS_NUM_CTX", "num_batch": "AGENTOS_NUM_BATCH",
    "max_steps": "AGENTOS_MAX_STEPS", "sandbox": "AGENTOS_SANDBOX", "scope": "AGENTOS_SCOPE",
    "plan_first": "AGENTOS_PLAN_FIRST", "quarantine": "AGENTOS_QUARANTINE", "embed_model": "AGENTOS_EMBED_MODEL",
    "keep_alive": "AGENTOS_KEEP_ALIVE",
}
SANDBOX_CHOICES = ("auto", "docker", "bwrap", "none")
SCOPE_PRESETS = ("read-only", "standard", "full")
RISKS = ("read", "write", "network", "exec")


def _load_settings(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


_SAVED = _load_settings(SETTINGS_FILE)


def _get(env: str, key: str, default: str) -> str:
    """Environment variable, then saved setting, then default."""
    value = os.getenv(env)
    if value is not None:
        return value
    if key in _SAVED:
        return str(_SAVED[key])
    return default


def _flag(env: str, key: str, default: bool) -> bool:
    value = os.getenv(env)
    if value is not None:
        return value == "1"
    if key in _SAVED:
        return bool(_SAVED[key])
    return default


def _int(env: str, key: str, default: int) -> int:
    try:
        return int(_get(env, key, str(default)))
    except ValueError:
        return default                       # a typo in settings.json must not stop the agent starting


def parse_setting(key: str, text: str):
    """Turn `agentos config set` text into the right type, or raise ValueError."""
    if key not in SAVEABLE:
        raise ValueError(f"unknown setting '{key}'. Settings: {', '.join(SAVEABLE)}")
    kind = SAVEABLE[key][1]
    if kind is bool:
        low = text.strip().lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off"):
            return False
        raise ValueError(f"{key} must be true or false")
    if kind is int:
        try:
            number = int(text)
        except ValueError:
            raise ValueError(f"{key} must be a whole number") from None
        if number < 1:
            raise ValueError(f"{key} must be at least 1")
        return number
    text = text.strip()
    if not text:
        raise ValueError(f"{key} can't be empty")
    if key == "sandbox" and text not in SANDBOX_CHOICES:
        raise ValueError(f"sandbox must be one of: {', '.join(SANDBOX_CHOICES)}")
    if key == "scope" and text not in SCOPE_PRESETS:
        bad = {r.strip() for r in text.split(",")} - set(RISKS)
        if bad:
            raise ValueError(f"scope must be {', '.join(SCOPE_PRESETS)} or a list of {', '.join(RISKS)}")
    return text


def saved_settings() -> dict:
    return _load_settings(SETTINGS_FILE)


def _resolve(key: str):
    """The value a setting has right now: environment variable, then saved, then default."""
    attr, kind, _what = SAVEABLE[key]
    env, default = ENV_VARS[key], DEFAULTS[attr]
    if kind is bool:
        return _flag(env, key, bool(default))
    if kind is int:
        return _int(env, key, int(str(default)))
    return _get(env, key, str(default))


def save_setting(key: str, value) -> None:
    """Save one setting to settings.json (private file) and apply it to this process."""
    global _SAVED
    data = saved_settings()
    if value is None:
        data.pop(key, None)
    else:
        data[key] = value
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    tmp = SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(SETTINGS_FILE)
    _SAVED = data
    globals()[SAVEABLE[key][0]] = _resolve(key)


# ---------------------------------------------------------------- model
# Which Ollama model to use. It must support tool calling ("tools" tag on ollama.com/library).
# The default is the non-thinking "Instruct 2507" build of Qwen3-4B: about 2.5 GB, fits a
# 4 GB laptop GPU, good at tool calls, and it never spends minutes reasoning before it acts.
# `agentos model list` shows alternatives; `agentos model use <name>` switches.
DEFAULT_MODEL = "qwen3:4b-instruct-2507-q4_K_M"
MODEL = _get("AGENTOS_MODEL", "model", DEFAULT_MODEL)

# Hybrid models (the original qwen3:4b/8b, qwen3.5) can "think out loud" before answering.
# That is slow on a laptop and leaks into answers, so it's off. AGENTOS_THINK=1 turns it back on.
THINK = os.getenv("AGENTOS_THINK", "0") == "1"

# Context window in tokens. Smaller = faster, but the model "forgets" earlier steps sooner.
NUM_CTX = _int("AGENTOS_NUM_CTX", "num_ctx", 4096)

# Tokens Ollama processes at once while reading the prompt. Ollama's default is 512. Its working
# buffer grows with this (with Qwen's 150k-word vocabulary, a few hundred MB at 512), so on a
# 4 GB GPU a smaller batch can be what lets the whole model fit. `agentos model tune` finds it.
NUM_BATCH = _int("AGENTOS_NUM_BATCH", "num_batch", 512)

# Keep the model loaded between requests, so only the first goal pays the loading cost.
# Ollama's default unloads after 5 minutes.
KEEP_ALIVE = _get("AGENTOS_KEEP_ALIVE", "keep_alive", "30m")

# ---------------------------------------------------------------- agent loop
# Hard limit on loop iterations. Without it, a confused model can loop forever.
MAX_STEPS = _int("AGENTOS_MAX_STEPS", "max_steps", 10)

# How long a single tool call may run before we kill it (seconds).
COMMAND_TIMEOUT = int(os.getenv("AGENTOS_TIMEOUT", "30"))

# Small models have small context windows. Long outputs get cut to this size.
MAX_OUTPUT_CHARS = int(os.getenv("AGENTOS_MAX_OUTPUT", "4000"))

# Tool calls per minute before the agent is throttled (stops runaway loops).
RATE_LIMIT_PER_MIN = int(os.getenv("AGENTOS_RATE_LIMIT", "20"))

# Before each step, old tool results are trimmed once the conversation is
# larger than this share of the context window (Phase 4 "compaction").
COMPACT_AT = float(os.getenv("AGENTOS_COMPACT_AT", "0.7"))

# ---------------------------------------------------------------- workspace and log
# The ONLY folder the agent's tools can see. Inside the sandbox it appears as /workspace.
WORKSPACE = Path(os.getenv("AGENTOS_WORKSPACE", Path.home() / "agentos-workspace"))

# Tamper-evident audit log: one JSON object per line, each chained to the previous by hash.
LOG_FILE = Path(os.getenv("AGENTOS_LOG", STATE_DIR / "audit.jsonl"))
CHECKPOINT_FILE = Path(os.getenv("AGENTOS_CHECKPOINTS", STATE_DIR / "audit-checkpoints.jsonl"))
AUDIT_KEY = Path(os.getenv("AGENTOS_AUDIT_KEY", STATE_DIR / "keys" / "audit_ed25519.pem"))

# Kill switch: `agentos stop` creates STOP_FILE and signals the process in PID_FILE.
STOP_FILE = STATE_DIR / "STOP"
PID_FILE = STATE_DIR / "agent.pid"

# ---------------------------------------------------------------- policy and scope
# Your policy file wins if it exists; otherwise the default in policies/default.yaml.
POLICY_FILE = Path(os.getenv("AGENTOS_POLICY", STATE_DIR / "policy.yaml"))
DEFAULT_POLICY_FILE = PACKAGE_DIR / "policies" / "default.yaml"

# Risks a task may use without asking to widen its scope (read, write, network, exec).
DEFAULT_SCOPE = _get("AGENTOS_SCOPE", "scope", "read,write,exec")
SCOPE_TTL_MINUTES = int(os.getenv("AGENTOS_SCOPE_TTL", "15"))

# False in unattended runs (scheduler, red team): anything that would ask is denied instead.
INTERACTIVE = os.getenv("AGENTOS_INTERACTIVE", "1") == "1"

# ---------------------------------------------------------------- injection guard (Phase 5)
GUARD_HEURISTICS = os.getenv("AGENTOS_GUARD", "1") == "1"            # flag text that looks like an injection
GUARD_QUARANTINE = _flag("AGENTOS_QUARANTINE", "quarantine", False)  # summarise untrusted text with a tool-less model first
TAINT_ESCALATION = os.getenv("AGENTOS_TAINT", "1") == "1"            # after untrusted input, risky calls always ask
PLAN_FIRST = _flag("AGENTOS_PLAN_FIRST", "plan_first", False)          # fix the tool plan before reading untrusted input
REDACTION = os.getenv("AGENTOS_REDACT", "1") == "1"                  # hide secrets from the model and the log
MEMORY_PROVENANCE = os.getenv("AGENTOS_PROVENANCE", "1") == "1"      # memories saved after untrusted input are untrusted
MCP_PINNING = os.getenv("AGENTOS_MCP_PINNING", "1") == "1"           # refuse MCP tools whose description changed

# ---------------------------------------------------------------- memory (Phase 4)
MEMORY_DB = Path(os.getenv("AGENTOS_MEMORY_DB", STATE_DIR / "memory.db"))
# Optional semantic search: an Ollama embedding model, e.g. nomic-embed-text. Empty = keyword search only.
MEMORY_EMBED_MODEL = _get("AGENTOS_EMBED_MODEL", "embed_model", "")
MEMORY_CONTEXT_ITEMS = int(os.getenv("AGENTOS_MEMORY_ITEMS", "5"))
SCHEDULE_FILE = STATE_DIR / "schedule.json"

# ---------------------------------------------------------------- sandbox
# auto   = Docker if it's running and the image is built, otherwise bubblewrap
# docker = always Docker      bwrap = always bubblewrap
# none   = NO isolation (Phase 1 behaviour). Only for debugging.
SANDBOX = _get("AGENTOS_SANDBOX", "sandbox", "auto")
SANDBOX_IMAGE = os.getenv("AGENTOS_SANDBOX_IMAGE", "agentos-sandbox:latest")
SANDBOX_MEMORY = os.getenv("AGENTOS_SANDBOX_MEMORY", "512m")   # RAM cap per command
SANDBOX_CPUS = os.getenv("AGENTOS_SANDBOX_CPUS", "1")          # CPU cores per command
SANDBOX_PIDS = int(os.getenv("AGENTOS_SANDBOX_PIDS", "128"))   # max processes (stops fork bombs)

# ---------------------------------------------------------------- web
HTTP_TIMEOUT = int(os.getenv("AGENTOS_HTTP_TIMEOUT", "15"))
HTTP_MAX_BYTES = int(os.getenv("AGENTOS_HTTP_MAX_BYTES", "1000000"))

# ---------------------------------------------------------------- MCP
# Which external MCP tool servers to load. See mcp_servers.json.
# The repo's mcp_servers.json when running from a checkout, otherwise ~/.agentos/mcp_servers.json.
_REPO_MCP = PROJECT_ROOT / "mcp_servers.json"
MCP_CONFIG = Path(os.getenv("AGENTOS_MCP_CONFIG", _REPO_MCP if _REPO_MCP.exists() else STATE_DIR / "mcp_servers.json"))
# Approved fingerprints of MCP tool descriptions (trust on first use; a change is refused).
MCP_PINS = Path(os.getenv("AGENTOS_MCP_PINS", STATE_DIR / "mcp_pins.json"))
MCP_TRUST_ON_FIRST_USE = os.getenv("AGENTOS_MCP_TOFU", "1") == "1"

# ---------------------------------------------------------------- dashboard (Phase 6)
DASHBOARD_HOST = "127.0.0.1"          # never 0.0.0.0: the dashboard can approve actions
DASHBOARD_PORT = int(os.getenv("AGENTOS_DASHBOARD_PORT", "8765"))

def output_dir() -> Path:
    """Where generated reports go: the repo's docs/ folder when running from a checkout,
    otherwise ~/.agentos/reports (never inside site-packages after a pip/pipx install)."""
    docs = PROJECT_ROOT / "docs"
    if (PROJECT_ROOT / "pyproject.toml").exists() and docs.is_dir():
        return docs
    return STATE_DIR / "reports"


# Built-in defaults, used when a saved setting is removed (`agentos config unset`).
DEFAULTS: dict[str, object] = {
    "MODEL": DEFAULT_MODEL, "NUM_CTX": 4096, "NUM_BATCH": 512, "MAX_STEPS": 10, "SANDBOX": "auto",
    "DEFAULT_SCOPE": "read,write,exec", "PLAN_FIRST": False, "GUARD_QUARANTINE": False,
    "MEMORY_EMBED_MODEL": "", "KEEP_ALIVE": "30m",
}
