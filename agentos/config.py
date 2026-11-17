"""
Settings for the agent, in one place.

Every value can be overridden with an environment variable, so you can
experiment without editing code, e.g.:

    AGENTOS_MODEL=qwen3:1.7b python main.py "how much disk space is free?"
"""

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent          # the repo folder when running from a checkout

# ---------------------------------------------------------------- model
# Which Ollama model to use. It must support tool calling
# (look for the "tools" tag on ollama.com/library).
MODEL = os.getenv("AGENTOS_MODEL", "qwen3:4b")

# qwen3 can "think out loud" before answering. That is slow on a laptop
# and leaks into answers, so it's off. AGENTOS_THINK=1 turns it back on.
THINK = os.getenv("AGENTOS_THINK", "0") == "1"

# Context window in tokens. Smaller = faster on CPU, but the model "forgets"
# earlier steps sooner. 4096 is enough for Phase 2 tasks.
NUM_CTX = int(os.getenv("AGENTOS_NUM_CTX", "4096"))

# Keep the model loaded in RAM between requests, so only the first goal
# pays the loading cost. Ollama's default unloads after 5 minutes.
KEEP_ALIVE = os.getenv("AGENTOS_KEEP_ALIVE", "30m")

# ---------------------------------------------------------------- agent loop
# Hard limit on loop iterations. Without it, a confused model can loop forever.
MAX_STEPS = int(os.getenv("AGENTOS_MAX_STEPS", "10"))

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

# Agentic OS keeps its own state OUTSIDE the workspace, so the agent can't edit
# its own audit log, memory or policy. Also outside OneDrive, so nothing syncs.
STATE_DIR = Path(os.getenv("AGENTOS_HOME", Path.home() / ".agentos"))

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
DEFAULT_SCOPE = os.getenv("AGENTOS_SCOPE", "read,write,exec")
SCOPE_TTL_MINUTES = int(os.getenv("AGENTOS_SCOPE_TTL", "15"))

# False in unattended runs (scheduler, red team): anything that would ask is denied instead.
INTERACTIVE = os.getenv("AGENTOS_INTERACTIVE", "1") == "1"

# ---------------------------------------------------------------- injection guard (Phase 5)
GUARD_HEURISTICS = os.getenv("AGENTOS_GUARD", "1") == "1"            # flag text that looks like an injection
GUARD_QUARANTINE = os.getenv("AGENTOS_QUARANTINE", "0") == "1"       # summarise untrusted text with a tool-less model first
TAINT_ESCALATION = os.getenv("AGENTOS_TAINT", "1") == "1"            # after untrusted input, risky calls always ask
PLAN_FIRST = os.getenv("AGENTOS_PLAN_FIRST", "0") == "1"             # fix the tool plan before reading untrusted input
REDACTION = os.getenv("AGENTOS_REDACT", "1") == "1"                  # hide secrets from the model and the log
MEMORY_PROVENANCE = os.getenv("AGENTOS_PROVENANCE", "1") == "1"      # memories saved after untrusted input are untrusted
MCP_PINNING = os.getenv("AGENTOS_MCP_PINNING", "1") == "1"           # refuse MCP tools whose description changed

# ---------------------------------------------------------------- memory (Phase 4)
MEMORY_DB = Path(os.getenv("AGENTOS_MEMORY_DB", STATE_DIR / "memory.db"))
# Optional semantic search: an Ollama embedding model, e.g. nomic-embed-text. Empty = keyword search only.
MEMORY_EMBED_MODEL = os.getenv("AGENTOS_EMBED_MODEL", "")
MEMORY_CONTEXT_ITEMS = int(os.getenv("AGENTOS_MEMORY_ITEMS", "5"))
SCHEDULE_FILE = STATE_DIR / "schedule.json"

# ---------------------------------------------------------------- sandbox
# auto   = Docker if it's running and the image is built, otherwise bubblewrap
# docker = always Docker      bwrap = always bubblewrap
# none   = NO isolation (Phase 1 behaviour). Only for debugging.
SANDBOX = os.getenv("AGENTOS_SANDBOX", "auto")
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
