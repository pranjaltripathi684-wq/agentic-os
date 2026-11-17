"""
Bridge to MCP (Model Context Protocol) servers.

MCP is a standard way to package tools so any agent can use them. A server
is a separate program; we start it, ask "what tools do you have?", and wrap
each one as a normal Tool, so the model and the approval gate treat it
exactly like a built-in tool.

Configure servers in mcp_servers.json. Security notes:
  - MCP servers run on YOUR machine with YOUR permissions, NOT in the sandbox.
    Only enable servers you trust. Every MCP tool call needs approval (risk EXEC).
  - A server's tool descriptions are text the model reads, so a malicious server
    can hide instructions there ("tool poisoning"), or behave nicely at first and
    change its description later (a "rug pull"). Each tool's description and
    schema get a SHA-256 fingerprint, pinned the first time you load it (trust
    on first use, like SSH host keys) in ~/.agentos/mcp_pins.json. If the
    fingerprint later changes, the tool is REFUSED until you review it and run
    `agentos mcp pin`.

For simplicity this starts the server fresh for each call. That's slower
(about a second) but means no background processes are left running.
"""

import asyncio
import hashlib
import importlib.util
import json
import re
import sys

from .. import config
from ..security.audit import log_event
from .base import Risk, Tool, ToolError, ToolResult, truncate


def _field(obj, *names, default=None):
    """MCP SDK v1 uses camelCase (inputSchema), v2 uses snake_case (input_schema). Accept both."""
    for n in names:
        value = getattr(obj, n, None)
        if value is not None:
            return value
    return default


def _server_params(cfg: dict):
    from mcp import StdioServerParameters
    command = cfg["command"]
    if command in ("python", "python3"):
        command = sys.executable           # use the same Python (and venv) as the agent
    return StdioServerParameters(command=command, args=cfg.get("args", []),
                                 env=cfg.get("env"), cwd=str(config.PROJECT_ROOT))


async def _with_session(cfg, work):
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client
    async with stdio_client(_server_params(cfg)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await work(session)


def _run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=config.COMMAND_TIMEOUT))


def fingerprint(name, description, schema) -> str:
    blob = json.dumps({"name": name, "description": description, "schema": schema}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


class MCPTool(Tool):
    risk = Risk.EXEC

    def __init__(self, server: str, cfg: dict, remote):
        self.server = server
        self.cfg = cfg
        self.remote_name = remote.name
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", f"mcp_{server}_{remote.name}")[:64]
        self.name = safe
        desc = (_field(remote, "description", default="") or "").strip()
        self.description = f"[MCP server '{server}'] {desc}"[:600]
        schema = _field(remote, "input_schema", "inputSchema", default=None) or {}
        self.parameters = {"type": "object", "properties": schema.get("properties", {}),
                           "required": schema.get("required", [])}
        self.fingerprint = fingerprint(remote.name, desc, self.parameters)

    def describe(self, args):
        return f"[MCP {self.server}] {self.remote_name} {json.dumps(args, ensure_ascii=False)}"

    def run(self, **kwargs):
        async def call(session):
            return await session.call_tool(self.remote_name, kwargs)
        try:
            res = _run(_with_session(self.cfg, call))
        except asyncio.TimeoutError:
            raise ToolError(f"MCP server '{self.server}' timed out") from None
        except Exception as e:                       # server crashed, bad config, etc.
            raise ToolError(f"MCP server '{self.server}' failed: {type(e).__name__}: {e}") from e
        parts = []
        for block in _field(res, "content", default=[]) or []:
            if _field(block, "type") == "text":
                parts.append(block.text)
            else:
                parts.append(f"[{_field(block, 'type', default='non-text')} content omitted]")
        text, cut = truncate("\n".join(parts))
        is_error = bool(_field(res, "is_error", "isError", default=False))
        if is_error:
            return ToolResult(False, error=text or "tool reported an error", untrusted=True)
        return ToolResult(True, text, truncated=cut, untrusted=True, meta={"server": self.server})


def load_config(path=None) -> dict:
    path = path or config.MCP_CONFIG
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {name: cfg for name, cfg in data.get("servers", {}).items() if cfg.get("enabled")}


def load_mcp_tools(path=None, accept_new=False):
    """Start each enabled server once, list its tools, check their pins, and wrap them.
    accept_new=True (used by `agentos mcp pin`) re-pins changed tools. Returns (tools, warnings)."""
    tools, warnings = [], []
    try:
        servers = load_config(path)
    except (OSError, json.JSONDecodeError) as e:
        return [], [f"mcp_servers.json is unreadable: {e}"]
    if not servers:
        return [], []
    if importlib.util.find_spec("mcp") is None:
        return [], ["MCP servers are enabled but the 'mcp' package isn't installed: pip install mcp"]

    async def list_tools(session):
        return (await session.list_tools()).tools

    pins = load_pins()
    changed = False
    for name, cfg in servers.items():
        try:
            remote_tools = _run(_with_session(cfg, list_tools))
        except Exception as e:
            warnings.append(f"MCP server '{name}' didn't start: {type(e).__name__}: {e}")
            continue
        for remote in remote_tools:
            tool = MCPTool(name, cfg, remote)
            key = f"{name}/{tool.remote_name}"
            pinned = pins.get(key)
            if pinned is None and not (accept_new or config.MCP_TRUST_ON_FIRST_USE):
                warnings.append(f"MCP tool {key} is new and not pinned; run `agentos mcp pin` to trust it")
                log_event("mcp_tool_refused", server=name, tool=tool.name, reason="not pinned",
                          fingerprint=tool.fingerprint)
                continue
            if pinned is not None and pinned != tool.fingerprint and not accept_new and config.MCP_PINNING:
                warnings.append(f"MCP tool {key} CHANGED its description or schema since you trusted it "
                                "(possible tool poisoning). Refused. Review it, then run `agentos mcp pin`.")
                log_event("mcp_tool_refused", server=name, tool=tool.name, reason="fingerprint changed",
                          pinned=pinned, fingerprint=tool.fingerprint)
                continue
            if pinned != tool.fingerprint:
                pins[key] = tool.fingerprint
                changed = True
                log_event("mcp_tool_pinned", server=name, tool=tool.name, fingerprint=tool.fingerprint)
            tools.append(tool)
            log_event("mcp_tool_loaded", server=name, tool=tool.name, fingerprint=tool.fingerprint)
    if changed:
        save_pins(pins)
    return tools, warnings


def load_pins() -> dict:
    try:
        return json.loads(config.MCP_PINS.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_pins(pins: dict):
    config.MCP_PINS.parent.mkdir(parents=True, exist_ok=True)
    config.MCP_PINS.write_text(json.dumps(pins, indent=2, sort_keys=True))
