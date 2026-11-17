"""MCP bridge tests, using the demo server in demo/mcp_demo_server.py."""

import json

import pytest

from agentos import config
from agentos.tools.base import ToolError
from agentos.tools.mcp_client import MCPTool, load_mcp_tools
from agentos.tools.registry import ToolRegistry

pytest.importorskip("mcp")


@pytest.fixture
def demo_config(tmp_path, monkeypatch):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"servers": {
        "demo": {"enabled": True, "command": "python3", "args": ["demo/mcp_demo_server.py"]},
        "off": {"enabled": False, "command": "does-not-exist"},
    }}))
    monkeypatch.setattr(config, "MCP_CONFIG", path)
    return path


def test_demo_tools_load_and_run(demo_config):
    tools, warnings = load_mcp_tools()
    assert warnings == []
    by_name = {t.name: t for t in tools}
    assert set(by_name) == {"mcp_demo_word_count", "mcp_demo_roll_dice"}
    wc = by_name["mcp_demo_word_count"]
    assert wc.risk.value == "exec" and wc.description.startswith("[MCP server 'demo']")
    assert wc.validate({"text": "a b"}) is None
    r = wc.run(text="one two three")
    assert r.ok and "words: 3" in r.output and r.untrusted


def test_registry_includes_mcp_tools(demo_config):
    reg = ToolRegistry.discover()
    assert "mcp_demo_roll_dice" in reg.names() and "run_shell" in reg.names()


def test_fingerprints_are_logged(demo_config):
    load_mcp_tools()
    events = [json.loads(line) for line in config.LOG_FILE.read_text().splitlines()]
    loaded = [e for e in events if e["event"] == "mcp_tool_loaded"]
    assert len(loaded) == 2 and all(len(e["fingerprint"]) == 16 for e in loaded)


def test_broken_server_gives_warning_not_crash(tmp_path, monkeypatch):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"servers": {"bad": {"enabled": True, "command": "false"}}}))
    monkeypatch.setattr(config, "MCP_CONFIG", path)
    monkeypatch.setattr(config, "COMMAND_TIMEOUT", 5)
    tools, warnings = load_mcp_tools()
    assert tools == [] and "bad" in warnings[0]


def test_failed_call_becomes_tool_error(demo_config, monkeypatch):
    tools, _ = load_mcp_tools()
    tool = tools[0]
    tool.cfg = {"command": "false"}
    monkeypatch.setattr(config, "COMMAND_TIMEOUT", 5)
    with pytest.raises(ToolError, match="failed|timed out"):
        tool.run(text="x")


def test_no_config_means_no_tools():
    assert load_mcp_tools() == ([], [])


def test_name_is_sanitised():
    from types import SimpleNamespace as NS
    t = MCPTool("my server!", {}, NS(name="do/thing", description="d", input_schema={"properties": {}}))
    assert t.name == "mcp_my_server__do_thing"
