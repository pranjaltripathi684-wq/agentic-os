import socket
import time

import pytest

from agentos.tools.base import ToolError
from agentos.tools.web import HttpGet, check_url, html_to_text


# ------------------------------------------------------------------ http_get tool
@pytest.mark.parametrize("url", [
    "http://127.0.0.1:11434/api/tags", "http://localhost/", "http://192.168.1.1/", "http://10.0.0.5/",
    "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://0.0.0.0/"])
def test_private_addresses_blocked(url):
    with pytest.raises(ToolError, match="private/local|resolve"):
        check_url(url)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "gopher://x", "javascript:alert(1)"])
def test_other_schemes_blocked(url):
    with pytest.raises(ToolError, match="only http"):
        check_url(url)


def test_public_address_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.215.14", 443))])
    assert check_url("https://example.com/") == "https://example.com/"


def test_hostname_that_resolves_to_private_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 80))])
    with pytest.raises(ToolError, match="private/local"):
        check_url("http://evil.example/")


def test_html_to_text_drops_scripts_and_styles():
    html = """<html><head><title>T</title><style>body{color:red}</style></head>
    <body><h1>Hello</h1><script>steal()</script><p>World   of
    text</p><noscript>x</noscript></body></html>"""
    assert html_to_text(html) == "Hello\nWorld of text"


def test_http_get_refuses_before_connecting():
    with pytest.raises(ToolError):
        HttpGet().run(url="http://127.0.0.1:1/")


# ------------------------------------------------------------------ dashboard
fastapi = pytest.importorskip("fastapi")
from conftest import FakeLLM, call, text_reply, tool_reply  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agentos.core.agent import Agent  # noqa: E402
from agentos.interfaces.web import Runner, create_app  # noqa: E402
from agentos.tools.files import WriteFile  # noqa: E402
from agentos.tools.registry import ToolRegistry  # noqa: E402

TOKEN = "test-token-123"


def client_for(script):
    registry = ToolRegistry([WriteFile()])
    llm = FakeLLM(script)
    runner = Runner(lambda approver, feed: Agent(registry, llm, approver, verbose=False, listeners=[feed], memory=None))
    return TestClient(create_app(runner, TOKEN)), runner


def wait(cond, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_token_host_and_csrf_are_enforced():
    c, _ = client_for([])
    assert c.get("/").status_code == 401
    assert c.get("/?token=wrong").status_code == 401
    assert c.get(f"/?token={TOKEN}", headers={"host": "evil.example:8765"}).status_code == 403
    page = c.get(f"/?token={TOKEN}")
    assert page.status_code == 200 and "Agentic OS" in page.text and page.headers["x-frame-options"] == "DENY"
    assert c.get("/api/state").status_code == 200                       # cookie now set
    assert c.post("/api/run", json={"goal": "x"}).status_code == 403    # no CSRF header


def test_run_approve_and_finish(ws):
    c, runner = client_for([tool_reply(call("write_file", path="a.txt", content="hi")), text_reply("Wrote a.txt")])
    h = {"X-AgentOS-Token": TOKEN}
    c.get(f"/?token={TOKEN}")
    assert c.post("/api/run", json={"goal": "write a.txt"}, headers=h).json() == {"started": True}
    assert wait(lambda: c.get("/api/state").json()["pending"])
    pending = c.get("/api/state").json()["pending"][0]
    assert pending["tool"] == "write_file" and "a.txt" in pending["summary"]
    assert c.post("/api/run", json={"goal": "second"}, headers=h).status_code == 409   # one task at a time
    assert c.post("/api/answer", json={"id": pending["id"], "value": "once"}, headers=h).json() == {"ok": True}
    assert wait(lambda: not runner.running)
    state = c.get("/api/state").json()
    assert (ws / "a.txt").read_text() == "hi" and state["audit"]["ok"]
    assert any(e["event"] == "answer" and e["answer"] == "Wrote a.txt" for e in state["events"])


def test_stop_denies_pending_requests(ws):
    c, runner = client_for([tool_reply(call("write_file", path="a.txt", content="hi")), text_reply("gave up")])
    h = {"X-AgentOS-Token": TOKEN}
    c.get(f"/?token={TOKEN}")
    c.post("/api/run", json={"goal": "x"}, headers=h)
    assert wait(lambda: c.get("/api/state").json()["pending"])
    c.post("/api/stop", headers=h)
    assert wait(lambda: not runner.running)
    assert not (ws / "a.txt").exists()
