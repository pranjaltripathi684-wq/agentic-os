"""Drive the TUI headlessly with Textual's test pilot and a fake model."""

import asyncio

import pytest
from conftest import FakeLLM, call, text_reply, tool_reply

pytest.importorskip("textual")

from agentos.core.agent import Agent  # noqa: E402
from agentos.interfaces.tui import AgentOSApp, ApprovalScreen  # noqa: E402
from agentos.tools.files import WriteFile  # noqa: E402
from agentos.tools.registry import ToolRegistry  # noqa: E402


def run(coro):
    return asyncio.run(coro)


def make_app(script):
    registry = ToolRegistry([WriteFile()])
    llm = FakeLLM(script)
    return AgentOSApp(registry, lambda approver, listener: Agent(registry, llm, approver, verbose=False,
                                                                 listeners=[listener], memory=None))


async def wait_for(pilot, condition, timeout=5.0):
    for _ in range(int(timeout / 0.05)):
        if condition():
            return True
        await pilot.pause(0.05)
    return False


@pytest.mark.parametrize("key,created", [("y", True), ("n", False)])
def test_goal_approval_popup_and_answer(ws, key, created):
    app = make_app([tool_reply(call("write_file", path="hello.txt", content="hi")), text_reply("Wrote hello.txt")])

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.click("#goal")
            await pilot.press(*"make hello.txt", "enter")
            assert await wait_for(pilot, lambda: isinstance(app.screen, ApprovalScreen))
            await pilot.press(key)
            assert await wait_for(pilot, lambda: not app.busy)
            text = "\n".join(str(line.text) for line in app.query_one("#activity").lines)
            return text
    text = run(scenario())
    assert (ws / "hello.txt").exists() is created
    assert ("Wrote hello.txt" in text) if created else ("blocked: denied by user" in text)


def test_audit_panel_shows_chain_status(ws):
    app = make_app([text_reply("nothing to do")])

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.click("#goal")
            await pilot.press(*"hi", "enter")
            await wait_for(pilot, lambda: not app.busy)
            await pilot.pause(0.1)
            app.refresh_side()
            return str(app.query_one("#status").render())
    assert "intact" in run(scenario())
