from agentos import config
from agentos.core.llm import _with_no_think, clean_content


def test_reasoning_is_removed():
    assert clean_content("<think>\nOkay, let me see...\n</think>\n\nYou have 945 GB free.") == "You have 945 GB free."
    assert clean_content("Okay, let me see.</think>You have 945 GB free.") == "You have 945 GB free."
    assert clean_content("<think>never closed") == ""
    assert clean_content("Plain answer.") == "Plain answer."
    assert clean_content(None) == ""


def test_no_think_added_for_qwen3_only(monkeypatch):
    monkeypatch.setattr(config, "THINK", False)
    msgs = [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]
    out = _with_no_think(msgs, "qwen3:4b")
    assert out[0]["content"].endswith("/no_think") and msgs[0]["content"] == "be brief"   # original untouched
    assert _with_no_think(msgs, "llama3.2:3b") is msgs
    monkeypatch.setattr(config, "THINK", True)
    assert _with_no_think(msgs, "qwen3:4b") is msgs


def test_dropped_connection_becomes_llm_error(monkeypatch):
    import httpx
    import pytest

    from agentos.core import llm

    def boom(**kwargs):
        raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
    monkeypatch.setattr(llm.ollama, "chat", boom)
    with pytest.raises(llm.LLMError, match="Lost the connection"):
        llm.chat([{"role": "user", "content": "hi"}])


def test_model_without_thinking_mode_is_retried_without_the_flag(monkeypatch):
    from types import SimpleNamespace as NS

    import ollama

    from agentos.core import llm
    calls = []

    def fake_chat(**kwargs):
        calls.append("think" in kwargs)
        if "think" in kwargs:
            raise ollama.ResponseError('"granite4:micro-h" does not support thinking', 400)
        return NS(message=NS(content="hello", tool_calls=None))
    monkeypatch.setattr(llm.ollama, "chat", fake_chat)
    monkeypatch.setattr(llm, "_NO_THINK_SUPPORT", set())
    msgs = [{"role": "user", "content": "hi"}]
    assert llm.chat(msgs, model="granite4:micro-h").content == "hello"
    assert llm.chat(msgs, model="granite4:micro-h").content == "hello"
    assert calls == [True, False, False]          # learned after the first refusal
