"""
The "brain": a thin wrapper around the Ollama chat API.

Keeping all model calls behind one small function means the rest of the
code never imports `ollama` directly. Later you can swap in a cloud API,
or a fake model for tests, by changing only this file (or passing a
different function into the Agent).
"""

import re

import httpx
import ollama

from .. import config


class LLMError(RuntimeError):
    """Raised when the model can't be reached or refuses the request."""


def clean_content(text: str) -> str:
    """
    Remove the model's private reasoning from its answer.

    qwen3 sometimes writes its reasoning inside <think>...</think> even when
    thinking is switched off (older Ollama versions ignore the `think` flag).
    Phase 1's first real run showed this: the answer began "Okay, let me see...".
    """
    if not text:
        return ""
    if "</think>" in text:                       # reasoning, then the real answer
        text = text.split("</think>")[-1]
    text = re.sub(r"<think>.*?(</think>|$)", "", text, flags=re.DOTALL)
    return text.strip()


_HYBRID_QWEN3 = re.compile(r"(^|/)qwen3([-:]|$)", re.IGNORECASE)
_NOT_HYBRID = ("instruct", "thinking", "2507", "coder")


def is_hybrid_qwen3(model: str) -> bool:
    """The original Qwen3 models (qwen3:4b, qwen3:8b...) can think or not. The 2507 'instruct' and
    'thinking' builds, and other families, don't understand the /no_think switch."""
    low = model.lower()
    return bool(_HYBRID_QWEN3.search(low)) and not any(word in low for word in _NOT_HYBRID)


def _with_no_think(messages, model):
    """Hybrid qwen3 understands '/no_think' in the system prompt as 'skip reasoning'."""
    if config.THINK or not is_hybrid_qwen3(model) or not messages:
        return messages
    first = messages[0]
    if isinstance(first, dict) and first.get("role") == "system" and "/no_think" not in first["content"]:
        return [{**first, "content": first["content"] + "\n/no_think"}] + list(messages[1:])
    return messages


def model_options() -> dict:
    """Ollama options for every call. Changing them makes Ollama reload the model."""
    return {"num_ctx": config.NUM_CTX, "num_batch": config.NUM_BATCH}


def chat(messages, tools=None, model=None):
    """
    Send the conversation so far to the model and return its reply.

    messages: list of {"role": ..., "content": ...} dicts (or ollama Message objects)
    tools:    list of tool schemas the model is allowed to *ask* for

    Returns an ollama Message with:
      .content     -> text the model wrote, reasoning removed (may be empty)
      .tool_calls  -> list of tool requests, or None
    """
    name = model or config.MODEL
    try:
        response = _chat_once(dict(model=name, messages=_with_no_think(messages, name), tools=tools or [],
                                   options=model_options(), keep_alive=config.KEEP_ALIVE))
    except ollama.ResponseError as e:
        if e.status_code == 404:
            raise LLMError(f"Model '{name}' isn't downloaded. Run: ollama pull {name}") from e
        raise LLMError(f"Ollama returned an error: {e.error}") from e
    except ConnectionError as e:
        raise LLMError("Can't reach Ollama. Is it running? Try `ollama serve` in another terminal.") from e
    except httpx.HTTPError as e:
        # e.g. Ollama crashed mid-answer, often because it ran out of memory
        raise LLMError(f"Lost the connection to Ollama ({type(e).__name__}). If this repeats, the model may not "
                       "fit in memory: try a smaller one with `agentos model use qwen3:1.7b`") from e
    message = response.message
    message.content = clean_content(message.content or "")
    return message


_NO_THINK_SUPPORT: set[str] = set()     # models that rejected the `think` flag; don't send it to them again


def _chat_once(kwargs):
    """
    Call Ollama with thinking switched off. Models that have no thinking mode at all
    (e.g. Qwen3-4B-Instruct-2507, Granite 4) make some Ollama versions answer
    "does not support thinking"; for those, retry once without the flag and remember.
    """
    if kwargs["model"] in _NO_THINK_SUPPORT:
        return ollama.chat(**kwargs)
    try:
        return ollama.chat(**kwargs, think=config.THINK)
    except ollama.ResponseError as e:
        if "support" in str(e.error).lower() and "think" in str(e.error).lower():
            _NO_THINK_SUPPORT.add(kwargs["model"])
            return ollama.chat(**kwargs)
        raise


def same_model(installed: str, wanted: str) -> bool:
    """'llama3.2' means 'llama3.2:latest'; otherwise names must match exactly
    (so qwen3:4b is NOT satisfied by qwen3:4b-instruct-2507-q4_K_M)."""
    if installed == wanted:
        return True
    return ":" not in wanted.rsplit("/", 1)[-1] and installed == wanted + ":latest"


def installed_models() -> list:
    """Names of the models Ollama has downloaded. Raises LLMError if Ollama isn't running."""
    try:
        return [m.model for m in ollama.list().models]
    except (ConnectionError, httpx.HTTPError) as e:
        raise LLMError("Can't reach Ollama. Is it running? Try `ollama serve` in another terminal.") from e


def check_ready(model=None):
    """Fail early, with a clear message, if Ollama or the model is missing."""
    name = model or config.MODEL
    if not any(same_model(m, name) for m in installed_models()):
        raise LLMError(f"Model '{name}' isn't downloaded. Run: agentos model use {name}   (or: ollama pull {name})")
