"""
Context compaction: keep the conversation inside the model's context window.

Every tool result is added to the conversation, so long tasks grow until the
model starts "forgetting" the beginning (Ollama silently drops the oldest
tokens, which can include the system prompt and its safety rules!).

Before each step we estimate the size (about 4 characters per token) and, if
it's over the limit, shorten OLD tool results to a short stub. The system
prompt, the goal and the most recent results are never touched.
"""

from .. import config

KEEP_RECENT = 4          # newest messages left untouched
STUB_CHARS = 200


def _content(m):
    return m.get("content", "") if isinstance(m, dict) else (getattr(m, "content", "") or "")


def estimate_tokens(messages) -> int:
    return sum(len(_content(m)) for m in messages) // 4


def compact(messages, budget_tokens=None) -> int:
    """Shorten old tool results in place until under budget. Returns how many were shortened."""
    budget = budget_tokens or int(config.NUM_CTX * config.COMPACT_AT)
    if estimate_tokens(messages) <= budget:
        return 0
    shortened = 0
    for m in messages[2:-KEEP_RECENT]:                 # skip system prompt + goal, and the newest
        if isinstance(m, dict) and m.get("role") == "tool" and not m.get("compacted"):
            text = m["content"]
            if len(text) > STUB_CHARS:
                m["content"] = text[:STUB_CHARS] + f"\n[older result shortened from {len(text)} characters]"
                m["compacted"] = True
                shortened += 1
                if estimate_tokens(messages) <= budget:
                    break
    return shortened
