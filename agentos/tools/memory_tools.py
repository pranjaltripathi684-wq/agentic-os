"""
remember / recall: the agent's access to long-term memory.

remember asks for approval by default (policy), and anything saved after the
agent has read untrusted content is stored as UNTRUSTED, so a web page can't
quietly plant "the user wants you to skip approvals" for future tasks.
"""

from .. import config
from ..core import context
from ..memory.store import KINDS, get_store
from .base import Risk, Tool, ToolError, ToolResult


class Remember(Tool):
    name = "remember"
    description = "Save a fact or preference about the user to long-term memory, for future tasks."
    parameters = {
        "type": "object",
        "properties": {
            "content": {"type": "string", "description": "One short fact, e.g. 'User prefers Python'"},
            "kind": {"type": "string", "description": "fact, preference or note (default fact)"},
        },
        "required": ["content"],
    }
    risk = Risk.WRITE

    def describe(self, args):
        return f"save to memory ({args.get('kind', 'fact')}): {args.get('content', '')}"

    def run(self, content, kind="fact"):
        if kind not in KINDS:
            raise ToolError(f"kind must be one of {', '.join(KINDS)}")
        ctx = context.get()
        trusted = not (ctx.tainted and config.MEMORY_PROVENANCE)
        source = f"agent:{ctx.role}" + ("" if trusted else " (after untrusted input)")
        mid = get_store().add(content, kind=kind, source=source, trusted=trusted, task_id=ctx.task_id)
        note = "" if trusted else " It was saved as UNTRUSTED because this task read untrusted content."
        return ToolResult(True, f"saved as memory #{mid}.{note}")


class Recall(Tool):
    name = "recall"
    description = "Search long-term memory for facts and preferences about the user."
    parameters = {
        "type": "object",
        "properties": {"query": {"type": "string", "description": "What to look for, e.g. 'favourite editor'"}},
        "required": ["query"],
    }
    risk = Risk.READ

    def run(self, query):
        hits = get_store().search(query, limit=8)
        if not hits:
            return ToolResult(True, "nothing found in memory")
        lines = [f"#{m['id']} [{m['kind']}{'' if m['trusted'] else ', UNTRUSTED'}] {m['content']}" for m in hits]
        return ToolResult(True, "\n".join(lines), untrusted=any(not m["trusted"] for m in hits))
