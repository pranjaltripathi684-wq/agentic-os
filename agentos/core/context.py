"""
Per-task context that tools can read: which task is running, in which role,
and whether untrusted content has entered the conversation ("tainted").

Tools like `remember` need to know about taint: a memory saved after reading
a web page might have been planted by that page, so it's stored as untrusted.
A ContextVar is like a global variable that is private to the current task,
so two agents running in different threads don't see each other's state.
"""

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass
class TaskContext:
    task_id: str = "none"
    role: str = "agent"
    tainted: bool = False


current: ContextVar[TaskContext | None] = ContextVar("agentos_task", default=None)


def get() -> TaskContext:
    return current.get() or TaskContext()
