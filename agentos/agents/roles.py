"""
Specialist roles for the multi-agent team.

Each role gets (1) only the tools it needs and (2) a task scope that matches.
Two independent layers: even if a prompt injection convinces the Researcher
to "just run this command", it has no run_shell tool AND its scope has no exec.

All roles share ONE loaded model with different system prompts. Loading
three models at once wouldn't fit in 12 GB of RAM.
"""

from dataclasses import dataclass

from ..tools.registry import ToolRegistry


@dataclass(frozen=True)
class Role:
    name: str
    tools: frozenset
    scope: str
    prompt: str


ROLES = {
    "researcher": Role(
        "researcher",
        frozenset({"read_file", "list_dir", "search_files", "http_get", "recall", "system_info"}),
        "read,network",
        "You are the RESEARCHER on a small team. You find and summarise information: read files in "
        "/workspace, fetch web pages, search memory. You cannot change anything or run commands. "
        "Finish with a concise summary of the facts your teammates need."),
    "operator": Role(
        "operator",
        frozenset({"run_shell", "write_file", "read_file", "list_dir", "search_files", "system_info"}),
        "read,write,exec",
        "You are the OPERATOR on a small team. You make changes in /workspace: write files and run "
        "commands in the sandbox. You have no internet. Finish by stating exactly what you changed."),
    "reviewer": Role(
        "reviewer",
        frozenset({"read_file", "list_dir", "search_files"}),
        "read",
        "You are the REVIEWER on a small team. Check whether the work actually achieved the goal by "
        "looking at the files in /workspace. Your final answer MUST start with PASS or FAIL, followed "
        "by one or two sentences of evidence."),
}


def registry_for(role: Role, full: ToolRegistry) -> ToolRegistry:
    """A registry containing only the tools this role may use."""
    return ToolRegistry([t for t in full if t.name in role.tools])
