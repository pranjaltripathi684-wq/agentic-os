"""
run_shell: the agent's most powerful tool, now inside the sandbox.

Same idea as Phase 1 (the model asks, you approve, it runs), except the
command no longer runs as you on your real system. It runs in the sandbox
from agentos/security/sandbox.py, which sees only /workspace and has no network.
"""

from ..security.sandbox import get_sandbox
from .base import Risk, Tool, ToolResult, truncate


class RunShell(Tool):
    name = "run_shell"
    description = ("Run one non-interactive bash command in an isolated Linux sandbox. "
                   "Only /workspace is visible and there is no internet. Needs user approval.")
    parameters = {
        "type": "object",
        "properties": {"command": {"type": "string", "description": "The bash command, e.g. 'ls -la'"}},
        "required": ["command"],
    }
    risk = Risk.EXEC

    def describe(self, args):
        return args.get("command", "")

    def run(self, command):
        box = get_sandbox()
        r = box.run(command)
        out, cut1 = truncate(r.stdout)
        err, cut2 = truncate(r.stderr)
        text = out
        if err:
            text += ("\n" if text else "") + "[stderr]\n" + err
        result = ToolResult(ok=(r.exit_code == 0), output=text, truncated=cut1 or cut2,
                            untrusted=True, meta={"exit_code": r.exit_code, "sandbox": box.name})
        if r.timed_out:
            result.error = "command timed out and was killed"
        return result
