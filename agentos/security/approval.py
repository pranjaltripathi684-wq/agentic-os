"""
The gate: every tool call passes through here before it runs.

    tool call
      -> stop requested?           (kill switch)
      -> rate limit                (runaway loops)
      -> task scope                (is this kind of access granted for this task?)
      -> plan check                (Phase 5: after untrusted input, only tools from the plan)
      -> policy                    (allow / ask / deny from the YAML policy)
      -> taint escalation          (after untrusted input, risky calls always ask)
      -> ask the human             (if needed; "allow for this task" remembered)

Approvers are the "human" part. The console one asks in the terminal; the
TUI and web dashboard have their own; AutoApprover answers fixed values for
tests and unattended runs.
"""

import time
from collections import deque
from dataclasses import dataclass

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from .. import config
from . import killswitch, scope
from .policy import Policy

console = Console()
RISK_COLOUR = {"read": "green", "write": "yellow", "network": "magenta", "exec": "red"}


@dataclass
class Decision:
    approved: bool
    reason: str
    rule: str = ""


@dataclass
class ApprovalRequest:
    tool: str
    risk: str
    summary: str
    reason: str          # why we're asking, from the policy
    tainted: bool


# ------------------------------------------------------------------ approvers
class ConsoleApprover:
    interactive = True

    def ask(self, req: ApprovalRequest) -> str:
        """Returns 'once', 'task' or 'deny'."""
        colour = RISK_COLOUR.get(req.risk, "yellow")
        note = f"\n[dim]why asking: {escape(req.reason)}[/dim]"
        if req.tainted:
            note += ("\n[bold magenta]The agent has read untrusted content this task. "
                     "Check this is what YOU asked for.[/bold magenta]")
        console.print(Panel(escape(req.summary) + note, title=f"[bold {colour}]The agent wants to use {escape(req.tool)}",
                            subtitle=f"risk: {req.risk}", border_style=colour))
        try:
            answer = console.input("[bold]Allow? \\[y]es once / \\[a]ll similar this task / \\[N]o: [/bold]")
        except (EOFError, KeyboardInterrupt):
            console.print()
            return "deny"
        return {"y": "once", "yes": "once", "a": "task", "all": "task"}.get(answer.strip().lower(), "deny")

    def ask_scope(self, risk: str, token) -> bool:
        console.print(Panel(f"This task's scope is: {token.describe()}.\n"
                            f"The agent now needs [bold]{risk}[/bold] access.",
                            title="[bold cyan]Widen task scope?", border_style="cyan"))
        try:
            return console.input(f"[bold]Grant {risk} for this task? \\[y/N] [/bold]").strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False


class AutoApprover:
    """Fixed answers. answer='deny' is what unattended runs use."""

    def __init__(self, answer="deny", widen_scope=False):
        self.answer, self.widen_scope, self.asked = answer, widen_scope, []
        self.interactive = answer != "deny"

    def ask(self, req):
        self.asked.append(req)
        return self.answer

    def ask_scope(self, risk, token):
        return self.widen_scope


# ------------------------------------------------------------------ the gate
class Gate:
    def __init__(self, approver=None, policy: Policy = None, token=None, task_id="task"):
        self.approver = approver or ConsoleApprover()
        self.policy = policy or Policy.load()
        self.token = token or scope.issue(task_id, scope.parse_risks(config.DEFAULT_SCOPE))
        self.grants = set()               # tools allowed "for this task"
        self.recent = deque()             # timestamps of executed calls
        self.planned_tools = None         # set by plan-first mode

    def check(self, tool, args: dict, tainted: bool = False) -> Decision:
        killswitch.check()
        risk = tool.risk.value
        interactive = self.approver.interactive and config.INTERACTIVE

        # rate limit
        now = time.time()
        while self.recent and now - self.recent[0] > 60:
            self.recent.popleft()
        if len(self.recent) >= config.RATE_LIMIT_PER_MIN:
            return Decision(False, f"rate limit: more than {config.RATE_LIMIT_PER_MIN} tool calls a minute",
                            "rate_limit")

        # task scope
        try:
            scope.verify(self.token)
        except scope.ScopeError as e:
            if "expired" in str(e) and interactive and self.approver.ask_scope("more time", self.token):
                self.token = scope.renew(self.token)
            else:
                return Decision(False, str(e), "scope")
        if not self.token.allows(risk):
            if interactive and self.approver.ask_scope(risk, self.token):
                self.token = scope.widen(self.token, risk)
            else:
                return Decision(False, f"'{risk}' is outside this task's scope ({self.token.describe()})", "scope")

        # plan-first: once untrusted content is in context, stick to the plan
        if tainted and self.planned_tools is not None and tool.name not in self.planned_tools:
            return Decision(False, f"{tool.name} wasn't in the plan made before reading untrusted content", "plan")

        verdict = self.policy.evaluate(tool, args)
        if verdict.decision == "deny":
            return Decision(False, f"policy: {verdict.reason}", verdict.rule)

        escalated = (tainted and config.TAINT_ESCALATION and verdict.decision == "allow"
                     and risk in self.policy.taint_escalate)
        if verdict.decision == "allow" and not escalated:
            self.recent.append(now)
            return Decision(True, f"policy: {verdict.reason}", verdict.rule)

        reason = ("untrusted content was read this task, so risky calls need you" if escalated
                  else verdict.reason)
        # "allow for this task" grants don't survive untrusted input for risky tools
        if tool.name in self.grants and not (tainted and risk in self.policy.taint_escalate):
            self.recent.append(now)
            return Decision(True, "allowed for this task by user", "grant")
        rule = "taint" if escalated else verdict.rule
        if not interactive:
            return Decision(False, f"needs approval, but nobody is here to approve ({reason})", rule)
        answer = self.approver.ask(ApprovalRequest(tool.name, risk, tool.describe(args), reason, tainted))
        if answer == "task":
            self.grants.add(tool.name)
        if answer in ("once", "task"):
            self.recent.append(now)
            return Decision(True, "approved by user" + (" for this task" if answer == "task" else ""), rule)
        return Decision(False, "denied by user", rule)
