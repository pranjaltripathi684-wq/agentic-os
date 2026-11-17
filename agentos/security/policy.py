"""
The policy engine: turns a tool call into allow / ask / deny, with a reason.

Phase 2 had two hard-coded rules (a denylist, and "read-only tools don't ask").
Now the rules live in a YAML file you can read and change without touching
code (policies/default.yaml, or your copy at ~/.agentos/policy.yaml).

Design principles:
  - Deny by default: a call that matches no rule is denied.
  - Every decision carries a human-readable reason and the rule that made it,
    so the audit log explains WHY something ran or didn't.
  - The policy is loaded from outside the workspace, so the agent can't edit it.
"""

import fnmatch
import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import urlparse

import yaml

from .. import config

DECISIONS = ("allow", "ask", "deny")
RISKS = ("read", "write", "network", "exec")


class PolicyError(ValueError):
    """The policy file is invalid."""


@dataclass
class Verdict:
    decision: str      # allow | ask | deny
    reason: str
    rule: str          # which part of the policy decided, e.g. "shell.deny_patterns[3]"


@dataclass
class Policy:
    risk_defaults: dict
    tools: dict = field(default_factory=dict)
    path_deny: list = field(default_factory=list)
    allow_domains: list = field(default_factory=list)
    deny_domains: list = field(default_factory=list)
    unlisted: str = "ask"
    shell_deny: list = field(default_factory=list)       # compiled regexes
    shell_auto_allow: set = field(default_factory=set)
    taint_escalate: set = field(default_factory=lambda: {"write", "network", "exec"})
    source: str = "(built in)"

    # ------------------------------------------------------------- loading
    @classmethod
    def load(cls, path=None):
        """Load ~/.agentos/policy.yaml if it exists, else policies/default.yaml."""
        if path is None:
            path = config.POLICY_FILE if config.POLICY_FILE.exists() else config.DEFAULT_POLICY_FILE
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (OSError, yaml.YAMLError) as e:
            raise PolicyError(f"can't read policy {path}: {e}") from e
        policy = cls.from_dict(data)
        policy.source = str(path)
        return policy

    @classmethod
    def from_dict(cls, d: dict):
        known = {"version", "risk_defaults", "tools", "paths", "network", "shell", "taint"}
        unknown = set(d) - known
        if unknown:
            raise PolicyError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")
        defaults = d.get("risk_defaults") or {}
        for risk in RISKS:
            if defaults.get(risk) not in DECISIONS:
                raise PolicyError(f"risk_defaults.{risk} must be one of {DECISIONS}")
        tools = d.get("tools") or {}
        for name, decision in tools.items():
            if decision not in DECISIONS:
                raise PolicyError(f"tools.{name} must be one of {DECISIONS}, not {decision!r}")
        net = d.get("network") or {}
        if net.get("unlisted", "ask") not in ("ask", "deny"):
            raise PolicyError("network.unlisted must be ask or deny")
        shell = d.get("shell") or {}
        try:
            deny = [re.compile(p, re.IGNORECASE) for p in shell.get("deny_patterns") or []]
        except re.error as e:
            raise PolicyError(f"bad regex in shell.deny_patterns: {e}") from e
        escalate = set((d.get("taint") or {}).get("escalate", ["write", "network", "exec"]))
        if not escalate <= set(RISKS):
            raise PolicyError(f"taint.escalate may only list {RISKS}")
        return cls(risk_defaults=dict(defaults), tools=dict(tools),
                   path_deny=list((d.get("paths") or {}).get("deny") or []),
                   allow_domains=[x.lower() for x in net.get("allow_domains") or []],
                   deny_domains=[x.lower() for x in net.get("deny_domains") or []],
                   unlisted=net.get("unlisted", "ask"), shell_deny=deny,
                   shell_auto_allow=set(shell.get("auto_allow") or []), taint_escalate=escalate)

    # ------------------------------------------------------------- evaluation
    def evaluate(self, tool, args: dict) -> Verdict:
        name, risk = tool.name, tool.risk.value

        # 1. deny rules
        if name == "run_shell":
            command = args.get("command", "")
            for i, rx in enumerate(self.shell_deny):
                if rx.search(command):
                    return Verdict("deny", "command matches a blocked pattern", f"shell.deny_patterns[{i}]")
            hit = self._path_hit(_shell_words(command))
            if hit:
                return Verdict("deny", f"command touches a protected path ({hit})", "paths.deny")
        for key, value in args.items():
            if key == "path" and isinstance(value, str):
                hit = self._path_hit([value])
                if hit:
                    return Verdict("deny", f"'{value}' is a protected path ({hit})", "paths.deny")
        host = None
        if name == "http_get":
            host = (urlparse(args.get("url", "")).hostname or "").lower()
            if _domain_match(host, self.deny_domains):
                return Verdict("deny", f"{host} is a blocked domain", "network.deny_domains")

        # 2. per-tool rules (exact name first, then wildcards like mcp_*)
        if name in self.tools:
            return Verdict(self.tools[name], f"rule for {name}", f"tools.{name}")
        for pattern, decision in self.tools.items():
            if fnmatch.fnmatch(name, pattern):
                return Verdict(decision, f"rule for {pattern}", f"tools.{pattern}")

        # 3. network
        if host is not None:
            if _domain_match(host, self.allow_domains):
                return Verdict("allow", f"{host} is an allowed domain", "network.allow_domains")
            return Verdict(self.unlisted, f"{host} is not on the allowed list", "network.unlisted")

        # 4. shell auto-allow
        if name == "run_shell" and self.risk_defaults["exec"] != "deny":
            ok, why = self.is_simple_readonly(args.get("command", ""))
            if ok:
                return Verdict("allow", "simple read-only command (runs in the sandbox)", "shell.auto_allow")

        # 5. defaults
        if risk in self.risk_defaults:
            return Verdict(self.risk_defaults[risk], f"default for {risk} tools", f"risk_defaults.{risk}")
        return Verdict("deny", "no rule matches (deny by default)", "default-deny")

    def is_simple_readonly(self, command: str):
        """True if every program in the command is on auto_allow and nothing writes or nests."""
        if not command.strip():
            return False, "empty"
        harmless = command.replace("&&", " ").replace("2>&1", " ").replace("2>/dev/null", " ")
        if re.search(r"[`<>&]|\$\(|\$\{", harmless):
            return False, "redirection, background job or substitution"
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=";|&")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            return False, "can't parse"
        segment_start, program = True, None
        for tok in tokens:
            if tok in (";", "|", "||", "&&"):
                segment_start = True
                continue
            if segment_start:
                if re.match(r"^\w+=", tok):            # VAR=value prefix
                    continue
                if tok not in self.shell_auto_allow:
                    return False, f"'{tok}' is not on auto_allow"
                program, segment_start = tok, False
                continue
            if program == "find" and tok in ("-exec", "-execdir", "-delete", "-ok", "-fprint", "-fprintf", "-fls"):
                return False, "find with an action"
            if program == "sort" and (tok in ("-o", "--output") or tok.startswith("--output=")):
                return False, "sort writing a file"
        return True, "ok"

    def _path_hit(self, words):
        for word in words:
            p = word.strip("'\"")
            for prefix in ("/workspace/", "./"):
                if p.startswith(prefix):
                    p = p[len(prefix):]
            p = str(PurePosixPath(p))
            for pattern in self.path_deny:
                # "**/x" should also match "x" at the top level
                if fnmatch.fnmatch(p, pattern) or (pattern.startswith("**/") and fnmatch.fnmatch(p, pattern[3:])):
                    return pattern
        return None

    def describe(self) -> str:
        lines = [f"policy: {self.source}", "risk defaults: " +
                 ", ".join(f"{k}={v}" for k, v in self.risk_defaults.items())]
        lines.append("tool rules: " + (", ".join(f"{k}={v}" for k, v in self.tools.items()) or "none"))
        lines.append(f"protected paths: {len(self.path_deny)} patterns")
        lines.append(f"allowed domains: {', '.join(self.allow_domains) or 'none'}; unlisted={self.unlisted}")
        lines.append(f"blocked domains: {len(self.deny_domains)}; shell deny patterns: {len(self.shell_deny)}")
        lines.append(f"shell auto-allow: {', '.join(sorted(self.shell_auto_allow))}")
        lines.append(f"after untrusted input, always ask for: {', '.join(sorted(self.taint_escalate))}")
        return "\n".join(lines)


def _domain_match(host: str, patterns) -> bool:
    for p in patterns:
        if fnmatch.fnmatch(host, p) or (p.startswith("*.") and host == p[2:]):
            return True
    return False


def _shell_words(command: str):
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()
