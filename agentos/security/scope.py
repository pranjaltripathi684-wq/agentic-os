"""
Task scope: a short-lived, signed "capability token" per task.

Least privilege: a task gets only the kinds of access (risks) it needs, for a
limited time. The default scope is read + write + exec (no network). If the
agent needs more mid-task, you're asked to widen the scope; unattended runs
can't widen it at all.

The token is signed with HMAC using a random key that exists only in this
process's memory. Nothing else can mint or extend a token, and an expired or
altered token is rejected. It's the same idea as a session cookie or a JWT,
scaled down to one process.
"""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

from .. import config

_KEY = secrets.token_bytes(32)   # new every run; never written to disk


class ScopeError(Exception):
    pass


@dataclass(frozen=True)
class CapabilityToken:
    task_id: str
    risks: frozenset
    issued_at: float
    expires_at: float
    signature: str

    def allows(self, risk: str) -> bool:
        return risk in self.risks

    def remaining(self) -> int:
        return max(0, int(self.expires_at - time.time()))

    def describe(self) -> str:
        return f"{', '.join(sorted(self.risks))} for {self.remaining() // 60} min"


def _sign(task_id, risks, issued, expires) -> str:
    msg = f"{task_id}|{','.join(sorted(risks))}|{issued:.3f}|{expires:.3f}".encode()
    return hmac.new(_KEY, msg, hashlib.sha256).hexdigest()


def parse_risks(text: str) -> frozenset:
    presets = {"read-only": "read", "standard": "read,write,exec", "full": "read,write,network,exec"}
    text = presets.get(text.strip(), text)
    risks = frozenset(r.strip() for r in text.split(",") if r.strip())
    bad = risks - {"read", "write", "network", "exec"}
    if bad:
        raise ScopeError(f"unknown risk(s): {', '.join(sorted(bad))}")
    return risks


def issue(task_id: str, risks, ttl_minutes: int = None) -> CapabilityToken:
    risks = frozenset(risks) | {"read"}          # reading the workspace is always in scope
    issued = time.time()
    expires = issued + 60 * (ttl_minutes or config.SCOPE_TTL_MINUTES)
    return CapabilityToken(task_id, risks, issued, expires, _sign(task_id, risks, issued, expires))


def widen(token: CapabilityToken, risk: str) -> CapabilityToken:
    verify(token)
    return issue(token.task_id, token.risks | {risk})


def renew(token: CapabilityToken) -> CapabilityToken:
    return issue(token.task_id, token.risks)


def verify(token: CapabilityToken):
    expected = _sign(token.task_id, token.risks, token.issued_at, token.expires_at)
    if not hmac.compare_digest(expected, token.signature):
        raise ScopeError("task scope token was tampered with")
    if time.time() > token.expires_at:
        raise ScopeError("task scope has expired")
