"""
Secret redaction: keep passwords and API keys away from the model and the log.

If the agent runs `cat .env` or reads a config file, any secret in the output
would be sent to the model (and, with a cloud model, off your machine) and
written to the audit log forever. Redaction replaces it with [REDACTED:kind]
before either happens.

Two methods:
  1. Patterns for well-known secret formats (AWS, GitHub, private keys...).
  2. The actual values of your environment variables whose names look secret
     (OPENAI_API_KEY, DB_PASSWORD, ...): if any of those values appear in text,
     they're replaced, whatever their format.
"""

import os
import re

PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
                               re.DOTALL)),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("openai_key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("url_credentials", re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)")),       # https://user:password@host
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    # key = value / key: value where the key name says it's secret
    ("assignment", re.compile(
        r"(?i)\b([A-Z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
        r"[A-Z0-9_]*)(\s*[:=]\s*)(['\"]?)([^\s'\"]{6,})\3")),
]

SECRET_ENV_NAME = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)")


def _env_secrets():
    return [v for k, v in os.environ.items() if SECRET_ENV_NAME.search(k) and len(v) >= 8]


def redact(text: str):
    """Return (redacted_text, number_of_secrets_found)."""
    if not text:
        return text, 0
    count = 0
    for value in _env_secrets():
        if value in text:
            count += text.count(value)
            text = text.replace(value, "[REDACTED:env]")
    for kind, pattern in PATTERNS:
        if kind == "assignment":
            def keep_name(m):
                return f"{m.group(1)}{m.group(2)}{m.group(3)}[REDACTED:secret]{m.group(3)}"
            text, n = pattern.subn(keep_name, text)
        else:
            text, n = pattern.subn(f"[REDACTED:{kind}]", text)
        count += n
    return text, count


def redact_obj(obj):
    """Redact every string inside dicts/lists (used for log entries)."""
    if isinstance(obj, str):
        return redact(obj)[0]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj
