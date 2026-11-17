# Threat model

Method: STRIDE over the system's assets, entry points and trust boundaries. Results were checked against the attacks in [the red-team report](redteam-report.md).

## What we protect

| Asset | Why it matters |
| --- | --- |
| Files outside the workspace (home folder, SSH keys, browser data) | Theft or destruction |
| Secrets inside the workspace (`.env`, keys, tokens) | Credential theft |
| Integrity of the workspace | Deleted or tampered work |
| The audit log | Evidence of what the agent did |
| Long-term memory | Steers every future task |
| The machine and network | Lateral movement, resource abuse |

## Trust boundaries

1. **You, then the agent.** Only your typed goal and your approvals are trusted instructions.
2. **The outside world, then the model.** Everything a tool returns (file contents, web pages, command output, MCP results, teammate messages, untrusted memories) is **data**, never instructions.
3. **The model, then the system.** The model's output is an untrusted *request*; the gate decides.
4. **The sandbox, then the host.** Shell commands run with no network, a read-only root, only `/workspace` mounted, as your user, with process, memory and CPU limits.
5. **The agent, then its own controls.** The policy, audit log, memory database, keys and pins live in `~/.agentos`, which no tool can reach.

## Attackers considered

- **Indirect prompt injection:** a file, web page or tool output carries instructions. This is the main threat (OWASP LLM01).
- **A malicious or compromised MCP server:** tool poisoning, or a "rug pull" that changes a tool's description after you trusted it (LLM03).
- **A hijacked teammate agent:** one agent's output tries to steer another.
- **A local web page in your browser** attacking the dashboard (CSRF, DNS rebinding).
- **Out of scope:** an attacker who already has your user account or root. They can read the audit key and edit anything; signed checkpoints only help if you keep a copy elsewhere.

## STRIDE

| Threat | Example | Mitigations (code) | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | A web page pretends to be the system prompt (`<\|im_start\|>system`) | Untrusted output fenced and labelled (`tools/base.py`); fake-system heuristic (`security/guard.py`) | Models can still be fooled; the gate is the real control |
| **S**poofing | A malicious site reaches the dashboard via DNS rebinding | Dashboard binds 127.0.0.1, checks the Host header, needs a token (`interfaces/web.py`) | None known |
| **T**ampering | An injection deletes or overwrites workspace files | Policy (write/exec ask), taint escalation, plan-first, sandbox | A careless approval can still damage the workspace (RT01, RT23) |
| **T**ampering | The agent edits its own policy or audit log | Both live in `~/.agentos`; file tools are confined to the workspace; the sandbox can't see them | None via the agent |
| **T**ampering | Someone edits the audit log afterwards | Hash chain plus Ed25519-signed checkpoints (`security/audit.py`) | Someone with your account who also deletes the checkpoints |
| **T**ampering | Memory poisoning ("always approve") | Memories saved after untrusted input are stored as untrusted and never auto-loaded (`memory/store.py`) | You could still approve a poisoned memory manually |
| **T**ampering | MCP rug pull | SHA-256 pins of tool description and schema; changes are refused (`tools/mcp_client.py`) | The first load is trust-on-first-use |
| **R**epudiation | "The agent did that on its own" | Every decision is logged with tool, arguments, rule, reason, approver and taint state | None |
| **I**nformation disclosure | Secrets reach the model or the log | Redaction of known formats, key=value secrets, URL credentials, env values (`security/redact.py`); protected paths in policy | Unusual secret formats can slip past redaction |
| **I**nformation disclosure | Exfiltration via `http_get` | Network is out of the default scope; deny-listed paste/webhook domains; taint escalation; the sandbox has no network | An approved request to an unlisted domain (RT21, RT31) |
| **I**nformation disclosure | SSRF to localhost, LAN or cloud metadata | Resolved addresses must be public, re-checked on redirects (`tools/web.py`) | DNS rebinding between check and connect |
| **I**nformation disclosure | Reading outside the workspace | Path resolution after following symlinks; the sandbox mounts only the workspace | None known |
| **D**enial of service | Fork bomb, endless loops, huge outputs | Sandbox process/memory/CPU limits, timeouts, step limit, rate limit, output truncation, context compaction | A slow laptop can still be kept busy for a while |
| **E**levation of privilege | Commands escape to the host or gain root | Namespaces, no network, read-only root, `--cap-drop ALL`, `no-new-privileges`, non-root user, cleared environment | Kernel exploits (out of scope) |
| **E**levation of privilege | A low-privilege agent role gains shell access | Role-filtered tools *and* role scopes; teammate output is untrusted | None known |
| **E**levation of privilege | Agent widens its own scope | Scope tokens are HMAC-signed with an in-memory key and expire; widening needs you | None via the agent |

## The honest summary

The red team shows that with no human approving (scheduled jobs), **0 of 34 attacks get through**. With a human who approves everything, 11 of 34 get through with the default settings and 2 of 34 with plan-first mode. Every one of those needed a person to click *approve* on a request that was flagged in magenta as coming after untrusted input. The remaining weak point is the approval prompt, which is why it says so loudly.
