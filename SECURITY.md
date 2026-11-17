# Security policy

Agentic OS is a security project, so finding holes in it is welcome.

## What counts

- A way for text the agent reads (a file, web page, command output, MCP tool, teammate agent) to make it **run a tool call that the policy should have blocked or asked about**
- A sandbox escape: reading or writing outside `/workspace`, reaching the network, or gaining privileges from `run_shell`
- A way to edit the audit log without `agentos audit verify` noticing (outside the documented limits in [docs/threat-model.md](docs/threat-model.md))
- Secrets that reach the model or the log despite redaction
- Bypassing the dashboard's token, CSRF header or Host check

Known, documented limitations (DNS rebinding in `http_get`, a human approving a flagged request, MCP servers running outside the sandbox) are listed in the threat model and don't need a report, but ideas for fixing them do.

## How to report

- **Bypasses of the defences:** the best report is a new entry in `agentos/redteam/payloads.yaml` plus the output of `agentos redteam --only <your ID>`. Open a pull request or an issue.
- **Anything that could hurt someone running Agentic OS today** (for example a sandbox escape): please email pranjaltripathi684@gmail.com first instead of opening a public issue, and allow a reasonable time for a fix.

Please only test against your own machine and your own accounts.
