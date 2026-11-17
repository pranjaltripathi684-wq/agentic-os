# Agentic OS

[![CI](https://github.com/pranjaltripathi684-wq/agentic-os/actions/workflows/ci.yml/badge.svg)](https://github.com/pranjaltripathi684-wq/agentic-os/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Local LLM](https://img.shields.io/badge/LLM-local%20via%20Ollama-black)

**A personal, secure-by-design AI agent for Linux.** Describe a goal in plain language and a local LLM (via Ollama) works out the steps and uses tools to do it. Every tool call passes a policy engine, task scopes, taint tracking and, when needed, you. Shell commands run in a sandbox, and everything lands in a tamper-evident audit log.

Most hobby agents give an LLM a shell and hope. This one assumes the model **will** be tricked by prompt injection, and is built so that a fooled model still can't do much damage. [The red-team report](docs/redteam-report.md) measures exactly how much.

![Attack success by defence level](docs/redteam-chart.svg)

> 34 attacks against a model that obeys every injected instruction. Unattended, the full defences stop **all 34**. Even with a human who approves everything, plan-first mode lets only 2 through.

## Features

| Area | What you get |
| --- | --- |
| Agent | Local LLM via Ollama, tool calling, step limit, context compaction, reasoning stripped from answers |
| Tools | `read_file` `write_file` `list_dir` `search_files` `system_info` `http_get` `run_shell` `remember` `recall`, plus any MCP server; drop a file in `agentos/tools/` to add one |
| Sandbox | bubblewrap or Docker: only the workspace visible, no network, read-only root, not root, no env secrets, process/memory/CPU limits. `agentos selftest` proves it |
| Policy engine | YAML rules: allow / ask / deny per risk, tool, path, domain and shell pattern; deny by default; every decision explained |
| Task scope | Signed, expiring capability tokens (read / write / network / exec); widening needs you |
| Injection defences | Untrusted output fenced, taint escalation, heuristics (incl. base64 and zero-width text), dual-LLM quarantine, plan-first mode |
| Secrets | Redaction of API keys, tokens, private keys, URL credentials and env values before the model or the log sees them |
| Audit | Hash-chained JSONL log, Ed25519-signed checkpoints, `agentos audit verify` names the first tampered entry |
| Memory | SQLite + full-text search (+ optional embeddings); memories saved after untrusted input are stored as untrusted |
| Multi-agent | Supervisor, then Researcher (no shell), Operator (no web) and Reviewer (read-only); teammate output is untrusted |
| Supply chain | MCP tool descriptions pinned by SHA-256; a changed tool (rug pull) is refused |
| Control | Kill switch (`agentos stop`), rate limit, scheduled unattended jobs where "ask" means "deny" |
| Interfaces | CLI, full-screen TUI, web dashboard (localhost, token, CSRF and DNS-rebinding protection), push-to-talk voice |
| Red team | 34 attacks mapped to the OWASP Top 10 for LLMs, a harness, and a generated report with before/after numbers |

## Quick start (WSL2 Ubuntu or Kali)

```bash
cd "/mnt/c/Users/Pranjal Tripathi/OneDrive/Desktop/Agentic OS"
bash scripts/setup_wsl.sh               # Ollama + qwen3:4b, bubblewrap, Python env, health check
source ~/.venvs/agentos/bin/activate    # every new terminal
agentos run "What's my OS, RAM and free disk space?"
```

Slow laptop? Use `--model qwen3:1.7b` (run `ollama pull qwen3:1.7b` first). The first task of a session loads the model, and later ones are faster.

## Commands

| Command | What it does |
| --- | --- |
| `agentos init` | Health check: Python, Ollama, sandbox self-test, policy, audit log |
| `agentos run "goal"` | One task. Options: `--team`, `--scope read-only/standard/full`, `--plan-first`, `--quarantine`, `--model`, `--sandbox` |
| `agentos chat` | Give goals one after another |
| `agentos tui` | Full-screen terminal UI with approval pop-ups and a live audit panel |
| `agentos dashboard` | Web UI at 127.0.0.1: start tasks, approve or deny, history, audit status |
| `agentos voice` | Push-to-talk (optional extras); you confirm each transcribed goal by keyboard |
| `agentos stop` | Kill switch, from another terminal |
| `agentos selftest` | Try 9 ways to escape the sandbox |
| `agentos audit verify / show / checkpoint` | Check, read or sign the audit log |
| `agentos policy show / check / edit` | Inspect or customise the rules; `check` tests a call without running it |
| `agentos memory list / add / search / forget` | Long-term memory |
| `agentos history [task]` | Past tasks, or every step of one |
| `agentos schedule add / list / remove`, `agentos daemon` | Unattended jobs, e.g. `--every daily@09:00` |
| `agentos mcp list / pin` | MCP servers and pinned tool fingerprints |
| `agentos redteam [--model ollama]` | Attack yourself and regenerate `docs/redteam-report.md` |
| `agentos tools` | Tools, their risk and the policy default |

`python main.py ...` works the same without installing.

## How a tool call is decided

```
model asks for a tool
  -> arguments valid?  -> kill switch / rate limit -> task scope -> (plan-first)
  -> policy: deny rules -> tool rules -> domains -> shell auto-allow -> risk defaults
  -> after untrusted input: risky calls always ask
  -> run (sandbox / confined file tools / SSRF-safe web / pinned MCP)
  -> redact secrets -> fence + scan untrusted output -> audit log
```

Details: [architecture](docs/architecture.md) and [threat model](docs/threat-model.md).

## Project layout

```
agentos/
  core/        agent loop, LLM client, task context
  tools/       base class, registry, file / web / shell / system / memory / MCP tools
  security/    gate + approvers, policy, scope tokens, sandbox, redaction, guard, audit, kill switch
  memory/      SQLite memory store, context compaction
  agents/      multi-agent team, scheduler
  interfaces/  TUI, web dashboard, voice
  redteam/     attack library, harness, report
  policies/    default.yaml
  cli.py       the agentos command
docs/          architecture, threat model, red-team report
sandbox/       Dockerfile for the Docker backend
tests/         190+ tests (fake model; no Ollama needed)
```

## Development

```bash
pip install -e ".[all]"
ruff check . && pytest -q           # sandbox escape tests run if bubblewrap/Docker are available
agentos redteam                     # regenerate the report
```

CI (GitHub Actions) runs lint, tests on Python 3.10 and 3.12, and a red-team regression run on every push.

## Known limitations

- A human who approves a flagged request can still be talked into damage. That's the main residual risk, shown honestly in the red-team report.
- `http_get` checks DNS and then connects, so a DNS-rebinding attacker could race it.
- MCP servers run outside the sandbox; only enable ones you trust.
- Signed audit checkpoints protect against tampering only if you keep a copy of them off the machine.
- Built and tested on Linux (WSL2, Ubuntu, Kali). macOS and Windows-native aren't supported.

## Author

**Pranjal Tripathi**, CSE student focused on security and AI agents.
[GitHub](https://github.com/pranjaltripathi684-wq) · [LinkedIn](https://linkedin.com/in/pranjaltripathi-sec)

Found a way past the defences? See [SECURITY.md](SECURITY.md). A new red-team payload is the best possible contribution.

## Licence

MIT, see [LICENSE](LICENSE).
