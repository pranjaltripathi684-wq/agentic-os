# Changelog

All notable changes to Agentic OS. Dates are when the work was finished; the build plan and
day-by-day notes are in [TIMELINE.md](TIMELINE.md).

## [1.0.0] - 2026-11-24

First public release: a personal, secure-by-design AI agent for Linux.

### Agent
- Local LLM via Ollama with tool calling, a step limit, context compaction and reasoning stripped from answers
- Default model `qwen3:4b-instruct-2507-q4_K_M`: no "thinking" delay, reliable tool calls, about 2.5 GB
- `agentos model list | use | pull | bench | tune`: switch models (saved), check that the model runs on the GPU, and
  find the context and batch size that fit a small GPU entirely
- `agentos config show | set | unset`: settings saved in `~/.agentos/settings.json`
- Multi-agent team (Supervisor, Researcher, Operator, Reviewer) with per-role tools and scopes
- SQLite memory with full-text search, provenance and task history; scheduled unattended jobs

### Security
- Sandboxed shell (bubblewrap or Docker) with a 9-check escape self-test
- YAML policy engine: allow / ask / deny by risk, tool, path, domain and shell pattern; deny by default
- Signed, expiring task-scope tokens; in plan-first mode the scope shrinks to what the planned tools need
- Prompt-injection defences: fenced untrusted output, taint escalation, heuristics, dual-LLM quarantine, plan-first
- Secret redaction, SSRF-safe web fetching, MCP tool pinning against rug pulls
- Hash-chained audit log with Ed25519-signed checkpoints; kill switch and rate limit

### Testing and evaluation
- 210+ tests that run without Ollama (fake models), mypy-clean, ruff-clean
- Red team: 34 attacks mapped to the OWASP Top 10 for LLMs, at three defence levels, with a generated report
- `agentos eval`: real-model tasks, safety checks, speed/GPU and an optional real-model red team, written to
  `docs/model-eval.md` and TIMELINE.md

### Interfaces and release
- CLI, Textual TUI, localhost web dashboard (token, CSRF and DNS-rebinding protection), push-to-talk voice
- CI: lint, type check, tests on Python 3.10 and 3.12, red-team regression run, wheel install smoke test
- Release workflow: GitHub Release with the wheel, and the sandbox image on ghcr.io
