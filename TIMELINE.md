# Agentic OS: build timeline

Each phase: what was built, how it was verified, and what's still to check on my own machine.

---

## Phase 1: Core agent loop (2026-11-06)

**Built:** agent loop with a step limit, `run_shell` tool, denylist + `[y/N]` approval, JSONL action log, Ollama wrapper.

**Verified:** 42 tests (fake model); end-to-end run through a mock Ollama server; first real run on my laptop (qwen3:4b, WSL2): "How much free disk do I have?" ran `df -h` with my approval and answered correctly (945 GB free).

**Problems found in the real run (fixed in Phase 2):** the answer leaked the model's reasoning; each step took 1 to 2.5 minutes on CPU.

---

## Phase 2: Tool plugins and sandbox (2026-11-07)

**Built:** `core/ tools/ security/` structure; `Tool` base class with risk levels and argument validation; auto-discovering registry; 7 tools (workspace-confined, symlink-safe file tools, SSRF-safe `http_get`, sandboxed `run_shell`, `system_info`); risk-based approval; untrusted output fenced; bubblewrap and Docker sandboxes with a 9-check escape self-test; MCP client + demo server.

**Bugs the tests caught:** bubblewrap left the sandbox's `/etc` writable (fixed with `--remount-ro /`); a dropped Ollama connection crashed the agent; the process-limit check missed cgroup v1.

---

## Phase 3: Policy engine and tamper-evident audit log (2026-11-07)

**Built**
- YAML policy engine (`agentos/policies/default.yaml`): allow/ask/deny per risk, tool, protected path, domain allow/deny lists, shell deny patterns, shell auto-allow for simple read-only commands; deny by default; every decision carries its rule. `agentos policy check` tests a call without running it
- Task scope: HMAC-signed, 15-minute capability tokens; default read+write+exec; widening needs approval
- Gate with "allow once / allow for this task / deny"
- Secret redaction (API keys, tokens, private keys, URL credentials, key=value secrets, env values) before the model and the log
- Hash-chained audit log in `~/.agentos/audit.jsonl`, Ed25519-signed checkpoints, `agentos audit verify`
- Kill switch (`agentos stop`, STOP file + interrupt + sandbox cleanup); rate limit (20 calls/min)
- Threat model (STRIDE): `docs/threat-model.md`

**Verified:** tests for every layer: edited, re-hashed, deleted and fully rewritten log entries are all detected; forged and expired scope tokens are rejected; 14 dangerous shell commands are denied, 7 simple ones auto-allowed.

---

## Phase 4: Memory and multi-agent (2026-11-07)

**Built**
- SQLite memory with FTS5 search, optional Ollama embeddings, provenance (memories saved after untrusted input are untrusted and never auto-loaded); `remember` / `recall` tools; task history; `agentos memory`, `agentos history`
- Context compaction (old tool results shortened before the context window overflows)
- Multi-agent team: Supervisor plans, then Researcher (read + web), Operator (shell + write) and Reviewer (read-only, PASS/FAIL). Roles get filtered tools *and* matching scopes; teammate output is fenced and starts the next agent tainted
- Scheduler (`agentos schedule`, `agentos daemon`): unattended jobs where anything that would ask is denied; desktop notifications

**Verified:** a hijacked Researcher can't reach `run_shell`; the Operator asks even for `ls` after reading teammate output; scheduled jobs can't run anything that needs approval.

---

## Phase 5: Red team and hardening (2026-11-07)

**Built**
- Injection guard: heuristics (override, role change, fake system tags, exfiltration, pipe-to-shell, approval bypass, zero-width text, and injections hidden in base64), dual-LLM quarantine mode, plan-first mode, taint escalation
- MCP pinning: SHA-256 of each tool's description + schema, trust on first use, changed tools refused
- 34 attacks (`agentos/redteam/payloads.yaml`) mapped to the OWASP Top 10 for LLMs; a harness that runs each one in a throwaway workspace with canaries, at 3 defence levels x 2 human behaviours, against an obedient (always-fooled) model
- Report generator: `docs/redteam-report.md` + chart

**Results (bubblewrap sandbox, obedient model)**

| Defence level | careless human | unattended |
| --- | --- | --- |
| Phase 2 baseline | 22/34 got through | 3/34 |
| Full defences | 11/34 | **0/34** |
| Full + plan-first | 2/34 | **0/34** |

**Harness bugs found and fixed:** a traceback echoing source code looked like a successful network connection (RT32); HTML comments never reached the model, so RT19 was rewritten with hidden text; the simulated shell was credited as "sandbox".

---

## Phase 6: Interfaces and release (2026-11-07)

**Built:** `agentos` command (17 subcommands) and `pip install -e .`; `agentos init` health check; Textual TUI with approval pop-ups and a live audit panel; FastAPI dashboard (127.0.0.1 only, random token, CSRF header, Host check against DNS rebinding, CSP, textContent only); push-to-talk voice with typed confirmation; desktop notifications (notify-send or a Windows toast from WSL); `pyproject.toml` with optional extras; GitHub Actions CI; architecture doc; README.

**Verified (in Claude's environment):** 194 tests pass on Python 3.10 after a clean `pip install -e ".[all]"`, with real escape tests on bubblewrap 0.9 and Docker; ruff clean; TUI driven headlessly (pop-up, y/n); dashboard approval flow and token/CSRF/host checks; end-to-end `agentos run` and `agentos run --team` through a mock Ollama server. Not yet run on bubblewrap 0.6.1 (Ubuntu 22.04's version); the laptop disconnected before that test.

---

## Still to do on my machine (final testing)

- [ ] `bash scripts/setup_wsl.sh`, then `agentos init`: everything ok
- [ ] `agentos selftest`: 9/9 PASS (screenshot)
- [ ] `pytest -q`: all pass (screenshot)
- [ ] `agentos run "What's my OS, RAM and free disk space?"`
- [ ] `agentos run "Write plan.md with three goals for this week, then list the folder"`
- [ ] `agentos run --scope full "Fetch https://example.com and tell me its title"`
- [ ] Escape attempts fail: "Read /etc/passwd", "Fetch http://127.0.0.1:11434/api/tags", "Run cat ~/.bashrc"
- [ ] Injection test: `cp demo/notes.txt ~/agentos-workspace/` then `agentos run "Summarise notes.txt"`
- [ ] `agentos run --team "Find the largest file in the workspace and write its name to biggest.txt"`
- [ ] `agentos tui` and `agentos dashboard`: approve a write from each
- [ ] `agentos stop` from a second terminal during a task
- [ ] `agentos audit verify`, `agentos audit checkpoint`, then edit one line of `~/.agentos/audit.jsonl` and verify again
- [ ] `agentos redteam --model ollama --levels full --humans careless`: how often does the REAL model fall for the injections?
- [ ] Record a 3 to 5 minute demo video; write the LinkedIn/blog post; push to GitHub; tag v1.0

**Real-model results**

- Model, date:
- Real-model red-team results:
- Notes:
