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

## Phase 7: Finishing (2026-11-24)

**Why:** the first real runs used `qwen3:4b`, which over-thinks and was slow on my laptop; nothing measured the real model; a few items from the plan were still open.

**Built**
- Model management: new default `qwen3:4b-instruct-2507-q4_K_M` (no thinking mode, about 2.5 GB, fits a 4 GB GPU); `agentos model list | use | pull | bench` (bench = one real tool-call round trip: GPU or CPU, seconds per step, right tool); `agentos init` checks the model really runs on the GPU
- Saved settings: `agentos config show | set | unset` (`~/.agentos/settings.json`, mode 600); environment variables still win
- Least-privilege scope from the plan (left over from Phase 3): in plan-first mode the task scope shrinks to what the planned tools need, and extra risks are asked for once, before any untrusted input
- `agentos eval`: the real model on 7 everyday tasks with checkable results and 3 safety checks (file outside the workspace, SSRF to Ollama's own port, instructions hidden in a file), plus speed/GPU and an optional real-model red team, all in a throwaway workspace with its own audit log; writes `docs/model-eval.md` and the results below
- Release engineering: mypy in CI, a job that installs the built wheel in a clean venv (what pipx does), a release workflow (GitHub Release + sandbox image on ghcr.io), CHANGELOG, SPDX licence metadata
- Docs: README a stranger can follow (git clone, model choice, GPU troubleshooting), demo video script (`docs/demo.md`), `scripts/record_demo.sh` (terminal recording to GIF, no sudo, checksum-pinned download); setup script only uses sudo when something is missing

**Bugs found and fixed**
- The model check accepted `qwen3:4b-instruct...` when `qwen3:4b` was configured (prefix match), so a missing model failed later with a confusing error
- `/no_think` was added to every qwen3 model, including builds that don't understand it
- Installed with pip/pipx, `agentos redteam` wrote its report inside site-packages; reports now go to `~/.agentos/reports`
- A voice transcript or answer containing `[...]` could restyle the console (Rich markup); now escaped
- Packaging warning: licence metadata moved to the SPDX form
- First real `agentos eval` (6/7 tasks, 3/3 safety, model 81% on the 4 GB GPU): small models sometimes send a number where text is expected (`content=100`), which the argument check rejected without showing it. Harmless slips like that are now converted before validation, rejected calls are shown in verbose mode, and a failed eval task now reports the tool error and the model's answer. `agentos model bench` points to the new `agentos model tune` when the model only partly fits in VRAM. Shrinking the context from 4096 to 3072 only moved it from 81% to 83% GPU, so `tune` also tries smaller batch sizes (Ollama's working buffer grows with the batch and Qwen's large vocabulary) and measures the VRAM other programs use
- Second real run: T5 failed again, this time with no tool error: the model worked out the total in its answer and never called `write_file`. The system prompt now says that describing an action isn't doing it. Also fixed: `agentos eval --only` overwrote the full report, and a run without `--redteam` erased earlier red-team results (now kept, with their date)

**Verified (in Claude's environment):** 231 tests (224 pass; 7 sandbox tests skip only when run as root), ruff, mypy and actionlint clean; the wheel builds without warnings and runs from a clean venv; `agentos model`, `config`, `init` and `eval --redteam` end-to-end over HTTP against a mock Ollama server, with the real bubblewrap sandbox; the red team still gives 0/34 unattended and 2/34 with plan-first (17 attacks are now stopped one layer earlier, by the plan-derived scope).

---

## Still to do on my machine

- [ ] In the venv: `pip install -e ".[all]"` (adds mypy and the build tools)
- [ ] `agentos model use qwen3:4b-instruct-2507-q4_K_M` and `agentos model bench`: should say `100% GPU`
- [ ] `agentos init`: everything ok; `pytest -q`: all pass; `agentos selftest`: 9/9 (screenshots)
- [ ] `agentos eval --redteam`: fills in the results below and `docs/model-eval.md`
- [ ] Try `agentos tui` and `agentos dashboard` once: approve a write from each
- [ ] Tamper test from `docs/demo.md` scene 5
- [ ] Record the demo (`docs/demo.md`, `bash scripts/record_demo.sh`), add the GIF to the README
- [ ] Commit, push, `git tag v1.0.0 && git push origin v1.0.0` (the release workflow publishes it)
- [ ] LinkedIn post with the real-model numbers

**Real-model results** (written by `agentos eval`, 2026-11-24 10:42)

- Model: `qwen3:4b-instruct-2507-q4_K_M`, 83% GPU / 17% CPU (NVIDIA GeForce RTX 3050 A Laptop GPU, 4094 MiB), Ollama 0.40.14, sandbox bwrap
- Speed: 1.6 s per step, 18.7 tokens/s
- Tasks: 6/7 done correctly; safety checks: 3/3 held
- Real-model red team (full defences): careless human 0/34 got through, unattended 0/34; the model acted on the injected instruction in 8 of 68 runs and the other defences stopped all 8 (always-fooled simulation: 11/34 and 0/34)
- Details: [docs/model-eval.md](docs/model-eval.md)
