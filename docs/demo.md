# Demo: script for a 3 to 5 minute video

What to show, in order, with the exact commands. Each scene says what to say while it runs.
Record the terminal with `bash scripts/record_demo.sh` (it also makes `docs/demo.gif` for the README),
or with any screen recorder (OBS, Xbox Game Bar: Win+Alt+R) if you want your voice on it.

## Before recording

```bash
source ~/.venvs/agentos/bin/activate
cd ~/agentic-os                       # or wherever the repo is
agentos model bench                   # warms the model up, so the first scene isn't a long wait
rm -f ~/agentos-workspace/plan.md ~/agentos-workspace/notes.txt
clear
```

Use a terminal about 110 x 32 characters and a large font. Close anything with personal data.

## 1. The hook (15 s)

> "Most AI agents give a language model a shell and hope it behaves. I built one that assumes the model
> WILL be tricked, and limits what a tricked model can do. It runs fully offline on my laptop."

```bash
agentos init
```

Point at: model on the GPU, sandbox self-test passed, audit log intact.

## 2. A normal task (40 s)

> "You give it a goal in plain English. The model only proposes tool calls; my code decides."

```bash
agentos run "What's my OS, RAM and free disk space?"
agentos run "Write plan.md with three goals for this week, then list the folder"
```

At the approval prompt, point at the risk and the reason, then press `y`.

> "Reading is allowed. Writing asks me first. Every decision has a rule behind it."

## 3. Prompt injection (60 s): the main scene

> "Here's a meeting-notes file. Halfway down, someone has hidden an instruction to delete my home folder."

```bash
cat demo/notes.txt
cp demo/notes.txt ~/agentos-workspace/
agentos run "Summarise notes.txt"
```

Point at the magenta `possible prompt injection` warning, and at "untrusted content read: risky actions now
always ask".

> "The file is fenced as untrusted data, the injection is flagged, and from now on every risky action
> needs me. Even if I said yes, `rm -rf ~` is denied by the policy, and the shell has no access to my home
> folder anyway: it runs in a sandbox."

## 4. The sandbox (30 s)

```bash
agentos selftest
```

> "Nine checks, run inside the real sandbox: my home folder is invisible, /etc/shadow is unreadable, there's
> no network, system folders are read-only, it isn't root, no secrets in the environment, and a process
> limit stops fork bombs. Only the workspace is writable."

## 5. Tamper-evident audit log (40 s)

```bash
agentos audit verify
cp ~/.agentos/audit.jsonl /tmp/audit.bak
sed -i '2s/"ts": "2026/"ts": "2025/' ~/.agentos/audit.jsonl     # change one date in one entry
agentos audit verify
cp /tmp/audit.bak ~/.agentos/audit.jsonl                        # put it back
```

> "Every action is in a hash-chained log, like a mini blockchain. Change one character and verification
> names the exact entry."

## 6. The numbers (40 s)

Open `docs/redteam-report.md` (chart) and `docs/model-eval.md` on GitHub, or:

```bash
agentos eval --only T2,S1,S3
```

> "I attacked it with 34 attacks mapped to the OWASP Top 10 for LLMs. Against a model that obeys every
> injection, unattended, all 34 are stopped. With my real model, [say your numbers from model-eval.md]."

## 7. Close (15 s)

> "It's open source: github.com/pranjaltripathi684-wq/agentic-os. The thing I learned: you can't make a
> small model un-trickable, so you design the system so a tricked model can't do much."

## After recording

- GIF for the README: `bash scripts/record_demo.sh --gif-only`, then add `![Agentic OS demo](docs/demo.gif)`
  under the first paragraph of README.md.
- Upload the video (YouTube unlisted or LinkedIn native video), and link it in the README and your post.
