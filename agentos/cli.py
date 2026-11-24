"""
The `agentos` command.

    agentos init                         first-time setup and health check
    agentos run "goal"                   do one task      (--team: use the multi-agent team)
    agentos chat                         keep giving goals until you type exit
    agentos tui | dashboard | voice      other interfaces
    agentos stop                         kill switch, from another terminal
    agentos audit verify|show|checkpoint
    agentos policy show|check|edit
    agentos memory list|add|search|forget      agentos history
    agentos schedule add|list|remove           agentos daemon
    agentos mcp list|pin                 agentos tools        agentos selftest
    agentos model list|use|pull|bench|tune   choose the model, check and tune it for your GPU
    agentos config show|set|unset        saved settings (~/.agentos/settings.json)
    agentos eval                         test the real model on your machine and record the results
    agentos redteam                      attack yourself and write docs/redteam-report.md

`python main.py "goal"` still works and means `agentos run "goal"`.
"""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape as esc
from rich.panel import Panel
from rich.table import Table

from . import __version__, config

console = Console()


# ------------------------------------------------------------------ shared setup
def apply_options(args):
    for opt, attr in (("model", "MODEL"), ("sandbox", "SANDBOX"), ("scope", "DEFAULT_SCOPE")):
        value = getattr(args, opt, None)
        if value:
            setattr(config, attr, value)
    if getattr(args, "plan_first", False):
        config.PLAN_FIRST = True
    if getattr(args, "quarantine", False):
        config.GUARD_QUARANTINE = True


def require_sandbox():
    from .security.sandbox import SandboxError, get_sandbox
    if os.getuid() == 0:
        console.print(Panel("You're running as root. The sandbox maps the agent to YOUR user, so as root it "
                            "would get root's access to the workspace and weaker limits. Run as a normal user.",
                            title="[bold red]RUNNING AS ROOT", border_style="red"))
    try:
        box = get_sandbox()
    except SandboxError as e:
        console.print(f"[bold red]Sandbox problem:[/bold red] {e}")
        sys.exit(1)
    if box.name == "none":
        console.print(Panel("Commands run as YOU with full access to your files. Use only for debugging.",
                            title="[bold red]NO SANDBOX", border_style="red"))
    return box


def require_model():
    from .core.llm import LLMError, check_ready
    try:
        check_ready()
    except LLMError as e:
        console.print(f"[bold red]{e}[/bold red]")
        sys.exit(1)


def load_registry(quiet=False):
    from .tools.registry import ToolRegistry
    registry = ToolRegistry.discover()
    if not quiet:
        for w in registry.warnings:
            console.print(f"[yellow]warning:[/yellow] {esc(w)}")
    return registry


def make_agent(registry, approver=None, scope=None, **kw):
    from .core.agent import Agent
    return Agent(registry, approver=approver, scope=scope, **kw)


def header(box, registry):
    console.print(f"[dim]Agentic OS {__version__} | model {config.MODEL} | sandbox {box.name} | {len(registry)} tools"
                  f" | scope {config.DEFAULT_SCOPE} | workspace {config.WORKSPACE}[/dim]")


def show_result(result):
    style = "green" if result.finished else "red"
    console.print(Panel(esc(result.answer or "(the model gave no answer)"), title="Answer", border_style=style))
    ran = sum(1 for s in result.steps if s.approved)
    taint = " | read untrusted content" if result.tainted else ""
    console.print(f"[dim]{ran} tool call(s) run, {len(result.steps) - ran} blocked{taint} | task {result.task_id} | "
                  f"`agentos history {result.task_id}` for details[/dim]")


# ------------------------------------------------------------------ commands
def cmd_run(args):
    from .core.llm import LLMError
    from .security import killswitch
    apply_options(args)
    box = require_sandbox()
    registry = load_registry()
    require_model()
    header(box, registry)
    goal = " ".join(args.goal)
    killswitch.register()
    try:
        if args.team:
            from .agents.team import Team
            from .core.llm import chat
            from .security.approval import ConsoleApprover
            result = Team(registry, chat, ConsoleApprover()).run(goal)
            colour = "green" if result.passed else "yellow"
            console.print(Panel(esc(result.answer), title="Team result: " + ("PASS" if result.passed else "not confirmed"),
                                border_style=colour))
        else:
            show_result(make_agent(registry, max_steps=args.max_steps).run(goal))
    except LLMError as e:
        console.print(f"[bold red]Model error:[/bold red] {esc(str(e))}")
    finally:
        killswitch.unregister()


def cmd_chat(args):
    from .core.llm import LLMError
    from .security import killswitch
    apply_options(args)
    box = require_sandbox()
    registry = load_registry()
    require_model()
    header(box, registry)
    console.print("[dim]Type a goal and press Enter. 'exit' to quit. Ctrl+C stops the current task.[/dim]")
    killswitch.register()
    try:
        while True:
            try:
                goal = console.input("\n[bold cyan]Goal:[/bold cyan] ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if goal.lower() in ("exit", "quit", "q"):
                break
            if goal:
                config.STOP_FILE.unlink(missing_ok=True)
                try:
                    show_result(make_agent(registry, max_steps=args.max_steps).run(goal))
                except LLMError as e:
                    console.print(f"[bold red]Model error:[/bold red] {esc(str(e))}")
    finally:
        killswitch.unregister()


def cmd_selftest(args):
    from .security.sandbox import self_test
    apply_options(args)
    box = require_sandbox()
    console.print(f"Sandbox backend: [bold]{box.name}[/bold]  (workspace {config.WORKSPACE})")
    checks = self_test(box)
    table = Table(title="Sandbox escape tests")
    for col in ("Check", "Result", "What happened"):
        table.add_column(col)
    for c in checks:
        table.add_row(c.name, "[green]PASS[/green]" if c.passed else "[bold red]FAIL[/bold red]", esc(c.detail))
    console.print(table)
    failed = [c for c in checks if not c.passed]
    console.print("[green]All escape attempts were blocked.[/green]" if not failed
                  else f"[bold red]{len(failed)} check(s) failed: the sandbox leaks.[/bold red]")
    sys.exit(1 if failed else 0)


def cmd_tools(args):
    registry = load_registry()
    from .security.policy import Policy
    policy = Policy.load()
    table = Table(title=f"{len(registry)} tools")
    for col in ("Tool", "Risk", "Policy default", "Description"):
        table.add_column(col)
    for t in registry:
        decision = policy.tools.get(t.name) or policy.risk_defaults.get(t.risk.value, "deny")
        table.add_row(esc(t.name), t.risk.value, decision, esc(t.description))
    console.print(table)


def cmd_stop(args):
    from .security import killswitch
    for line in killswitch.request_stop():
        console.print(f"- {line}")
    console.print("[dim]The STOP file stays until the next task starts.[/dim]")


def cmd_audit(args):
    from .security import audit
    if args.action == "verify":
        r = audit.verify()
        if r.ok:
            console.print(f"[green]OK[/green]: {r.entries} entries, chain intact"
                          + (f", {r.checkpoints} signed checkpoint(s) valid" if r.checkpoints else
                             " (no signed checkpoints yet: `agentos audit checkpoint`)"))
        else:
            console.print(f"[bold red]TAMPERED[/bold red] at entry {r.bad_seq}: {r.reason}")
            sys.exit(2)
    elif args.action == "show":
        table = Table(title=f"Last {args.n} audit entries ({config.LOG_FILE})")
        for col in ("#", "time", "event", "tool", "decision", "detail"):
            table.add_column(col, overflow="fold")
        for e in audit.read_entries(last=args.n):
            decision = "" if "approved" not in e else ("ran" if e["approved"] else "blocked")
            detail = e.get("reason") or e.get("goal") or e.get("answer") or ""
            if e.get("args"):
                detail = json.dumps(e["args"])[:80] + "  " + detail
            table.add_row(str(e["seq"]), e["ts"][11:19], e["event"], esc(e.get("tool", "")), decision, esc(detail[:120]))
        console.print(table)
    elif args.action == "checkpoint":
        try:
            cp = audit.checkpoint()
        except ImportError:
            console.print("[red]Needs the cryptography package: pip install cryptography[/red]")
            sys.exit(1)
        except RuntimeError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)
        console.print(f"Signed entry {cp['seq']} (hash {cp['hash'][:16]}...) with key {config.AUDIT_KEY}")
        console.print(f"[dim]Public key: {cp['public_key']}  Keep a copy somewhere else to make "
                      "checkpoints meaningful against someone with access to this machine.[/dim]")


def cmd_policy(args):
    from .security.policy import Policy, PolicyError
    try:
        policy = Policy.load()
    except PolicyError as e:
        console.print(f"[bold red]{e}[/bold red]")
        sys.exit(1)
    if args.action == "show":
        console.print(policy.describe())
    elif args.action == "edit":
        if not config.POLICY_FILE.exists():
            config.POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(config.DEFAULT_POLICY_FILE, config.POLICY_FILE)
            console.print(f"Copied the default policy to [bold]{config.POLICY_FILE}[/bold].")
        console.print(f"Edit {config.POLICY_FILE}, then check it with `agentos policy show`.")
    elif args.action == "check":
        from .tools.registry import ToolRegistry
        tool = ToolRegistry.discover(include_mcp=False).get(args.tool)
        if tool is None:
            console.print(f"[red]no tool called {args.tool}[/red]")
            sys.exit(1)
        verdict = policy.evaluate(tool, json.loads(args.args or "{}"))
        colour = {"allow": "green", "ask": "yellow", "deny": "red"}[verdict.decision]
        console.print(f"[bold {colour}]{verdict.decision.upper()}[/bold {colour}]: {verdict.reason}  "
                      f"[dim](rule: {verdict.rule})[/dim]")


def cmd_memory(args):
    from .memory.store import get_store
    store = get_store()
    if args.action == "add":
        mid = store.add(" ".join(args.text), kind=args.kind, source="user", trusted=True)
        console.print(f"Saved memory #{mid}.")
    elif args.action == "forget":
        console.print("Forgotten." if store.forget(args.id) else f"No memory #{args.id}.")
    else:
        rows = store.search(" ".join(args.text), limit=20) if args.action == "search" else store.list()
        table = Table(title="Memory")
        for col in ("#", "kind", "trusted", "source", "content"):
            table.add_column(col, overflow="fold")
        for m in rows:
            trusted = "yes" if m["trusted"] else "[red]NO[/red]"
            table.add_row(str(m["id"]), m["kind"], trusted, esc(m["source"]), esc(m["content"]))
        console.print(table if rows else "No memories.")


def cmd_history(args):
    from .memory.store import get_store
    store = get_store()
    if args.task:
        table = Table(title=f"Task {args.task}")
        for col in ("step", "tool", "what", "ran", "ok", "why"):
            table.add_column(col, overflow="fold")
        for s in store.steps(args.task):
            table.add_row(str(s["n"]), esc(s["tool"]), esc(s["summary"][:80]), "yes" if s["approved"] else "no",
                          "" if s["ok"] is None else ("yes" if s["ok"] else "no"), esc(s["reason"] or ""))
        console.print(table)
        return
    table = Table(title="Recent tasks")
    for col in ("task", "started", "role", "goal", "steps", "done", "untrusted input", "answer"):
        table.add_column(col, overflow="fold")
    for t in store.history(args.n):
        table.add_row(t["id"], (t["started_at"] or "")[:16], t["role"], esc(t["goal"][:50]), str(t["n_steps"]),
                      "yes" if t["finished"] else "no", "yes" if t["tainted"] else "", esc((t["answer"] or "")[:60]))
    console.print(table)


def cmd_schedule(args):
    from .agents import scheduler
    if args.action == "add":
        try:
            job = scheduler.add(" ".join(args.goal), args.every, args.scope)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)
        console.print(f"Added job {job['id']}: every {job['every']}, scope {job['scope']}. Run `agentos daemon`.")
    elif args.action == "remove":
        console.print("Removed." if scheduler.remove(args.id) else "No such job.")
    else:
        table = Table(title="Scheduled jobs (unattended: anything that would ask is denied)")
        for col in ("id", "every", "scope", "goal", "last run", "last answer"):
            table.add_column(col, overflow="fold")
        for j in scheduler.list_jobs():
            table.add_row(j["id"], j["every"], j["scope"], esc(j["goal"]), j.get("last_run") or "never",
                          esc((j.get("last_answer") or "")[:60]))
        console.print(table)


def cmd_daemon(args):
    from .agents import scheduler
    apply_options(args)
    require_sandbox()
    registry = load_registry()
    require_model()
    scheduler.daemon(lambda scope: make_agent(registry, scope=scope, verbose=False),
                     poll_seconds=args.poll, say=console.print)


def cmd_mcp(args):
    from .tools.mcp_client import load_config, load_mcp_tools, load_pins
    if args.action == "pin":
        tools, warnings = load_mcp_tools(accept_new=True)
        console.print(f"Pinned {len(tools)} MCP tool(s) at their current descriptions.")
        return
    servers = load_config()
    console.print(f"Config: {config.MCP_CONFIG} | enabled servers: {', '.join(servers) or 'none'}")
    tools, warnings = load_mcp_tools() if servers else ([], [])
    pins = load_pins()
    for t in tools:
        console.print(f"- {t.name}  fingerprint {t.fingerprint}  "
                      f"{'pinned' if pins.get(f'{t.server}/{t.remote_name}') == t.fingerprint else 'NOT pinned'}")
    for w in warnings:
        console.print(f"[yellow]warning:[/yellow] {esc(w)}")


def cmd_model(args):
    from .core import models
    from .core.llm import LLMError, same_model
    action = args.action or "list"
    try:
        if action == "list":
            installed = models.list_installed()
            gpu = models.nvidia_gpu()
            table = Table(title=f"Models in Ollama (current: {config.MODEL})")
            for col in ("", "model", "size", "tools", "thinking", "runs on"):
                table.add_column(col)
            for m in installed:
                mark = "[green]*[/green]" if same_model(m.name, config.MODEL) else ""
                yes_no = {True: "yes", False: "[red]no[/red]", None: "?"}
                table.add_row(mark, esc(m.name), f"{m.size_gb} GB", yes_no[m.tools],
                              {True: "yes", False: "no", None: "?"}[m.thinking], models.where_it_runs(models.gpu_share(m.name)))
            console.print(table if installed else "No models downloaded yet.")
            console.print(f"[dim]GPU: {esc(gpu) if gpu else 'no NVIDIA GPU visible'}. 'runs on' is filled in for "
                          "models that are loaded right now.[/dim]")
            missing = [r for r in models.RECOMMENDED if not any(same_model(m.name, r[0]) for m in installed)]
            if missing:
                console.print("\n[bold]Recommended, not downloaded:[/bold]")
                for name, size, why in missing:
                    console.print(f"  {name:<32} {size:>7}  {why}")
                console.print("[dim]Switch with: agentos model use <name>   (downloads it if needed)[/dim]")
        elif action == "pull":
            _pull_with_progress(args.name)
        elif action == "use":
            name = args.name
            if not any(same_model(m, name) for m in [i.name for i in models.list_installed()]):
                if not args.yes and console.input(f"'{esc(name)}' isn't downloaded. Download it now? \\[y/N] "
                                                  ).strip().lower() not in ("y", "yes"):
                    console.print("Nothing changed.")
                    return
                _pull_with_progress(name)
            tools, thinking = models.capabilities(name)
            if tools is False and not args.force:
                console.print(f"[bold red]{esc(name)} can't call tools[/bold red], so it can't drive the agent. "
                              "Pick a model with the 'tools' tag (or add --force).")
                sys.exit(1)
            config.save_setting("model", name)
            console.print(f"Agentic OS now uses [bold]{esc(name)}[/bold] (saved in {config.SETTINGS_FILE}).")
            _env_note("model")
            if thinking:
                console.print("[dim]This is a thinking model; Agentic OS switches thinking off for speed.[/dim]")
            console.print("[dim]Check it: agentos model bench[/dim]")
        elif action == "tune":
            _tune(args.name or config.MODEL, args.yes)
        elif action == "bench":
            names = args.names or [config.MODEL]
            table = Table(title="Model benchmark: one tool-call round trip on this machine")
            for col in ("model", "load", "runs on", "picked tool", "answer ok", "s/step", "tokens/s", "verdict"):
                table.add_column(col, overflow="fold")
            notes = []
            for name in names:
                console.print(f"[dim]benchmarking {esc(name)}...[/dim]")
                r = models.bench(name)
                notes += r.notes
                if r.error:
                    table.add_row(esc(name), "", "", "", "", "", "", f"[red]{esc(r.error)}[/red]")
                    continue
                colour = "green" if r.verdict == "good" else "yellow" if r.tool_ok else "red"
                tool_colour = "green" if r.tool_ok else "red"
                table.add_row(esc(name), f"{r.load_s}s", models.where_it_runs(r.gpu),
                              f"[{tool_colour}]{esc(r.tool_called)}[/{tool_colour}]",
                              "yes" if r.answer_ok else "no", str(r.step_s), str(r.tokens_per_s),
                              f"[{colour}]{r.verdict}[/{colour}]")
            console.print(table)
            for n in dict.fromkeys(notes):
                console.print(f"[yellow]note:[/yellow] {n}")
    except LLMError as e:
        console.print(f"[bold red]{esc(str(e))}[/bold red]")
        sys.exit(1)


def _tune(name, yes=False):
    from .core import models
    console.print(f"Tuning [bold]{esc(name)}[/bold] for this GPU: up to {len(models.TUNE_CANDIDATES)} benchmarks, "
                  "best settings first. Takes a few minutes.")

    def show(t):
        where = models.where_it_runs(t.gpu)
        result = f"[red]{esc(t.error)}[/red]" if t.error else f"{where}, {t.step_s} s/step" + (
            "" if t.tool_ok else ", [red]wrong tool[/red]")
        console.print(f"  num_ctx {t.num_ctx:<5} num_batch {t.num_batch:<4} -> {result}")
    baseline, trials, best = models.tune(name, on_trial=show)
    if baseline:
        used, total = baseline
        console.print(f"[dim]With the model unloaded, other programs were using {used} of {total} MiB of VRAM.[/dim]")
    if best is None:
        console.print("[red]No setting worked; check `agentos model bench` for the error.[/red]")
        return
    fits = best.gpu is not None and best.gpu >= 0.99
    console.print(("[green]Fits fully on the GPU[/green]" if fits else "[yellow]Nothing fits fully on the GPU[/yellow]")
                  + f" with num_ctx {best.num_ctx}, num_batch {best.num_batch}: {best.step_s} s per step.")
    if not fits:
        console.print("[dim]Closing apps that use the GPU (browser video, games) frees VRAM; a smaller model "
                      "(agentos model use qwen3:1.7b) fits easily but is less reliable.[/dim]")
    if (best.num_ctx, best.num_batch) == (config.NUM_CTX, config.NUM_BATCH):
        console.print("These are already your settings.")
        return
    if yes or console.input("Save these settings? \\[y/N] ").strip().lower() in ("y", "yes"):
        config.save_setting("num_ctx", best.num_ctx)
        config.save_setting("num_batch", best.num_batch)
        console.print(f"Saved: num_ctx = {best.num_ctx}, num_batch = {best.num_batch}")


def _pull_with_progress(name):
    from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn

    from .core import models
    with Progress(TextColumn("{task.description}"), BarColumn(), DownloadColumn(), console=console) as bar:
        task = bar.add_task(f"pulling {name}", total=None)

        def show(status, done, total):
            if total:
                bar.update(task, description=f"{name}: {status[:40]}", completed=done, total=total)
            else:
                bar.update(task, description=f"{name}: {status[:40]}")
        models.pull(name, on_progress=show)
    console.print(f"[green]Downloaded {esc(name)}.[/green]")


def cmd_config(args):
    if args.action == "show":
        saved = config.saved_settings()
        table = Table(title=f"Settings ({config.SETTINGS_FILE})")
        for col in ("setting", "value", "from", "what it does"):
            table.add_column(col, overflow="fold")
        for key, (attr, _kind, what) in config.SAVEABLE.items():
            env = config.ENV_VARS[key]
            source = f"env {env}" if os.getenv(env) is not None else "saved" if key in saved else "default"
            table.add_row(key, esc(str(getattr(config, attr))), source, what)
        console.print(table)
        return
    if args.key not in config.SAVEABLE:
        console.print(f"[red]Unknown setting '{esc(str(args.key))}'.[/red] Settings: {', '.join(config.SAVEABLE)}")
        sys.exit(1)
    if args.action == "unset":
        config.save_setting(args.key, None)
        console.print(f"{args.key} is back to its default ({esc(str(config.DEFAULTS[config.SAVEABLE[args.key][0]]))}).")
        _env_note(args.key)
        return
    if args.value is None:
        console.print("usage: agentos config set <setting> <value>")
        sys.exit(1)
    try:
        value = config.parse_setting(args.key, args.value)
    except ValueError as e:
        console.print(f"[red]{esc(str(e))}[/red]")
        sys.exit(1)
    if args.key == "sandbox" and value == "none":
        console.print("[bold red]Warning:[/bold red] with sandbox 'none', shell commands run as you, with full access.")
    config.save_setting(args.key, value)
    console.print(f"Saved: {args.key} = {esc(str(value))}")
    _env_note(args.key)


def _env_note(key):
    env = config.ENV_VARS[key]
    if os.getenv(env) is not None:
        console.print(f"[yellow]Note:[/yellow] {env} is set in this terminal and overrides the saved value "
                      f"(unset {env} to use it).")


def cmd_redteam(args):
    from .redteam.harness import LEVELS, run_all, save_results
    from .redteam.report import rates, write_report
    if args.model == "ollama":
        require_model()
    levels = tuple(args.levels.split(",")) if args.levels else tuple(LEVELS)
    humans = tuple(args.humans.split(","))
    only = args.only.split(",") if args.only else None
    console.print(f"Red team: model={args.model} levels={','.join(levels)} humans={','.join(humans)}")

    def progress(o):
        mark = "[bold red]THROUGH[/bold red]" if o.success else "[green]blocked[/green]"
        console.print(f"  {o.id} {o.level:<9} {o.human:<8} {mark} {', '.join(o.blocked_by)}")
    meta, outcomes = run_all(levels, humans, only, args.model, progress=progress)
    out = Path(args.out) if args.out else config.output_dir()
    save_results(meta, outcomes, out / "redteam-results.json")
    path = write_report(meta, outcomes, out)
    for (level, human), (s, n) in sorted(rates(outcomes).items()):
        console.print(f"{level:<10} {human:<9} {s}/{n} attacks got through")
    console.print(f"Report: [bold]{path}[/bold]")


def cmd_eval(args):
    from .evaluation import previous_redteam, run_eval, summary_counts, update_timeline, write_report
    from .security import killswitch
    apply_options(args)
    if args.max_steps:
        config.MAX_STEPS = args.max_steps
    box = require_sandbox()
    require_model()
    only = {x.strip().upper() for x in args.only.split(",")} if args.only else None
    console.print(f"Evaluating [bold]{esc(config.MODEL)}[/bold] with the {box.name} sandbox. Everything runs in a "
                  "throwaway workspace; your files, memory and audit log aren't touched. `agentos stop` ends it.")
    config.STOP_FILE.unlink(missing_ok=True)
    killswitch.register()
    try:
        results = run_eval(only=only, redteam=args.redteam, verbose=args.verbose, progress=lambda t: console.print(esc(t)))
    finally:
        killswitch.unregister()
    out = Path(args.out) if args.out else config.output_dir()
    if only and not args.out:
        path = None                    # a partial run must not replace the full report
    else:
        if not results.get("redteam"):
            results["redteam"] = previous_redteam(out / "model-eval.json", results["model"])
        path = write_report(results, out)
    tp, tn, sp, sn = summary_counts(results)
    b = results["bench"]
    lines = [f"Model {results['model']} on {results['runs_on']}: {b['step_s']} s per step",
             f"Tasks done correctly: {tp}/{tn}      Safety checks held: {sp}/{sn}"]
    if results.get("redteam"):
        r = results["redteam"]["rates"]
        c, a = r.get("full/careless", [0, 0]), r.get("full/absent", [0, 0])
        lines.append(f"Real-model red team: careless {c[0]}/{c[1]} got through, unattended {a[0]}/{a[1]}")
    lines.append(f"Report: {path}" if path else "Partial run (--only): the full report in docs/ was left as it is.")
    console.print(Panel(esc("\n".join(lines)), title="agentos eval", border_style="green" if sp == sn else "red"))
    if not only and not args.no_timeline and update_timeline(results, config.PROJECT_ROOT / "TIMELINE.md"):
        console.print("[dim]Wrote the results into TIMELINE.md (Real-model results).[/dim]")


def cmd_dashboard(args):
    try:
        from .interfaces.web import serve
    except ImportError:
        console.print("[red]The dashboard needs: pip install fastapi uvicorn[/red]")
        sys.exit(1)
    apply_options(args)
    require_sandbox()
    require_model()
    serve(port=args.port)


def cmd_tui(args):
    try:
        from .interfaces.tui import run_tui
    except ImportError:
        console.print("[red]The TUI needs: pip install textual[/red]")
        sys.exit(1)
    apply_options(args)
    require_sandbox()
    registry = load_registry()
    require_model()
    run_tui(registry)


def cmd_voice(args):
    from .interfaces import voice
    apply_options(args)
    require_sandbox()
    registry = load_registry()
    require_model()
    voice.voice_loop(lambda: make_agent(registry), seconds=args.seconds)


def cmd_init(args):
    """Check everything and create ~/.agentos. Safe to run again."""
    from .core.llm import LLMError, check_ready
    from .security import audit
    from .security.sandbox import SandboxError, get_sandbox, self_test
    ok = True

    def line(good, text, fix=""):
        nonlocal ok
        ok &= bool(good)
        mark = "[green]ok[/green]   " if good else "[red]FIX[/red]  "
        console.print(mark + text + (f"\n       -> {fix}" if not good and fix else ""))

    console.print(f"[bold]Agentic OS {__version__} setup[/bold]\n")
    line(sys.version_info >= (3, 10), f"Python {sys.version.split()[0]}", "needs Python 3.10 or newer")
    line(os.getuid() != 0, "running as a normal user", "don't run Agentic OS as root")
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(config.STATE_DIR, 0o700)
    config.WORKSPACE.mkdir(parents=True, exist_ok=True)
    line(True, f"state folder {config.STATE_DIR} (private, outside the workspace)")
    line(True, f"workspace {config.WORKSPACE}")
    try:
        check_ready()
        line(True, f"Ollama is running and has {config.MODEL}")
        _gpu_line(line)
    except LLMError as e:
        line(False, "Ollama / model", str(e))
    try:
        box = get_sandbox()
        failed = [c.name for c in self_test(box) if not c.passed]
        line(not failed and box.name != "none", f"sandbox: {box.name}, escape self-test "
             + ("passed" if not failed else "FAILED: " + ", ".join(failed)), "see `agentos selftest`")
    except SandboxError as e:
        line(False, "sandbox", str(e))
    from .security.policy import Policy, PolicyError
    try:
        line(True, f"policy: {Policy.load().source}")
    except PolicyError as e:
        line(False, "policy", str(e))
    r = audit.verify()
    line(r.ok, f"audit log: {r.entries} entries" + ("" if r.ok else f", TAMPERED: {r.reason}"))
    for extra, pkg in (("signed checkpoints", "cryptography"), ("TUI", "textual"), ("dashboard", "fastapi")):
        try:
            __import__(pkg)
            line(True, f"{extra} available")
        except ImportError:
            console.print(f"[yellow]opt[/yellow]  {extra} not installed (pip install {pkg})")
    console.print("\n" + ("[green]Ready.[/green] Try: agentos run \"What's my OS and free disk space?\""
                          if ok else "[yellow]Fix the items above, then run `agentos init` again.[/yellow]"))


def _gpu_line(line):
    """Load the model once and report whether it landed on the GPU."""
    from .core import models
    gpu = models.nvidia_gpu()
    console.print("[dim]       loading the model once to see where it runs...[/dim]")
    try:
        models.llm._chat_once(dict(model=config.MODEL, messages=[{"role": "user", "content": "hi"}],
                                   options={**models.llm.model_options(), "num_predict": 1},
                                   keep_alive=config.KEEP_ALIVE))
    except Exception as e:                         # init reports problems; it never crashes
        line(False, f"model failed to load: {type(e).__name__}", "try a smaller model: agentos model use qwen3:1.7b")
        return
    place = models.where_it_runs(models.gpu_share(config.MODEL))
    if place == "100% GPU":
        line(True, "model runs on the GPU" + (f" ({gpu})" if gpu else ""))
    elif gpu:
        line(False, f"GPU {gpu} is visible, but the model runs on: {place}",
             "see README > Speed and the GPU (usually: update Ollama, or pick a smaller model)")
    else:
        console.print(f"[yellow]note[/yellow] no NVIDIA GPU visible, so the model runs on: {place}. "
                      "That works, but each step takes longer.")


# ------------------------------------------------------------------ parser
COMMANDS = {"init", "run", "chat", "selftest", "tools", "stop", "audit", "policy", "memory", "history", "schedule",
            "daemon", "mcp", "model", "config", "eval", "redteam", "dashboard", "tui", "voice"}


def build_parser():
    p = argparse.ArgumentParser(prog="agentos", description="Agentic OS: a secure-by-design personal AI agent.")
    p.add_argument("--version", action="version", version=f"agentos {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def agent_opts(sp):
        sp.add_argument("--model", help=f"Ollama model (default {config.MODEL})")
        sp.add_argument("--sandbox", choices=["auto", "docker", "bwrap", "none"])
        sp.add_argument("--scope", help="risks the task may use without asking: read-only, standard, full, "
                                        f"or a list like read,write (default {config.DEFAULT_SCOPE})")
        sp.add_argument("--max-steps", type=int)
        sp.add_argument("--plan-first", action="store_true", help="commit to a tool list before reading untrusted input")
        sp.add_argument("--quarantine", action="store_true", help="summarise untrusted text with a tool-less model first")

    sp = sub.add_parser("run", help="do one task")
    sp.add_argument("goal", nargs="+")
    sp.add_argument("--team", action="store_true", help="split the goal across researcher/operator/reviewer agents")
    agent_opts(sp)
    sp.set_defaults(func=cmd_run)
    sp = sub.add_parser("chat", help="interactive: give goals one after another")
    agent_opts(sp)
    sp.set_defaults(func=cmd_chat)
    sp = sub.add_parser("init", help="first-time setup and health check")
    sp.set_defaults(func=cmd_init)
    sp = sub.add_parser("selftest", help="try to escape the sandbox")
    sp.add_argument("--sandbox", choices=["auto", "docker", "bwrap", "none"])
    sp.set_defaults(func=cmd_selftest)
    sub.add_parser("tools", help="list tools and their risk").set_defaults(func=cmd_tools)
    sub.add_parser("stop", help="stop a running agent (kill switch)").set_defaults(func=cmd_stop)

    sp = sub.add_parser("audit", help="tamper-evident log")
    sp.add_argument("action", choices=["verify", "show", "checkpoint"])
    sp.add_argument("-n", type=int, default=20)
    sp.set_defaults(func=cmd_audit)
    sp = sub.add_parser("policy", help="show, check or edit the policy")
    sp.add_argument("action", choices=["show", "check", "edit"])
    sp.add_argument("tool", nargs="?")
    sp.add_argument("args", nargs="?", help="JSON arguments, e.g. '{\"command\": \"ls\"}'")
    sp.set_defaults(func=cmd_policy)
    sp = sub.add_parser("memory", help="long-term memory")
    sp.add_argument("action", choices=["list", "add", "search", "forget"])
    sp.add_argument("text", nargs="*")
    sp.add_argument("--kind", default="fact", choices=["fact", "preference", "note"])
    sp.set_defaults(func=cmd_memory, id=None)
    sp = sub.add_parser("history", help="past tasks, or one task's steps")
    sp.add_argument("task", nargs="?")
    sp.add_argument("-n", type=int, default=20)
    sp.set_defaults(func=cmd_history)
    sp = sub.add_parser("schedule", help="scheduled jobs")
    sp.add_argument("action", choices=["add", "list", "remove"])
    sp.add_argument("goal", nargs="*")
    sp.add_argument("--every", default="daily@09:00", help="30m, 2h or daily@09:00")
    sp.add_argument("--scope", default="read-only")
    sp.set_defaults(func=cmd_schedule)
    sp = sub.add_parser("daemon", help="run scheduled jobs when due")
    sp.add_argument("--poll", type=int, default=30)
    agent_opts(sp)
    sp.set_defaults(func=cmd_daemon)
    sp = sub.add_parser("mcp", help="MCP servers and pinned tools")
    sp.add_argument("action", choices=["list", "pin"])
    sp.set_defaults(func=cmd_mcp)
    sp = sub.add_parser("model", help="list, switch, download or benchmark models")
    msub = sp.add_subparsers(dest="action")
    msub.add_parser("list", help="downloaded models, where they run, recommendations")
    mp = msub.add_parser("use", help="switch model (saved); downloads it if needed")
    mp.add_argument("name")
    mp.add_argument("-y", "--yes", action="store_true", help="download without asking")
    mp.add_argument("--force", action="store_true", help="use it even if Ollama says it can't call tools")
    msub.add_parser("pull", help="download a model").add_argument("name")
    msub.add_parser("bench", help="time one tool-call round trip; check GPU use").add_argument("names", nargs="*")
    mp = msub.add_parser("tune", help="find the context and batch size that fit your GPU, and save them")
    mp.add_argument("name", nargs="?")
    mp.add_argument("-y", "--yes", action="store_true", help="save without asking")
    sp.set_defaults(func=cmd_model)
    sp = sub.add_parser("config", help="saved settings")
    sp.add_argument("action", choices=["show", "set", "unset"])
    sp.add_argument("key", nargs="?")
    sp.add_argument("value", nargs="?")
    sp.set_defaults(func=cmd_config)
    sp = sub.add_parser("redteam", help="attack yourself and write a report")
    sp.add_argument("--model", default="obedient", choices=["obedient", "ollama"])
    sp.add_argument("--levels", help="comma list of baseline, full, full+plan")
    sp.add_argument("--humans", default="careless,absent")
    sp.add_argument("--only", help="comma list of attack IDs, e.g. RT01,RT04")
    sp.add_argument("--out", help="folder for the report (default: the repo's docs/, or ~/.agentos/reports)")
    sp.set_defaults(func=cmd_redteam)
    sp = sub.add_parser("eval", help="test the real model on this machine and record the results")
    sp.add_argument("--redteam", action="store_true", help="also run the 34 attacks with the real model (slow)")
    sp.add_argument("--only", help="comma list of check IDs, e.g. T2,S1")
    sp.add_argument("--out", help="folder for model-eval.md (default: the repo's docs/, or ~/.agentos/reports)")
    sp.add_argument("--no-timeline", action="store_true", help="don't write the results into TIMELINE.md")
    sp.add_argument("--verbose", action="store_true", help="show every agent step")
    sp.add_argument("--model", help=f"Ollama model (default {config.MODEL})")
    sp.add_argument("--sandbox", choices=["auto", "docker", "bwrap", "none"])
    sp.add_argument("--max-steps", type=int)
    sp.add_argument("--plan-first", action="store_true", help="evaluate with plan-first mode on")
    sp.add_argument("--quarantine", action="store_true", help="evaluate with the quarantine model on")
    sp.set_defaults(func=cmd_eval)
    sp = sub.add_parser("dashboard", help="web dashboard on 127.0.0.1")
    sp.add_argument("--port", type=int, default=config.DASHBOARD_PORT)
    agent_opts(sp)
    sp.set_defaults(func=cmd_dashboard)
    sp = sub.add_parser("tui", help="full-screen terminal interface")
    agent_opts(sp)
    sp.set_defaults(func=cmd_tui)
    sp = sub.add_parser("voice", help="push-to-talk (optional extras)")
    sp.add_argument("--seconds", type=int, default=6)
    agent_opts(sp)
    sp.set_defaults(func=cmd_voice)
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["chat"]
    elif argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv = ["run"] + argv                      # `agentos "goal"` == `agentos run "goal"`
    # Phase 2 compatibility: python main.py --selftest / --list-tools
    argv = ["selftest" if a == "--selftest" else "tools" if a == "--list-tools" else a for a in argv]
    args = build_parser().parse_args(argv)
    if args.command == "memory" and args.action == "forget":
        if not args.text or not args.text[0].isdigit():
            console.print("usage: agentos memory forget <id>")
            sys.exit(1)
        args.id = int(args.text[0])
    if args.command == "config" and args.action != "show" and not args.key:
        console.print("usage: agentos config set <setting> <value>  |  agentos config unset <setting>")
        sys.exit(1)
    if args.command == "policy" and args.action == "check" and not args.tool:
        console.print("usage: agentos policy check <tool> '<json args>'")
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
