"""
Full-screen terminal interface (Textual): `agentos tui`.

    +-------------------------------+-------------------------+
    | Activity: steps, tool calls,  | Audit log (live)        |
    | decisions, answers            | chain status            |
    +-------------------------------+-------------------------+
    | Goal: ____________________________________  [Enter]     |
    +---------------------------------------------------------+

The agent runs in a background thread so the screen stays responsive. When it
needs approval, it pauses and the UI shows a pop-up; the thread waits on a
threading.Event until you answer. Keys: y = allow once, a = allow for this
task, n / Esc = deny, Ctrl+S = stop the running task, Ctrl+Q = quit.
"""

import threading

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Input, RichLog, Static

from .. import config
from ..security import audit
from ..security.approval import RISK_COLOUR


class ApprovalScreen(ModalScreen):
    BINDINGS = [Binding("y", "answer('once')", "allow once"), Binding("a", "answer('task')", "allow for task"),
                Binding("n", "answer('deny')", "deny"), Binding("escape", "answer('deny')", "deny")]
    CSS = """
    ApprovalScreen { align: center middle; }
    #box { width: 80; height: auto; border: thick $warning; background: $surface; padding: 1 2; }
    #buttons { height: auto; margin-top: 1; }
    Button { margin-right: 2; }
    """

    def __init__(self, req):
        super().__init__()
        self.req = req

    def compose(self) -> ComposeResult:
        colour = RISK_COLOUR.get(self.req.risk, "yellow")
        text = (f"[bold {colour}]The agent wants to use {self.req.tool}[/] (risk: {self.req.risk})\n\n"
                f"{escape(self.req.summary)}\n\n[dim]why asking: {escape(self.req.reason)}[/dim]")
        if self.req.tainted:
            text += "\n[bold magenta]Untrusted content was read this task. Is this what YOU asked for?[/]"
        with Vertical(id="box"):
            yield Static(text)
            with Horizontal(id="buttons"):
                yield Button("Allow once (y)", id="once", variant="success")
                yield Button("Allow for task (a)", id="task", variant="warning")
                yield Button("Deny (n)", id="deny", variant="error")

    def on_button_pressed(self, event):
        self.dismiss(event.button.id)

    def action_answer(self, answer):
        self.dismiss(answer)


class ScopeScreen(ModalScreen):
    BINDINGS = [Binding("y", "answer(True)", "grant"), Binding("n", "answer(False)", "refuse"),
                Binding("escape", "answer(False)", "refuse")]
    CSS = ApprovalScreen.CSS.replace("$warning", "$accent")

    def __init__(self, risk, token):
        super().__init__()
        self.risk, self.token = risk, token

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Static(f"[bold cyan]Widen task scope?[/]\n\nCurrent scope: {self.token.describe()}\n"
                         f"The agent now needs [bold]{self.risk}[/bold] access.")
            with Horizontal(id="buttons"):
                yield Button("Grant (y)", id="yes", variant="warning")
                yield Button("Refuse (n)", id="no", variant="error")

    def on_button_pressed(self, event):
        self.dismiss(event.button.id == "yes")

    def action_answer(self, value):
        self.dismiss(value)


class TUIApprover:
    """Bridges the agent's thread and the UI: show a pop-up, wait for the answer."""
    interactive = True

    def __init__(self, app):
        self.app = app

    def _wait(self, screen, default):
        done, box = threading.Event(), {"value": default}

        def callback(value):
            box["value"] = value
            done.set()
        self.app.call_from_thread(self.app.push_screen, screen, callback)
        done.wait(timeout=600)                  # no answer in 10 minutes: treat as no
        return box["value"]

    def ask(self, req):
        return self._wait(ApprovalScreen(req), "deny")

    def ask_scope(self, risk, token):
        return self._wait(ScopeScreen(risk, token), False)


class AgentOSApp(App):
    TITLE = "Agentic OS"
    BINDINGS = [Binding("ctrl+s", "stop", "stop task"), Binding("ctrl+q", "quit", "quit")]
    CSS = """
    #main { height: 1fr; }
    #activity { width: 2fr; border: round $primary; }
    #side { width: 1fr; }
    #audit { border: round $secondary; height: 1fr; }
    #status { height: auto; border: round $secondary; padding: 0 1; }
    """

    def __init__(self, registry, make_agent=None):
        super().__init__()
        self.registry = registry
        self.make_agent = make_agent or self._default_agent
        self.busy = False

    def _default_agent(self, approver, listener):
        from ..core.agent import Agent
        return Agent(self.registry, approver=approver, verbose=False, listeners=[listener])

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main"):
            yield RichLog(id="activity", markup=True, wrap=True)
            with Vertical(id="side"):
                yield Static(id="status")
                yield RichLog(id="audit", markup=True, wrap=True)
        yield Input(placeholder="Type a goal and press Enter", id="goal")
        yield Footer()

    def on_mount(self):
        self.refresh_side()
        self.set_interval(2, self.refresh_side)
        self.query_one("#activity", RichLog).write(
            f"[dim]model {config.MODEL} | sandbox {config.SANDBOX} | {len(self.registry)} tools | "
            f"scope {config.DEFAULT_SCOPE}[/dim]")
        self.query_one("#goal", Input).focus()

    def refresh_side(self):
        r = audit.verify()
        chain = f"[green]intact ({r.entries})[/green]" if r.ok else f"[bold red]TAMPERED at {r.bad_seq}[/]"
        self.query_one("#status", Static).update(
            f"audit chain: {chain}\nstate: {'[yellow]running[/]' if self.busy else 'idle'}")
        log = self.query_one("#audit", RichLog)
        log.clear()
        for e in audit.read_entries(last=25):
            mark = "" if "approved" not in e else (" [green]ran[/]" if e["approved"] else " [red]blocked[/]")
            log.write(f"[dim]{e['seq']} {e['ts'][11:19]}[/dim] {e['event']} {e.get('tool', '')}{mark}")

    def on_input_submitted(self, event):
        goal = event.value.strip()
        if not goal:
            return
        if self.busy:
            self.query_one("#activity", RichLog).write("[yellow]A task is already running (Ctrl+S stops it).[/]")
            return
        event.input.value = ""
        self.busy = True
        config.STOP_FILE.unlink(missing_ok=True)
        self.query_one("#activity", RichLog).write(f"\n[bold cyan]Goal:[/] {escape(goal)}")
        self.run_worker(lambda: self._run(goal), thread=True, exclusive=True)

    def _run(self, goal):
        log = self.query_one("#activity", RichLog)

        def write(text):
            self.call_from_thread(log.write, text)

        def listener(event, data):
            if event == "thinking":
                write(f"[dim]step {data['step']}: thinking...[/dim]")
            elif event == "tool_request":
                write(f"  [bold]{data['tool']}[/bold] ({data['risk']}): {escape(data['summary'][:120])}")
            elif event == "tool_result":
                if not data["approved"]:
                    write(f"    [red]blocked: {escape(data['reason'])}[/red]")
                else:
                    write("    [green]ok[/green]" if data.get("ok") else "    [yellow]failed[/yellow]")
                    if data.get("injection"):
                        write(f"    [bold magenta]possible prompt injection: {', '.join(data['injection'])}[/]")
        try:
            result = self.make_agent(TUIApprover(self), listener).run(goal)
            colour = "green" if result.finished else "red"
            write(f"[bold {colour}]Answer:[/] {escape(result.answer)}")
        except Exception as e:
            write(f"[bold red]Error:[/] {escape(str(e))}")
        finally:
            self.busy = False
            self.call_from_thread(self.refresh_side)

    def action_stop(self):
        config.STATE_DIR.mkdir(parents=True, exist_ok=True)
        config.STOP_FILE.touch()
        self.query_one("#activity", RichLog).write("[bold red]Stop requested.[/]")


def run_tui(registry):
    AgentOSApp(registry).run()
