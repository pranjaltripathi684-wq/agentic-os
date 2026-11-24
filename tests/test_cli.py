"""The agentos command and the voice loop (with fakes)."""

import json
from types import SimpleNamespace as NS

import pytest

from agentos import cli, config
from agentos.interfaces import voice
from agentos.security import audit


def run_cli(*argv):
    cli.main(list(argv))


def test_goal_without_subcommand_means_run(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli, "cmd_run", lambda args: seen.update(goal=args.goal, team=args.team))
    run_cli("check", "my", "disk")
    assert seen == {"goal": ["check", "my", "disk"], "team": False}


def test_policy_check(capsys):
    run_cli("policy", "check", "run_shell", json.dumps({"command": "cat .env"}))
    assert "DENY" in capsys.readouterr().out
    run_cli("policy", "check", "read_file", json.dumps({"path": "notes.txt"}))
    assert "ALLOW" in capsys.readouterr().out


def test_policy_edit_copies_default(capsys):
    run_cli("policy", "edit")
    assert config.POLICY_FILE.read_text() == config.DEFAULT_POLICY_FILE.read_text()


def test_memory_commands(capsys):
    run_cli("memory", "add", "I", "use", "Kali", "--kind", "fact")
    run_cli("memory", "search", "kali")
    assert "I use Kali" in capsys.readouterr().out
    run_cli("memory", "forget", "1")
    assert "Forgotten" in capsys.readouterr().out


def test_audit_commands(capsys):
    audit.log_event("test", n=1)
    run_cli("audit", "verify")
    assert "OK" in capsys.readouterr().out
    run_cli("audit", "checkpoint")
    run_cli("audit", "verify")
    assert "1 signed checkpoint" in capsys.readouterr().out
    config.LOG_FILE.write_text(config.LOG_FILE.read_text().replace('"n": 1', '"n": 2'))
    with pytest.raises(SystemExit):
        run_cli("audit", "verify")
    assert "TAMPERED" in capsys.readouterr().out


def test_schedule_commands(capsys):
    run_cli("schedule", "add", "check", "disk", "--every", "2h")
    run_cli("schedule", "list")
    out = capsys.readouterr().out
    assert "check disk" in out and "2h" in out
    with pytest.raises(SystemExit):
        run_cli("schedule", "add", "x", "--every", "sometimes")


def test_stop_command(capsys):
    run_cli("stop")
    assert config.STOP_FILE.exists()


def test_selftest_with_no_sandbox_fails(capsys):
    with pytest.raises(SystemExit) as e:
        run_cli("selftest", "--sandbox", "none")
    assert e.value.code == 1 and "FAIL" in capsys.readouterr().out


def test_voice_loop_needs_typed_confirmation(monkeypatch):
    ran = []
    agent = NS(run=lambda goal: ran.append(goal) or NS(answer="done"))
    answers = iter(["", "n", "", "y", "q"])
    heard = iter(["delete everything", "check my disk"])
    monkeypatch.setattr(voice, "speak", lambda text: True)
    voice.voice_loop(lambda: agent, listen=lambda: next(heard), ask=lambda prompt: next(answers))
    assert ran == ["check my disk"]


def test_hostile_text_cannot_break_or_restyle_the_console(capsys, monkeypatch):
    import agentos.security.approval as approval
    from agentos.security.approval import ApprovalRequest, ConsoleApprover
    hostile = "rm -rf x [/bold] [red]APPROVED BY ADMIN[/red] [/]"
    monkeypatch.setattr(approval.console, "input", lambda *a, **k: "n")
    assert ConsoleApprover().ask(ApprovalRequest("run_shell", "exec", hostile, "why [/x]", True)) == "deny"
    out = capsys.readouterr().out
    assert "[red]APPROVED BY ADMIN[/red]" in out          # shown literally, not as formatting
    run_cli("memory", "add", "[/weird] markup [bold]")
    run_cli("memory", "list")
    assert "[/weird] markup [bold]" in capsys.readouterr().out


def test_voice_transcript_and_answer_are_shown_literally(capsys, monkeypatch):
    agent = NS(run=lambda goal: NS(answer="[/] done [red]x[/red]"))
    answers = iter(["", "y", "q"])
    monkeypatch.setattr(voice, "speak", lambda text: True)
    voice.voice_loop(lambda: agent, listen=lambda: "check [bold]disk[/", ask=lambda prompt: next(answers))
    out = capsys.readouterr().out
    assert "check [bold]disk[/" in out and "[/] done [red]x[/red]" in out


@pytest.mark.parametrize("share, gpu, expect", [
    (1.0, "RTX 3050", "ok   model runs on the GPU (RTX 3050)"),
    (0.0, "RTX 3050", "FIX  GPU RTX 3050 is visible, but the model runs on: CPU only"),
    (0.0, None, "no NVIDIA GPU visible, so the model runs on: CPU only"),
    (1.0, None, "ok   model runs on the GPU"),
])
def test_init_reports_where_the_model_runs(monkeypatch, capsys, share, gpu, expect):
    from rich.console import Console

    from agentos.core import models
    monkeypatch.setattr(cli, "console", Console(width=200))
    monkeypatch.setattr(models, "nvidia_gpu", lambda: gpu)
    monkeypatch.setattr(models, "gpu_share", lambda name: share)
    monkeypatch.setattr(models.llm, "_chat_once", lambda kw: None)
    results = []

    def line(good, text, fix=""):
        results.append(good)
        cli.console.print(("ok   " if good else "FIX  ") + text)
    cli._gpu_line(line)
    assert expect in capsys.readouterr().out
