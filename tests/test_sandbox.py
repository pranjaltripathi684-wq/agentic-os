"""
Sandbox tests. Tests for a backend that isn't installed are skipped.

The most important ones run the same escape attempts as `python main.py --selftest`.
"""

import os
import shutil

import pytest

from agentos import config
from agentos.security import sandbox as sb
from agentos.security.sandbox import (BwrapSandbox, DockerSandbox, NoSandbox, SandboxError, get_sandbox,
                                      self_test)

HAS_BWRAP = BwrapSandbox.available()
AS_ROOT = os.getuid() == 0     # root ignores process limits and can read anything; run tests as a normal user
HAS_DOCKER = DockerSandbox.available() and DockerSandbox.image_exists()


# ---------------------------------------------------------------- command construction (always runs)
def test_docker_command_has_every_hardening_flag(monkeypatch, ws):
    monkeypatch.setattr(DockerSandbox, "image_exists", staticmethod(lambda: True))
    argv = DockerSandbox().build_command("ls", "agentos-test")
    joined = " ".join(argv)
    for flag in ["--rm", "--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--pids-limit 128", "--memory 512m", "--memory-swap 512m", f"{ws.resolve()}:/workspace:rw"]:
        assert flag in joined, flag
    assert argv[-3:] == ["bash", "-c", "ls"]
    assert f"--user {os.getuid()}:{os.getgid()}" in joined


def test_bwrap_command_hides_home_and_env(ws):
    argv = BwrapSandbox().build_command("ls", "x")
    joined = " ".join(argv)
    assert "--unshare-all" in argv and "--clearenv" in argv and "--die-with-parent" in argv
    assert f"--bind {ws.resolve()} /workspace" in joined
    assert str(os.path.expanduser("~")) + " " not in joined.replace(str(ws.resolve()), "")
    assert "--ro-bind /etc /etc" not in joined          # only an allowlist of /etc
    assert argv.index("--remount-ro") > argv.index("--chdir")   # root made read-only after all mounts


def test_missing_docker_image_explains_how_to_build(monkeypatch):
    monkeypatch.setattr(DockerSandbox, "image_exists", staticmethod(lambda: False))
    with pytest.raises(SandboxError, match="build_sandbox.sh"):
        DockerSandbox()


def test_auto_with_nothing_available_refuses(monkeypatch):
    monkeypatch.setattr(config, "SANDBOX", "auto")
    monkeypatch.setattr(DockerSandbox, "available", classmethod(lambda cls: False))
    monkeypatch.setattr(BwrapSandbox, "available", classmethod(lambda cls: False))
    with pytest.raises(SandboxError, match="No sandbox available"):
        get_sandbox()


def test_unknown_backend(monkeypatch):
    monkeypatch.setattr(config, "SANDBOX", "chroot")
    with pytest.raises(SandboxError, match="unknown"):
        get_sandbox()


def test_parse_size():
    assert sb._parse_size("512m") == 512 * 1024**2 and sb._parse_size("1g") == 1024**3


# ---------------------------------------------------------------- the no-sandbox backend FAILS the escape tests
def test_no_sandbox_fails_self_test():
    # Proves the self-test can actually detect a leak, rather than always saying PASS.
    checks = {c.name: c.passed for c in self_test(NoSandbox())}
    assert checks["home folder hidden"] is False
    assert checks["secrets not passed in"] is False
    assert checks["workspace writable"] is True


# ---------------------------------------------------------------- real escape tests
def _escape_suite(box):
    checks = self_test(box)
    failed = [f"{c.name}: {c.detail}" for c in checks if not c.passed]
    assert not failed, failed
    assert len(checks) == 9


def _behaviour(box, ws):
    r = box.run("echo hi > made.txt && cat made.txt && pwd")
    assert r.exit_code == 0 and r.stdout.split() == ["hi", "/workspace"]
    assert (ws / "made.txt").read_text() == "hi\n" and (ws / "made.txt").stat().st_uid == os.getuid()
    assert box.run("exit 7").exit_code == 7


def _timeout(box, monkeypatch):
    monkeypatch.setattr(config, "COMMAND_TIMEOUT", 2)
    r = box.run("sleep 30")
    assert r.timed_out


@pytest.mark.skipif(not HAS_BWRAP or AS_ROOT, reason="bubblewrap not available, or running as root")
class TestBwrap:
    def test_escape_attempts_blocked(self):
        _escape_suite(BwrapSandbox())

    def test_runs_commands(self, ws):
        _behaviour(BwrapSandbox(), ws)

    def test_timeout_kills_everything(self, monkeypatch):
        _timeout(BwrapSandbox(), monkeypatch)

    def test_fork_bomb_is_contained(self, monkeypatch):
        monkeypatch.setattr(config, "COMMAND_TIMEOUT", 10)
        r = BwrapSandbox().run("for i in $(seq 1000); do sleep 5 & done 2>&1 | tail -1; echo survived")
        assert "survived" in r.stdout or r.timed_out
        # bash reports a failed fork as "fork: Resource temporarily unavailable" or "fork: Interrupted system call"
        assert "fork:" in r.stdout + r.stderr or r.timed_out


@pytest.mark.skipif(not HAS_DOCKER, reason="Docker or the sandbox image not available")
class TestDocker:
    def test_escape_attempts_blocked(self):
        _escape_suite(DockerSandbox())

    def test_runs_commands(self, ws):
        _behaviour(DockerSandbox(), ws)

    def test_timeout_kills_container(self, monkeypatch):
        _timeout(DockerSandbox(), monkeypatch)
        import subprocess
        running = subprocess.run(["docker", "ps", "-q", "--filter", "name=agentos-"],
                                 capture_output=True, text=True).stdout.strip()
        assert running == ""


def test_shutil_which_sanity():
    assert shutil.which("bash")
