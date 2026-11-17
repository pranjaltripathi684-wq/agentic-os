"""
The sandbox: where shell commands actually run.

Phase 1 ran approved commands directly as you, so a single bad approval could
read ~/.ssh or delete your files. Now every command runs in an isolated box:

    only ~/agentos-workspace is visible (as /workspace)   no network
    the rest of the system is read-only                   not root, no extra privileges
    limits on memory, CPU and number of processes         no environment variables (secrets)

Two backends do this job:

  DockerSandbox  a throwaway container per command (--rm). Strongest and most
                 portable, but Docker uses a lot of RAM on a 12 GB laptop.
  BwrapSandbox   bubblewrap: the same Linux features Docker uses (namespaces),
                 without a daemon. Starts in milliseconds; used by Flatpak.

Both are built from the same Linux kernel features:
  namespaces  -> what a process can SEE (files, network, other processes, users)
  cgroups /   -> how much it can USE (memory, CPU, process count)
  rlimits
  capabilities / no-new-privileges -> what it's ALLOWED to do (no root powers, no sudo)

`python main.py --selftest` runs the escape tests at the bottom of this file
against whichever backend you have. Save that output as Phase 2 proof.
"""

import os
import shutil
import signal
import subprocess
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from .. import config


class SandboxError(RuntimeError):
    """The sandbox can't be used (not installed, image missing, etc.)."""


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _workspace() -> Path:
    ws = config.WORKSPACE.resolve()
    ws.mkdir(parents=True, exist_ok=True)
    return ws


class Sandbox(ABC):
    name = "abstract"

    @classmethod
    @abstractmethod
    def available(cls) -> bool:
        ...

    @abstractmethod
    def build_command(self, command: str, run_id: str) -> list:
        """The full argv that runs `command` inside the sandbox. Kept separate so it can be unit-tested."""

    def run(self, command: str) -> ExecResult:
        run_id = f"agentos-{uuid.uuid4().hex[:12]}"
        argv = self.build_command(command, run_id)
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", start_new_session=True, **self.popen_extra(),
        )
        try:
            out, err = proc.communicate(timeout=config.COMMAND_TIMEOUT)
            return ExecResult(proc.returncode, out, err)
        except subprocess.TimeoutExpired:
            self.kill(proc, run_id)
            out, err = proc.communicate()
            return ExecResult(-1, out, err, timed_out=True)
        except KeyboardInterrupt:            # Ctrl+C or `agentos stop`: kill the sandbox too, then stop
            self.kill(proc, run_id)
            proc.communicate()
            raise

    def popen_extra(self) -> dict:
        return {}

    def kill(self, proc, run_id):
        try:
            os.killpg(proc.pid, signal.SIGKILL)   # the whole process group, not just bash
        except ProcessLookupError:
            pass


# --------------------------------------------------------------------------- Docker
class DockerSandbox(Sandbox):
    name = "docker"

    @classmethod
    def available(cls) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    @staticmethod
    def image_exists() -> bool:
        r = subprocess.run(["docker", "image", "inspect", config.SANDBOX_IMAGE], capture_output=True)
        return r.returncode == 0

    def __init__(self):
        if not self.image_exists():
            raise SandboxError(f"Docker image '{config.SANDBOX_IMAGE}' not found. "
                               "Build it with: bash scripts/build_sandbox.sh")

    def build_command(self, command, run_id):
        mem = config.SANDBOX_MEMORY
        return [
            "docker", "run", "--rm", "--name", run_id,
            "--network", "none",                          # no network at all
            "--read-only",                                # container filesystem is read-only...
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",   # ...except a small scratch /tmp
            "--cap-drop", "ALL",                          # no Linux capabilities (root powers)
            "--security-opt", "no-new-privileges",        # setuid programs like sudo can't gain privileges
            "--memory", mem, "--memory-swap", mem,        # RAM cap, no extra swap
            "--cpus", str(config.SANDBOX_CPUS),
            "--pids-limit", str(config.SANDBOX_PIDS),     # stops fork bombs
            "--user", f"{os.getuid()}:{os.getgid()}",     # your uid, so files you get back are yours
            "--hostname", "agentos-sandbox",
            "--env", "HOME=/workspace",
            "-v", f"{_workspace()}:/workspace:rw",        # the only writable host folder
            "-w", "/workspace",
            config.SANDBOX_IMAGE, "bash", "-c", command,
        ]

    def kill(self, proc, run_id):
        # Killing the `docker run` client does NOT stop the container. Stop it by name.
        subprocess.run(["docker", "kill", run_id], capture_output=True)
        super().kill(proc, run_id)


# --------------------------------------------------------------------------- bubblewrap
# Only these parts of /etc are visible. Binding all of /etc could leak secrets
# (Wi-Fi passwords, proxy credentials, API keys in /etc/environment).
ETC_ALLOW = ["alternatives", "ld.so.cache", "ld.so.conf", "ld.so.conf.d", "localtime",
             "passwd", "group", "nsswitch.conf", "ssl", "ca-certificates", "mime.types",
             "magic", "bash.bashrc", "inputrc", "profile"]


def _count_my_processes() -> int:
    uid, n = os.getuid(), 0
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                if os.stat(f"/proc/{pid}").st_uid == uid:
                    n += 1
            except OSError:
                pass
    return n


class BwrapSandbox(Sandbox):
    name = "bwrap"

    @classmethod
    def available(cls) -> bool:
        if not shutil.which("bwrap"):
            return False
        # Some systems block unprivileged user namespaces; try a real (empty) run.
        try:
            r = subprocess.run(cls().build_command("true", "probe"), capture_output=True, timeout=10)
            return r.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def build_command(self, command, run_id):
        argv = ["bwrap",
                "--unshare-all",           # new namespaces: no network, own PIDs, own hostname, own users
                "--die-with-parent",       # if we're killed, everything inside dies too
                "--new-session",           # can't inject keystrokes into your terminal (TIOCSTI)
                "--ro-bind", "/usr", "/usr"]
        # Modern distros make /bin, /lib... symlinks into /usr; recreate them the same way.
        for d in ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"):
            if os.path.islink(d):
                argv += ["--symlink", os.readlink(d), d]
            elif os.path.isdir(d):
                argv += ["--ro-bind", d, d]
        for name in ETC_ALLOW:
            argv += ["--ro-bind-try", f"/etc/{name}", f"/etc/{name}"]
        argv += [
            "--proc", "/proc", "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--bind", str(_workspace()), "/workspace",   # the only writable host folder
            "--chdir", "/workspace",
            "--hostname", "agentos-sandbox",
            # bwrap builds the sandbox's / as a temporary in-memory folder, writable by default.
            # Make it read-only like Docker's --read-only; /tmp and /workspace stay writable
            # because they are separate mounts. (Found by the self-test: /etc was writable.)
            "--remount-ro", "/",
            "--clearenv",                               # no environment variables leak in (API keys!)
            "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "--setenv", "HOME", "/workspace",
            "--setenv", "LANG", "C.UTF-8",
            "--setenv", "TERM", "dumb",
            "bash", "-c", command,
        ]
        return argv

    def popen_extra(self):
        # bubblewrap has no cgroup limits, so use classic rlimits instead.
        # RLIMIT_NPROC counts ALL your processes, so allow what you already run + the sandbox budget.
        nproc = _count_my_processes() + config.SANDBOX_PIDS
        mem = _parse_size(config.SANDBOX_MEMORY)

        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
            resource.setrlimit(resource.RLIMIT_AS, (mem * 4, mem * 4))   # virtual memory; x4 for libc overhead
            resource.setrlimit(resource.RLIMIT_FSIZE, (200 * 1024**2,) * 2)  # no file over 200 MB
            cpu = config.COMMAND_TIMEOUT + 5
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        return {"preexec_fn": limits}


def _parse_size(text: str) -> int:
    text = text.strip().lower()
    units = {"k": 1024, "m": 1024**2, "g": 1024**3}
    if text and text[-1] in units:
        return int(float(text[:-1]) * units[text[-1]])
    return int(text)


# --------------------------------------------------------------------------- no sandbox
class NoSandbox(Sandbox):
    """Phase 1 behaviour: runs as you, with full access. Debugging only."""
    name = "none"

    @classmethod
    def available(cls):
        return True

    def build_command(self, command, run_id):
        return ["bash", "-c", command]

    def popen_extra(self):
        return {"cwd": str(_workspace())}


# --------------------------------------------------------------------------- choosing one
_cache = {}


def get_sandbox() -> Sandbox:
    """The sandbox chosen by config.SANDBOX (auto/docker/bwrap/none). Created once, then reused."""
    key = (config.SANDBOX, config.SANDBOX_IMAGE, str(config.WORKSPACE))
    if key in _cache:
        return _cache[key]
    choice = config.SANDBOX
    if choice == "docker":
        if not DockerSandbox.available():
            raise SandboxError("Docker isn't running. Start Docker, or use AGENTOS_SANDBOX=bwrap.")
        box = DockerSandbox()
    elif choice == "bwrap":
        if not BwrapSandbox.available():
            raise SandboxError("bubblewrap isn't installed or can't run. Install: sudo apt install bubblewrap")
        box = BwrapSandbox()
    elif choice == "none":
        box = NoSandbox()
    elif choice == "auto":
        if DockerSandbox.available() and DockerSandbox.image_exists():
            box = DockerSandbox()
        elif BwrapSandbox.available():
            box = BwrapSandbox()
        else:
            raise SandboxError(
                "No sandbox available. Install bubblewrap (sudo apt install bubblewrap) or start Docker "
                "and run scripts/build_sandbox.sh. To run WITHOUT isolation (not recommended): "
                "AGENTOS_SANDBOX=none")
    else:
        raise SandboxError(f"unknown AGENTOS_SANDBOX value '{choice}' (use auto, docker, bwrap or none)")
    _cache[key] = box
    return box


# --------------------------------------------------------------------------- escape tests
def _small_number(out: str, limit: int = 4096) -> bool:
    """True if the last line is a process limit low enough to stop a fork bomb."""
    last = out.strip().splitlines()[-1] if out.strip() else ""
    return last.isdigit() and int(last) <= limit


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


def self_test(box: Sandbox) -> list:
    """
    Try to break out of the sandbox in the ways that matter, and report each result.
    Every check should PASS (meaning the escape attempt FAILED).
    """
    ws = _workspace()
    canary = Path.home() / ".agentos-canary"          # a file in your real home folder
    canary.write_text("if you can read this, the sandbox leaks")
    secret_var = "AGENTOS_CANARY_SECRET"
    os.environ[secret_var] = "s3cr3t-value"
    checks = []

    def attempt(name, command, ok):
        r = box.run(command)
        out = (r.stdout + r.stderr).strip()
        checks.append(Check(name, ok(r, out), out.splitlines()[-1][:80] if out else f"exit {r.exit_code}"))

    try:
        attempt("home folder hidden", f"cat '{canary}'",
                lambda r, o: r.exit_code != 0 and "leaks" not in o)
        attempt("/etc/shadow unreadable", "cat /etc/shadow", lambda r, o: r.exit_code != 0)
        attempt("no network", "timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/80' && echo CONNECTED",
                lambda r, o: "CONNECTED" not in o)
        attempt("can't write to /usr", "touch /usr/agentos-test", lambda r, o: r.exit_code != 0)
        attempt("can't write to /etc", "touch /etc/agentos-test", lambda r, o: r.exit_code != 0)
        attempt("not root", "id -u", lambda r, o: o.strip() != "0")
        attempt("secrets not passed in", f"echo ${{{secret_var}:-none}}",
                lambda r, o: "s3cr3t" not in o)
        # cgroup v2 path, then cgroup v1 path (Docker), then the rlimit (bubblewrap)
        attempt("process limit set",
                "cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max 2>/dev/null "
                "|| ulimit -u",
                lambda r, o: _small_number(o))
        attempt("workspace writable", "echo ok > .agentos-selftest && cat .agentos-selftest",
                lambda r, o: r.exit_code == 0 and o == "ok")
    finally:
        canary.unlink(missing_ok=True)
        os.environ.pop(secret_var, None)
        (ws / ".agentos-selftest").unlink(missing_ok=True)
    return checks
