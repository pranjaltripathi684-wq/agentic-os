"""
Kill switch: stop a running agent from another terminal with `agentos stop`.

How it works:
  - When an agent starts, it writes its process ID to ~/.agentos/agent.pid.
  - `agentos stop` creates ~/.agentos/STOP, sends that process an interrupt
    (like pressing Ctrl+C in its terminal), and kills any Docker sandbox
    containers still running.
  - The agent checks for the STOP file before every model call and tool call,
    and the sandbox kills its child processes when interrupted.
"""

import os
import signal
import subprocess

from .. import config


class StopRequested(Exception):
    """Raised inside the agent when a stop was requested."""


def register():
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    config.STOP_FILE.unlink(missing_ok=True)
    config.PID_FILE.write_text(str(os.getpid()))


def unregister():
    try:
        if config.PID_FILE.read_text().strip() == str(os.getpid()):
            config.PID_FILE.unlink()
    except OSError:
        pass


def stop_requested() -> bool:
    return config.STOP_FILE.exists()


def check():
    if stop_requested():
        raise StopRequested("stop requested with `agentos stop`")


def request_stop() -> list:
    """Stop everything. Returns a list of what was done, for printing."""
    done = []
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    config.STOP_FILE.touch()
    done.append("created the STOP file")
    try:
        pid = int(config.PID_FILE.read_text().strip())
        if pid != os.getpid():
            os.kill(pid, signal.SIGINT)
            done.append(f"interrupted agent process {pid}")
    except (OSError, ValueError):
        done.append("no running agent process found")
    try:
        ids = subprocess.run(["docker", "ps", "-q", "--filter", "name=agentos-"],
                             capture_output=True, text=True, timeout=10).stdout.split()
        if ids:
            subprocess.run(["docker", "kill", *ids], capture_output=True, timeout=20)
            done.append(f"killed {len(ids)} sandbox container(s)")
    except (OSError, subprocess.TimeoutExpired):
        pass
    return done
