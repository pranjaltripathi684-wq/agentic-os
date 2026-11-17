"""
system_info: basic facts about the machine, gathered in Python.

Questions like "how much RAM do I have?" don't need a shell command at all.
A narrow, read-only tool is safer than a general one, so the model gets this
instead of running `free -h` (and it runs without asking).
"""

import os
import platform
import shutil
import sys

from .. import config
from .base import Risk, Tool, ToolResult


def _meminfo():
    info = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                key, value = line.split(":", 1)
                info[key] = int(value.split()[0]) * 1024     # kB -> bytes
    except (OSError, ValueError):
        pass
    return info


def _gb(n):
    return f"{n / 1024**3:.1f} GB"


class SystemInfo(Tool):
    name = "system_info"
    description = "Get OS, CPU, memory, disk space and uptime of the user's machine."
    parameters = {"type": "object", "properties": {}, "required": []}
    risk = Risk.READ

    def run(self):
        lines = [
            f"os: {platform.platform()}",
            f"cpu_cores: {os.cpu_count()}",
            f"python: {sys.version.split()[0]}",
        ]
        mem = _meminfo()
        if "MemTotal" in mem:
            lines.append(f"memory: {_gb(mem['MemAvailable'])} free of {_gb(mem['MemTotal'])}")
        for label, path in (("disk /", "/"), ("disk workspace", config.WORKSPACE)):
            try:
                du = shutil.disk_usage(path)
                lines.append(f"{label}: {_gb(du.free)} free of {_gb(du.total)}")
            except OSError:
                pass
        try:
            with open("/proc/uptime") as f:
                hours = float(f.read().split()[0]) / 3600
            lines.append(f"uptime: {hours:.1f} hours")
        except OSError:
            pass
        return ToolResult(True, "\n".join(lines))
