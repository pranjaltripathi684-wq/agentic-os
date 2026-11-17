"""
File tools, confined to the workspace folder.

These run in Python, not in the sandbox, so the confinement is enforced
here in code by `resolve_in_workspace`. Attacks it has to stop:

    ../../etc/passwd             path traversal
    /home/you/.ssh/id_rsa        absolute path outside the workspace
    link -> /home/you            a symlink inside the workspace pointing out of it

The trick: turn the path into its real, absolute form with .resolve()
(which follows ".." and symlinks), THEN check it's still inside the workspace.
Checking before resolving is a classic bug.
"""

import fnmatch
import os
from pathlib import Path

from .. import config
from .base import Risk, Tool, ToolError, ToolResult, truncate

MAX_READ_BYTES = 2_000_000
MAX_WRITE_BYTES = 1_000_000
MAX_LIST = 200
MAX_MATCHES = 50


def workspace() -> Path:
    ws = config.WORKSPACE.resolve()
    ws.mkdir(parents=True, exist_ok=True)
    return ws


def resolve_in_workspace(path: str) -> Path:
    """Turn a model-supplied path into a real path, refusing anything outside the workspace."""
    ws = workspace()
    raw = (path or ".").strip()
    if raw.startswith("~"):
        raise ToolError("'~' is not allowed; paths are relative to the workspace")
    # Inside the sandbox the workspace is called /workspace, so accept that spelling too.
    if raw == "/workspace" or raw.startswith("/workspace/"):
        raw = raw[len("/workspace"):].lstrip("/") or "."
    candidate = Path(raw)
    full = (candidate if candidate.is_absolute() else ws / candidate).resolve()
    if full != ws and ws not in full.parents:
        raise ToolError(f"'{path}' is outside the workspace. Only files under /workspace are allowed.")
    return full


def display(p: Path) -> str:
    """Show paths the way the model knows them: /workspace/..."""
    rel = p.relative_to(workspace())
    return "/workspace" if str(rel) == "." else f"/workspace/{rel}"


class ReadFile(Tool):
    name = "read_file"
    description = "Read a text file inside /workspace."
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "File path, e.g. notes.txt"}},
        "required": ["path"],
    }
    risk = Risk.READ

    def run(self, path):
        p = resolve_in_workspace(path)
        if not p.is_file():
            raise ToolError(f"no such file: {display(p)}")
        if p.stat().st_size > MAX_READ_BYTES:
            raise ToolError(f"file is larger than {MAX_READ_BYTES // 1_000_000} MB")
        data = p.read_bytes()
        if b"\x00" in data[:8000]:
            raise ToolError("this looks like a binary file, not text")
        text, cut = truncate(data.decode("utf-8", errors="replace"))
        return ToolResult(True, text, truncated=cut, untrusted=True, meta={"path": display(p)})


class WriteFile(Tool):
    name = "write_file"
    description = "Create or overwrite a text file inside /workspace (set append=true to add to the end)."
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path, e.g. reports/summary.md"},
            "content": {"type": "string", "description": "Full text to write"},
            "append": {"type": "boolean", "description": "Add to the end instead of overwriting"},
        },
        "required": ["path", "content"],
    }
    risk = Risk.WRITE

    def describe(self, args):
        mode = "append to" if args.get("append") else "write"
        preview = args.get("content", "")
        preview = preview[:300] + ("..." if len(preview) > 300 else "")
        return f"{mode} {args.get('path')} ({len(args.get('content', ''))} chars):\n{preview}"

    def run(self, path, content, append=False):
        if len(content.encode()) > MAX_WRITE_BYTES:
            raise ToolError(f"content is larger than {MAX_WRITE_BYTES // 1_000_000} MB")
        p = resolve_in_workspace(path)
        if p == workspace() or p.is_dir():
            raise ToolError("path is a folder, not a file")
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a" if append else "w", encoding="utf-8") as f:
            f.write(content)
        return ToolResult(True, f"{'appended' if append else 'wrote'} {len(content)} characters",
                          meta={"path": display(p)})


class ListDir(Tool):
    name = "list_dir"
    description = "List files and folders inside /workspace (or a subfolder)."
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "Folder, default /workspace"}},
        "required": [],
    }
    risk = Risk.READ

    def run(self, path="."):
        p = resolve_in_workspace(path)
        if not p.is_dir():
            raise ToolError(f"not a folder: {path}")
        entries = sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        lines = []
        for e in entries[:MAX_LIST]:
            if e.is_symlink():
                lines.append(f"link  {e.name}")
            elif e.is_dir():
                lines.append(f"dir   {e.name}/")
            else:
                lines.append(f"file  {e.name}  ({e.stat().st_size} bytes)")
        if len(entries) > MAX_LIST:
            lines.append(f"... and {len(entries) - MAX_LIST} more")
        return ToolResult(True, "\n".join(lines) or "(empty folder)", meta={"path": display(p)})


class SearchFiles(Tool):
    name = "search_files"
    description = ("Find files inside /workspace by name pattern (like *.py), "
                   "optionally only those containing some text.")
    parameters = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "description": "File name pattern, e.g. *.txt (default *)"},
            "text": {"type": "string", "description": "Only files containing this text (case-insensitive)"},
            "path": {"type": "string", "description": "Folder to search, default /workspace"},
        },
        "required": [],
    }
    risk = Risk.READ

    def run(self, pattern="*", text="", path="."):
        root = resolve_in_workspace(path)
        ws = workspace()
        needle = text.lower()
        hits = []
        for dirpath, dirnames, filenames in os.walk(root):   # os.walk doesn't follow symlinked folders
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for fname in filenames:
                if not fnmatch.fnmatch(fname, pattern):
                    continue
                fp = Path(dirpath) / fname
                real = fp.resolve()
                if fp.is_symlink() and real != ws and ws not in real.parents:
                    continue                                # symlink pointing outside: skip
                if not needle:
                    hits.append(display(fp))
                elif fp.stat().st_size <= MAX_READ_BYTES:
                    try:
                        for n, line in enumerate(fp.read_text(errors="ignore").splitlines(), 1):
                            if needle in line.lower():
                                hits.append(f"{display(fp)}:{n}: {line.strip()[:200]}")
                                break
                    except OSError:
                        continue
                if len(hits) >= MAX_MATCHES:
                    break
            if len(hits) >= MAX_MATCHES:
                break
        out = "\n".join(hits) if hits else "no matches"
        if len(hits) >= MAX_MATCHES:
            out += f"\n[stopped at {MAX_MATCHES} matches]"
        # matched lines are file contents, so treat them as untrusted when searching text
        return ToolResult(True, out, untrusted=bool(needle))
