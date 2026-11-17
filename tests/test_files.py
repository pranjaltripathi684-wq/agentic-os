import os

import pytest

from agentos.tools.base import ToolError
from agentos.tools.files import ListDir, ReadFile, SearchFiles, WriteFile, resolve_in_workspace


def test_write_then_read(ws):
    assert WriteFile().run(path="notes/a.txt", content="hello").ok
    r = ReadFile().run(path="notes/a.txt")
    assert r.ok and r.output == "hello" and r.untrusted
    assert r.meta["path"] == "/workspace/notes/a.txt"


def test_append(ws):
    WriteFile().run(path="log.txt", content="a\n")
    WriteFile().run(path="log.txt", content="b\n", append=True)
    assert (ws / "log.txt").read_text() == "a\nb\n"


def test_workspace_prefix_is_accepted(ws):
    (ws / "x.txt").write_text("x")
    assert ReadFile().run(path="/workspace/x.txt").output == "x"


@pytest.mark.parametrize("bad", ["../secret.txt", "../../etc/passwd", "/etc/passwd", "~/.ssh/id_rsa",
                                 "notes/../../outside.txt", "/workspace/../etc/passwd"])
def test_escapes_are_refused(ws, bad):
    with pytest.raises(ToolError):
        resolve_in_workspace(bad)


def test_symlink_pointing_outside_is_refused(ws, isolated):
    outside = isolated / "secret.txt"
    outside.write_text("top secret")
    os.symlink(outside, ws / "innocent.txt")
    with pytest.raises(ToolError):
        ReadFile().run(path="innocent.txt")
    with pytest.raises(ToolError):
        WriteFile().run(path="innocent.txt", content="overwrite")
    assert outside.read_text() == "top secret"


def test_symlinked_folder_pointing_outside_is_refused(ws, isolated):
    os.symlink(isolated, ws / "up")
    with pytest.raises(ToolError):
        ListDir().run(path="up")


def test_binary_file_rejected(ws):
    (ws / "img.bin").write_bytes(b"\x89PNG\x00\x00\x01")
    with pytest.raises(ToolError, match="binary"):
        ReadFile().run(path="img.bin")


def test_list_dir(ws):
    (ws / "sub").mkdir()
    (ws / "a.txt").write_text("12345")
    out = ListDir().run().output
    assert out.splitlines()[0].startswith("dir   sub/")
    assert "a.txt  (5 bytes)" in out


def test_search_by_name_and_text(ws):
    (ws / "a.py").write_text("print('hi')\n# TODO fix\n")
    (ws / "b.py").write_text("print('bye')\n")
    (ws / "c.txt").write_text("TODO later\n")
    assert SearchFiles().run(pattern="*.py").output.count("/workspace/") == 2
    r = SearchFiles().run(pattern="*.py", text="todo")
    assert "/workspace/a.py:2:" in r.output and "b.py" not in r.output and r.untrusted


def test_search_skips_symlink_escape(ws, isolated):
    (isolated / "secret.txt").write_text("password=hunter2")
    os.symlink(isolated / "secret.txt", ws / "s.txt")
    assert "hunter2" not in SearchFiles().run(text="password").output


def test_write_refuses_folder(ws):
    (ws / "d").mkdir()
    with pytest.raises(ToolError):
        WriteFile().run(path="d", content="x")
