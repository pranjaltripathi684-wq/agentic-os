"""
Long-term memory in one SQLite file (~/.agentos/memory.db).

What's stored:
  memories  facts and preferences ("I use Kali", "keep answers short"), each with
            its SOURCE (user, agent, tool) and whether it's TRUSTED
  tasks     every goal you gave, its answer, and whether untrusted content was read
  steps     every tool call in every task (a readable history next to the audit log)

Search uses SQLite's built-in full-text index (FTS5, keyword search with
ranking). Optionally, an Ollama embedding model (e.g. nomic-embed-text) adds
"meaning" search, so "laptop specs" can find "machine has 12 GB RAM".

Memory poisoning defence: anything the agent saves after reading untrusted
content is stored as UNTRUSTED. Untrusted memories are never added to the
system prompt automatically; `recall` returns them fenced as data, and you can
review and delete them with `agentos memory list` / `agentos memory forget`.
"""

import array
import math
import re
import sqlite3
import threading
from datetime import datetime, timezone

from .. import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    id INTEGER PRIMARY KEY, kind TEXT NOT NULL, content TEXT NOT NULL, source TEXT NOT NULL,
    trusted INTEGER NOT NULL, task_id TEXT, created_at TEXT NOT NULL, embedding BLOB);
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(content, content='memories', content_rowid='id');
CREATE TRIGGER IF NOT EXISTS mem_ai AFTER INSERT ON memories BEGIN
    INSERT INTO memories_fts(rowid, content) VALUES (new.id, new.content); END;
CREATE TRIGGER IF NOT EXISTS mem_ad AFTER DELETE ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, content) VALUES ('delete', old.id, old.content); END;
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY, goal TEXT, role TEXT, started_at TEXT, ended_at TEXT,
    finished INTEGER, answer TEXT, tainted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS steps (
    task_id TEXT, n INTEGER, tool TEXT, summary TEXT, approved INTEGER, ok INTEGER, reason TEXT);
"""
KINDS = ("fact", "preference", "note")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fts_query(text: str) -> str:
    words = [w for w in re.findall(r"\w+", text.lower()) if len(w) > 2][:12]
    return " OR ".join(f'"{w}"' for w in words)


def _embed(text):
    if not config.MEMORY_EMBED_MODEL:
        return None
    try:
        import ollama
        vec = ollama.embed(model=config.MEMORY_EMBED_MODEL, input=text).embeddings[0]
        return array.array("f", vec).tobytes()
    except Exception:
        return None                          # embeddings are optional; never fail a save over them


def _cosine(a: bytes, b: bytes) -> float:
    x, y = array.array("f", a), array.array("f", b)
    dot = sum(p * q for p, q in zip(x, y, strict=False))
    norm = math.sqrt(sum(p * p for p in x)) * math.sqrt(sum(q * q for q in y))
    return dot / norm if norm else 0.0


class MemoryStore:
    def __init__(self, path=None):
        self.path = path or config.MEMORY_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)

    # ------------------------------------------------------------- memories
    def add(self, content: str, kind="fact", source="user", trusted=True, task_id=None) -> int:
        content = content.strip()
        if not content:
            raise ValueError("memory is empty")
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        emb = _embed(content)
        with self.lock, self.db:
            cur = self.db.execute(
                "INSERT INTO memories(kind, content, source, trusted, task_id, created_at, embedding) "
                "VALUES (?,?,?,?,?,?,?)", (kind, content[:2000], source, int(trusted), task_id, _now(), emb))
        return cur.lastrowid

    def forget(self, memory_id: int) -> bool:
        with self.lock, self.db:
            return self.db.execute("DELETE FROM memories WHERE id=?", (memory_id,)).rowcount > 0

    def get(self, memory_id: int):
        row = self.db.execute("SELECT * FROM memories WHERE id=?", (memory_id,)).fetchone()
        return dict(row) if row else None

    def list(self, limit=100, trusted_only=False):
        sql = "SELECT id, kind, content, source, trusted, created_at FROM memories"
        sql += " WHERE trusted=1" if trusted_only else ""
        return [dict(r) for r in self.db.execute(sql + " ORDER BY id DESC LIMIT ?", (limit,))]

    def search(self, query: str, limit=5, trusted_only=False):
        """Keyword search (FTS5, best match first), topped up with meaning search if embeddings are on."""
        results, seen = [], set()
        fq = _fts_query(query)
        if fq:
            sql = ("SELECT m.id, m.kind, m.content, m.source, m.trusted, m.created_at FROM memories_fts f "
                   "JOIN memories m ON m.id = f.rowid WHERE memories_fts MATCH ?"
                   + (" AND m.trusted=1" if trusted_only else "") + " ORDER BY bm25(memories_fts) LIMIT ?")
            for r in self.db.execute(sql, (fq, limit)):
                results.append(dict(r))
                seen.add(r["id"])
        q_emb = _embed(query) if len(results) < limit else None
        if q_emb:
            sql = "SELECT id, kind, content, source, trusted, created_at, embedding FROM memories WHERE embedding IS NOT NULL"
            sql += " AND trusted=1" if trusted_only else ""
            scored = sorted(((_cosine(q_emb, r["embedding"]), r) for r in self.db.execute(sql)),
                            key=lambda t: t[0], reverse=True)
            for score, r in scored:
                if len(results) >= limit:
                    break
                if r["id"] not in seen and score > 0.5:
                    d = dict(r)
                    d.pop("embedding")
                    results.append(d)
        return results

    def context_for(self, goal: str) -> str:
        """Trusted memories to put in the system prompt: all preferences + the best-matching facts."""
        prefs = [dict(r) for r in self.db.execute(
            "SELECT id, content FROM memories WHERE trusted=1 AND kind='preference' ORDER BY id DESC LIMIT 10")]
        facts = [m for m in self.search(goal, config.MEMORY_CONTEXT_ITEMS, trusted_only=True)
                 if m["kind"] != "preference"]
        if not prefs and not facts:
            return ""
        lines = ["What you know about the user (from memory, saved by the user):"]
        lines += [f"- preference: {p['content']}" for p in prefs]
        lines += [f"- {m['content']}" for m in facts]
        return "\n".join(lines)

    # ------------------------------------------------------------- task history
    def start_task(self, task_id, goal, role="agent"):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO tasks(id, goal, role, started_at) VALUES (?,?,?,?)",
                            (task_id, goal, role, _now()))

    def record_step(self, task_id, n, tool, summary, approved, ok, reason):
        with self.lock, self.db:
            self.db.execute("INSERT INTO steps VALUES (?,?,?,?,?,?,?)",
                            (task_id, n, tool, summary[:500], int(approved), None if ok is None else int(ok), reason))

    def end_task(self, task_id, finished, answer, tainted):
        with self.lock, self.db:
            self.db.execute("UPDATE tasks SET ended_at=?, finished=?, answer=?, tainted=? WHERE id=?",
                            (_now(), int(finished), (answer or "")[:2000], int(tainted), task_id))

    def history(self, limit=20):
        return [dict(r) for r in self.db.execute(
            "SELECT t.*, (SELECT COUNT(*) FROM steps s WHERE s.task_id=t.id) AS n_steps "
            "FROM tasks t ORDER BY started_at DESC LIMIT ?", (limit,))]

    def steps(self, task_id):
        return [dict(r) for r in self.db.execute("SELECT * FROM steps WHERE task_id=? ORDER BY n", (task_id,))]


_stores: dict = {}


def get_store() -> MemoryStore:
    """One store per database path (tests point config.MEMORY_DB at a temp file)."""
    key = str(config.MEMORY_DB)
    if key not in _stores:
        _stores[key] = MemoryStore()
    return _stores[key]
