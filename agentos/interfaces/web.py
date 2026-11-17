"""
Web dashboard: `agentos dashboard`, then open the printed link.

Start tasks, approve or deny tool calls, watch the audit log, see task history.

A dashboard that can approve actions is itself an attack target, so:
  - It listens on 127.0.0.1 only: other machines on your network can't reach it.
  - A random access token is required (in the link, then a cookie).
  - Every POST must also carry the token in a header. A malicious web page in
    your browser can make your browser send the cookie (CSRF), but it can't
    read the token to put it in the header.
  - The Host header must be 127.0.0.1 or localhost. This stops "DNS rebinding",
    where a hostile site points its own name at 127.0.0.1 to reach local services.
  - Everything the agent produced is inserted with textContent, never innerHTML,
    so a web page the agent read can't inject script into the dashboard.
"""

import secrets
import threading
import time
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .. import config
from .. import notify as _notify
from ..security import audit


def notify_fn(title, message):
    _notify.notify(title, message)


class WebApprover:
    """Pending approvals wait here until someone clicks a button in the dashboard."""
    interactive = True

    def __init__(self, timeout=600):
        self.pending = {}
        self.lock = threading.Lock()
        self.timeout = timeout

    def _wait(self, kind, payload, default):
        rid = uuid.uuid4().hex[:8]
        item = {"id": rid, "kind": kind, **payload, "event": threading.Event(), "answer": default}
        with self.lock:
            self.pending[rid] = item
        notify_fn("Agentic OS needs you", payload.get("summary") or f"widen scope: {payload.get('risk')}")
        item["event"].wait(self.timeout)
        with self.lock:
            self.pending.pop(rid, None)
        return item["answer"]

    def ask(self, req):
        return self._wait("tool", {"tool": req.tool, "risk": req.risk, "summary": req.summary,
                                   "reason": req.reason, "tainted": req.tainted}, "deny")

    def ask_scope(self, risk, token):
        return self._wait("scope", {"risk": risk, "scope": token.describe()}, False)

    def answer(self, rid, value):
        with self.lock:
            item = self.pending.get(rid)
        if not item:
            return False
        item["answer"] = value
        item["event"].set()
        return True

    def list(self):
        with self.lock:
            return [{k: v for k, v in item.items() if k not in ("event", "answer")} for item in self.pending.values()]


class Runner:
    """Runs one task at a time in a background thread and keeps its event feed."""

    def __init__(self, make_agent, make_team=None):
        self.make_agent, self.make_team = make_agent, make_team
        self.approver = WebApprover()
        self.events, self.running, self.last_answer = [], False, ""
        self.lock = threading.Lock()

    def feed(self, event, data):
        with self.lock:
            self.events.append({"t": time.strftime("%H:%M:%S"), "event": event,
                                **{k: v for k, v in data.items() if isinstance(v, (str, int, bool, list, type(None)))}})
            self.events = self.events[-200:]

    def start(self, goal, team=False):
        with self.lock:
            if self.running:
                return False
            self.running, self.events = True, []
        config.STOP_FILE.unlink(missing_ok=True)

        def work():
            try:
                if team and self.make_team:
                    result = self.make_team(self.approver, self.feed).run(goal)
                else:
                    result = self.make_agent(self.approver, self.feed).run(goal)
                self.last_answer = result.answer
                self.feed("answer", {"answer": result.answer})
            except Exception as e:
                self.feed("error", {"error": f"{type(e).__name__}: {e}"})
            finally:
                self.running = False
        threading.Thread(target=work, daemon=True).start()
        return True


def create_app(runner: Runner, token: str, port: int = None) -> FastAPI:
    app = FastAPI(title="Agentic OS", docs_url=None, redoc_url=None, openapi_url=None)
    port = port or config.DASHBOARD_PORT
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", "127.0.0.1", "localhost", "testserver"}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"error": "bad host"}, status_code=403)          # DNS rebinding
        supplied = request.query_params.get("token") or request.cookies.get("agentos_token")
        if not supplied or not secrets.compare_digest(supplied, token):
            return JSONResponse({"error": "missing or wrong token"}, status_code=401)
        if request.method == "POST" and not secrets.compare_digest(request.headers.get("x-agentos-token", ""), token):
            return JSONResponse({"error": "missing CSRF header"}, status_code=403)
        response = await call_next(request)
        response.set_cookie("agentos_token", token, httponly=True, samesite="strict")
        response.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                                       "style-src 'self' 'unsafe-inline'; connect-src 'self'")
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/", response_class=HTMLResponse)
    def index():
        return PAGE.replace("__TOKEN__", token)

    @app.get("/api/state")
    def state():
        from ..memory.store import get_store
        r = audit.verify()
        with runner.lock:
            events = list(runner.events)
        return {"running": runner.running, "events": events, "pending": runner.approver.list(),
                "audit": {"ok": r.ok, "entries": r.entries, "reason": r.reason, "checkpoints": r.checkpoints},
                "audit_tail": [{k: e.get(k) for k in ("seq", "ts", "event", "tool", "approved", "reason")}
                               for e in audit.read_entries(last=30)],
                "history": [{k: t[k] for k in ("id", "started_at", "goal", "finished", "tainted", "answer")}
                            for t in get_store().history(15)],
                "model": config.MODEL, "sandbox": config.SANDBOX}

    @app.post("/api/run")
    async def run(request: Request):
        body = await request.json()
        goal = str(body.get("goal", "")).strip()
        if not goal:
            raise HTTPException(400, "goal is empty")
        if not runner.start(goal, bool(body.get("team"))):
            raise HTTPException(409, "a task is already running")
        return {"started": True}

    @app.post("/api/answer")
    async def answer(request: Request):
        body = await request.json()
        value = body.get("value")
        if value not in ("once", "task", "deny", True, False):
            raise HTTPException(400, "bad answer")
        if not runner.approver.answer(str(body.get("id")), value):
            raise HTTPException(404, "no such pending request")
        return {"ok": True}

    @app.post("/api/stop")
    def stop():
        config.STATE_DIR.mkdir(parents=True, exist_ok=True)
        config.STOP_FILE.touch()
        for rid in [p["id"] for p in runner.approver.list()]:
            runner.approver.answer(rid, "deny")
        return {"ok": True}

    return app


def serve(port=None, host=None):
    import uvicorn

    from ..agents.team import Team
    from ..core.agent import Agent
    from ..core.llm import chat
    from ..tools.registry import ToolRegistry
    registry = ToolRegistry.discover()
    runner = Runner(lambda approver, feed: Agent(registry, approver=approver, verbose=False, listeners=[feed]),
                    lambda approver, feed: Team(registry, chat, approver, verbose=False, listeners=[feed]))
    token = secrets.token_urlsafe(16)
    port = port or config.DASHBOARD_PORT
    print(f"\n  Agentic OS dashboard: http://127.0.0.1:{port}/?token={token}\n  (only this machine can reach it; "
          "the token changes every start)\n")
    uvicorn.run(create_app(runner, token, port), host=config.DASHBOARD_HOST, port=port, log_level="warning")


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Agentic OS</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 :root { --bg:#f6f7f9; --card:#fff; --ink:#1d2330; --mute:#6b7280; --line:#e3e6eb; --red:#c0392b; --green:#1e8e4f; --amber:#b7791f; --violet:#7b3fb3; }
 @media (prefers-color-scheme: dark) { :root { --bg:#14171c; --card:#1d2128; --ink:#e7e9ee; --mute:#9aa3b2; --line:#2c323c; } }
 * { box-sizing:border-box } body { margin:0; font:14px/1.45 system-ui,sans-serif; background:var(--bg); color:var(--ink); }
 header { padding:14px 20px; border-bottom:1px solid var(--line); display:flex; gap:16px; align-items:baseline; }
 header h1 { font-size:18px; margin:0 } .mute { color:var(--mute) }
 main { display:grid; grid-template-columns: 1.4fr 1fr; gap:16px; padding:16px 20px; }
 section { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; }
 h2 { font-size:14px; margin:0 0 10px } form { display:flex; gap:8px } input[type=text] { flex:1; padding:8px; border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--ink) }
 button { padding:7px 12px; border-radius:6px; border:1px solid var(--line); background:var(--bg); color:var(--ink); cursor:pointer }
 button.ok { background:var(--green); color:#fff; border:0 } button.warn { background:var(--amber); color:#fff; border:0 } button.no { background:var(--red); color:#fff; border:0 }
 .feed { max-height:420px; overflow:auto; font-family:ui-monospace,monospace; font-size:12.5px }
 .feed div { padding:2px 0; border-bottom:1px dashed var(--line) }
 .pending { border:2px solid var(--amber); border-radius:8px; padding:10px; margin-bottom:10px }
 .pending.tainted { border-color:var(--violet) } pre { white-space:pre-wrap; margin:6px 0 }
 table { width:100%; border-collapse:collapse; font-size:12.5px } td,th { text-align:left; padding:4px 6px; border-bottom:1px solid var(--line); vertical-align:top }
 .bad { color:var(--red); font-weight:600 } .good { color:var(--green); font-weight:600 }
</style></head><body>
<header><h1>Agentic OS</h1><span id="meta" class="mute"></span><span id="chain"></span></header>
<main>
 <div>
  <section><h2>New task</h2>
   <form id="f"><input type="text" id="goal" placeholder="What should the agent do?" autocomplete="off">
   <label class="mute"><input type="checkbox" id="team"> team</label><button class="ok">Run</button>
   <button type="button" class="no" id="stop">Stop</button></form></section>
  <section style="margin-top:16px"><h2>Waiting for you</h2><div id="pending" class="mute">Nothing to approve.</div></section>
  <section style="margin-top:16px"><h2>Current task</h2><div id="feed" class="feed mute">Idle.</div></section>
 </div>
 <div>
  <section><h2>Audit log</h2><table id="audit"></table></section>
  <section style="margin-top:16px"><h2>History</h2><table id="history"></table></section>
 </div>
</main>
<script>
const TOKEN = "__TOKEN__";
const $ = id => document.getElementById(id);
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
async function post(path, body) {
  const r = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json","X-AgentOS-Token":TOKEN}, body:JSON.stringify(body||{})});
  if (!r.ok) alert((await r.json()).detail || "request failed");
}
$("f").onsubmit = e => { e.preventDefault(); const g = $("goal").value.trim(); if (g) { post("/api/run", {goal:g, team:$("team").checked}); $("goal").value=""; } };
$("stop").onclick = () => post("/api/stop");
function row(cells) { const tr = el("tr"); cells.forEach(c => { const td = el("td"); if (c instanceof Node) td.appendChild(c); else td.textContent = c ?? ""; tr.appendChild(td); }); return tr; }
function describe(ev) {
  if (ev.event === "thinking") return "step " + ev.step + ": thinking...";
  if (ev.event === "tool_request") return ev.tool + " (" + ev.risk + "): " + ev.summary;
  if (ev.event === "tool_result") return ev.approved ? ("  " + (ev.ok ? "ok" : "failed") + (ev.injection && ev.injection.length ? "  !! possible injection: " + ev.injection.join(", ") : "")) : "  blocked: " + ev.reason;
  if (ev.event === "answer") return "ANSWER: " + ev.answer;
  if (ev.event === "error") return "ERROR: " + ev.error;
  if (ev.event === "task_start") return "== " + (ev.role || "agent") + ": " + ev.goal;
  return ev.event;
}
async function tick() {
  let s; try { s = await (await fetch("/api/state")).json(); } catch { return; }
  $("meta").textContent = "model " + s.model + " | sandbox " + s.sandbox + (s.running ? " | running" : " | idle");
  const c = $("chain"); c.textContent = s.audit.ok ? "audit chain intact (" + s.audit.entries + ")" : "AUDIT LOG TAMPERED: " + s.audit.reason; c.className = s.audit.ok ? "good" : "bad";
  const p = $("pending"); p.replaceChildren();
  if (!s.pending.length) p.textContent = "Nothing to approve.";
  s.pending.forEach(item => {
    const box = el("div", undefined, "pending" + (item.tainted ? " tainted" : ""));
    if (item.kind === "scope") {
      box.appendChild(el("b", "Widen task scope to include " + item.risk + "?"));
      box.appendChild(el("div", "current scope: " + item.scope, "mute"));
      [["Grant", true, "warn"], ["Refuse", false, "no"]].forEach(([t, v, cl]) => { const b = el("button", t, cl); b.onclick = () => post("/api/answer", {id:item.id, value:v}); box.appendChild(b); });
    } else {
      box.appendChild(el("b", item.tool + " (risk: " + item.risk + ")"));
      box.appendChild(el("pre", item.summary));
      box.appendChild(el("div", "why asking: " + item.reason, "mute"));
      if (item.tainted) box.appendChild(el("div", "Untrusted content was read this task. Is this what YOU asked for?", "bad"));
      [["Allow once", "once", "ok"], ["Allow for task", "task", "warn"], ["Deny", "deny", "no"]].forEach(([t, v, cl]) => { const b = el("button", t, cl); b.style.marginRight = "6px"; b.onclick = () => post("/api/answer", {id:item.id, value:v}); box.appendChild(b); });
    }
    p.appendChild(box);
  });
  const f = $("feed"); f.replaceChildren(); if (!s.events.length) f.textContent = s.running ? "Starting..." : "Idle.";
  s.events.forEach(ev => f.appendChild(el("div", ev.t + "  " + describe(ev))));
  f.scrollTop = f.scrollHeight;
  const a = $("audit"); a.replaceChildren(row(["#", "time", "event", "tool", ""]));
  s.audit_tail.slice().reverse().forEach(e => a.appendChild(row([e.seq, (e.ts||"").slice(11,19), e.event, e.tool, e.approved === undefined || e.approved === null ? "" : (e.approved ? "ran" : "blocked")])));
  const h = $("history"); h.replaceChildren(row(["started", "goal", "done", "answer"]));
  s.history.forEach(t => h.appendChild(row([(t.started_at||"").slice(0,16), t.goal, t.finished ? "yes" : "no", (t.answer||"").slice(0,80)])));
}
tick(); setInterval(tick, 1500);
</script></body></html>"""
