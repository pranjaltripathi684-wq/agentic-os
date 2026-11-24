"""
Choosing and checking the model: `agentos model list | use | pull | bench`.

Small local models differ a lot in how well they call tools, how fast they are
on a laptop, and whether they waste time "thinking". The benchmark here answers
the three questions that matter for an agent, on YOUR machine:

  1. Does it run on the GPU or the CPU?            (ollama ps: share of the model in VRAM)
  2. Does it pick the right tool for a simple goal? (one real tool-call round)
  3. How fast is one agent step?                    (seconds per step, tokens per second)
"""

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field

import ollama

from .. import config
from . import llm

# Models known to work with Agentic OS. Sizes are the Ollama download (Q4 quantisation).
RECOMMENDED = [
    ("qwen3:4b-instruct-2507-q4_K_M", "2.5 GB", "default: no thinking, reliable tool calls, fits a 4 GB GPU"),
    ("qwen3:1.7b", "1.4 GB", "for CPU-only or low-RAM machines; less reliable on multi-step goals"),
    ("llama3.2:3b", "2.0 GB", "a different family, useful to compare red-team results"),
    ("qwen3:8b", "5.2 GB", "smarter but needs about 6 GB of free VRAM/RAM; thinking switched off"),
]

SYSTEM_INFO_SCHEMA = {"type": "function", "function": {
    "name": "system_info", "description": "Show this computer's operating system, CPU, RAM and free disk space.",
    "parameters": {"type": "object", "properties": {}, "required": []}}}
WRITE_FILE_SCHEMA = {"type": "function", "function": {
    "name": "write_file", "description": "Write text to a file in the workspace.",
    "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                   "required": ["path", "content"]}}}
BENCH_GOAL = "Which operating system is this computer running, and how much RAM does it have?"
BENCH_TOOL_RESULT = "OS: Ubuntu 22.04.5 LTS (WSL2)\nCPU: 8 cores\nRAM: 11.6 GB total, 7.9 GB free\nDisk: 945 GB free"
BENCH_SYSTEM = ("You are Agentic OS, an assistant that completes tasks on the user's Linux machine using tools. "
                "Use one tool at a time. When the task is done, reply with a short final answer and no tool calls.")


# ------------------------------------------------------------------ what's installed
@dataclass
class InstalledModel:
    name: str
    size_gb: float
    tools: bool | None              # None = unknown (older Ollama doesn't report capabilities)
    thinking: bool | None


def capabilities(name: str):
    """(tools, thinking) as reported by `ollama show`, or (None, None) if this Ollama doesn't say."""
    try:
        caps = getattr(ollama.show(name), "capabilities", None)
    except Exception:
        return None, None
    if not caps:
        return None, None
    caps = [str(c) for c in caps]
    return "tools" in caps, "thinking" in caps


def list_installed() -> list:
    try:
        models = ollama.list().models
    except Exception as e:
        raise llm.LLMError("Can't reach Ollama. Is it running? Try `ollama serve` in another terminal.") from e
    out = []
    for m in models:
        name = m.model or ""
        tools, thinking = capabilities(name)
        out.append(InstalledModel(name, round((m.size or 0) / 1e9, 1), tools, thinking))
    return out


def _loaded(name: str):
    try:
        running = ollama.ps().models
    except Exception:
        return None
    for m in running:
        if llm.same_model(m.model or "", name) or llm.same_model(getattr(m, "name", "") or "", name):
            return m
    return None


def gpu_share(name: str):
    """Fraction (0..1) of a LOADED model that sits in GPU memory, or None if it isn't loaded."""
    m = _loaded(name)
    if m is None:
        return None
    size = m.size or 0
    return (m.size_vram or 0) / size if size else None


def loaded_context(name: str):
    """The context length Ollama allocated for a loaded model (newer Ollama versions report it)."""
    m = _loaded(name)
    return getattr(m, "context_length", None) if m is not None else None


def unload(name: str) -> None:
    """Ask Ollama to free the model's memory now (keep_alive=0)."""
    try:
        ollama.generate(model=name, prompt="", keep_alive=0)
    except Exception:
        pass


def _nvidia_smi():
    wsl = "/usr/lib/wsl/lib/nvidia-smi"
    return shutil.which("nvidia-smi") or (wsl if os.path.exists(wsl) else None)


def vram():
    """(used MiB, total MiB) on the first NVIDIA GPU, or None."""
    exe = _nvidia_smi()
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        used, total = (int(x.strip()) for x in out.splitlines()[0].split(","))
        return used, total
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return None


def nvidia_gpu():
    """Name and memory of the NVIDIA GPU, if the driver is visible (WSL2 gets it from Windows)."""
    exe = _nvidia_smi()
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--query-gpu=name,memory.total", "--format=csv,noheader"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.splitlines()[0].strip() if out else None


def where_it_runs(share) -> str:
    if share is None:
        return "not loaded"
    if share >= 0.99:
        return "100% GPU"
    if share <= 0.01:
        return "CPU only"
    return f"{share:.0%} GPU / {1 - share:.0%} CPU"


# ------------------------------------------------------------------ download
def pull(name: str, on_progress=None):
    """Download a model. on_progress(status, completed_bytes, total_bytes) is called as it goes."""
    try:
        for p in ollama.pull(name, stream=True):
            if on_progress:
                on_progress(p.status or "", p.completed or 0, p.total or 0)
    except ollama.ResponseError as e:
        raise llm.LLMError(f"Ollama couldn't download '{name}': {e.error}") from e
    except Exception as e:
        raise llm.LLMError(f"Download of '{name}' failed: {type(e).__name__}: {e}") from e


# ------------------------------------------------------------------ benchmark
@dataclass
class BenchResult:
    model: str
    load_s: float = 0.0
    gpu: float | None = None
    tool_ok: bool = False
    tool_called: str = ""
    step_s: float = 0.0                 # average seconds per agent step (model call)
    tokens_per_s: float = 0.0
    answer_ok: bool = False
    answer: str = ""
    think_leak: bool = False
    error: str = ""
    notes: list = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.error:
            return "error"
        if not self.tool_ok:
            return "can't drive the agent (no correct tool call)"
        if self.think_leak:
            return "works, but leaks its reasoning"
        if self.step_s > 30:
            return "works, but very slow"
        if self.step_s > 10:
            return "works, a bit slow"
        return "good"


def _seconds(ns) -> float:
    return round((ns or 0) / 1e9, 2)


def bench(name: str) -> BenchResult:
    """One realistic agent round trip: goal -> tool call -> tool result -> final answer."""
    r = BenchResult(name)
    opts = {**llm.model_options(), "temperature": 0}
    try:
        warm = llm._chat_once(dict(model=name, messages=[{"role": "user", "content": "Reply with one word: ready"}],
                                   options=opts, keep_alive=config.KEEP_ALIVE))
        r.load_s = _seconds(getattr(warm, "load_duration", 0))
        r.gpu = gpu_share(name)

        messages = llm._with_no_think([{"role": "system", "content": BENCH_SYSTEM},
                                       {"role": "user", "content": BENCH_GOAL}], name)
        started = time.time()
        first = llm._chat_once(dict(model=name, messages=messages, tools=[SYSTEM_INFO_SCHEMA, WRITE_FILE_SCHEMA],
                                    options=opts, keep_alive=config.KEEP_ALIVE))
        t1 = time.time() - started
        calls = first.message.tool_calls or []
        r.tool_called = ", ".join(c.function.name for c in calls) or "(answered without a tool)"
        r.tool_ok = any(c.function.name == "system_info" for c in calls)
        raw = first.message.content or ""
        r.think_leak = "<think>" in raw or "</think>" in raw or bool(getattr(first.message, "thinking", None))

        if r.tool_ok:
            messages = messages + [first.message, {"role": "tool", "content": BENCH_TOOL_RESULT,
                                                   "tool_name": "system_info"}]
            started = time.time()
            second = llm._chat_once(dict(model=name, messages=messages, tools=[SYSTEM_INFO_SCHEMA, WRITE_FILE_SCHEMA],
                                         options=opts, keep_alive=config.KEEP_ALIVE))
            t2 = time.time() - started
            raw2 = second.message.content or ""
            r.think_leak = r.think_leak or "<think>" in raw2 or bool(getattr(second.message, "thinking", None))
            r.answer = llm.clean_content(raw2)
            r.answer_ok = bool(r.answer) and not second.message.tool_calls and (
                "ubuntu" in r.answer.lower() or "11.6" in r.answer or "12" in r.answer)
            r.step_s = round((t1 + t2) / 2, 1)
            tokens, ns = getattr(second, "eval_count", 0) or 0, getattr(second, "eval_duration", 0) or 0
        else:
            r.step_s = round(t1, 1)
            tokens, ns = getattr(first, "eval_count", 0) or 0, getattr(first, "eval_duration", 0) or 0
        r.tokens_per_s = round(tokens / (ns / 1e9), 1) if ns else 0.0
        if r.gpu is None:
            r.gpu = gpu_share(name)
    except ollama.ResponseError as e:
        r.error = "not downloaded" if e.status_code == 404 else str(e.error)
    except Exception as e:
        r.error = f"{type(e).__name__}: {e}"
    ctx = loaded_context(name)
    if ctx and ctx > config.NUM_CTX * 1.5:
        r.notes.append(f"Ollama reserved a {ctx}-token context for a {config.NUM_CTX}-token setting, probably for "
                       "parallel requests. Restarting Ollama with OLLAMA_NUM_PARALLEL=1 frees that VRAM.")
    if r.gpu is not None and 0.01 < r.gpu < 0.99:
        r.notes.append("Part of the model runs on the CPU because it doesn't quite fit in VRAM, which slows every step. "
                       "`agentos model tune` tries smaller context and batch sizes and saves the best one that fits.")
    elif r.gpu is not None and r.gpu <= 0.01 and nvidia_gpu():
        r.notes.append("An NVIDIA GPU is visible but the model runs on the CPU. See README > Speed and the GPU.")
    return r


# ------------------------------------------------------------------ tuning for small GPUs
# (num_ctx, num_batch), best first: more context is better, a bigger batch reads prompts faster.
TUNE_CANDIDATES = [(4096, 512), (4096, 256), (4096, 128), (3072, 256), (3072, 128), (2048, 128)]


@dataclass
class TuneTrial:
    num_ctx: int
    num_batch: int
    gpu: float | None
    step_s: float
    tool_ok: bool
    error: str = ""


def _with_options(num_ctx, num_batch, fn):
    saved = config.NUM_CTX, config.NUM_BATCH
    config.NUM_CTX, config.NUM_BATCH = num_ctx, num_batch
    try:
        return fn()
    finally:
        config.NUM_CTX, config.NUM_BATCH = saved


def best_trial(trials):
    """The first trial (in preference order) that fits fully on the GPU, else the fastest one that works."""
    usable = [t for t in trials if not t.error and t.tool_ok]
    full = [t for t in usable if t.gpu is not None and t.gpu >= 0.99]
    if full:
        return full[0]
    return min(usable, key=lambda t: t.step_s) if usable else None


def tune(name: str, on_trial=None, candidates=TUNE_CANDIDATES):
    """
    Measure VRAM used by everything else, then bench each candidate until one fits fully
    on the GPU. Returns (other_apps_vram, trials, best). other_apps_vram is (used, total) MiB or None.
    """
    unload(name)
    time.sleep(2)                              # give the driver a moment to release the memory
    baseline = vram()
    trials = []
    for num_ctx, num_batch in candidates:
        r = _with_options(num_ctx, num_batch, lambda: bench(name))
        trial = TuneTrial(num_ctx, num_batch, r.gpu, r.step_s, r.tool_ok, r.error)
        trials.append(trial)
        if on_trial:
            on_trial(trial)
        if not trial.error and trial.tool_ok and trial.gpu is not None and trial.gpu >= 0.99:
            break                              # candidates are in preference order, so this is the best
    return baseline, trials, best_trial(trials)
