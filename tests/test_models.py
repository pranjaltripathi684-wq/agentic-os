"""Model management, saved settings and the model benchmark (Ollama faked)."""

import json
from types import SimpleNamespace as NS

import pytest

from agentos import cli, config
from agentos.core import llm, models


# ------------------------------------------------------------------ names
def test_model_names_match_exactly():
    assert llm.same_model("qwen3:4b", "qwen3:4b")
    assert llm.same_model("llama3.2:latest", "llama3.2")
    assert not llm.same_model("qwen3:4b-instruct-2507-q4_K_M", "qwen3:4b")      # the old prefix bug
    assert not llm.same_model("qwen3:4b", "qwen3:4b-instruct-2507-q4_K_M")
    assert llm.same_model("hf.co/unsloth/Qwen3-4B-Instruct-2507-GGUF:Q4_K_M", "hf.co/unsloth/Qwen3-4B-Instruct-2507-GGUF:Q4_K_M")


def test_no_think_only_for_hybrid_qwen3():
    assert llm.is_hybrid_qwen3("qwen3:4b") and llm.is_hybrid_qwen3("qwen3:8b") and llm.is_hybrid_qwen3("qwen3")
    for name in ("qwen3:4b-instruct-2507-q4_K_M", "qwen3:4b-thinking-2507-q8_0", "qwen3.5:4b", "qwen3-coder:30b",
                 "llama3.2:3b", "hf.co/unsloth/Qwen3-4B-Instruct-2507-GGUF:Q4_K_M"):
        assert not llm.is_hybrid_qwen3(name), name
    msgs = [{"role": "system", "content": "x"}]
    assert llm._with_no_think(msgs, config.DEFAULT_MODEL) is msgs


def test_check_ready_names_the_fix(monkeypatch):
    monkeypatch.setattr(llm.ollama, "list", lambda: NS(models=[NS(model="qwen3:4b")]))
    with pytest.raises(llm.LLMError, match="agentos model use qwen3:4b-instruct"):
        llm.check_ready("qwen3:4b-instruct-2507-q4_K_M")
    llm.check_ready("qwen3:4b")


# ------------------------------------------------------------------ settings
def test_settings_round_trip(isolated):
    config.save_setting("model", "llama3.2:3b")
    assert config.MODEL == "llama3.2:3b"
    data = json.loads(config.SETTINGS_FILE.read_text())
    assert data == {"model": "llama3.2:3b"}
    assert oct(config.SETTINGS_FILE.stat().st_mode)[-3:] == "600"
    config.save_setting("model", None)
    assert config.MODEL == config.DEFAULT_MODEL and config.saved_settings() == {}


def test_settings_parsing():
    assert config.parse_setting("plan_first", "yes") is True
    assert config.parse_setting("plan_first", "off") is False
    assert config.parse_setting("max_steps", "15") == 15
    assert config.parse_setting("scope", "read,network") == "read,network"
    assert config.parse_setting("scope", "read-only") == "read-only"
    for key, bad in (("max_steps", "lots"), ("max_steps", "0"), ("sandbox", "chroot"), ("plan_first", "maybe"),
                     ("nope", "1"), ("model", "  "), ("scope", "readonly"), ("scope", "read,root")):
        with pytest.raises(ValueError):
            config.parse_setting(key, bad)


def test_saved_file_is_read_with_env_winning(tmp_path, monkeypatch):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"model": "saved-model", "max_steps": "oops", "plan_first": True}))
    monkeypatch.setattr(config, "_SAVED", config._load_settings(path))
    monkeypatch.delenv("AGENTOS_MODEL", raising=False)
    assert config._get("AGENTOS_MODEL", "model", "d") == "saved-model"
    assert config._int("AGENTOS_MAX_STEPS", "max_steps", 10) == 10          # a typo falls back to the default
    assert config._flag("AGENTOS_PLAN_FIRST", "plan_first", False) is True
    monkeypatch.setenv("AGENTOS_MODEL", "env-model")
    assert config._get("AGENTOS_MODEL", "model", "d") == "env-model"
    path.write_text("not json")
    assert config._load_settings(path) == {}


def test_environment_still_wins_after_saving(monkeypatch, capsys):
    monkeypatch.setenv("AGENTOS_MODEL", "from-env")
    cli.main(["config", "set", "model", "saved-one"])
    assert config.MODEL == "from-env" and config.saved_settings()["model"] == "saved-one"
    assert "AGENTOS_MODEL is set" in capsys.readouterr().out
    monkeypatch.delenv("AGENTOS_MODEL")
    cli.main(["config", "unset", "model"])
    assert config.MODEL == config.DEFAULT_MODEL


def test_model_use_prompt_shows_the_choice(fake_ollama, monkeypatch):
    seen = []
    monkeypatch.setattr(cli.console, "input", lambda prompt: seen.append(prompt) or "n")
    cli.main(["model", "use", "qwen3:1.7b"])
    assert "\\[y/N]" in seen[0] and config.MODEL == config.DEFAULT_MODEL       # escaped, so Rich shows [y/N]


def test_config_command(capsys):
    cli.main(["config", "set", "plan_first", "true"])
    assert config.PLAN_FIRST is True
    cli.main(["config", "show"])
    out = capsys.readouterr().out
    assert "plan_first" in out and "saved" in out
    cli.main(["config", "unset", "plan_first"])
    assert config.PLAN_FIRST is False
    with pytest.raises(SystemExit):
        cli.main(["config", "set", "max_steps", "many"])
    with pytest.raises(SystemExit):
        cli.main(["config", "set"])


# ------------------------------------------------------------------ fake Ollama
class FakeOllama:
    """Enough of the ollama module for list / show / ps / pull / chat."""

    def __init__(self, installed=("qwen3:4b",), caps=("completion", "tools"), on_gpu=1.0, picks="system_info"):
        self.installed, self.caps, self.on_gpu, self.picks = list(installed), list(caps), on_gpu, picks
        self.loaded, self.pulled, self.fits, self.options = set(), [], None, {}

    def list(self):
        return NS(models=[NS(model=m, size=2_500_000_000) for m in self.installed])

    def show(self, name):
        return NS(capabilities=self.caps)

    def ps(self):
        return NS(models=[NS(model=m, name=m, size=1000, size_vram=int(1000 * self.on_gpu)) for m in self.loaded])

    def pull(self, name, stream=True):
        self.pulled.append(name)
        self.installed.append(name)
        yield NS(status="pulling manifest", completed=None, total=None)
        yield NS(status="success", completed=10, total=10)

    def generate(self, model, prompt="", keep_alive=None):
        if keep_alive == 0:
            self.loaded.discard(model)
        return NS(response="")

    def chat(self, **kw):
        self.options = kw.get("options") or {}
        if self.fits:
            self.on_gpu = 1.0 if self.fits(self.options) else 0.83
        self.loaded.add(kw["model"])
        has_tool_result = any((m.get("role") if isinstance(m, dict) else getattr(m, "role", "")) == "tool"
                              for m in kw["messages"])
        if kw.get("tools") and not has_tool_result:
            calls = [NS(function=NS(name=self.picks, arguments={}))] if self.picks else None
            msg = NS(role="assistant", content="", tool_calls=calls, thinking=None)
        else:
            msg = NS(role="assistant", content="Ubuntu 22.04 with 11.6 GB of RAM.", tool_calls=None, thinking=None)
        return NS(message=msg, load_duration=2_000_000_000, eval_count=40, eval_duration=1_000_000_000)


@pytest.fixture
def fake_ollama(monkeypatch):
    fake = FakeOllama()
    for name in ("list", "show", "ps", "pull", "chat", "generate"):
        monkeypatch.setattr(models.ollama, name, getattr(fake, name))
    monkeypatch.setattr(models, "nvidia_gpu", lambda: "NVIDIA GeForce RTX 3050 Laptop GPU, 4096 MiB")
    return fake


def test_bench_good_model(fake_ollama):
    r = models.bench("qwen3:4b")
    assert r.tool_ok and r.answer_ok and not r.think_leak and r.gpu == 1.0
    assert r.load_s == 2.0 and r.tokens_per_s == 40.0 and r.verdict == "good" and not r.notes


def test_bench_spots_cpu_and_wrong_tool(fake_ollama):
    fake_ollama.on_gpu, fake_ollama.picks = 0.0, "write_file"
    r = models.bench("qwen3:4b")
    assert not r.tool_ok and r.verdict.startswith("can't drive")
    assert models.where_it_runs(r.gpu) == "CPU only" and "runs on the CPU" in r.notes[0]
    fake_ollama.on_gpu = 0.81
    assert "agentos model tune" in models.bench("qwen3:4b").notes[0]
    assert models.where_it_runs(0.6) == "60% GPU / 40% CPU" and models.where_it_runs(None) == "not loaded"


def test_model_use_downloads_and_saves(fake_ollama, capsys):
    cli.main(["model", "use", "llama3.2:3b", "--yes"])
    assert fake_ollama.pulled == ["llama3.2:3b"]
    assert config.MODEL == "llama3.2:3b" and config.saved_settings()["model"] == "llama3.2:3b"


def test_model_use_refuses_models_without_tools(fake_ollama, capsys):
    fake_ollama.caps = ["completion"]
    with pytest.raises(SystemExit):
        cli.main(["model", "use", "qwen3:4b"])
    assert "can't call tools" in capsys.readouterr().out and config.MODEL == config.DEFAULT_MODEL


def test_model_list_and_bench_commands(fake_ollama, capsys, monkeypatch):
    from rich.console import Console
    monkeypatch.setattr(cli, "console", Console(width=200))
    cli.main(["model"])
    out = capsys.readouterr().out
    assert "qwen3:4b" in out and "Recommended" in out and config.DEFAULT_MODEL in out
    cli.main(["model", "bench", "qwen3:4b"])
    out = capsys.readouterr().out
    assert "system_info" in out and "good" in out and "100% GPU" in out


def test_options_go_to_every_call(fake_ollama, monkeypatch):
    monkeypatch.setattr(config, "NUM_CTX", 3072)
    monkeypatch.setattr(config, "NUM_BATCH", 128)
    models.bench("qwen3:4b")
    assert fake_ollama.options["num_ctx"] == 3072 and fake_ollama.options["num_batch"] == 128


def test_tune_stops_at_the_first_setting_that_fits(fake_ollama, monkeypatch):
    fake_ollama.fits = lambda o: o["num_batch"] <= 128           # like a 4 GB card: only a small batch fits
    monkeypatch.setattr(models, "vram", lambda: (700, 4096))
    monkeypatch.setattr(models.time, "sleep", lambda s: None)
    seen = []
    baseline, trials, best = models.tune("qwen3:4b", on_trial=seen.append)
    assert baseline == (700, 4096)
    assert [(t.num_ctx, t.num_batch) for t in trials] == [(4096, 512), (4096, 256), (4096, 128)]
    assert (best.num_ctx, best.num_batch, best.gpu) == (4096, 128, 1.0) and seen == trials
    assert (config.NUM_CTX, config.NUM_BATCH) == (4096, 512)     # tuning doesn't leave settings changed


def test_tune_without_a_full_fit_picks_the_fastest():
    t = [models.TuneTrial(4096, 512, 0.8, 9.0, True), models.TuneTrial(2048, 128, 0.9, 6.5, True),
         models.TuneTrial(3072, 128, None, 0.0, False, error="boom")]
    assert models.best_trial(t).num_ctx == 2048
    assert models.best_trial([t[2]]) is None


def test_tune_command_saves(fake_ollama, monkeypatch, capsys):
    fake_ollama.fits = lambda o: o["num_ctx"] <= 3072 and o["num_batch"] <= 256
    monkeypatch.setattr(models, "vram", lambda: (650, 4096))
    monkeypatch.setattr(models.time, "sleep", lambda s: None)
    cli.main(["model", "tune", "qwen3:4b", "--yes"])
    out = capsys.readouterr().out
    assert "650 of 4096 MiB" in out and "Fits fully on the GPU" in out
    assert config.NUM_CTX == 3072 and config.NUM_BATCH == 256
    assert config.saved_settings() == {"num_ctx": 3072, "num_batch": 256}
