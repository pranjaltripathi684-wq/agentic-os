#!/usr/bin/env bash
# One-time setup for WSL2 Ubuntu (also works on Kali / Debian). Safe to re-run.
#     git clone https://github.com/pranjaltripathi684-wq/agentic-os.git && cd agentic-os
#     bash scripts/setup_wsl.sh
#
# sudo is used only if something is missing (system packages, Ollama). Re-running it on a
# machine that already has them needs no sudo.
#
# Pick another model:  AGENTOS_MODEL=qwen3:1.7b bash scripts/setup_wsl.sh
set -euo pipefail
cd "$(dirname "$0")/.."

DEFAULT_MODEL="qwen3:4b-instruct-2507-q4_K_M"
MODEL="${AGENTOS_MODEL:-$DEFAULT_MODEL}"
# The virtual environment lives in your Linux home, NOT in a OneDrive / Windows folder:
# OneDrive would try to sync thousands of library files.
VENV="$HOME/.venvs/agentos"

echo "==> System packages"
missing=()
for cmd in git curl zstd bwrap python3; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
python3 -m venv --help >/dev/null 2>&1 || missing+=("python3-venv")
if [ ${#missing[@]} -gt 0 ]; then
  echo "    missing: ${missing[*]} (installing with sudo)"
  sudo apt-get update -y
  sudo apt-get install -y python3-venv python3-pip git curl zstd bubblewrap
else
  echo "    all present"
fi

echo "==> Ollama and the model ($MODEL)"
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi
if ! curl -s http://127.0.0.1:11434/api/tags >/dev/null; then
  echo "    starting ollama serve in the background (log: /tmp/ollama.log)"
  nohup ollama serve >/tmp/ollama.log 2>&1 &
  sleep 3
fi
ollama pull "$MODEL"

echo "==> GPU"
if command -v nvidia-smi >/dev/null 2>&1 || [ -x /usr/lib/wsl/lib/nvidia-smi ]; then
  smi=$(command -v nvidia-smi || echo /usr/lib/wsl/lib/nvidia-smi)
  echo "    $("$smi" --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null | head -1)"
  echo "    (agentos init checks the model really runs on it)"
else
  echo "    no NVIDIA GPU visible: the model will run on the CPU (slower, still works)"
fi

echo "==> Python environment at $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install -e ".[all]"
if [ "$MODEL" != "$DEFAULT_MODEL" ]; then
  "$VENV/bin/agentos" config set model "$MODEL"
fi

mkdir -p "$HOME/agentos-workspace"

echo "==> Sandbox"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "    Docker found: building the sandbox image"
  bash scripts/build_sandbox.sh
else
  echo "    Docker not running: Agentic OS will use bubblewrap (lighter on RAM)"
fi

echo "==> Health check"
"$VENV/bin/agentos" init || true

cat <<MSG

Done. In every new terminal:
    source $VENV/bin/activate
    agentos run "What's my OS, RAM and free disk space?"

Then test the model on this machine and record the results:
    agentos eval

Optional voice mode:
    pip install -e ".[voice]" && sudo apt install -y espeak-ng
MSG
