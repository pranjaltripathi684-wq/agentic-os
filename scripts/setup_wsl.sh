#!/usr/bin/env bash
# One-time setup for WSL2 Ubuntu (also works on Kali / Debian). Safe to re-run.
#     cd "/mnt/c/Users/Pranjal Tripathi/OneDrive/Desktop/Agentic OS"
#     bash scripts/setup_wsl.sh
set -euo pipefail
cd "$(dirname "$0")/.."

MODEL="${AGENTOS_MODEL:-qwen3:4b}"
# The virtual environment lives in your Linux home, NOT in the OneDrive folder:
# OneDrive would try to sync thousands of library files.
VENV="$HOME/.venvs/agentos"

echo "==> System packages"
sudo apt-get update -y
sudo apt-get install -y python3-venv python3-pip git curl zstd bubblewrap

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

echo "==> Python environment at $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install -e ".[all]"

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

Optional voice mode:
    pip install -e ".[voice]" && sudo apt install -y espeak-ng
MSG
