#!/usr/bin/env bash
# Record your terminal while you run the demo, then turn it into docs/demo.gif for the README.
# No sudo needed: asciinema goes into the Agentic OS venv, agg (cast -> GIF) into ~/.local/bin.
#
#   bash scripts/record_demo.sh             record: run the demo commands, then press Ctrl+D (or type exit)
#   bash scripts/record_demo.sh --gif-only  make the GIF again from docs/demo.cast (e.g. at another speed)
#
# The recording contains everything shown in the terminal. Don't type passwords or tokens while it runs.
set -euo pipefail
cd "$(dirname "$0")/.."

VENV="${VENV:-$HOME/.venvs/agentos}"
AGG="$HOME/.local/bin/agg"
AGG_URL="https://github.com/asciinema/agg/releases/download/v1.9.0/agg-x86_64-unknown-linux-gnu"
AGG_SHA256="f111e315cd71056b116302342553dd765b7297579ed511f111d0cedb442aeda6"
CAST="docs/demo.cast"
GIF="docs/demo.gif"
SPEED="${SPEED:-1.3}"

if [ ! -x "$VENV/bin/asciinema" ]; then
  echo "==> Installing asciinema into $VENV"
  "$VENV/bin/pip" install -q "asciinema==2.4.0"
fi

if [ ! -x "$AGG" ]; then
  echo "==> Downloading agg (asciinema GIF generator) to $AGG"
  mkdir -p "$(dirname "$AGG")"
  curl -fsSL -o "$AGG.download" "$AGG_URL"
  # Pinned checksum: if the download was swapped or corrupted, refuse to run it.
  echo "$AGG_SHA256  $AGG.download" | sha256sum -c --quiet || { rm -f "$AGG.download"; echo "agg checksum mismatch"; exit 1; }
  mv "$AGG.download" "$AGG"
  chmod +x "$AGG"
fi

if [ "${1:-}" != "--gif-only" ]; then
  cat <<'MSG'

Recording starts now. Follow docs/demo.md, then press Ctrl+D (or type exit) to stop.
Waits longer than 2 seconds (the model thinking) are cut short in the recording, so take your time.

MSG
  "$VENV/bin/asciinema" rec --overwrite -i 2 --cols 110 --rows 32 -t "Agentic OS demo" "$CAST"
fi

echo "==> Making $GIF"
"$AGG" --idle-time-limit 2 --speed "$SPEED" --theme monokai --font-size 15 --last-frame-duration 4 "$CAST" "$GIF"
echo
echo "Made $GIF ($(du -h "$GIF" | cut -f1)). To show it in the README, add this line under the first paragraph:"
echo
echo "    ![Agentic OS demo](docs/demo.gif)"
echo
echo "Too long? Try SPEED=2 bash scripts/record_demo.sh --gif-only"
