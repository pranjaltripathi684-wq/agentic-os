#!/usr/bin/env bash
# Build the Docker sandbox image. Only needed if you want the Docker backend;
# bubblewrap (AGENTOS_SANDBOX=bwrap) needs no image.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${AGENTOS_SANDBOX_IMAGE:-agentos-sandbox:latest}"
docker build -t "$IMAGE" sandbox/
echo "Built $IMAGE. Check it with: python main.py --sandbox docker --selftest"
