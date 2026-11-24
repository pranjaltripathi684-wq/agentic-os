#!/usr/bin/env bash
# Get the Docker sandbox image. Only needed for the Docker backend;
# bubblewrap (the default when Docker isn't running) needs no image.
#
#   bash scripts/build_sandbox.sh          build it here from sandbox/Dockerfile
#   bash scripts/build_sandbox.sh --pull   download the published one from GitHub's registry instead
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${AGENTOS_SANDBOX_IMAGE:-agentos-sandbox:latest}"
PUBLISHED="${AGENTOS_SANDBOX_PUBLISHED:-ghcr.io/pranjaltripathi684-wq/agentos-sandbox:latest}"

if [ "${1:-}" = "--pull" ]; then
  docker pull "$PUBLISHED"
  docker tag "$PUBLISHED" "$IMAGE"
  echo "Pulled $PUBLISHED as $IMAGE."
else
  docker build -t "$IMAGE" sandbox/
  echo "Built $IMAGE."
fi
echo "Check it with: agentos selftest --sandbox docker"
