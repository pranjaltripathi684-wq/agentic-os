# The sandbox image: a small Debian with common command-line tools.
# Every agent command runs in a fresh, throwaway container from this image.
# Build: bash scripts/build_sandbox.sh
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash coreutils findutils grep sed gawk diffutils procps file tree jq bc \
      less zip unzip xz-utils python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# A normal, unprivileged user. At run time Docker uses --user <your uid> anyway,
# so files the agent creates in /workspace are owned by you, not root.
RUN useradd --create-home --uid 1000 agent
USER agent
WORKDIR /workspace
