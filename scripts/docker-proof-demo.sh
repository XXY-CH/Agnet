#!/usr/bin/env bash
set -euo pipefail

docker build \
  --build-arg AGNET_NODE_BASE_IMAGE="${AGNET_NODE_BASE_IMAGE:-node:22-bookworm-slim}" \
  -t agnet-proof-demo \
  .
docker run --rm agnet-proof-demo
