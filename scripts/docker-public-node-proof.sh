#!/usr/bin/env bash
set -euo pipefail

docker build \
  -f Dockerfile.public-node-proof \
  --build-arg AGNET_GO_BASE_IMAGE="${AGNET_GO_BASE_IMAGE:-golang:1.26.1-bookworm}" \
  --build-arg AGNET_NODE_BASE_IMAGE="${AGNET_NODE_BASE_IMAGE:-node:22-bookworm-slim}" \
  -t agnet-public-node-proof \
  .
docker run --rm agnet-public-node-proof
