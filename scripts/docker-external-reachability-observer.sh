#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: bash scripts/docker-external-reachability-observer.sh <bundle.json> <observed-bundle.json> <observer-trusted-zones.json>" >&2
  exit 1
fi

docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$PWD:/app" \
  -w /app \
  "${AGNET_NODE_BASE_IMAGE:-node:22-bookworm-slim}" \
  node scripts/external-reachability-observer.mjs "$@"
