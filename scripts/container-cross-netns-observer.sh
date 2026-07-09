#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: bash scripts/container-cross-netns-observer.sh <bundle.json> <observed-bundle.json> <observer-trusted-zones.json>" >&2
  exit 1
fi

container run --rm \
  -v "$PWD:/app" \
  -w /app \
  "${AGNET_NODE_BASE_IMAGE:-node:24-alpine}" \
  node scripts/external-reachability-observer.mjs "$@" cross-netns
