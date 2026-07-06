#!/usr/bin/env bash
set -euo pipefail

docker build -f Dockerfile.public-node-proof -t agnet-public-node-proof .
docker run --rm agnet-public-node-proof
