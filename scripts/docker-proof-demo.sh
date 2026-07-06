#!/usr/bin/env bash
set -euo pipefail

docker build -t agnet-proof-demo .
docker run --rm agnet-proof-demo
