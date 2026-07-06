#!/usr/bin/env bash
set -euo pipefail

mkdir -p state
go build -o state/public-node-proof-go ./cmd/go-fed-discovery
node scripts/public-node-proof.mjs state/public-node-proof-go
