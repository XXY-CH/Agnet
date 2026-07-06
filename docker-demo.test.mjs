import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

test("Docker proof demo delegates to the local proof script", async () => {
  const dockerfile = await readFile("Dockerfile", "utf8");
  const script = await readFile("scripts/docker-proof-demo.sh", "utf8");

  assert.match(dockerfile, /FROM node:/);
  assert.match(dockerfile, /COPY \. \./);
  assert.match(dockerfile, /CMD \["bash", "scripts\/proof-demo\.sh"\]/);
  assert.match(script, /docker build -t agnet-proof-demo \./);
  assert.match(script, /docker run --rm agnet-proof-demo/);
});

test("Docker public node proof delegates to the public-listen proof", async () => {
  const dockerfile = await readFile("Dockerfile.public-node-proof", "utf8");
  const script = await readFile("scripts/docker-public-node-proof.sh", "utf8");

  assert.match(dockerfile, /FROM golang:1\.26\.1-bookworm AS go-builder/);
  assert.match(dockerfile, /go build -o \/out\/public-node-proof-go \.\/cmd\/go-fed-discovery/);
  assert.match(dockerfile, /FROM node:22-bookworm-slim/);
  assert.match(dockerfile, /CMD \["node", "scripts\/public-node-proof\.mjs", "state\/public-node-proof-go"\]/);
  assert.match(script, /docker build -f Dockerfile\.public-node-proof -t agnet-public-node-proof \./);
  assert.match(script, /docker run --rm agnet-public-node-proof/);
});
