import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

test("Docker proof demo delegates to the local proof script", async () => {
  const dockerfile = await readFile("Dockerfile", "utf8");
  const script = await readFile("scripts/docker-proof-demo.sh", "utf8");

  assert.match(dockerfile, /ARG AGNET_NODE_BASE_IMAGE=node:22-bookworm-slim/);
  assert.match(dockerfile, /FROM \$\{AGNET_NODE_BASE_IMAGE\}/);
  assert.match(dockerfile, /COPY \. \./);
  assert.match(dockerfile, /CMD \["bash", "scripts\/proof-demo\.sh"\]/);
  assert.match(script, /--build-arg AGNET_NODE_BASE_IMAGE="\$\{AGNET_NODE_BASE_IMAGE:-node:22-bookworm-slim\}"/);
  assert.match(script, /docker build[\s\S]*-t agnet-proof-demo[\s\S]*\./);
  assert.match(script, /docker run --rm agnet-proof-demo/);
});

test("Docker public node proof delegates to the public-listen proof", async () => {
  const dockerfile = await readFile("Dockerfile.public-node-proof", "utf8");
  const script = await readFile("scripts/docker-public-node-proof.sh", "utf8");

  assert.match(dockerfile, /ARG AGNET_GO_BASE_IMAGE=golang:1\.26\.1-bookworm/);
  assert.match(dockerfile, /FROM \$\{AGNET_GO_BASE_IMAGE\} AS go-builder/);
  assert.match(dockerfile, /go build -o \/out\/public-node-proof-go \.\/cmd\/go-fed-discovery/);
  assert.match(dockerfile, /ARG AGNET_NODE_BASE_IMAGE=node:22-bookworm-slim/);
  assert.match(dockerfile, /FROM \$\{AGNET_NODE_BASE_IMAGE\}/);
  assert.match(dockerfile, /CMD \["node", "scripts\/public-node-proof\.mjs", "state\/public-node-proof-go"\]/);
  assert.match(script, /--build-arg AGNET_GO_BASE_IMAGE="\$\{AGNET_GO_BASE_IMAGE:-golang:1\.26\.1-bookworm\}"/);
  assert.match(script, /--build-arg AGNET_NODE_BASE_IMAGE="\$\{AGNET_NODE_BASE_IMAGE:-node:22-bookworm-slim\}"/);
  assert.match(script, /docker build[\s\S]*-f Dockerfile\.public-node-proof[\s\S]*-t agnet-public-node-proof[\s\S]*\./);
  assert.match(script, /docker run --rm agnet-public-node-proof/);
});

test("Docker external reachability observer delegates to the observer script", async () => {
  const script = await readFile("scripts/docker-external-reachability-observer.sh", "utf8");

  assert.match(script, /AGNET_NODE_BASE_IMAGE:-node:22-bookworm-slim/);
  assert.match(script, /--add-host=host\.docker\.internal:host-gateway/);
  assert.match(script, /-v "\$PWD:\/app"/);
  assert.equal(script.trimEnd().split("\n").at(-1).trim(), 'node scripts/external-reachability-observer.mjs "$@" container');
});
