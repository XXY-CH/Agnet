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
