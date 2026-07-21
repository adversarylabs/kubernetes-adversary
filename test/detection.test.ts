import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseAdversaryManifest } from "@adversarylabs/sdk";

test("declares deterministic automatic detection", async () => {
  const source = await readFile(new URL("../adversary.yaml", import.meta.url), "utf8");
  const manifest = parseAdversaryManifest(source);

  assert.deepEqual(manifest.detection?.files, [
    "k8s/**/*.yml",
    "k8s/**/*.yaml",
    "kubernetes/**/*.yml",
    "kubernetes/**/*.yaml",
    "manifests/**/*.yml",
    "manifests/**/*.yaml",
    "**/*deployment*.yml",
    "**/*deployment*.yaml",
    "**/*service*.yml",
    "**/*service*.yaml",
    "**/*ingress*.yml",
    "**/*ingress*.yaml"
  ]);
  assert.equal(manifest.detection?.entrypoint, undefined);
});

