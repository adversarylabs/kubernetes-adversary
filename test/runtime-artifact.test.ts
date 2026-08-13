import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

test("the bundled runtime executes without node_modules", async () => {
  const artifact = await mkdtemp(join(tmpdir(), "kubernetes-artifact-"));
  const target = await mkdtemp(join(tmpdir(), "kubernetes-target-"));
  await mkdir(join(artifact, "dist"), { recursive: true });
  await cp(join(projectRoot, "dist", "index.js"), join(artifact, "dist", "index.js"));
  await cp(join(projectRoot, "schema"), join(artifact, "schema"), { recursive: true });
  await cp(join(projectRoot, "schemas"), join(artifact, "schemas"), { recursive: true });
  await cp(join(projectRoot, "THIRD_PARTY_NOTICES.md"), join(artifact, "THIRD_PARTY_NOTICES.md"));
  await writeFile(join(artifact, "package.json"), '{"type":"module"}\n');

  const notices = await readFile(join(artifact, "THIRD_PARTY_NOTICES.md"), "utf8");
  assert.deepEqual([...notices.matchAll(/^## (.+?) \(/gm)].map((match) => match[1]), [
    "@adversarylabs/sdk", "ajv", "fast-deep-equal", "fast-uri", "json-schema-traverse", "yaml",
  ]);
  assert.match(notices, /Permission is hereby granted/);
  assert.match(notices, /Redistribution and use in source and binary forms/);

  const runtime = await import(pathToFileURL(join(artifact, "dist", "index.js")).href) as {
    createApp(): { run(options: { input: unknown }): Promise<{ adversary: { name: string; version?: string }; findings: unknown[] }> };
  };
  const result = await runtime.createApp().run({ input: { source: { path: target } } });
  assert.equal(result.adversary.name, "kubernetes");
  assert.equal(result.adversary.version, "0.0.11");
  assert.deepEqual(result.findings, []);
});
