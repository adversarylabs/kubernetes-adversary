import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, writeFile } from "node:fs/promises";
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
  await writeFile(join(artifact, "package.json"), '{"type":"module"}\n');

  const runtime = await import(pathToFileURL(join(artifact, "dist", "index.js")).href) as {
    createApp(): { run(options: { input: unknown }): Promise<{ adversary: { name: string; version?: string }; findings: unknown[] }> };
  };
  const result = await runtime.createApp().run({ input: { source: { path: target } } });
  assert.equal(result.adversary.name, "kubernetes");
  assert.equal(result.adversary.version, "0.0.11");
  assert.deepEqual(result.findings, []);
});
