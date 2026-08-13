import { build } from "esbuild";
import { copyFile, mkdir, rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });
await build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  outfile: "dist/index.js",
  banner: {
    js: "import { createRequire as __adversaryCreateRequire } from 'node:module'; const require = __adversaryCreateRequire(import.meta.url);",
  },
});

await mkdir("schema", { recursive: true });
await copyFile(
  "node_modules/@adversarylabs/sdk/schemas/adversary.manifest.v1.schema.json",
  "schema/adversary.manifest.v1.schema.json",
);
await mkdir("schemas", { recursive: true });
await copyFile(
  "node_modules/@adversarylabs/sdk/schemas/adversary.review.v1.schema.json",
  "schemas/adversary.review.v1.schema.json",
);
