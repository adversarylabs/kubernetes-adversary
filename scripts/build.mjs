import { build } from "esbuild";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });
const result = await build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  outfile: "dist/index.js",
  metafile: true,
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

const licenseCatalog = new Map([
  ["@adversarylabs/sdk", ["MIT", "node_modules/@adversarylabs/sdk/LICENSE"]],
  ["ajv", ["MIT", "node_modules/ajv/LICENSE"]],
  ["fast-deep-equal", ["MIT", "node_modules/fast-deep-equal/LICENSE"]],
  ["fast-uri", ["BSD-3-Clause", "node_modules/fast-uri/LICENSE"]],
  ["json-schema-traverse", ["MIT", "node_modules/json-schema-traverse/LICENSE"]],
  ["yaml", ["ISC", "node_modules/yaml/LICENSE"]],
]);
const bundledPackages = [...new Set(Object.keys(result.metafile.inputs).flatMap((input) => {
  const marker = "node_modules/";
  const offset = input.lastIndexOf(marker);
  if (offset < 0) return [];
  const parts = input.slice(offset + marker.length).split("/");
  return [parts[0].startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0]];
}))].sort();
const notices = bundledPackages.map((name) => {
  const entry = licenseCatalog.get(name);
  if (entry === undefined) throw new Error(`missing full license text mapping for bundled package ${name}`);
  return [name, ...entry];
});
const noticeSections = await Promise.all(notices.map(async ([name, license, path]) =>
  `## ${name} (${license})\n\n${(await readFile(path, "utf8")).trim()}`,
));
await writeFile("THIRD_PARTY_NOTICES.md", `# Third-party notices\n\n${noticeSections.join("\n\n")}\n`);
