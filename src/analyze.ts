import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { type RuleContext } from "@adversarylabs/sdk";
import { isScalar, parseAllDocuments } from "yaml";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);

interface SourceFile {
  path: string;
  source: string;
  status: "added" | "modified" | "repository";
  changedLines: Set<number>;
}
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const sources: SourceFile[] = [];
  for (const file of scoped) {
    if (file.status === "repository") {
      sources.push({
        path: file.path,
        source: file.content,
        status: "repository",
        changedLines: new Set<number>(),
      });
      continue;
    }
    const change = await changedSource(ctx, file.path);
    sources.push({
      path: file.path,
      source: file.content,
      status: change.status,
      changedLines: change.changedLines,
    });
  }
  ctx.summary.files_scanned = sources.length;

  const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }
}

function evaluate(rule: RuleSpec, sources: SourceFile[], allPaths: string[]): Detection[] {
  const match = rule.match;
  if (match.kind === "missing-file") {
    const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
    const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
    if (triggers.length === 0 || required) return [];
    return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
  }

  const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
  if (match.kind === "selector-template-mismatch") {
    return matchingSources.flatMap((file) => findSelectorTemplateMismatches(rule, file));
  }

  if (match.kind === "missing-content") {
    return matchingSources.flatMap((file) => {
      if (!test(file.source, match.trigger) || test(file.source, match.required)) return [];
      const location = locate(file.source, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  if (match.kind === "indented-block-missing-content") {
    return matchingSources.flatMap((file) =>
      extractIndentedBlocks(file.source, match.blockStart).flatMap((block) => {
        if (!test(block.source, match.trigger) || test(block.source, match.required)) return [];
        const location = locateFromIndex(file.source, block.start);
        return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
      }),
    );
  }

  return matchingSources.flatMap((file) => {
    if (!match.requires.every((pattern) => test(file.source, pattern))) return [];
    const location = locate(file.source, match.pattern);
    if (location === undefined) return [];
    return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
  });
}

const SELECTOR_WORKLOADS = new Set(["DaemonSet", "Deployment", "ReplicaSet", "StatefulSet"]);

function findSelectorTemplateMismatches(rule: RuleSpec, file: SourceFile): Detection[] {
  const detections: Detection[] = [];
  let documents;
  try {
    documents = parseAllDocuments(file.source, { prettyErrors: false, uniqueKeys: true });
  } catch {
    return [];
  }

  for (const document of documents) {
    if (document.errors.length > 0) continue;
    let manifest: Record<string, unknown> | undefined;
    try {
      manifest = asRecord(document.toJS({ maxAliasCount: 100 }));
    } catch {
      continue;
    }
    if (!manifest || typeof manifest.kind !== "string" || !SELECTOR_WORKLOADS.has(manifest.kind)) continue;

    const specValue = asRecord(manifest.spec);
    const selector = asRecord(asRecord(specValue?.selector)?.matchLabels);
    const templateLabels = asRecord(asRecord(asRecord(specValue?.template)?.metadata)?.labels);
    if (!selector) continue;

    for (const [key, expected] of Object.entries(selector)) {
      if (typeof expected !== "string") continue;
      const actual = templateLabels?.[key];
      if (actual === expected) continue;

      const node = document.getIn(["spec", "selector", "matchLabels", key], true);
      const index = isScalar(node) && node.range ? node.range[0] : document.range?.[0] ?? 0;
      const templateNode = document.getIn(["spec", "template", "metadata", "labels", key], true);
      const templateIndex = isScalar(templateNode) && templateNode.range ? templateNode.range[0] : undefined;
      const selectorLine = lineAtIndex(file.source, index);
      const templateLine = templateIndex === undefined ? undefined : lineAtIndex(file.source, templateIndex);
      if (!changed(file, selectorLine, templateLine)) continue;
      const workloadName = asRecord(manifest.metadata)?.name;
      const displayName = typeof workloadName === "string" ? `${manifest.kind} ${workloadName}` : manifest.kind;
      const actualDescription = actual === undefined ? "missing" : JSON.stringify(actual);
      detections.push({
        rule,
        file: file.path,
        ...locateFromIndex(file.source, index),
        label: `${displayName} selector label ${key} does not match its pod template`,
        data: {
          workloadKind: manifest.kind,
          workloadName: typeof workloadName === "string" ? workloadName : undefined,
          selectorKey: key,
          selectorValue: expected,
          templateValue: actual ?? null,
          mismatch: `expected ${JSON.stringify(expected)}, found ${actualDescription}`,
        },
      });
    }
  }
  return detections;
}

function changed(file: SourceFile, selectorLine: number, templateLine?: number): boolean {
  if (file.status !== "modified") return true;
  if (file.changedLines.has(selectorLine)) return true;
  return templateLine !== undefined && file.changedLines.has(templateLine);
}

function lineAtIndex(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<SourceFile, "changedLines" | "status">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  return { changedLines: changedLineNumbers(patch), status: "modified" };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function test(source: string, expression: MatchExpression): boolean {
  return new RegExp(expression.pattern, expression.flags).test(source);
}

function locate(source: string, expression: MatchExpression): { line: number; snippet: string } | undefined {
  const match = new RegExp(expression.pattern, expression.flags).exec(source);
  if (match?.index === undefined) return undefined;
  return locateFromIndex(source, match.index);
}

function locateFromIndex(source: string, index: number): { line: number; snippet: string } {
  const line = source.slice(0, index).split(/\r?\n/).length;
  return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}

function extractIndentedBlocks(source: string, start: MatchExpression): Array<{ source: string; start: number }> {
  const flags = start.flags.includes("g") ? start.flags : `${start.flags}g`;
  const expression = new RegExp(start.pattern, flags);
  const blocks: Array<{ source: string; start: number }> = [];
  let match: RegExpExecArray | null;

  while ((match = expression.exec(source)) !== null) {
    const lineStart = source.lastIndexOf("\n", Math.max(0, match.index - 1)) + 1;
    const lineEnd = source.indexOf("\n", match.index);
    const firstLineEnd = lineEnd < 0 ? source.length : lineEnd;
    const indentation = source.slice(lineStart, firstLineEnd).match(/^[ \t]*/)?.[0].length ?? 0;
    let end = source.length;
    let cursor = firstLineEnd < source.length ? firstLineEnd + 1 : source.length;

    while (cursor < source.length) {
      const nextLineEnd = source.indexOf("\n", cursor);
      const currentEnd = nextLineEnd < 0 ? source.length : nextLineEnd;
      const line = source.slice(cursor, currentEnd);
      if (line.trim() !== "") {
        const currentIndentation = line.match(/^[ \t]*/)?.[0].length ?? 0;
        if (currentIndentation <= indentation) { end = cursor; break; }
      }
      cursor = currentEnd < source.length ? currentEnd + 1 : source.length;
    }

    blocks.push({ source: source.slice(match.index, end), start: match.index });
    expression.lastIndex = Math.max(expression.lastIndex, end);
  }

  return blocks;
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}
