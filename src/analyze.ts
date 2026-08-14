import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { basename, join, sep } from "node:path";
import { promisify } from "node:util";
import { type RuleContext } from "@adversarylabs/sdk";
import { isAlias, isMap, isScalar, parseAllDocuments, type Document } from "yaml";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);

interface SourceFile {
  path: string;
  source: string;
  previousSource?: string;
  status: "added" | "modified" | "repository";
  changedLines: Set<number>;
}
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown>; semanticKey?: string }

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
      ...(change.previousSource === undefined ? {} : { previousSource: change.previousSource }),
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

  if (match.kind === "explicit-run-as-root") {
    return matchingSources.flatMap((file) => findExplicitRootUsers(rule, file));
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
    const location = match.anchors === undefined
      ? locate(file.source, match.pattern)
      : locateEligible(file, match.pattern, match.anchors);
    if (location === undefined) return [];
    return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
  });
}

const SELECTOR_WORKLOADS = new Set(["DaemonSet", "Deployment", "ReplicaSet", "StatefulSet"]);
const CONTAINER_COLLECTIONS = ["containers", "initContainers", "ephemeralContainers"] as const;

function findExplicitRootUsers(rule: RuleSpec, file: SourceFile): Detection[] {
  if (isHelmValuesFile(file.path)) return [];
  const current = collectExplicitRootUsers(rule, file);
  if (file.status !== "modified" || file.previousSource === undefined) return current;
  const previous = collectExplicitRootUsers(rule, {
    path: file.path,
    source: file.previousSource,
    status: "repository",
    changedLines: new Set<number>(),
  });
  const previousKeys = new Set(previous.flatMap((detection) =>
    detection.semanticKey === undefined ? [] : [detection.semanticKey]));
  return current.filter((detection) =>
    detection.semanticKey === undefined || !previousKeys.has(detection.semanticKey));
}

function collectExplicitRootUsers(rule: RuleSpec, file: SourceFile): Detection[] {
  const detections: Detection[] = [];
  let documents;
  try {
    documents = parseAllDocuments(file.source, { prettyErrors: false, uniqueKeys: true });
  } catch {
    return [];
  }

  for (const [documentIndex, document] of documents.entries()) {
    if (document.errors.length > 0) continue;
    let manifest: Record<string, unknown> | undefined;
    try {
      manifest = asRecord(document.toJS({ maxAliasCount: 100 }));
    } catch {
      continue;
    }
    if (!manifest || typeof manifest.kind !== "string" || typeof manifest.apiVersion !== "string") continue;
    const podSpecPath = podSpecPathFor(manifest.apiVersion, manifest.kind);
    if (podSpecPath === undefined) continue;
    const podSpec = asRecord(valueAtPath(manifest, podSpecPath));
    if (podSpec === undefined) continue;

    const podSecurityContextPath = [...podSpecPath, "securityContext"];
    const podSecurityContext = asRecord(podSpec.securityContext);
    const podRunAsUser = podSecurityContext?.runAsUser;
    const podRunAsNonRoot = podSecurityContext?.runAsNonRoot;
    const podRunAsUserEvidence = fieldNodeEvidence(document, podSecurityContextPath, "runAsUser");
    const containers = CONTAINER_COLLECTIONS.flatMap((collection) => {
      const value = podSpec[collection];
      return Array.isArray(value)
        ? value.map((container, index) => ({ collection, index, container: asRecord(container) })).filter(
          (entry): entry is { collection: typeof collection; index: number; container: Record<string, unknown> } =>
            entry.container !== undefined,
        )
        : [];
    });

    for (const { collection, index, container } of containers) {
      const securityContext = asRecord(container.securityContext);
      const effectiveRunAsNonRoot = securityContext?.runAsNonRoot ?? podRunAsNonRoot;
      if (securityContext?.runAsUser !== 0 || effectiveRunAsNonRoot === true) continue;
      const securityContextPath = [...podSpecPath, collection, index, "securityContext"];
      const runAsUser = fieldNodeEvidence(document, securityContextPath, "runAsUser");
      const policyNodes = securityContext?.runAsNonRoot === false
        ? [fieldNodeEvidence(document, securityContextPath, "runAsNonRoot").primary]
        : securityContext?.runAsNonRoot === undefined && podRunAsNonRoot === false
          ? [fieldNodeEvidence(document, podSecurityContextPath, "runAsNonRoot").primary]
          : [];
      addRootDetection(
        detections,
        rule,
        file,
        document,
        runAsUser.value,
        runAsUser.primary,
        policyNodes,
        manifest.kind,
        container.name,
        "container",
        `${documentIndex}:${podSpecPath.join(".")}:${collection}:${containerIdentity(container, index)}`,
      );
    }

    if (podRunAsUser !== 0 || containers.length === 0) continue;
    const inheritingContainers = containers.filter(({ container }) => {
      const securityContext = asRecord(container.securityContext);
      const effectiveRunAsNonRoot = securityContext?.runAsNonRoot ?? podRunAsNonRoot;
      return securityContext?.runAsUser === undefined && effectiveRunAsNonRoot !== true;
    });
    if (inheritingContainers.length === 0) continue;
    const activationNodes = inheritingContainers.flatMap(({ collection, index }) => [
      document.getIn([...podSpecPath, collection, index, "name"], true),
      document.getIn([...podSpecPath, collection, index, "image"], true),
    ]);
    const policyNodes = inheritingContainers.flatMap(({ collection, index, container }) => {
      const securityContext = asRecord(container.securityContext);
      return securityContext?.runAsNonRoot === false
        ? [fieldNodeEvidence(document, [...podSpecPath, collection, index, "securityContext"], "runAsNonRoot").primary]
        : [];
    });
    if (podRunAsNonRoot === false) {
      policyNodes.push(fieldNodeEvidence(document, podSecurityContextPath, "runAsNonRoot").primary);
    }
    addRootDetection(
      detections,
      rule,
      file,
      document,
      podRunAsUserEvidence.value,
      podRunAsUserEvidence.primary,
      [...policyNodes, ...activationNodes],
      manifest.kind,
      undefined,
      "pod",
      `${documentIndex}:${podSpecPath.join(".")}:pod:${inheritingContainerIdentity(inheritingContainers)}`,
    );
  }

  return detections;
}

function isHelmValuesFile(path: string): boolean {
  return /^values(?:[-._][^/]*)?\.ya?ml$/i.test(basename(path));
}

function podSpecPathFor(apiVersion: string, kind: string): Array<string> | undefined {
  const [group] = apiVersion.includes("/") ? apiVersion.split("/", 1) : [""];
  if (group === "" && apiVersion === "v1") {
    if (kind === "Pod") return ["spec"];
    if (kind === "PodTemplate") return ["template", "spec"];
    if (kind === "ReplicationController") return ["spec", "template", "spec"];
    return undefined;
  }
  if (group === "apps" && ["DaemonSet", "Deployment", "ReplicaSet", "StatefulSet"].includes(kind)) {
    return ["spec", "template", "spec"];
  }
  if (group === "batch" && kind === "Job") return ["spec", "template", "spec"];
  if (group === "batch" && kind === "CronJob") return ["spec", "jobTemplate", "spec", "template", "spec"];
  return undefined;
}

function valueAtPath(value: unknown, path: readonly string[]): unknown {
  let current = value;
  for (const segment of path) {
    current = asRecord(current)?.[segment];
  }
  return current;
}

function containerIdentity(container: Record<string, unknown>, index: number): string {
  return typeof container.name === "string" && container.name.length > 0
    ? `name:${container.name}`
    : `index:${index}`;
}

function inheritingContainerIdentity(
  containers: Array<{
    collection: typeof CONTAINER_COLLECTIONS[number];
    index: number;
    container: Record<string, unknown>;
  }>,
): string {
  return CONTAINER_COLLECTIONS.flatMap((collection) => containers
    .filter((entry) => entry.collection === collection)
    .map(({ index, container }) => containerIdentity(container, index))
    .sort()
    .map((identity) => `${collection}:${identity}`))
    .join(",");
}

function fieldNodeEvidence(
  document: Document,
  parentPath: readonly (string | number)[],
  field: string,
): { value: unknown; primary: unknown } {
  const parent = document.getIn(parentPath, true);
  if (isAlias(parent)) {
    const resolved = parent.resolve(document);
    if (isMap(resolved)) {
      return { value: resolved.get(field, true), primary: parent };
    }
  }
  const value = document.getIn([...parentPath, field], true);
  return { value, primary: value };
}

function addRootDetection(
  detections: Detection[],
  rule: RuleSpec,
  file: SourceFile,
  document: Document,
  runAsUserNode: unknown,
  primaryEvidenceNode: unknown,
  policyNodes: unknown[],
  workloadKind: string,
  containerName: unknown,
  source: "container" | "pod",
  semanticKey: string,
): void {
  if (!isNumericZeroNode(runAsUserNode, document)) return;
  const primaryIndex = nodeStart(primaryEvidenceNode);
  if (primaryIndex === undefined) return;
  const resolvedValueIndex = isAlias(runAsUserNode)
    ? nodeStart(runAsUserNode.resolve(document))
    : nodeStart(runAsUserNode);
  const eligibleIndexes = [primaryIndex, resolvedValueIndex, ...policyNodes.map(nodeStart)]
    .filter((index): index is number => index !== undefined);
  const index = file.status === "modified"
    ? eligibleIndexes.find((candidate) => file.changedLines.has(lineAtIndex(file.source, candidate)))
    : primaryIndex;
  if (index === undefined) return;
  const name = typeof containerName === "string" ? containerName : undefined;
  detections.push({
    rule,
    file: file.path,
    ...locateFromIndex(file.source, index),
    label: source === "container" && name !== undefined
      ? `Container ${name} explicitly sets runAsUser to UID 0`
      : `${workloadKind} explicitly sets runAsUser to UID 0`,
    data: { workloadKind, containerName: name, source, runAsUser: 0 },
    semanticKey,
  });
}

function isNumericZeroNode(node: unknown, document: Document): boolean {
  const resolved = isAlias(node) ? node.resolve(document) : node;
  return isScalar(resolved) && resolved.value === 0;
}

function nodeStart(node: unknown): number | undefined {
  if ((!isScalar(node) && !isAlias(node)) || node.range === null || node.range === undefined) return undefined;
  return node.range[0];
}

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
): Promise<Pick<SourceFile, "changedLines" | "status" | "previousSource">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  let previousSource: string | undefined;
  try {
    previousSource = await gitOutput(ctx.repoPath, ["show", `${base}:${path}`]);
  } catch {
    // Preserve current changed-line behavior if the base blob cannot be read.
  }
  return {
    changedLines: changedLineNumbers(patch),
    status: "modified",
    ...(previousSource === undefined ? {} : { previousSource }),
  };
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

function locateEligible(
  file: SourceFile,
  expression: MatchExpression,
  anchors: readonly MatchExpression[],
): { line: number; snippet: string } | undefined {
  const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
  for (const match of file.source.matchAll(new RegExp(expression.pattern, flags))) {
    if (match.index === undefined || match[0] === "") continue;
    if (file.status !== "modified") return locateFromIndex(file.source, match.index);
    const line = eligibleSemanticAnchor(file, match.index, match[0], anchors);
    if (line !== undefined) return locateFromLine(file.source, line);
  }
  return undefined;
}

function eligibleSemanticAnchor(
  file: SourceFile,
  offset: number,
  matchedSource: string,
  anchors: readonly MatchExpression[],
): number | undefined {
  let eligible: number | undefined;
  for (const anchor of anchors) {
    const flags = anchor.flags.includes("g") ? anchor.flags : `${anchor.flags}g`;
    for (const match of matchedSource.matchAll(new RegExp(anchor.pattern, flags))) {
      if (match.index === undefined || match[0] === "") continue;
      const startLine = lineAtIndex(file.source, offset + match.index);
      const endLine = lineAtIndex(file.source, offset + match.index + match[0].length - 1);
      for (let line = startLine; line <= endLine; line += 1) {
        if (file.changedLines.has(line) && (eligible === undefined || line < eligible)) eligible = line;
      }
    }
  }
  return eligible;
}

function locateFromLine(source: string, line: number): { line: number; snippet: string } {
  return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
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
