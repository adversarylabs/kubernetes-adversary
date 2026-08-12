import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);
const ruleId = "kubernetes.selector-template-mismatch";

test("an unrelated document edit does not surface a legacy selector mismatch", async () => {
  const repo = await repositoryWithLegacyMismatch();
  await writeFile(join(repo, "resources.yaml"), resources("new diagnostic"));

  const output = await changedReview(repo, ["resources.yaml"]);
  assert.deepEqual(output.findings.filter((finding) => finding.ruleId === ruleId), []);
});

test("a newly added manifest remains eligible in full", async () => {
  const repo = await repositoryWithLegacyMismatch();
  await writeFile(join(repo, "added.yaml"), mismatchedDeployment("added"));

  const output = await changedReview(repo, ["added.yaml"]);
  const findings = output.findings.filter((finding) => finding.ruleId === ruleId);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.evidence[0]?.location.line, 6);
});

test("changing either side of a selector mismatch remains eligible", async () => {
  const repo = await repositoryWithLegacyMismatch();
  const path = "resources.yaml";
  await writeFile(join(repo, path), resources("old diagnostic").replace("app: worker", "app: changed"));

  const output = await changedReview(repo, [path]);
  assert.equal(output.findings.filter((finding) => finding.ruleId === ruleId).length, 1);
});

async function repositoryWithLegacyMismatch(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "kubernetes-selector-scope-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await writeFile(join(repo, "resources.yaml"), resources("old diagnostic"));
  await execute("git", ["add", "resources.yaml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

function resources(diagnostic: string): string {
  return `${mismatchedDeployment("legacy")}---
apiVersion: v1
kind: ConfigMap
metadata: {name: settings}
data:
  diagnostic: ${diagnostic}
`;
}

function mismatchedDeployment(name: string): string {
  return `apiVersion: apps/v1
kind: Deployment
metadata: {name: ${name}}
spec:
  selector:
    matchLabels: {app: api}
  template:
    metadata:
      labels: {app: worker}
    spec: {containers: []}
`;
}

async function changedReview(repoPath: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}
