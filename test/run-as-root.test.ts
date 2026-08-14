import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);
const ruleId = "kubernetes.run-as-root";

test("reports explicit effective UID 0 in known Pod workloads", async () => {
  const root = await temporaryTree({
    "pod.yaml": `apiVersion: v1
kind: Pod
metadata: {name: direct-root}
spec:
  containers:
    - name: app
      image: example/app:v1
      securityContext:
        runAsUser: 0
`,
    "deployment.yaml": `apiVersion: apps/v1
kind: Deployment
metadata: {name: init-root}
spec:
  selector: {matchLabels: {app: example}}
  template:
    metadata: {labels: {app: example}}
    spec:
      containers:
        - name: app
          image: example/app:v1
          securityContext: {runAsUser: 10001}
      initContainers:
        - name: setup
          image: example/setup:v1
          securityContext:
            runAsUser: 0
`,
    "cronjob.yaml": `apiVersion: batch/v1
kind: CronJob
metadata: {name: inherited-root}
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          securityContext:
            runAsUser: 0
          containers:
            - name: job
              image: example/job:v1
          restartPolicy: Never
`,
  });
  try {
    const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
    const observations = output.rawObservations?.filter((item) => item.ruleId === ruleId) ?? [];
    assert.equal(observations.length, 3);
    assert.deepEqual(observations.map((item) => item.location?.snippet), [
      "runAsUser: 0",
      "runAsUser: 0",
      "runAsUser: 0",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("runAsNonRoot false and non-workload YAML do not prove root execution", async () => {
  const root = await temporaryTree({
    "pod.yaml": `apiVersion: v1
kind: Pod
metadata: {name: unenforced-user}
spec:
  containers:
    - name: app
      image: example/nonroot:v1
      securityContext:
        runAsNonRoot: false
    - name: text
      image: example/nonroot:v1
      env:
        - name: DOCUMENTATION
          value: "runAsUser: 0"
      # An example only: runAsUser: 0
`,
    "values.yaml": `toolbox:
  containerSecurityContext:
    runAsNonRoot: false
    runAsUser: 0
`,
    "config.yaml": `apiVersion: v1
kind: ConfigMap
metadata: {name: documentation}
data:
  example: |
    securityContext:
      runAsUser: 0
`,
  });
  try {
    const output = await createApp().run({ input: { source: { path: root } } });
    assert.equal(output.findings.some((finding) => finding.ruleId === ruleId), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("non-root enforcement and explicit container overrides suppress ineffective Pod defaults", async () => {
  const root = await temporaryTree({
    "pods.yaml": `apiVersion: v1
kind: Pod
metadata: {name: rejected-root}
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 0
  containers:
    - name: app
      image: example/app:v1
---
apiVersion: v1
kind: Pod
metadata: {name: overridden-root}
spec:
  securityContext:
    runAsUser: 0
  containers:
    - name: app
      image: example/app:v1
      securityContext:
        runAsUser: 10001
    - name: sidecar
      image: example/sidecar:v1
      securityContext:
        runAsNonRoot: true
---
apiVersion: v1
kind: Pod
metadata: {name: inherited-non-root-enforcement}
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: app
      image: example/app:v1
      securityContext:
        runAsUser: 0
`,
  });
  try {
    const output = await createApp().run({ input: { source: { path: root } } });
    assert.equal(output.findings.some((finding) => finding.ruleId === ruleId), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("modified findings require a changed semantic runAsUser line", async () => {
  const root = await gitRepository(workload("10001", "old note"));
  try {
    await writeFile(join(root, "pod.yaml"), workload("0", "old note"));
    const output = await changedReview(root);
    const observation = output.rawObservations?.find((item) => item.ruleId === ruleId);
    assert.equal(observation?.location?.snippet, "runAsUser: 0");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("comment, string, unrelated, and runAsNonRoot-only edits stay quiet", async () => {
  const original = `apiVersion: v1
kind: Pod
metadata:
  name: locality
  annotations:
    note: old
spec:
  containers:
    - name: app
      image: example/app:v1
      securityContext:
        runAsNonRoot: true
    - name: documented
      image: example/app:v1
      env:
        - name: EXAMPLE
          value: "runAsUser: 10001"
      # runAsUser: 10001
`;
  const root = await gitRepository(original);
  try {
    await writeFile(join(root, "pod.yaml"), original
      .replace("note: old", "note: new")
      .replace("runAsNonRoot: true", "runAsNonRoot: false")
      .replace('value: "runAsUser: 10001"', 'value: "runAsUser: 0"')
      .replace("# runAsUser: 10001", "# runAsUser: 0"));
    const output = await changedReview(root);
    assert.equal(output.findings.some((finding) => finding.ruleId === ruleId), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function workload(runAsUser: string, note: string): string {
  return `apiVersion: v1
kind: Pod
metadata:
  name: changed-root
  annotations: {note: ${note}}
spec:
  containers:
    - name: app
      image: example/app:v1
      securityContext:
        runAsUser: ${runAsUser}
`;
}

async function temporaryTree(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "kubernetes-root-rule-"));
  for (const [path, content] of Object.entries(files)) await writeFile(join(root, path), content);
  return root;
}

async function gitRepository(content: string): Promise<string> {
  const root = await temporaryTree({ "pod.yaml": content });
  await execute("git", ["init", "--quiet", root]);
  await execute("git", ["-C", root, "config", "user.email", "tests@example.com"]);
  await execute("git", ["-C", root, "config", "user.name", "Tests"]);
  await execute("git", ["-C", root, "add", "pod.yaml"]);
  await execute("git", ["-C", root, "commit", "--quiet", "-m", "baseline"]);
  return root;
}

async function changedReview(root: string) {
  return createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: ["pod.yaml"],
      },
    },
    includeRawObservations: true,
  });
}
