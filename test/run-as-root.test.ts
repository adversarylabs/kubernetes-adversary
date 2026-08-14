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

test("container runAsNonRoot false overrides Pod enforcement while retaining an inherited UID", async () => {
  const root = await temporaryTree({
    "pods.yaml": `apiVersion: v1
kind: Pod
metadata: {name: inherited-override}
spec:
  securityContext: {runAsUser: 0, runAsNonRoot: true}
  containers:
    - name: app
      image: example/app:v1
      securityContext: {runAsNonRoot: false}
---
apiVersion: v1
kind: Pod
metadata: {name: direct-override}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - name: app
      image: example/app:v1
      securityContext: {runAsUser: 0, runAsNonRoot: false}
---
apiVersion: v1
kind: Pod
metadata: {name: non-root-uid}
spec:
  securityContext: {runAsUser: 0}
  containers:
    - name: app
      image: example/app:v1
      securityContext: {runAsUser: 10001, runAsNonRoot: false}
`,
  });
  try {
    const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
    const observations = output.rawObservations?.filter((item) => item.ruleId === ruleId) ?? [];
    assert.equal(observations.length, 2);
    assert.equal(observations.every((item) => item.location?.snippet.includes("runAsUser: 0")), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("resolves a numeric zero through a YAML alias and anchors the alias use", async () => {
  const root = await temporaryTree({
    "pod.yaml": `apiVersion: v1
kind: Pod
metadata: {name: aliases}
spec:
  containers:
    - name: anchor
      image: example/app:v1
      securityContext:
        runAsNonRoot: true
        runAsUser: &root 0
    - name: inherited
      image: example/app:v1
      securityContext:
        runAsNonRoot: false
        runAsUser: *root
`,
  });
  try {
    const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
    const observations = output.rawObservations?.filter((item) => item.ruleId === ruleId) ?? [];
    assert.equal(observations.length, 1);
    assert.equal(observations[0]?.location?.snippet, "runAsUser: *root");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("resolves a mapping alias used directly as a container security context", async () => {
  const root = await temporaryTree({
    "pod.yaml": `apiVersion: v1
kind: Pod
metadata: {name: mapping-alias}
spec:
  securityContext: &rootContext
    runAsUser: 0
  containers:
    - name: explicit-alias
      image: example/app:v1
      securityContext: *rootContext
`,
  });
  try {
    const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
    const observation = output.rawObservations?.find((item) => item.ruleId === ruleId);
    assert.equal(observation?.location?.snippet, "securityContext: *rootContext");
    assert.equal((observation as { data?: { containerName?: string } } | undefined)?.data?.containerName, "explicit-alias");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("resolves a mapping alias used as an inherited Pod security context", async () => {
  const root = await temporaryTree({
    "pod.yaml": `apiVersion: v1
kind: Pod
metadata: {name: pod-mapping-alias}
rootContext: &rootContext
  runAsUser: 0
spec:
  securityContext: *rootContext
  containers:
    - name: inherited
      image: example/app:v1
`,
  });
  try {
    const output = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
    const observation = output.rawObservations?.find((item) => item.ruleId === ruleId);
    assert.equal(observation?.location?.snippet, "securityContext: *rootContext");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("recognizes YAML numeric zero forms but not quoted strings", async () => {
  for (const value of ["0", "00", "0x0", "0o0", "+0", "-0", "0.0"]) {
    const root = await temporaryTree({ "pod.yaml": workload(value, "numeric") });
    try {
      const output = await createApp().run({ input: { source: { path: root } } });
      assert.equal(output.findings.some((finding) => finding.ruleId === ruleId), true, value);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }

  const root = await temporaryTree({ "pod.yaml": workload('"0"', "quoted") });
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

test("a changed container enforcement override exposes an inherited Pod UID", async () => {
  const original = `apiVersion: v1
kind: Pod
metadata: {name: changed-enforcement}
spec:
  securityContext: {runAsUser: 0, runAsNonRoot: true}
  containers:
    - name: app
      image: example/app:v1
      securityContext: {runAsNonRoot: true}
`;
  const root = await gitRepository(original);
  try {
    await writeFile(join(root, "pod.yaml"), original.replace(
      "securityContext: {runAsNonRoot: true}",
      "securityContext: {runAsNonRoot: false}",
    ));
    const output = await changedReview(root);
    const observation = output.rawObservations?.find((item) => item.ruleId === ruleId);
    assert.equal(observation?.location?.snippet, "securityContext: {runAsNonRoot: false}");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a redundant false override and a deletion-only UID inheritance stay quiet", async () => {
  const redundantFalse = `apiVersion: v1
kind: Pod
metadata: {name: redundant-false}
spec:
  securityContext: {runAsUser: 0}
  containers:
    - name: app
      image: example/app:v1
      securityContext: {}
`;
  const redundantRoot = await gitRepository(redundantFalse);
  try {
    await writeFile(join(redundantRoot, "pod.yaml"), redundantFalse.replace(
      "securityContext: {}",
      "securityContext: {runAsNonRoot: false}",
    ));
    const output = await changedReview(redundantRoot);
    assert.equal(output.findings.some((finding) => finding.ruleId === ruleId), false);
  } finally {
    await rm(redundantRoot, { recursive: true, force: true });
  }

  const explicitUID = `apiVersion: v1
kind: Pod
metadata: {name: deleted-override}
spec:
  securityContext: {runAsUser: 0}
  containers:
    - name: app
      image: example/app:v1
      securityContext: {runAsUser: 10001}
`;
  const deletionRoot = await gitRepository(explicitUID);
  try {
    await writeFile(join(deletionRoot, "pod.yaml"), explicitUID.replace(
      "securityContext: {runAsUser: 10001}",
      "securityContext: {}",
    ));
    const output = await changedReview(deletionRoot);
    assert.equal(output.findings.some((finding) => finding.ruleId === ruleId), false);
  } finally {
    await rm(deletionRoot, { recursive: true, force: true });
  }
});

test("Helm values filenames stay quiet even when the document mimics a Pod", async () => {
  for (const path of ["values.yaml", "values-production.yml"]) {
    const root = await temporaryTree({ [path]: workload("0", "helm-values") });
    try {
      const output = await createApp().run({ input: { source: { path: root } } });
      assert.equal(output.findings.some((finding) => finding.ruleId === ruleId), false, path);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("a changed Pod-level enforcement policy exposes an inherited UID 0", async () => {
  const manifest = (policy: string) => `apiVersion: v1
kind: Pod
metadata: {name: changed-pod-policy}
spec:
  securityContext:
    runAsUser: 0
    runAsNonRoot: ${policy}
  containers:
    - name: app
      image: example/app:v1
`;
  const root = await gitRepository(manifest("true"));
  try {
    await writeFile(join(root, "pod.yaml"), manifest("false"));
    const output = await changedReview(root);
    const observation = output.rawObservations?.find((item) => item.ruleId === ruleId);
    assert.equal(observation?.location?.snippet, "runAsNonRoot: false");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a newly exposed inheriting container reports even when another container was already exposed", async () => {
  const manifest = (secondPolicy: string) => `apiVersion: v1
kind: Pod
metadata: {name: partial-policy-change}
spec:
  securityContext: {runAsUser: 0}
  containers:
    - name: already-exposed
      image: example/app:v1
    - name: newly-exposed
      image: example/app:v1
      securityContext: {runAsNonRoot: ${secondPolicy}}
`;
  const root = await gitRepository(manifest("true"));
  try {
    await writeFile(join(root, "pod.yaml"), manifest("false"));
    const output = await changedReview(root);
    const observation = output.rawObservations?.find((item) => item.ruleId === ruleId);
    assert.equal(observation?.location?.snippet, "securityContext: {runAsNonRoot: false}");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an added container inheriting an existing Pod UID 0 anchors the new container", async () => {
  const original = `apiVersion: v1
kind: Pod
metadata: {name: added-inheritor}
spec:
  securityContext: {runAsUser: 0}
  containers:
    - name: existing
      image: example/app:v1
      securityContext: {runAsUser: 10001}
`;
  const root = await gitRepository(original);
  try {
    await writeFile(join(root, "pod.yaml"), `${original}    - name: added
      image: example/sidecar:v1
`);
    const output = await changedReview(root);
    const observation = output.rawObservations?.find((item) => item.ruleId === ruleId);
    assert.match(observation?.location?.snippet ?? "", /name: added|image: example\/sidecar/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("container names keep explicit-root identity stable across list insertion", async () => {
  const prefix = `apiVersion: v1
kind: Pod
metadata: {name: inserted-root}
spec:
  containers:
`;
  const legacy = `    - name: legacy
      image: example/old:v1
      securityContext: {runAsUser: 0}
`;
  const added = `    - name: added
      image: example/new:v1
      securityContext: {runAsUser: 0}
`;
  const root = await gitRepository(`${prefix}${legacy}`);
  try {
    await writeFile(join(root, "pod.yaml"), `${prefix}${added}${legacy}`);
    const output = await changedReview(root);
    const observations = output.rawObservations?.filter((item) => item.ruleId === ruleId) ?? [];
    assert.equal(observations.length, 1);
    assert.equal((observations[0] as { data?: { containerName?: string } } | undefined)?.data?.containerName, "added");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("comment-only edits on existing root policy remain quiet by prior YAML semantics", async () => {
  const original = workload("0 # old explanation", "existing-root");
  const root = await gitRepository(original);
  try {
    await writeFile(join(root, "pod.yaml"), original.replace("# old explanation", "# clearer explanation"));
    const output = await changedReview(root);
    assert.equal(output.findings.some((finding) => finding.ruleId === ruleId), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a changed YAML anchor definition activates and anchors an unchanged UID alias use", async () => {
  const manifest = (uid: number) => `apiVersion: v1
kind: Pod
metadata: {name: changed-alias}
spec:
  securityContext: {runAsUser: &uid ${uid}}
  containers:
    - name: app
      image: example/app:v1
      securityContext: {runAsUser: *uid}
`;
  const root = await gitRepository(manifest(10001));
  try {
    await writeFile(join(root, "pod.yaml"), manifest(0));
    const output = await changedReview(root);
    const observation = output.rawObservations?.find((item) => item.ruleId === ruleId);
    assert.equal(observation?.location?.snippet, "securityContext: {runAsUser: &uid 0}");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("built-in kind names under custom API groups remain out of scope", async () => {
  const root = await temporaryTree({
    "custom.yaml": `apiVersion: widgets.example/v1
kind: Deployment
metadata: {name: custom}
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext: {runAsUser: 0}
`,
  });
  try {
    const output = await createApp().run({ input: { source: { path: root } } });
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
