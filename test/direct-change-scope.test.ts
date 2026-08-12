import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);
const directRuleIds = [
  "kubernetes.privileged",
  "kubernetes.host-pid-or-network",
  "kubernetes.cluster-admin-binding",
  "kubernetes.host-path",
  "kubernetes.run-as-root",
  "kubernetes.mutable-image",
  "kubernetes.wildcard-rbac",
  "kubernetes.secret-in-configmap",
];

test("unrelated manifest edits do not surface legacy direct findings", async () => {
  const root = await gitRepository({ "resources.yaml": directRisks("old diagnostic") });
  try {
    const baseline = await createApp().run({
      input: { source: { path: root } },
      includeRawObservations: true,
    });
    for (const ruleId of directRuleIds) {
      assert.equal(
        baseline.rawObservations?.some((observation) => observation.ruleId === ruleId),
        true,
        `${ruleId} was not represented by the baseline fixture`,
      );
    }

    await writeFile(join(root, "resources.yaml"), directRisks("new diagnostic"));
    const output = await changedReview(root, ["resources.yaml"]);
    assert.equal(
      output.rawObservations?.some((observation) => directRuleIds.includes(observation.ruleId)),
      false,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("direct matching continues past legacy occurrences", async () => {
  const manifests = (secondPrivileged: boolean) => `apiVersion: v1
kind: Pod
metadata: {name: legacy}
spec:
  containers:
    - name: legacy
      image: example/legacy:v1
      securityContext:
        privileged: true
---
apiVersion: v1
kind: Pod
metadata: {name: changed}
spec:
  containers:
    - name: changed
      image: example/changed:v1
      securityContext:
        privileged: ${secondPrivileged}
`;
  const root = await gitRepository({ "pods.yaml": manifests(false) });
  try {
    await writeFile(join(root, "pods.yaml"), manifests(true));
    const output = await changedReview(root, ["pods.yaml"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "kubernetes.privileged",
    );
    assert.equal(observation?.location?.line, 19);
    assert.equal(observation?.location?.snippet, "privileged: true");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("absence-based security-context rules remain holistic", async () => {
  const manifest = (diagnostic: string) => `apiVersion: v1
kind: Pod
metadata:
  name: node-agent
  annotations:
    diagnostic: ${diagnostic}
spec:
  containers:
    - name: agent
      image: example/agent:v1
      securityContext:
        privileged: false
        runAsUser: 0
        capabilities:
          add:
            - SYS_ADMIN
`;
  const root = await gitRepository({ "agent.yaml": manifest("old") });
  try {
    await writeFile(join(root, "agent.yaml"), manifest("new"));
    const output = await changedReview(root, ["agent.yaml"]);
    assert.equal(
      output.findings.some((finding) => finding.ruleId === "kubernetes.allow-privilege-escalation"),
      true,
    );
    assert.equal(
      output.findings.some((finding) => finding.ruleId === "kubernetes.sys-admin-without-drop-all"),
      true,
    );
    assert.equal(
      output.findings.some((finding) => finding.ruleId === "kubernetes.run-as-root"),
      false,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("new manifests remain fully eligible for direct findings", async () => {
  const root = await gitRepository({ "README.md": "# resources\n" });
  try {
    await writeFile(join(root, "added.yaml"), `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        privileged: true
`);
    const output = await changedReview(root, ["added.yaml"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "kubernetes.privileged"), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function directRisks(diagnostic: string): string {
  return `apiVersion: v1
kind: Pod
metadata: {name: host-access}
spec:
  hostNetwork: true
  containers:
    - name: app
      image: example/app:v1
      securityContext:
        privileged: true
        runAsUser: 0
  volumes:
    - name: host
      hostPath:
        path: /var/lib
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: app-admin}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: app
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: broad-reader}
rules:
  - apiGroups: [""]
    resources: ["*"]
    verbs: ["get"]
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  annotations:
    diagnostic: ${diagnostic}
data:
  password: SuperSecretPassw0rd
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: floating}
spec:
  template:
    spec:
      containers:
        - name: app
          image: example/floating:latest
`;
}

async function changedReview(root: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
    includeRawObservations: true,
  });
}

async function gitRepository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "kubernetes-direct-scope-"));
  await execute("git", ["init", "--quiet", root]);
  await execute("git", ["-C", root, "config", "user.email", "tests@example.com"]);
  await execute("git", ["-C", root, "config", "user.name", "Tests"]);
  for (const [path, content] of Object.entries(files)) {
    await writeFile(join(root, path), content);
  }
  await execute("git", ["-C", root, "add", "."]);
  await execute("git", ["-C", root, "commit", "--quiet", "-m", "baseline"]);
  return root;
}
