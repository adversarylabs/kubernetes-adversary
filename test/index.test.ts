import assert from "node:assert/strict";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [{"key": "privileged", "id": "kubernetes.privileged"}, {"key": "host-pid-or-network", "id": "kubernetes.host-pid-or-network"}, {"key": "cluster-admin-binding", "id": "kubernetes.cluster-admin-binding"}, {"key": "host-path", "id": "kubernetes.host-path"}, {"key": "allow-privilege-escalation", "id": "kubernetes.allow-privilege-escalation"}, {"key": "run-as-root", "id": "kubernetes.run-as-root"}, {"key": "mutable-image", "id": "kubernetes.mutable-image"}, {"key": "wildcard-rbac", "id": "kubernetes.wildcard-rbac"}, {"key": "secret-in-configmap", "id": "kubernetes.secret-in-configmap"}];

test("every shipped rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "kubernetes");
});
