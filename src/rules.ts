import { Adversary, Confidence, Severity, type ObservationInit } from "@adversarylabs/sdk";
import { spec, type RuleSpec } from "./spec.js";

const byId = new Map<string, RuleSpec>(spec.rules.map((rule) => [rule.id, rule]));

export function registerRules(app: Adversary): void {
  for (const rule of spec.rules) {
    app.defineRule({
      id: rule.id,
      category: rule.category,
      defaultSeverity: rule.severity,
      defaultConfidence: rule.confidence,
      aggregate(observations) {
        return {
          title: rule.title,
          category: rule.category,
          summary: observations.length === 1 ? rule.summary : `${rule.summary} (${observations.length} locations)`,
          whyItMatters: rule.whyItMatters,
          impact: rule.impact,
          recommendation: rule.recommendation,
          remediation: { complexity: rule.complexity },
          tags: rule.tags,
          confidence: Confidence.High,
        };
      },
    });
  }
}

export function observationFor(detection: { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }): ObservationInit {
  const rule = byId.get(detection.rule.id);
  if (rule === undefined) throw new Error(`Unknown rule ${detection.rule.id}`);
  return {
    ruleId: rule.id,
    subject: detection.file,
    groupKey: `${rule.id}:${detection.file}`,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    confidence: rule.confidence,
    confidenceAggregation: "maximum",
    severityAggregation: "highest",
    location: { file: detection.file, line: detection.line, label: detection.label, snippet: detection.snippet },
    evidence: { label: detection.label, ...detection.data },
    tags: rule.tags,
  };
}

export { Severity };
