import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "kubernetes";
    readonly displayName: "Kubernetes";
    readonly description: "Reviews Kubernetes manifests for workload isolation, image integrity, and host access.";
    readonly files: ["**/*.yml", "**/*.yaml"];
    readonly rules: [{
        readonly id: "kubernetes.privileged";
        readonly title: "Container runs privileged";
        readonly summary: "Container runs privileged";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Container runs privileged weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Remove privileged mode and grant only required capabilities.";
        readonly complexity: "small";
        readonly tags: ["security", "privileged"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "privileged:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kubernetes.host-path";
        readonly title: "Pod mounts a hostPath volume";
        readonly summary: "Pod mounts a hostPath volume";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Pod mounts a hostPath volume weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Replace hostPath with a scoped volume or a constrained read-only path.";
        readonly complexity: "small";
        readonly tags: ["security", "host-path"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "hostPath:\\s*(?:\\n|\\{)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kubernetes.mutable-image";
        readonly title: "Workload image uses a mutable tag";
        readonly summary: "Workload image uses a mutable tag";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Workload image uses a mutable tag weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Pin production images by digest.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-image"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "image:\\s*[^\\s]+:(?:latest|main|edge)\\b";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
