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
    readonly description: "Reviews Kubernetes manifests for privileged workloads, host access, RBAC, and image integrity.";
    readonly files: ["**/*.yml", "**/*.yaml"];
    readonly rules: [{
        readonly id: "kubernetes.privileged";
        readonly title: "Container runs privileged";
        readonly summary: "Container runs privileged";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Privileged containers effectively get host-level capabilities.";
        readonly impact: "Container escape becomes trivial.";
        readonly recommendation: "Remove privileged mode; grant only required capabilities.";
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
        readonly id: "kubernetes.host-pid-or-network";
        readonly title: "Pod shares host PID, IPC, or network namespace";
        readonly summary: "Pod shares host PID, IPC, or network namespace";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Host namespaces break container isolation.";
        readonly impact: "Host process visibility and port binding.";
        readonly recommendation: "Remove hostPID/hostIPC/hostNetwork unless required for a node agent.";
        readonly complexity: "small";
        readonly tags: ["security", "host-ns"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "host(?:PID|IPC|Network):\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kubernetes.cluster-admin-binding";
        readonly title: "Workload ServiceAccount bound to cluster-admin";
        readonly summary: "Workload ServiceAccount bound to cluster-admin";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Full cluster control from any pod using that SA.";
        readonly impact: "Cluster takeover from a single compromised pod.";
        readonly recommendation: "Create a least-privilege Role/ClusterRole for the app.";
        readonly complexity: "small";
        readonly tags: ["security", "rbac"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "kind:\\s*ClusterRoleBinding[\\s\\S]{0,400}roleRef:[\\s\\S]{0,120}name:\\s*cluster-admin[\\s\\S]{0,200}kind:\\s*ServiceAccount";
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
        readonly whyItMatters: "hostPath is a classic escape and credential theft path.";
        readonly impact: "Host filesystem access from the pod.";
        readonly recommendation: "Prefer PVC/CSI; never mount docker.sock into untrusted pods.";
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
        readonly id: "kubernetes.allow-privilege-escalation";
        readonly title: "allowPrivilegeEscalation not disabled for root or added caps";
        readonly summary: "allowPrivilegeEscalation not disabled for root or added caps";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Processes can gain more privileges than the parent.";
        readonly impact: "Privilege escalation inside the container.";
        readonly recommendation: "Set allowPrivilegeEscalation: false on all containers.";
        readonly complexity: "small";
        readonly tags: ["security", "pss"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "(?:runAsUser:\\s*0|capabilities:[\\s\\S]{0,80}add:)(?![\\s\\S]{0,200}allowPrivilegeEscalation:\\s*false)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kubernetes.run-as-root";
        readonly title: "Container explicitly runs as root";
        readonly summary: "Container explicitly runs as root";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Root in container increases escape impact.";
        readonly impact: "Broader host impact on escape.";
        readonly recommendation: "Run as non-root; set runAsNonRoot: true.";
        readonly complexity: "small";
        readonly tags: ["security", "root"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "(?:runAsUser:\\s*0\\b|runAsNonRoot:\\s*false)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kubernetes.mutable-image";
        readonly title: "Image uses latest or has no tag/digest";
        readonly summary: "Image uses latest or has no tag/digest";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Floating tags make deploys non-reproducible.";
        readonly impact: "Unexpected image content on redeploy.";
        readonly recommendation: "Pin images by version tag or digest.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "image"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "image:\\s*[\\\"']?[^\\\"'\\s:@]+(?::latest)?[\\\"']?\\s*(?:$|#)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kubernetes.wildcard-rbac";
        readonly title: "Role grants wildcard verbs and resources";
        readonly summary: "Role grants wildcard verbs and resources";
        readonly category: "permissions";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Wildcard RBAC is near-admin on the API group scope.";
        readonly impact: "Over-broad cluster or namespace power.";
        readonly recommendation: "Enumerate exact resources and verbs.";
        readonly complexity: "small";
        readonly tags: ["permissions", "rbac"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "(?:verbs|resources):\\s*\\[[^\\]]*[\\\"']?\\*[\\\"']?";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kubernetes.secret-in-configmap";
        readonly title: "ConfigMap carries credential-shaped values";
        readonly summary: "ConfigMap carries credential-shaped values";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "ConfigMaps are not Secrets and are widely readable.";
        readonly impact: "Credentials leak via casual kubectl dumps.";
        readonly recommendation: "Move credentials to a Secret or external secret manager.";
        readonly complexity: "small";
        readonly tags: ["secrets", "configmap"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yml", "**/*.yaml"];
            readonly pattern: {
                readonly pattern: "kind:\\s*ConfigMap[\\s\\S]{0,400}(?:password|token|secret|api[_-]?key)\\s*:\\s*[\\\"']?[A-Za-z0-9/+=_\\-]{12,}";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
