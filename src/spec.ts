import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface IndentedBlockMissingContentMatch { kind: "indented-block-missing-content"; files: string[]; blockStart: MatchExpression; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
interface SelectorTemplateMismatch { kind: "selector-template-mismatch"; files: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | IndentedBlockMissingContentMatch | MissingFileMatch | SelectorTemplateMismatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

export const spec = {
  "id": "kubernetes",
  "displayName": "Kubernetes",
  "description": "Reviews Kubernetes manifests for workload isolation, selector integrity, RBAC, and image safety.",
  "files": [
    "**/*.yml",
    "**/*.yaml"
  ],
  "rules": [
    {
      "id": "kubernetes.privileged",
      "title": "Container runs privileged",
      "summary": "Container runs privileged",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Privileged containers effectively get host-level capabilities.",
      "impact": "Container escape becomes trivial.",
      "recommendation": "Remove privileged mode; grant only required capabilities.",
      "complexity": "small",
      "tags": [
        "security",
        "privileged"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "pattern": {
          "pattern": "privileged:\\s*true",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "kubernetes.host-pid-or-network",
      "title": "Pod shares host PID, IPC, or network namespace",
      "summary": "Pod shares host PID, IPC, or network namespace",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Host namespaces break container isolation.",
      "impact": "Host process visibility and port binding.",
      "recommendation": "Remove hostPID/hostIPC/hostNetwork unless required for a node agent.",
      "complexity": "small",
      "tags": [
        "security",
        "host-ns"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "pattern": {
          "pattern": "host(?:PID|IPC|Network):\\s*true",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "kubernetes.cluster-admin-binding",
      "title": "Workload ServiceAccount bound to cluster-admin",
      "summary": "Workload ServiceAccount bound to cluster-admin",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Full cluster control from any pod using that SA.",
      "impact": "Cluster takeover from a single compromised pod.",
      "recommendation": "Create a least-privilege Role/ClusterRole for the app.",
      "complexity": "small",
      "tags": [
        "security",
        "rbac"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "pattern": {
          "pattern": "kind:\\s*ClusterRoleBinding[\\s\\S]{0,400}roleRef:[\\s\\S]{0,120}name:\\s*cluster-admin[\\s\\S]{0,200}kind:\\s*ServiceAccount",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "kubernetes.host-path",
      "title": "Pod mounts a hostPath volume",
      "summary": "Pod mounts a hostPath volume",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "hostPath is a classic escape and credential theft path.",
      "impact": "Host filesystem access from the pod.",
      "recommendation": "Prefer PVC/CSI; never mount docker.sock into untrusted pods.",
      "complexity": "small",
      "tags": [
        "security",
        "host-path"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "pattern": {
          "pattern": "hostPath:\\s*(?:\\n|\\{)",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "kubernetes.allow-privilege-escalation",
      "title": "allowPrivilegeEscalation not disabled for root or added caps",
      "summary": "allowPrivilegeEscalation not disabled for root or added caps",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Processes can gain more privileges than the parent.",
      "impact": "Privilege escalation inside the container.",
      "recommendation": "Set allowPrivilegeEscalation: false on all containers.",
      "complexity": "small",
      "tags": [
        "security",
        "pss"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "pattern": {
          "pattern": "(?:runAsUser:\\s*0|capabilities:[\\s\\S]{0,80}add:)(?![\\s\\S]{0,200}allowPrivilegeEscalation:\\s*false)",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "kubernetes.run-as-root",
      "title": "Container explicitly runs as root",
      "summary": "Container explicitly runs as root",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Root in container increases escape impact.",
      "impact": "Broader host impact on escape.",
      "recommendation": "Run as non-root; set runAsNonRoot: true.",
      "complexity": "small",
      "tags": [
        "security",
        "root"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "pattern": {
          "pattern": "(?:runAsUser:\\s*0\\b|runAsNonRoot:\\s*false)",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "kubernetes.sys-admin-without-drop-all",
      "title": "SYS_ADMIN is added without dropping default capabilities",
      "summary": "SYS_ADMIN is added without dropping default capabilities",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Setting privileged to false does not remove Linux capabilities, and adding SYS_ADMIN without first dropping the defaults leaves more privileges than the manifest explicitly requests.",
      "impact": "A compromised process retains the runtime's default capability set in addition to broad node-level SYS_ADMIN powers.",
      "recommendation": "Drop ALL capabilities before adding back only the capabilities the container requires.",
      "complexity": "small",
      "tags": [
        "security",
        "capabilities",
        "least-privilege"
      ],
      "match": {
        "kind": "indented-block-missing-content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "blockStart": {
          "pattern": "^[ \\t]*securityContext:\\s*$",
          "flags": "im"
        },
        "trigger": {
          "pattern": "(?:privileged:\\s*false[\\s\\S]*capabilities:[\\s\\S]*add:[\\s\\S]*-\\s*SYS_ADMIN\\b|capabilities:[\\s\\S]*add:[\\s\\S]*-\\s*SYS_ADMIN\\b[\\s\\S]*privileged:\\s*false)",
          "flags": "i"
        },
        "required": {
          "pattern": "drop:\\s*(?:\\[[^\\]]*[\\\"']?ALL[\\\"']?[^\\]]*\\]|(?:\\r?\\n\\s*-\\s*ALL\\b))",
          "flags": "i"
        }
      }
    },
    {
      "id": "kubernetes.mutable-image",
      "title": "Image uses latest or has no tag/digest",
      "summary": "Image uses latest or has no tag/digest",
      "category": "supply-chain",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Floating tags make deploys non-reproducible.",
      "impact": "Unexpected image content on redeploy.",
      "recommendation": "Pin images by version tag or digest.",
      "complexity": "small",
      "tags": [
        "supply-chain",
        "image"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "pattern": {
          "pattern": "image:\\s*[\\\"']?[^\\\"'\\s:@]+(?::latest)?[\\\"']?\\s*(?:$|#)",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "kubernetes.selector-template-mismatch",
      "title": "Workload selector does not match pod template",
      "summary": "Workload selector does not match pod template",
      "category": "correctness",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "A controller's matchLabels must be present with the same values on its pod template.",
      "impact": "Kubernetes rejects the workload, preventing it from being created or updated.",
      "recommendation": "Make every spec.selector.matchLabels entry match the corresponding spec.template.metadata.labels entry.",
      "complexity": "trivial",
      "tags": [
        "kubernetes",
        "selector",
        "workload"
      ],
      "match": {
        "kind": "selector-template-mismatch",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ]
      }
    },
    {
      "id": "kubernetes.wildcard-rbac",
      "title": "Role grants wildcard verbs and resources",
      "summary": "Role grants wildcard verbs and resources",
      "category": "permissions",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Wildcard RBAC is near-admin on the API group scope.",
      "impact": "Over-broad cluster or namespace power.",
      "recommendation": "Enumerate exact resources and verbs.",
      "complexity": "small",
      "tags": [
        "permissions",
        "rbac"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "pattern": {
          "pattern": "(?:verbs|resources):\\s*\\[[^\\]]*[\\\"']?\\*[\\\"']?",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "kubernetes.secret-in-configmap",
      "title": "ConfigMap carries credential-shaped values",
      "summary": "ConfigMap carries credential-shaped values",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "ConfigMaps are not Secrets and are widely readable.",
      "impact": "Credentials leak via casual kubectl dumps.",
      "recommendation": "Move credentials to a Secret or external secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "configmap"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.yml",
          "**/*.yaml"
        ],
        "pattern": {
          "pattern": "kind:\\s*ConfigMap[\\s\\S]{0,400}(?:password|token|secret|api[_-]?key)\\s*:\\s*[\\\"']?[A-Za-z0-9/+=_\\-]{12,}",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
