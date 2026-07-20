export const spec = {
    "id": "kubernetes",
    "displayName": "Kubernetes",
    "description": "Reviews Kubernetes manifests for workload isolation, image integrity, and host access.",
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
            "whyItMatters": "Container runs privileged weakens an important security boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Remove privileged mode and grant only required capabilities.",
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
            "id": "kubernetes.host-path",
            "title": "Pod mounts a hostPath volume",
            "summary": "Pod mounts a hostPath volume",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Pod mounts a hostPath volume weakens an important security boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Replace hostPath with a scoped volume or a constrained read-only path.",
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
            "id": "kubernetes.mutable-image",
            "title": "Workload image uses a mutable tag",
            "summary": "Workload image uses a mutable tag",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Workload image uses a mutable tag weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Pin production images by digest.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "mutable-image"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.yml",
                    "**/*.yaml"
                ],
                "pattern": {
                    "pattern": "image:\\s*[^\\s]+:(?:latest|main|edge)\\b",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};
