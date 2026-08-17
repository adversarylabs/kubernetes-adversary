# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `kubernetes.allow-privilege-escalation` | High | `allowPrivilegeEscalation` not set false (defaults true) on containers that also add capabilities or run as root |
| `kubernetes.cluster-admin-binding` | Critical | RoleBinding/ClusterRoleBinding references `cluster-admin` for a workload ServiceAccount |
| `kubernetes.host-path` | High | Volume mounts host filesystem via `hostPath` |
| `kubernetes.host-pid-or-network` | Critical | Pod shares host PID, IPC, or network namespace |
| `kubernetes.mutable-image` | High | Production image reference uses `:latest` or untagged floating tag without digest |
| `kubernetes.privileged` | Critical | Container or pod runs with `privileged: true` |
| `kubernetes.run-as-root` | High | A Pod or Pod-template workload explicitly selects UID 0 for an effective container security context |
| `kubernetes.secret-in-configmap` | High | ConfigMap `data` carries credential-shaped values (passwords, tokens, keys) |
| `kubernetes.selector-template-mismatch` | High | A workload's `spec.selector.matchLabels` cannot match its pod template labels |
| `kubernetes.sys-admin-without-drop-all` | High | SYS_ADMIN is added without dropping default capabilities |
| `kubernetes.wildcard-rbac` | High | Role/ClusterRole grants `verbs: ["*"]` and `resources: ["*"]` |
