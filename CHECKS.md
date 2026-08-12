> **Shipped in 0.0.4:** , , , , , , , , 
>
> Rules documented below that are not in that list are deferred (not yet in `src/spec.ts`).

# Checks — what kubernetes detects

This file is the **public audit list** of detectors for the **kubernetes** adversary. If a rule id appears here, it is part of the product surface: high-confidence workload isolation and image integrity defects with file:line evidence in Kubernetes YAML/JSON manifests.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** Kubernetes API objects (`Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `ReplicaSet`, and pod templates nested in them), plus `PodSecurityPolicy` / `SecurityContext` / `ServiceAccount` binding when present. Service objects without pod specs stay out of scope; ConfigMaps are scanned only for credential-shaped data (`kubernetes.secret-in-configmap`).

**Precision stance:** Prefer silence on dev-only manifests under clear paths (`**/testdata/**`, `**/examples/**` optional) only when path heuristics are reliable; otherwise report consistently and let owners path-filter. Do not flag missing resource requests alone (noisy). Do flag privileged + host mounts.

Public grounding: Kubernetes security documentation, NSA/CISA Kubernetes Hardening Guide patterns, and recurring misconfig classes (privileged pods, hostPath, mutable tags) seen across public charts and cluster audits.

---

## Critical

### `kubernetes.privileged`

| | |
| --- | --- |
| **What** | Container or pod runs with `privileged: true` |
| **Why** | Privileged containers effectively get host-level capabilities; container escape becomes trivial |
| **Looks for** | `securityContext.privileged: true` on pod or container |
| **Stays quiet when** | Field absent or false; `allowPrivilegeEscalation: false` alone does **not** suppress if privileged is true |
| **Public examples** | NSA/CISA Kubernetes Hardening Guide; countless “privileged: true” defaults in older DaemonSet examples; cluster breakouts starting from privileged workloads |
| **Remediation** | Drop privileged; grant only needed capabilities via `capabilities.add` |

### `kubernetes.host-pid-or-network`

| | |
| --- | --- |
| **What** | Pod shares host PID, IPC, or network namespace |
| **Why** | Breaks container isolation; enables host process visibility and port binding |
| **Looks for** | `hostPID: true`, `hostIPC: true`, or `hostNetwork: true` on pod spec |
| **Stays quiet when** | All false/absent |
| **Public examples** | Documented as high-risk in Kubernetes security docs; common in “node agent” tutorials that over-share namespaces |
| **Remediation** | Remove host namespaces unless a node agent truly requires them—and isolate those agents |

### `kubernetes.cluster-admin-binding`

| | |
| --- | --- |
| **What** | RoleBinding/ClusterRoleBinding references `cluster-admin` for a workload ServiceAccount |
| **Why** | Full cluster control from any pod using that SA |
| **Looks for** | `kind: ClusterRoleBinding` / `RoleBinding` with `roleRef.name: cluster-admin` and subjects including `ServiceAccount` |
| **Stays quiet when** | Subjects are human `User`/`Group` in clearly labeled bootstrap/admin manifests; any `ServiceAccount` subject always fires |
| **Public examples** | Kubernetes RBAC good practices; frequent audit finding “workload SA bound to cluster-admin” |
| **Remediation** | Create least-privilege Role/ClusterRole for the app |

---

## High

### `kubernetes.host-path`

| | |
| --- | --- |
| **What** | Volume mounts host filesystem via `hostPath` |
| **Why** | Read/write hostPath is a classic container-escape and host credential theft path |
| **Looks for** | `volumes[].hostPath` especially paths like `/`, `/etc`, `/var/run/docker.sock`, `/var/lib/kubelet`, `/home` |
| **Stays quiet when** | No hostPath; or hostPath is a well-known read-only path **and** mount is `readOnly: true` for non-sensitive paths (e.g. `/etc/ssl/certs`)—still fire on docker.sock and root paths always |
| **Public examples** | Docker socket mounts in public k8s examples; hostPath CVEs and escape writeups |
| **Remediation** | Prefer emptyDir, PVC, CSI; never mount docker.sock into untrusted pods |

### `kubernetes.allow-privilege-escalation`

| | |
| --- | --- |
| **What** | `allowPrivilegeEscalation` not set false (defaults true) on containers that also add capabilities or run as root |
| **Why** | Processes can gain more privileges than the parent |
| **Looks for** | Missing `allowPrivilegeEscalation: false` when `runAsUser: 0` or `capabilities.add` is present |
| **Stays quiet when** | Explicit `allowPrivilegeEscalation: false`; or non-root without added caps |
| **Public examples** | Pod Security Standards (baseline/restricted); PSS restricted requires false |
| **Remediation** | Set `allowPrivilegeEscalation: false` on all containers |

### `kubernetes.run-as-root`

| | |
| --- | --- |
| **What** | Container explicitly runs as UID 0 without justification markers |
| **Why** | Root in container increases escape impact |
| **Looks for** | `runAsUser: 0` or `runAsNonRoot: false` |
| **Stays quiet when** | `runAsNonRoot: true` or `runAsUser` ≥ 1; absence alone is medium-only (many charts omit—prefer fire when combined with writable root FS or privileged-adjacent settings) |
| **Public examples** | Pod Security Standards restricted profile |
| **Remediation** | Run as non-root; set `runAsNonRoot: true` |

### `kubernetes.mutable-image`

| | |
| --- | --- |
| **What** | Production image reference uses `:latest` or untagged floating tag without digest |
| **Why** | Tags move; deploys become non-reproducible and supply-chain fragile |
| **Looks for** | `image:` values ending in `:latest` or with no tag and no digest; exclude `imagePullPolicy: Never` local dev only when clearly local |
| **Stays quiet when** | Any explicit version tag or `@sha256:` digest is present — recommend digests in remediation, but do not flag versioned tags (that would fire on most production manifests) |
| **Public examples** | Kubernetes image best practices; supply-chain guidance to pin digests |
| **Remediation** | Pin by digest; use admission policy to ban `:latest` |

### `kubernetes.selector-template-mismatch`

| | |
| --- | --- |
| **What** | A workload's `spec.selector.matchLabels` cannot match its pod template labels |
| **Why** | Kubernetes rejects Deployments, StatefulSets, DaemonSets, and ReplicaSets whose selectors do not match their templates |
| **Looks for** | A selector label that is missing from `spec.template.metadata.labels` or has a different value |
| **Stays quiet when** | Every explicit `matchLabels` entry matches; the template has extra labels; only `matchExpressions` are used; or the object is not a supported workload |
| **Public examples** | [Kubernetes review showing the API rejection](https://github.com/kubernetes/kubernetes/pull/6807#discussion_r28971809); [core maintainer explaining the selector/template invariant](https://github.com/kubernetes/kubernetes/pull/6807#discussion_r28979581) |
| **Remediation** | Synchronize `spec.selector.matchLabels` with the corresponding pod-template labels |

### `kubernetes.wildcard-rbac`

| | |
| --- | --- |
| **What** | Role/ClusterRole grants `verbs: ["*"]` and `resources: ["*"]` |
| **Why** | Equivalent to broad admin on the API group scope |
| **Looks for** | RBAC rules with wildcard verbs and resources |
| **Stays quiet when** | Wildcards are limited to non-sensitive resources with read-only verbs only if both are not `*` |
| **Public examples** | [Prisma/Cortex “wildcard use is not minimized”](https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/ensure-minimized-wildcard-use-in-roles-and-clusterroles); Helm chart audits |
| **Remediation** | Enumerate exact resources and verbs |

### `kubernetes.secret-in-configmap`

| | |
| --- | --- |
| **What** | ConfigMap `data` carries credential-shaped values (passwords, tokens, keys) |
| **Why** | ConfigMaps are not Secrets: no encryption-at-rest integration, broader RBAC read access, and they appear in casual `kubectl get cm -o yaml` dumps |
| **Looks for** | `kind: ConfigMap` data keys matching `password\|token\|secret\|credential` with non-placeholder values (length/entropy gate) |
| **Stays quiet when** | Values are templated (`{{ }}`, `${VAR}`), empty, or obvious placeholders (`changeme`); config words that merely contain the keyword (`keyspace`, `host_key_algorithms`) with low-entropy values |
| **Public examples** | Kubernetes docs state ConfigMaps “do not provide secrecy”; DB passwords in ConfigMaps are a recurring audit finding |
| **Remediation** | Move to a Secret (or external secret manager) and reference via `secretKeyRef` |

---

## Medium

### `kubernetes.capabilities-sysadmin`

| | |
| --- | --- |
| **What** | Adds `SYS_ADMIN`, `NET_ADMIN`, or `SYS_PTRACE` capabilities |
| **Why** | Dangerous capabilities approach privileged mode |
| **Looks for** | `capabilities.add` containing those caps |
| **Stays quiet when** | Only benign caps (`NET_BIND_SERVICE`, `CHOWN`) or drop-all |
| **Public examples** | Linux capability-based breakouts; K8s hardening guides |
| **Remediation** | Drop all; add minimal caps only |

### `kubernetes.automount-sa-token`

| | |
| --- | --- |
| **What** | Pod automounts service account token when not needed |
| **Why** | Stolen token is cluster API credential |
| **Looks for** | `automountServiceAccountToken: true` or absent (default true) **on pods that also have privileged/hostPath** (co-occurrence to reduce noise) |
| **Stays quiet when** | `automountServiceAccountToken: false`; or workload clearly needs K8s API with least-privilege SA |
| **Public examples** | K8s security annotations guidance; token theft post-exploitation paths |
| **Remediation** | Set `automountServiceAccountToken: false` when API access is unused |

### `kubernetes.secrets-as-env-from-all`

| | |
| --- | --- |
| **What** | Entire Secret projected into env via `envFrom.secretRef` |
| **Why** | Over-exposes secrets to process environment and child procs. Advisory: this pattern is widespread and often acceptable — keep severity low and lead with the `secretKeyRef` alternative |
| **Looks for** | `envFrom` with `secretRef` |
| **Stays quiet when** | Individual `secretKeyRef` for specific keys |
| **Public examples** | 12-factor vs secret-env debates; env dumping incidents |
| **Remediation** | Mount specific keys; prefer files with restricted mode |

---

## Out of scope

| Concern | Owner |
| --- | --- |
| Helm chart templating / Chart.yaml deps | `helm` |
| Terraform `kubernetes_*` resources | `terraform` (manifests still in scope here if rendered YAML) |
| Dockerfile build | `container/dockerfile` |
| Generic secret literals | `security/secrets` |
