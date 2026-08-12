# kubernetes

**kubernetes** reviews Kubernetes manifests for **workload isolation, selector integrity, RBAC overprivilege, and floating images**.

It is a **workload isolation reviewer**, not a cluster runtime scanner. When it reports, a pod or binding likely weakens host or API isolation.

## What it does

1. **Discovers** Kubernetes YAML/JSON manifests.
2. **Runs deterministic detectors** for securityContext, hostPath, RBAC, and image tags.
3. **Synthesizes a review** with file:line evidence.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)**.

Highlights:

| Area | Examples |
| --- | --- |
| Workloads | privileged, hostPID/IPC/Network, hostPath, selector/template mismatches |
| Identity | cluster-admin ServiceAccount bindings |
| Images | :latest / untagged images |
| RBAC / secrets | wildcard verbs; credentials in ConfigMaps |

### Ownership boundaries

| Concern | Owned by |
| --- | --- |
| Helm chart packaging | [`helm`](https://github.com/adversarylabs/helm-adversary) |
| Terraform kubernetes_* resources | [`terraform`](https://github.com/adversarylabs/terraform-adversary) |
| Generic secret scanning | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire.
- Prefer missing a weak signal over a false positive on normal production code.
