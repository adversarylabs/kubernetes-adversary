# Kubernetes adversary

Reviews Kubernetes manifests for workload isolation, selector integrity, RBAC, and image safety.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates authored Kubernetes manifests for workload privilege, host access, identities, RBAC, secrets, selectors, capabilities, and image reproducibility.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns this packaging or orchestration layer. Adjacent container, Kubernetes, Helm, Kustomize, and secret concerns remain with their specialist adversaries.
