# container/kubernetes — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `kubernetes`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Kubernetes YAML

## Mission

Review Kubernetes manifests for workload isolation, selector integrity, RBAC, and image safety.

## In scope (fair miss if humans raised it and we did not)

- Privileged pods, hostPath, hostNetwork
- RBAC overreach
- Mutable image tags
- Workload selectors that do not match pod-template labels

## Out of scope (not a miss for this adversary)

- App source
- Helm-specific chart structure

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
