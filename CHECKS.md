# Initial checks

## kubernetes.privileged

- Severity: critical
- Category: security
- Recommendation: Remove privileged mode and grant only required capabilities.

## kubernetes.host-path

- Severity: high
- Category: security
- Recommendation: Replace hostPath with a scoped volume or a constrained read-only path.

## kubernetes.mutable-image

- Severity: medium
- Category: supply-chain
- Recommendation: Pin production images by digest.

