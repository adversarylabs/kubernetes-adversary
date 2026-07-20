# Kubernetes adversary

Reviews Kubernetes manifests for workload isolation, image integrity, and host access.

## Checks

- **Container runs privileged:** Remove privileged mode and grant only required capabilities.
- **Pod mounts a hostPath volume:** Replace hostPath with a scoped volume or a constrained read-only path.
- **Workload image uses a mutable tag:** Pin production images by digest.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```
