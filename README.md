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

## Automatic detection

`adversary auto` selects the kubernetes adversary when changes include `k8s/**/*.yml` or `k8s/**/*.yaml`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.
