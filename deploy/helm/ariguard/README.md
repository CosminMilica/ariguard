# AriGuard Helm chart

Deploys the whole app with one command: the **agent** (privileged DaemonSet that
loads the eBPF engine + rules into each node's kernel) and, optionally, the
**console** (backend + SQLite + frontend). Images are pulled from GHCR.

## Prerequisites
- Kubernetes ≥ 1.25, nodes on Linux kernel ≥ 5.7 with BTF (`/sys/kernel/btf/vmlinux`).
- The agent runs `privileged` with `hostPID` and host mounts (`/sys/fs/bpf`,
  `/sys/kernel/tracing`, `/sys/kernel/debug`, `/sys/fs/cgroup`) — it needs a
  PodSecurity `privileged` namespace (the chart labels it).
- Public images on `ghcr.io/cosminmilica` (or override `image.registry`).

## Install

```sh
helm upgrade --install ariguard deploy/helm/ariguard -n ariguard-system --create-namespace
```

> The agent is `privileged`. On a cluster that enforces PodSecurity, label the
> namespace first: `kubectl label ns ariguard-system pod-security.kubernetes.io/enforce=privileged`.

Agent-only (no console):

```sh
helm upgrade --install ariguard deploy/helm/ariguard -n ariguard-system \
  --set console.enabled=false
```

Detect mode (observe, no kill):

```sh
helm upgrade --install ariguard deploy/helm/ariguard -n ariguard-system \
  --set agent.enforce=false
```

## Access the console

```sh
# default (expose: none) — port-forward:
kubectl -n ariguard-system port-forward svc/ariguard-console-frontend 8080:80
# then open http://localhost:8080

# or expose it directly:
helm upgrade --install ariguard deploy/helm/ariguard -n ariguard-system \
  --set console.expose=nodePort           # NodePort on the frontend
# or
  --set console.expose=ingress --set console.ingress.host=ariguard.example.com
```

## Values

| Key | Default | Description |
|---|---|---|
| `image.registry` | `ghcr.io/cosminmilica` | image registry/namespace |
| `image.tag` | `""` → `Chart.appVersion` | tag for all three images |
| `image.pullPolicy` | `IfNotPresent` | pull policy |
| `agent.image` | `ariguard-agent` | agent image name |
| `agent.enforce` | `true` | `true` = kill at the terminal step; `false` = observe only |
| `agent.sinkUrl` | `""` | where the agent pushes audit; empty + console on → the console backend svc |
| `agent.resources` | small requests | agent container resources |
| `console.enabled` | `true` | deploy the console (false = agent only) |
| `console.backend.image` | `ariguard-console-backend` | backend image name |
| `console.frontend.image` | `ariguard-console-frontend` | frontend image name |
| `console.storage.size` | `1Gi` | SQLite PVC size |
| `console.storage.storageClassName` | `""` | PVC storage class (empty = default) |
| `console.expose` | `none` | `none` \| `nodePort` \| `ingress` |
| `console.nodePort.port` | — | pin a NodePort when `expose=nodePort` |
| `console.ingress.{host,className,annotations,tls}` | `ariguard.local` | Ingress settings when `expose=ingress` |
| `namespace` | `ariguard-system` | install namespace |

## What gets created
- `ServiceAccount`, `ClusterRole` (+binding) for pod list/watch.
- `DaemonSet` `ariguard-agent` (privileged; loads the baked-in BPF object + policy).
- When `console.enabled`: `ariguard-console-backend` (Deployment + Service + PVC)
  and `ariguard-console-frontend` (Deployment + Service), plus a NodePort/Ingress
  when `console.expose` is set.

## Upgrade / uninstall

```sh
helm upgrade ariguard deploy/helm/ariguard -n ariguard-system --set agent.enforce=true
helm uninstall ariguard -n ariguard-system
```

## Notes
- The eBPF object and compiled rules are **baked into the agent image** — there is
  no separate BPF deployment; the agent loads them at startup.
- Policy can be hot-swapped in place (SIGHUP) without reloading the programs.
- Make targets: `make helm-lint`, `make helm-template`, `make helm-package`,
  `make helm-install`, `make helm-uninstall`.
