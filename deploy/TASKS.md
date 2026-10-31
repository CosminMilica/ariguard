# deploy — Tasks

Dev environment + Kubernetes manifests. See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 0 — Local dev environment
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[~]` DEP-0.1 | `make dev-up`: provision a Linux VM on macOS (Lima/multipass) | — | VM with kernel ≥ 5.7, BTF, `CONFIG_BPF_LSM` |
| `[~]` DEP-0.2 | kind single-node cluster inside the VM | DEP-0.1 | `kubectl get nodes` works |

> DEP-0.1/0.2: `deploy/lima/statewall.yaml` + `make dev-up`/`dev-down` authored and wired
> (Ubuntu 24.04, toolchain provisioning, BPF LSM cmdline, kind cluster). Not yet run —
> needs `brew install lima` on the host, then `make dev-up`. Flip to `[x]` once the VM
> boots with BTF + `bpf` in the active LSM list and `kubectl get nodes` works.
| `[ ]` DEP-0.3 | Build + load component images into kind | DEP-0.2 | images available to the cluster |

## Phase 1 — Agent workload
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` DEP-1.1 | Agent DaemonSet (privileged, hostPID, bpf/cgroup mounts) | DEP-0.3, AGT-1.1 | agent runs on every node |

## Phase 3 — Control plane
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` DEP-3.1 | control-plane Deployment + RBAC + CRD install (kustomize) | CP-3.1 | operator reconciles in-cluster |

## Phase 4 — Baseline for comparison
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` DEP-4.1 | Install Falco (and/or Tetragon) for head-to-head measurement | DEP-0.3 | baseline tool running alongside |
