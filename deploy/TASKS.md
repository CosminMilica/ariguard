# deploy — Tasks

Dev environment + Kubernetes manifests. See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 0 — Local dev environment
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` DEP-0.1 | `make dev-up`: provision a Linux VM on macOS (Lima/multipass) | — | VM with kernel ≥ 5.7, BTF, `CONFIG_BPF_LSM` |
| `[x]` DEP-0.2 | kind single-node cluster inside the VM | DEP-0.1 | `kubectl get nodes` works |
| `[x]` DEP-0.4 | Host access: fixed API port 16443 + `make kubeconfig` (kubectl / Lens) | DEP-0.2 | host `kubectl get nodes` works |
| `[x]` DEP-0.3 | Build + load component images into kind (`make image kind-load`; run in the VM) | DEP-0.2 | images available to the cluster; verified by ci-e2e (builds + loads the agent image each run) |

## Phase 1 — Agent workload
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` DEP-1.1 | Agent DaemonSet (privileged, hostPID, bpf/cgroup mounts) (`deploy/k8s`; run in the VM) | DEP-0.3, AGT-1.1 | agent runs on every node; verified by ci-e2e (DaemonSet ready in detect + enforce overlays) |

## Phase 3 — Control plane
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` DEP-3.1 | control-plane Deployment + RBAC + CRD install (kustomize) | CP-3.1 | operator reconciles in-cluster |

## Phase 4 — Baseline for comparison
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` DEP-4.1 | Install Falco (and/or Tetragon) for head-to-head measurement | DEP-0.3 | baseline tool running alongside |
