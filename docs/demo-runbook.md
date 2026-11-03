# Demo runbook

Reproducible steps to show AriGuard detecting and blocking a **real** web-RCE container escape, for
the thesis defense. Everything runs on the local Lima VM + kind cluster; no external services.

## 0. Prerequisites

- Lima VM `statewall` running (`limactl list` shows it), with the repo mounted at the same host path.
- A kind cluster inside the VM (node `statewall-dev-control-plane`).
- Host kubeconfig exported once: `make kubeconfig` → `~/.kube/ariguard-dev.yaml`.

```sh
export KUBECONFIG=~/.kube/ariguard-dev.yaml
kubectl get nodes          # statewall-dev-control-plane Ready
```

> **Cluster-name caveat.** The kind cluster is named **`statewall-dev`**, but the Makefile's
> `kind-load` target hardcodes `--name ariguard-dev`. Load images with the real name:
> `kind load docker-image <img> --name statewall-dev` (not `make kind-load`). The in-VM kube
> context is `kind-statewall-dev` (pass `ARIGUARD_KUBE_CONTEXT=kind-statewall-dev` to the e2e tests).

## 1. Build + load the agent image (in the VM)

```sh
limactl shell statewall
cd <repo>                       # same path as the host
make build-agent build-bpf      # Go agent + Rust eBPF object
make image                      # ariguard-agent:dev (linux/arm64)
kind load docker-image ariguard-agent:dev --name statewall-dev
exit
```

The committed `testdata/golden/policy-full.bin` (7 rules) is baked into the image.

## 2. The demo — real web RCE → container escape

The testbed drives a real exploit over HTTP (no hand-written attack pod): the FSM sees the app
spawning the escape syscalls in its own cgroup. Two scenarios bracket the privilege spectrum.

### Slice 1 — RCE as an unprivileged user (DVWA)

```sh
KUBECONFIG=~/.kube/ariguard-dev.yaml LOCAL_PORT=8099 tests/testbed/run.sh
cat tests/testbed/RESULTS.md
```

Show: `container-escape` fires on real RCE-driven syscalls and reaches **`escalating`**, then the OS
blocks `setns`/`mount` for `www-data` (no `CAP_SYS_ADMIN` even in a privileged pod). AriGuard
**detects the attempt**; reverse-shell false positives are **0** (loopback/AF_UNIX ignored by
`PATH_INET`).

### Slice 2 — RCE as root (detect, then enforce + isolate)

```sh
KUBECONFIG=~/.kube/ariguard-dev.yaml LOCAL_PORT=8099 tests/testbed/run-root.sh
cat tests/testbed/RESULTS-root.md
```

Show, in order:
- **Detect:** the full chain completes to **`compromised`** (`openat`→`setns`→`fsmount`→`execve`).
- **Enforce:** the terminal `execve` comes back `enforced=true` — killed **synchronously** (the
  exploit transcript's step 4 prints nothing: the payload never ran).
- **Isolation (Tier C1):** the pod is autonomously quarantined — label `ariguard.io/quarantine=true`
  + a deny-all `NetworkPolicy/ariguard-quarantine`, with no operator in the loop.

## 3. The console

```sh
kubectl -n ariguard-system port-forward svc/ariguard-console-frontend 8080:80
# http://localhost:8080
```

Point at: **Triage/Incidents** (the `ISOLATED` badge), **Timeline** (the chain's states in order),
**Actors** (the compromised image as one actor, with its C2 `dst_ip`s), **Coverage** (ATT&CK ×
hooks), **Performance**.

## 4. Cleanup

```sh
kubectl delete ns ariguard-testbed
kubectl apply -k deploy/k8s/overlays/detect   # agent back to detect-only
```

## Notes

- **kindnet** does not enforce NetworkPolicy, so Tier C1's quarantine object is created but traffic
  is not actually cut here; a Cilium/Calico CNI would enforce it, or `--isolate-fallback=evict` cuts
  the network on kindnet by deleting the pod.
- Real exploits run only against this isolated cluster — **never in CI** (CI keeps the deterministic
  synthetic drivers in `testdata/workloads/`).
