# deploy — dev environment & manifests

## Local dev VM (macOS)

AriGuard's kernel work needs Linux. On macOS we run a [Lima](https://lima-vm.io/) VM
(Ubuntu 24.04, kernel 6.8 with BTF and BPF LSM) with the full toolchain pre-installed.

### Prerequisites (host)

```sh
brew install lima        # provides limactl
```

### Bring it up

```sh
make dev-up              # start VM, apply BPF LSM cmdline, create kind cluster
limactl shell ariguard  # enter the VM; the repo is mounted at the same path
```

`make dev-up` restarts the VM once so the `lsm=...,bpf` kernel cmdline takes effect —
required to attach BPF LSM programs (phase 2). Verify inside the VM:

```sh
cat /sys/kernel/btf/vmlinux >/dev/null && echo "BTF ok"
grep -o 'bpf' /sys/kernel/security/lsm   # bpf must be listed
```

### Access from the host (kubectl / Lens)

The kind API server listens on `127.0.0.1:16443` in the VM; Lima forwards it to the
host. Export the kubeconfig once per cluster creation:

```sh
make kubeconfig          # writes ~/.kube/ariguard-dev.yaml
KUBECONFIG=~/.kube/ariguard-dev.yaml kubectl get nodes
```

In Lens: *Add Cluster → from kubeconfig file* and pick `~/.kube/ariguard-dev.yaml`.

### Tear down

```sh
make dev-down            # delete kind cluster, stop & delete the VM
```

## Layout

| Path | Purpose |
|---|---|
| `lima/ariguard.yaml` | VM definition + toolchain provisioning (Go, Rust+bpf-linker, buf, kind, kubectl, docker, bpftool) |
| `kind/cluster.yaml` | single-node kind cluster config |
| `docker/Dockerfile` | agent image: binary + BPF object + policy bundle |
| `k8s/base/` | namespace, RBAC, agent DaemonSet (detect-only) |
| `k8s/overlays/detect`, `k8s/overlays/enforce` | enforce overlay appends `--enforce` to the agent args |
| `k8s/overlays/isolate` | enforce + autonomous isolation: appends `--enforce --isolate=on` |
| `demo-escape.sh` | container-escape demo: detect-only, then enforce |

The VM mounts `~/work/ariguard` writable; edit on the host, build in the VM. Adjust the
mount in `lima/ariguard.yaml` if your checkout lives elsewhere.

## Agent image and DaemonSet

```sh
# in the VM
make build-agent build-bpf golden
make image kind-load                 # ariguard-agent:dev, linux/arm64 (IMAGE_PLATFORM to override)
kubectl apply -k deploy/k8s/overlays/detect    # or overlays/enforce
make demo-escape                     # detect-only run, flip --enforce, run again
```

Base image: `ubuntu:24.04`. The agent loads the object with cilium/ebpf (no libbpf, no
runtime dependencies), so `scratch` would work, but ubuntu matches the VM build's glibc
if the binary is dynamically linked, and gives a shell for `kubectl exec` debugging.
Revisit (distroless/scratch) once the image is hardened.

The pod is `privileged: true` with `hostPID: true`, and also lists
`BPF, PERFMON, SYS_ADMIN, SYS_RESOURCE, KILL` explicitly (documentation of what is needed;
`KILL` backs `bpf_send_signal`, `SYS_RESOURCE` the memlock rlimit). Host mounts:
`/sys/fs/cgroup` (ro, pod cgroup ids), `/sys/fs/bpf`, `/sys/kernel/tracing` and
`/sys/kernel/debug` (ro, tracepoint ids). The `ariguard-system` namespace is labelled
Pod Security `privileged`. RBAC: ClusterRole `ariguard-agent` with `list`/`watch` on
`pods`. Metrics: `--metrics-addr=:9102`, port `metrics`, Prometheus scrape annotations.
