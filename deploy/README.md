# deploy — dev environment & manifests

## Local dev VM (macOS)

Statewall's kernel work needs Linux. On macOS we run a [Lima](https://lima-vm.io/) VM
(Ubuntu 24.04, kernel 6.8 with BTF and BPF LSM) with the full toolchain pre-installed.

### Prerequisites (host)

```sh
brew install lima        # provides limactl
```

### Bring it up

```sh
make dev-up              # start VM, apply BPF LSM cmdline, create kind cluster
limactl shell statewall  # enter the VM; the repo is mounted at the same path
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
make kubeconfig          # writes ~/.kube/statewall-dev.yaml
KUBECONFIG=~/.kube/statewall-dev.yaml kubectl get nodes
```

In Lens: *Add Cluster → from kubeconfig file* and pick `~/.kube/statewall-dev.yaml`.

### Tear down

```sh
make dev-down            # delete kind cluster, stop & delete the VM
```

## Layout

| Path | Purpose |
|---|---|
| `lima/statewall.yaml` | VM definition + toolchain provisioning (Go, Rust+bpf-linker, buf, kind, kubectl, docker, bpftool) |
| `kind/cluster.yaml` | single-node kind cluster config |
| `k8s/` | DaemonSet + operator manifests (phase 1 / 3) |

The VM mounts `~/work/statewall` writable; edit on the host, build in the VM. Adjust the
mount in `lima/statewall.yaml` if your checkout lives elsewhere.
