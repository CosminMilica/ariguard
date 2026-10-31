# test/e2e — end-to-end gate (detect + enforce)

The CI gate for Phase 2. It builds a fresh agent image, deploys the DaemonSet
into the kind cluster, runs the benign + attack workloads, and asserts from the
three sources of truth: the BPF maps in the VM host kernel (`bpftool`), the audit
JSONL (`check_audit.py`), and Kubernetes pod state / Prometheus metrics.

Runs **inside the Lima VM** against the kind cluster. The matching quick manual
path is `testdata/scripts/phase{1,2}-exit-check.sh`; those stay in place.

## Layout

| File | Purpose |
|---|---|
| `e2e_test.go` | `TestDetectMode`, `TestEnforceMode`, deploy/wait/assert flow |
| `exec.go` | `kubectl` / `bpftool` / `make` runners with timeouts and captured output |
| `bpftool.go` | parse `bpftool map dump -j` (byte-array or BTF-formatted) |

## What it provisions

- Builds `make image kind-load` once per run (fresh image, never cached).
- Deploys `deploy/k8s/overlays/{detect,enforce}` into `ariguard-system`; each
  mode starts from a clean slate (prior namespace deleted and waited gone).
- Creates `ariguard-eval` fresh each mode (pinned by `testdata/expectations.json`
  and the workload manifests — it cannot be randomized without breaking the
  checker), applies `testdata/workloads/{benign,attack}`.

## What it asserts

**Detect (`overlays/detect`)**
- `AG_POLICY`: `enforce == 0`, `num_rules == 3`.
- `AG_RULES`, `AG_TRANSITIONS` non-empty.
- `check_audit.py` (dry-run) exits 0.
- Every attack pod is Running/Succeeded (never Failed) — detection only.
- `ariguard_kills_total == 0`.

**Enforce (`overlays/enforce`)**
- `AG_POLICY`: `enforce == 1`, `num_rules == 3`.
- `AG_RULES`, `AG_TRANSITIONS` non-empty; `AG_PODS` non-empty.
- `check_audit.py --enforce` exits 0 — every attacker's terminal record has
  `enforced=true` and nothing non-attacker is enforced. By decision F5 the kernel
  sets `enforced=1` only when the cgroup is in `AG_PODS`, so this proves per-pod
  attribution and the `AG_PODS` gate end to end (chosen over resolving pod→cgroup
  ids directly, which depends on the node's cgroup-driver layout).
- `ariguard_kills_total` rose by exactly one per attacker (4).
- Benign and `kube-system` pods are neither Failed nor restarted.
- Pod phase `Failed` is required only for `container-escape` and
  `container-escape-connect`. `reverse-seq` and `fileless-seq` run their terminal
  `execve` in a forked child, so `bpf_send_signal(SIGKILL)` kills the child and
  the pod can stay Running; the kill for those is proven by the audit record and
  the kills metric, with pod phase recorded only as a secondary signal.

Maps are read with `sudo bpftool map dump name <MAP> -j` on the node (the
DaemonSet shares the host kernel). `bpftool` is not required inside the pod.

## How to run

```sh
# inside the VM
make ci-e2e
```

`ci-e2e` builds everything fresh (`build-bpf build-agent golden`), then runs the
Go test with `-tags e2e` and `ARIGUARD_REQUIRE_E2E=1`; the test itself runs both
modes (detect then enforce). It needs a kill-capable `bin/ariguard.bpf.o`.

Standalone: `ARIGUARD_REQUIRE_E2E=1 go test -tags e2e -v ./test/e2e` (the test
drives `make image kind-load`, so `bin/ariguard-agent`, `bin/ariguard.bpf.o`
and `testdata/golden/policy.bin` must already be built).

## What must be true in the VM

- kind cluster reachable (`kubectl get nodes`) and kernel BTF at
  `/sys/kernel/btf/vmlinux` — otherwise the test SKIPs, or FAILs under
  `ARIGUARD_REQUIRE_E2E=1`.
- Passwordless `sudo bpftool` (the maps live in the host kernel).
- `bin/ariguard.bpf.o` is the Phase 2 **kill-capable** object, and the
  `KILL` capability / BPF LSM cmdline from `make dev-up` is in effect.
- A single agent instance (one node) so `bpftool map dump name` is unambiguous.

## Environment variables

| Var | Default | Meaning |
|---|---|---|
| `ARIGUARD_REQUIRE_E2E` | unset | `1`: missing prerequisites FAIL instead of SKIP (CI) |
| `ARIGUARD_E2E_ARTIFACTS` | temp dir | where logs, events, descriptions and `AG_*.json` dumps are written |
| `ARIGUARD_E2E_ATTACK_SECONDS` | `30` | settle time after attacks are applied |
| `ARIGUARD_KUBECONFIG` | kubectl default | kubeconfig for the kind cluster |
| `ARIGUARD_KUBE_CONTEXT` | `kind-ariguard-dev` | kube context (empty to omit) |

On teardown the harness always dumps pod logs, `kubectl get events`,
`kubectl describe` of the attack pods, and the `AG_*` map dumps to the artifacts
dir, then deletes `ariguard-eval` and the overlay.
