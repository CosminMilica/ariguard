# Real-attack testbed

Credible evaluation: run a **real exploit against a real vulnerable app** and measure what the
in-kernel FSM actually detects — as opposed to the synthetic drivers in
[`testdata/workloads/`](../../testdata/workloads/), which hand-walk the exact syscalls each rule
watches. The synthetic drivers stay the CI gate (fast, deterministic); this testbed is the
efficacy evidence and is **never run in CI** (it executes a real exploit).

See the plan and task IDs (T1/T2/T3) in [`docs/backlog.md`](../../docs/backlog.md).

## Scenarios

Two real web-RCE escapes that bracket the privilege spectrum — same container-escape kill-chain,
two outcomes decided by the privilege the RCE lands with.

**Slice 1 — web RCE as an unprivileged user (DVWA).**
```
HTTP command-injection (DVWA)  ->  www-data shell  ->  recon  ->  escape chain (stalls)
```
www-data has no `CAP_SYS_ADMIN` even in a privileged pod; the OS stops the escape and AriGuard
detects the *attempt* (reaches `escalating`). See [`RESULTS.md`](RESULTS.md).

**Slice 2 — web RCE as root (common misconfiguration).**
```
HTTP command-injection (root app)  ->  root shell  ->  recon  ->  escape chain (completes)
```
The chain completes to `compromised`; under `--enforce` the terminal step is killed
synchronously (`enforced=true`, payload never runs). See [`RESULTS-root.md`](RESULTS-root.md).

In both, every post-exploit command travels over the web RCE, so the FSM never sees a
hand-written attack pod — it sees the app spawning the escape syscalls inside the target's cgroup.

## Layout

| Path | What |
|---|---|
| `app/dvwa.yaml` | slice 1 target: DVWA + MariaDB (runs as www-data), `privileged` + `hostPID` |
| `app/vuln-root.yaml` | slice 2 target: a command-injection web app running as **root**, `privileged` + `hostPID` |
| `exploit/escape-via-rce.sh` | slice 1 exploit: DVWA command-injection over HTTP, then the escape chain |
| `exploit/escape-as-root.sh` | slice 2 exploit: root-app command-injection, then the full escape chain |
| `run.sh` | slice 1 runner: agent detect-only → DVWA → exploit → `RESULTS.md` |
| `run-root.sh` | slice 2 runner: root app, detect then enforce → `RESULTS-root.md` |
| `RESULTS.md`, `RESULTS-root.md` | generated baselines (transcript + agent audit + analysis) |

## Run

From the host with the exported kubeconfig, or in the VM with the kind context:

```sh
KUBECONFIG=~/.kube/ariguard-dev.yaml ./run.sh         # slice 1 (detect)
KUBECONFIG=~/.kube/ariguard-dev.yaml ./run-root.sh    # slice 2 (detect + enforce)
```

## Notes

- **Isolated cluster only.** `privileged` + `hostPID` + a real exploit. Authorized security
  research on our own tool; do not point it at anything else.
- **Detect-only.** This slice measures detection; the chain is allowed to complete so every
  reached state is visible. Enforcement is tested separately.
- **kind caveat.** kindnet does not enforce NetworkPolicy, so Tier C1 quarantine is created but
  not network-enforced here (see [`docs/architecture.md`](../../docs/architecture.md)).
- **Cleanup.** `kubectl delete ns ariguard-testbed`.
