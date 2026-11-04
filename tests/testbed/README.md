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

## More kill-chains

Beyond the two container-escape slices, the testbed exercises the other real kill-chains and
proves they do **not** fire on benign look-alikes:

- **reverse-shell** (`app/reverse-shell.yaml`, `exploit/reverse-shell.sh`) — a command-injectable
  app and an in-cluster listener; the exploit opens a socket back, redirects stdio onto it and
  exec's a shell **in-place** (`connect → dup2 → execve /bin/sh`). The exec must be in the same
  process (`os.execv`, not a fork) for the process-scoped chain to complete; under `--enforce` the
  terminal `execve` is killed (`SIGKILL`, exit 137).
- **lateral movement / F2** (`app/lateral.yaml`, `exploit/lateral.sh`) — a three-tier app across
  two namespaces (`ariguard-testbed/frontend → ariguard-internal/backend → .../db`). RCE on the
  frontend pivots to the internal backend and from there to the db; the agent resolves each
  `connect` destination IP to the target pod and emits observed **pod→pod edges** (one
  cross-namespace), shown on the Network pivots view.
- **benign twins** (`app/benign-twins.yaml`) — a client and a log processor that run the same
  hooks (`openat`, `connect`, `dup2`, `execve`) legitimately. The suite asserts they raise **zero**
  incidents: detection keys on the ordered chain, not the individual syscalls.

## Layout

| Path | What |
|---|---|
| `app/dvwa.yaml` | slice 1 target: DVWA + MariaDB (runs as www-data), `privileged` + `hostPID` |
| `app/vuln-root.yaml` | slice 2 target: a command-injection web app running as **root**, `privileged` + `hostPID` |
| `app/reverse-shell.yaml` | reverse-shell target + attacker listener |
| `app/lateral.yaml` | three-tier app (frontend/backend/db) across two namespaces, for F2 |
| `app/benign-twins.yaml` | benign look-alike workloads (false-positive check) |
| `exploit/escape-via-rce.sh` | slice 1 exploit: DVWA command-injection over HTTP, then the escape chain |
| `exploit/escape-as-root.sh` | slice 2 exploit: root-app command-injection, then the full escape chain |
| `exploit/reverse-shell.sh` | reverse-shell payload (base64-shipped) to the listener |
| `exploit/lateral.sh` | two-hop pivot frontend→backend→db |
| `run.sh` | slice 1 runner: agent detect-only → DVWA → exploit → `RESULTS.md` |
| `run-root.sh` | slice 2 runner: root app, detect then enforce → `RESULTS-root.md` |
| `run-suite.sh` | efficacy suite: every scenario + benign twins → detection/FP table → `RESULTS-suite.md` |
| `RESULTS*.md` | generated baselines (transcript + agent audit + analysis) |

## Efficacy suite

`run-suite.sh` runs every scenario against a running `--enforce --sink-url` agent, reads the
console, and writes a detection / lateral-edge / false-positive table to `RESULTS-suite.md`. It
exits non-zero if any benign twin raised an incident.

```sh
KUBE_CONTEXT=kind-statewall-dev ./run-suite.sh
```

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
